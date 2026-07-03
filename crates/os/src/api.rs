//! The Windows API surface exemu understands, and its native implementations.
//!
//! [`Api`] enumerates the recognized symbols; [`Api::classify`] maps a
//! `(dll, name)` pair to one. [`WinOs::dispatch`] runs the call using the
//! arguments already in guest registers/stack and returns an [`Outcome`]
//! (a return value, or process termination).

use std::collections::VecDeque;

use exemu_core::{CpuState, Memory, Reg, Result};

use crate::{WinOs, HANDLE_PROCESS_HEAP, HANDLE_STDERR, HANDLE_STDIN, HANDLE_STDOUT};

/// The result of servicing an API call.
pub(crate) enum Outcome {
    /// Put this value in `rax` and `ret` to the caller.
    Return(u64),
    /// Terminate the process with this exit code.
    Exit(i32),
    /// The handler has already set `rip`/`rsp` itself (it is driving a
    /// re-entrant guest call). Leave the CPU untouched and keep executing.
    Resume,
}

/// One in-flight `_initterm` invocation: the constructors still to call, the
/// address to return to when they are all done, and the stack pointer at
/// `_initterm` entry (which points at that return address).
pub(crate) struct InittermFrame {
    pub remaining: VecDeque<u64>,
    pub ret: u64,
    pub saved_rsp: u64,
}

/// A queued sequence of guest callbacks (e.g. a dialog proc receiving
/// WM_INITDIALOG then WM_COMMAND). Each entry is `(func, args)`; `args` are
/// passed per the ABI. When the queue drains, control returns to `ret_addr`
/// with `rsp = final_rsp` and the API's result in the accumulator.
pub(crate) struct CbFrame {
    pub remaining: VecDeque<(u64, Vec<u64>)>,
    pub ret_addr: u64,
    pub final_rsp: u64,
    pub result: u64,
    /// A modal dialog loop: when the queue drains, keep pumping the window and
    /// dispatching WM_COMMANDs to the dialog proc until it calls EndDialog
    /// (which sets `dialog_result`); then return that value to the caller.
    pub modal: bool,
}

/// Every Windows symbol the emulator implements natively. Anything else
/// becomes [`Api::Unsupported`] and returns 0.
#[derive(Debug, Clone)]
pub enum Api {
    GetStdHandle,
    WriteFile,
    WriteConsoleA,
    WriteConsoleW,
    ExitProcess,
    TerminateProcess,
    GetCommandLineA,
    GetCommandLineW,
    GetModuleHandleA,
    GetModuleHandleW,
    GetProcessHeap,
    HeapAlloc,
    HeapFree,
    HeapReAlloc,
    VirtualAlloc,
    VirtualFree,
    GetLastError,
    SetLastError,
    GetCurrentProcessId,
    GetCurrentThreadId,
    GetCurrentProcess,
    IsDebuggerPresent,
    Sleep,
    QueryPerformanceCounter,
    QueryPerformanceFrequency,
    GetSystemTimeAsFileTime,
    GetTickCount,
    GetACP,
    SetConsoleCP,
    SetConsoleOutputCP,
    GetConsoleMode,
    SetConsoleMode,
    GetStartupInfoA,
    GetStartupInfoW,
    GetEnvironmentStringsW,
    FreeEnvironmentStringsW,
    LoadLibraryA,
    FreeLibrary,
    GetProcAddress,

    // --- msvcrt C runtime -------------------------------------------------
    Malloc,
    Calloc,
    Realloc,
    Free,
    /// memcpy / memmove (both implemented overlap-safe).
    Memcpy,
    Memset,
    Memcmp,
    Strlen,
    /// The C `exit` family — terminate with the argument.
    CrtExit,
    /// __getmainargs / __wgetmainargs — populate argc/argv/env.
    GetMainArgs,
    /// _initterm / _initterm_e — run a table of initializer callbacks.
    Initterm,
    /// Not an import: the thunk that sequences `_initterm` callbacks.
    InittermDriver,
    /// A CRT startup/teardown hook we can safely no-op, returning 0.
    CrtNoop,
    // C stdio output (routed to the host console).
    Fputs,
    Fputc,
    Fwrite,
    Puts,

    // --- Win32 string helpers (kernel32/user32) ---------------------------
    CharNextA,
    CharNextW,
    CharPrevW,
    LstrlenA,
    LstrlenW,
    LstrcpyW,
    LstrcpynW,
    LstrcatW,
    LstrcmpW,
    LstrcmpiW,
    /// A handle/pointer-returning Win32 stub that must be non-null for the
    /// caller to proceed; returns a fake handle. Carries its stdcall argc.
    FakeHandle { sym: String, argc: u32 },

    // --- Filesystem (host-backed sandbox) ---------------------------------
    CreateFileW,
    ReadFileApi,
    CloseHandle,
    CreateDirectoryW,
    GetTempPathW,
    GetTempFileNameW,
    GetFileSizeApi,
    SetFilePointerApi,
    GetFileAttributesW,
    DeleteFileW,
    GetModuleFileNameW,
    GlobalAlloc,
    GlobalLock,
    GlobalFreeUnlock,
    GetVersion,
    GetVersionEx,
    GetSystemDirectoryW,
    GetWindowsDirectoryW,

    // --- GUI: dialog driving + control text -------------------------------
    /// Not an import: drives a queued sequence of guest callbacks.
    CallbackDriver,
    /// CreateDialogParamW / DialogBoxParamW — invoke the DLGPROC.
    CreateDialogParam { modal: bool },
    SetDlgItemTextW,
    GetDlgItemTextW,
    GetDlgItemApi,
    SendMessageApi,
    SetWindowTextApi,
    GetWindowTextApi,
    GetMessageApi,
    PeekMessageApi,
    IsDialogMessageApi,
    /// COM object creation — we have no COM, so fail cleanly (null out the
    /// interface pointer and return an error HRESULT) instead of returning
    /// S_OK with a null interface, which callers dereference and crash on.
    CoCreateInstanceApi,
    DestroyWindowApi,
    PostQuitMessageApi,
    EndDialogApi,

    // --- custom (CreateWindowEx) windows + GDI ----------------------------
    RegisterClassApi { ex: bool },
    CreateWindowExApi,
    DefWindowProcApi,
    DispatchMessageApi,
    BeginPaintApi,
    EndPaintApi,
    GetClientRectApi,
    FillRectApi,
    RectangleApi,
    TextOutApi,
    SetTextColorApi,
    CreateSolidBrushApi,
    CreatePenApi,
    GetStockObjectApi,
    SelectObjectApi,
    MoveToExApi,
    LineToApi,
    SetPixelApi,
    /// Accepted window/GDI stubs that just return `r` (ShowWindow,
    /// UpdateWindow, TranslateMessage, DeleteObject, ...).
    WinStub { r: u64, argc: u32 },

    /// Not an import: the sentinel return address pushed under the entry
    /// point. If the entry `ret`s here, terminate with the code in EAX.
    ReturnExit,
    /// A recognized-by-shape but unimplemented import (`dll!name`). We still
    /// record its stdcall argument count (from a table) so 32-bit stack
    /// cleanup stays correct even though the behavior is a stub.
    Unsupported { sym: String, argc: u32 },
}

impl Api {
    pub fn classify(dll: &str, name: &str) -> Api {
        match name {
            "GetStdHandle" => Api::GetStdHandle,
            "WriteFile" => Api::WriteFile,
            "WriteConsoleA" => Api::WriteConsoleA,
            "WriteConsoleW" => Api::WriteConsoleW,
            "ExitProcess" => Api::ExitProcess,
            "TerminateProcess" => Api::TerminateProcess,
            "GetCommandLineA" => Api::GetCommandLineA,
            "GetCommandLineW" => Api::GetCommandLineW,
            "GetModuleHandleA" => Api::GetModuleHandleA,
            "GetModuleHandleW" => Api::GetModuleHandleW,
            "GetProcessHeap" => Api::GetProcessHeap,
            "HeapAlloc" => Api::HeapAlloc,
            "HeapFree" => Api::HeapFree,
            "HeapReAlloc" => Api::HeapReAlloc,
            "VirtualAlloc" => Api::VirtualAlloc,
            "VirtualFree" => Api::VirtualFree,
            "GetLastError" => Api::GetLastError,
            "SetLastError" => Api::SetLastError,
            "GetCurrentProcessId" => Api::GetCurrentProcessId,
            "GetCurrentThreadId" => Api::GetCurrentThreadId,
            "GetCurrentProcess" => Api::GetCurrentProcess,
            "IsDebuggerPresent" => Api::IsDebuggerPresent,
            "Sleep" => Api::Sleep,
            "QueryPerformanceCounter" => Api::QueryPerformanceCounter,
            "QueryPerformanceFrequency" => Api::QueryPerformanceFrequency,
            "GetSystemTimeAsFileTime" => Api::GetSystemTimeAsFileTime,
            "GetTickCount" | "GetTickCount64" => Api::GetTickCount,
            "GetACP" => Api::GetACP,
            "SetConsoleCP" => Api::SetConsoleCP,
            "SetConsoleOutputCP" => Api::SetConsoleOutputCP,
            "GetConsoleMode" => Api::GetConsoleMode,
            "SetConsoleMode" => Api::SetConsoleMode,
            "GetStartupInfoA" => Api::GetStartupInfoA,
            "GetStartupInfoW" => Api::GetStartupInfoW,
            "GetEnvironmentStringsW" => Api::GetEnvironmentStringsW,
            "FreeEnvironmentStringsW" => Api::FreeEnvironmentStringsW,
            "LoadLibraryA" => Api::LoadLibraryA,
            "FreeLibrary" => Api::FreeLibrary,
            "GetProcAddress" => Api::GetProcAddress,

            // msvcrt / UCRT C runtime.
            "malloc" => Api::Malloc,
            "calloc" => Api::Calloc,
            "realloc" => Api::Realloc,
            "free" => Api::Free,
            "memcpy" | "memmove" => Api::Memcpy,
            "memset" => Api::Memset,
            "memcmp" => Api::Memcmp,
            "strlen" => Api::Strlen,
            "exit" | "_exit" | "_cexit" | "_c_exit" => Api::CrtExit,
            "__getmainargs" | "__wgetmainargs" => Api::GetMainArgs,
            "_initterm" | "_initterm_e" => Api::Initterm,
            "fputs" => Api::Fputs,
            "fputc" | "putc" | "putchar" => Api::Fputc,
            "fwrite" => Api::Fwrite,
            "puts" => Api::Puts,

            // Win32 string helpers.
            "CharNextA" => Api::CharNextA,
            "CharNextW" => Api::CharNextW,
            "CharPrevW" => Api::CharPrevW,
            "lstrlenA" => Api::LstrlenA,
            "lstrlenW" => Api::LstrlenW,
            "lstrcpyW" | "lstrcpyA" => Api::LstrcpyW,
            "lstrcpynW" | "lstrcpynA" => Api::LstrcpynW,
            "lstrcatW" | "lstrcatA" => Api::LstrcatW,
            "lstrcmpW" | "lstrcmpA" => Api::LstrcmpW,
            "lstrcmpiW" | "lstrcmpiA" => Api::LstrcmpiW,

            // Filesystem.
            "CreateFileW" => Api::CreateFileW,
            "ReadFile" => Api::ReadFileApi,
            "CloseHandle" => Api::CloseHandle,
            "CreateDirectoryW" => Api::CreateDirectoryW,
            "GetTempPathW" => Api::GetTempPathW,
            "GetTempFileNameW" => Api::GetTempFileNameW,
            "GetFileSize" => Api::GetFileSizeApi,
            "SetFilePointer" => Api::SetFilePointerApi,
            "GetFileAttributesW" => Api::GetFileAttributesW,
            "DeleteFileW" => Api::DeleteFileW,
            "GetModuleFileNameW" | "GetModuleFileNameA" => Api::GetModuleFileNameW,
            "GetVersion" => Api::GetVersion,
            "GetVersionExW" | "GetVersionExA" => Api::GetVersionEx,
            "GetSystemDirectoryW" => Api::GetSystemDirectoryW,
            "GetWindowsDirectoryW" | "GetSystemWindowsDirectoryW" => Api::GetWindowsDirectoryW,

            // GUI dialog driving.
            "CreateDialogParamW" => Api::CreateDialogParam { modal: false },
            "DialogBoxParamW" => Api::CreateDialogParam { modal: true },
            "SetDlgItemTextW" => Api::SetDlgItemTextW,
            "GetDlgItemTextW" => Api::GetDlgItemTextW,
            "GetDlgItem" => Api::GetDlgItemApi,
            "SendMessageW" | "PostMessageW" => Api::SendMessageApi,
            "SetWindowTextW" => Api::SetWindowTextApi,
            "GetWindowTextW" => Api::GetWindowTextApi,
            "GetMessageW" => Api::GetMessageApi,
            "PeekMessageW" => Api::PeekMessageApi,
            "IsDialogMessageW" | "IsDialogMessage" => Api::IsDialogMessageApi,
            "CoCreateInstance" | "CoGetClassObject" => Api::CoCreateInstanceApi,
            "DestroyWindow" => Api::DestroyWindowApi,
            "PostQuitMessage" => Api::PostQuitMessageApi,
            "EndDialog" => Api::EndDialogApi,
            "GlobalAlloc" | "LocalAlloc" => Api::GlobalAlloc,
            "GlobalLock" | "LocalLock" | "GlobalHandle" => Api::GlobalLock,
            "GlobalFree" | "GlobalUnlock" | "LocalFree" | "LocalUnlock" => Api::GlobalFreeUnlock,
            "__set_app_type" | "_set_fmode" | "_get_fmode" | "__setusermatherr"
            | "_configthreadlocale" | "_controlfp" | "_controlfp_s"
            | "__C_specific_handler" | "_XcptFilter" | "_amsg_exit"
            | "signal" | "_lock" | "_unlock" | "_onexit" | "atexit" | "__dllonexit"
            | "_setmode" | "setlocale" | "_set_new_mode" | "__p__fmode"
            | "_configure_narrow_argv" | "_initialize_narrow_environment"
            | "_get_initial_narrow_environment" | "_set_app_type" => Api::CrtNoop,

            // Handle/pointer-returning Win32 functions: return a non-null
            // fake handle so GUI setup "succeeds" and the program proceeds.
            // BOOL-returning functions that must report success (non-zero)
            // so callers don't treat setup as failed and bail/throw.
            "SetConsoleCtrlHandler" | "SetConsoleTitleW" | "FlushConsoleInputBuffer"
            | "SetHandleCount" | "SetThreadPriority"
            | "GetDC" | "GetWindowDC" | "LoadCursorW" | "LoadIconW" | "LoadImageW"
            | "LoadBitmapW" | "GetSystemMenu" | "CreatePopupMenu" | "CreateBrushIndirect"
            | "CreateFontIndirectW" | "FindWindowExW" | "SetTimer" | "GetModuleHandleExW" => {
                Api::FakeHandle { sym: format!("{dll}!{name}"), argc: win32_argc(dll, name).unwrap_or(0) }
            }

            // Custom windows + GDI.
            "RegisterClassW" | "RegisterClassA" => Api::RegisterClassApi { ex: false },
            "RegisterClassExW" | "RegisterClassExA" => Api::RegisterClassApi { ex: true },
            "CreateWindowExW" | "CreateWindowExA" => Api::CreateWindowExApi,
            "DefWindowProcW" | "DefWindowProcA" => Api::DefWindowProcApi,
            "DispatchMessageW" | "DispatchMessageA" => Api::DispatchMessageApi,
            "BeginPaint" => Api::BeginPaintApi,
            "EndPaint" => Api::EndPaintApi,
            "GetClientRect" => Api::GetClientRectApi,
            "FillRect" => Api::FillRectApi,
            "Rectangle" => Api::RectangleApi,
            "TextOutW" | "TextOutA" => Api::TextOutApi,
            "SetTextColor" => Api::SetTextColorApi,
            "CreateSolidBrush" => Api::CreateSolidBrushApi,
            "CreatePen" => Api::CreatePenApi,
            "GetStockObject" => Api::GetStockObjectApi,
            "SelectObject" => Api::SelectObjectApi,
            "MoveToEx" => Api::MoveToExApi,
            "LineTo" => Api::LineToApi,
            "SetPixel" | "SetPixelV" => Api::SetPixelApi,
            // Accepted no-effect window/GDI stubs.
            "ShowWindow" | "UpdateWindow" | "TranslateMessage" | "DeleteObject" | "InvalidateRect"
            | "SetBkColor" | "SetBkMode" | "ReleaseDC" | "GetSysColor" | "GetSystemMetrics"
            | "SetWindowPos" | "MoveWindow" | "ValidateRect" => {
                let r = match name {
                    "GetSysColor" => 0x00C0_C0C0,
                    "GetSystemMetrics" => 0,
                    _ => TRUE,
                };
                Api::WinStub { r, argc: win32_argc(dll, name).unwrap_or(0) }
            }

            _ => Api::Unsupported {
                sym: format!("{dll}!{name}"),
                argc: win32_argc(dll, name).unwrap_or(0),
            },
        }
    }

    /// Number of 4-byte stack arguments to clean off in 32-bit stdcall mode
    /// (the Win32 default: the callee pops its arguments). cdecl functions
    /// (the C runtime) and internal thunks return 0. Ignored in 64-bit mode.
    pub(crate) fn argc(&self) -> u32 {
        match self {
            Api::GetStdHandle => 1,
            Api::WriteFile => 5,
            Api::WriteConsoleA | Api::WriteConsoleW => 5,
            Api::ExitProcess => 1,
            Api::TerminateProcess => 2,
            Api::GetCommandLineA | Api::GetCommandLineW => 0,
            Api::GetModuleHandleA | Api::GetModuleHandleW => 1,
            Api::GetProcessHeap => 0,
            Api::HeapAlloc => 3,
            Api::HeapReAlloc => 4,
            Api::HeapFree => 3,
            Api::VirtualAlloc => 4,
            Api::VirtualFree => 3,
            Api::GetLastError => 0,
            Api::SetLastError => 1,
            Api::GetCurrentProcessId | Api::GetCurrentThreadId | Api::GetCurrentProcess => 0,
            Api::IsDebuggerPresent => 0,
            Api::Sleep => 1,
            Api::QueryPerformanceCounter => 1,
            Api::QueryPerformanceFrequency => 1,
            Api::GetSystemTimeAsFileTime => 1,
            Api::GetTickCount => 0,
            Api::GetACP => 0,
            Api::SetConsoleCP | Api::SetConsoleOutputCP => 1,
            Api::GetConsoleMode => 2,
            Api::SetConsoleMode => 2,
            Api::GetStartupInfoA | Api::GetStartupInfoW => 1,
            Api::GetEnvironmentStringsW => 0,
            Api::FreeEnvironmentStringsW => 1,
            Api::LoadLibraryA => 1,
            Api::FreeLibrary => 1,
            Api::GetProcAddress => 2,
            // cdecl C runtime and internal thunks: caller cleans up.
            Api::Malloc | Api::Calloc | Api::Realloc | Api::Free | Api::Memcpy | Api::Memset
            | Api::Memcmp | Api::Strlen | Api::CrtExit | Api::GetMainArgs | Api::Initterm
            | Api::CrtNoop | Api::InittermDriver | Api::ReturnExit
            | Api::Fputs | Api::Fputc | Api::Fwrite | Api::Puts => 0,
            // Win32 string helpers.
            Api::CharNextA | Api::CharNextW | Api::LstrlenA | Api::LstrlenW => 1,
            Api::CharPrevW | Api::LstrcpyW | Api::LstrcatW | Api::LstrcmpW | Api::LstrcmpiW => 2,
            Api::LstrcpynW => 3,
            // Filesystem.
            Api::CloseHandle | Api::DeleteFileW | Api::GetFileAttributesW | Api::GlobalLock
            | Api::GlobalFreeUnlock => 1,
            Api::GetVersion => 0,
            Api::GetVersionEx => 1,
            // GUI.
            Api::CallbackDriver => 0,
            Api::GetDlgItemApi | Api::GetWindowTextApi => 2,
            Api::SetWindowTextApi | Api::IsDialogMessageApi | Api::EndDialogApi => 2,
            Api::DestroyWindowApi | Api::PostQuitMessageApi => 1,
            Api::SetDlgItemTextW => 3,
            Api::GetDlgItemTextW | Api::SendMessageApi | Api::GetMessageApi => 4,
            Api::PeekMessageApi => 5,
            Api::CreateDialogParam { .. } | Api::CoCreateInstanceApi => 5,
            Api::CreateDirectoryW | Api::GetTempPathW | Api::GetFileSizeApi | Api::GlobalAlloc
            | Api::GetSystemDirectoryW | Api::GetWindowsDirectoryW => 2,
            Api::GetModuleFileNameW => 3,
            Api::SetFilePointerApi | Api::GetTempFileNameW => 4,
            Api::ReadFileApi => 5,
            Api::CreateFileW => 7,
            // Custom windows + GDI.
            Api::RegisterClassApi { .. } | Api::CreateSolidBrushApi | Api::GetStockObjectApi
            | Api::DispatchMessageApi => 1,
            Api::BeginPaintApi | Api::EndPaintApi | Api::GetClientRectApi | Api::SetTextColorApi
            | Api::SelectObjectApi => 2,
            Api::FillRectApi | Api::CreatePenApi | Api::LineToApi => 3,
            Api::DefWindowProcApi | Api::MoveToExApi | Api::SetPixelApi => 4,
            Api::RectangleApi | Api::TextOutApi => 5,
            Api::CreateWindowExApi => 12,
            // Fake-handle, stub and unimplemented carry their looked-up
            // stdcall footprint so the stack stays balanced.
            Api::WinStub { argc, .. }
            | Api::FakeHandle { argc, .. }
            | Api::Unsupported { argc, .. } => *argc,
        }
    }
}

/// Stdcall argument count (number of 4-byte stack parameters) for common
/// Win32 functions, so 32-bit callee stack cleanup is correct even when the
/// function is only a stub. `None` means unknown (caller-cleanup fallback).
/// `wsprintf*` are intentionally cdecl (variadic) → 0.
pub(crate) fn win32_argc(dll: &str, name: &str) -> Option<u32> {
    // A few ordinal imports we recognize by (dll, ordinal).
    if let Some(ord) = name.strip_prefix("#ord") {
        return match (dll, ord) {
            ("comctl32.dll", "17") => Some(0), // InitCommonControls
            _ => None,
        };
    }
    let n = match name {
        // --- 0 args ---
        "GetCommandLineW" | "GetLastError" | "GetTickCount" | "GetVersion" | "GetCurrentProcess"
        | "CloseClipboard" | "CreatePopupMenu" | "EmptyClipboard" | "GetMessagePos"
        | "OleUninitialize" | "wsprintfW" | "wsprintfA" => 0,

        // --- 1 arg ---
        "SetConsoleTitleW" | "FlushConsoleInputBuffer" | "SetHandleCount"
        | "InitializeCriticalSection" | "DeleteCriticalSection" | "EnterCriticalSection"
        | "LeaveCriticalSection"
        | "CloseHandle" | "FindClose" | "FreeLibrary" | "GetFileAttributesW" | "DeleteFileW"
        | "GlobalFree" | "GlobalLock" | "GlobalUnlock" | "RemoveDirectoryW"
        | "SetCurrentDirectoryW" | "GetModuleHandleA" | "GetModuleHandleW" | "Sleep"
        | "SetErrorMode" | "lstrlenA" | "lstrlenW" | "DestroyWindow" | "GetDC" | "IsWindow"
        | "IsWindowEnabled" | "IsWindowVisible" | "OpenClipboard" | "PostQuitMessage"
        | "RegisterClassW" | "SetCursor" | "SetForegroundWindow" | "GetSysColor"
        | "GetSystemMetrics" | "TranslateMessage" | "DispatchMessageW" | "MessageBoxIndirectW"
        | "DeleteObject" | "CreateBrushIndirect" | "CreateFontIndirectW" | "RegCloseKey"
        | "SHBrowseForFolderW" | "SHFileOperationW" | "OleInitialize" | "CoTaskMemFree"
        | "ImageList_Destroy" => 1,

        // --- 2 args ---
        "SetConsoleCtrlHandler" | "SetThreadPriority"
        | "CompareFileTime" | "CreateDirectoryW" | "GetFileSize" | "GlobalAlloc" | "MoveFileW"
        | "SetEnvironmentVariableW" | "SetFileAttributesW" | "WaitForSingleObject"
        | "GetExitCodeProcess" | "GetTempPathW" | "GetSystemDirectoryW" | "GetWindowsDirectoryW"
        | "EnableWindow" | "EndDialog" | "EndPaint" | "ExitWindowsEx" | "GetClientRect"
        | "GetDlgItem" | "GetSystemMenu" | "GetWindowLongW" | "GetWindowRect" | "LoadBitmapW"
        | "LoadCursorW" | "ReleaseDC" | "ScreenToClient" | "SetClipboardData" | "SetWindowTextW"
        | "ShowWindow" | "BeginPaint" | "GetDeviceCaps" | "SelectObject" | "SetBkColor"
        | "SetBkMode" | "SetTextColor" | "RegDeleteKeyW" | "RegDeleteValueW"
        | "SHGetPathFromIDListW" | "lstrcatW" | "lstrcmpW" | "lstrcmpiA" | "lstrcmpiW"
        | "lstrcpyA" | "lstrcpyW" => 2,

        // --- 3 args ---
        "ExpandEnvironmentStringsW" | "CopyFileW" | "SetFileSecurityW" | "LoadLibraryExW"
        | "GetShortPathNameW" | "MoveFileExW" | "CheckDlgButton" | "EnableMenuItem"
        | "InvalidateRect" | "SetClassLongW" | "SetDlgItemTextW" | "SetWindowLongW"
        | "GetClassInfoW" | "OpenProcessToken" | "LookupPrivilegeValueW"
        | "SHGetSpecialFolderLocation" | "ImageList_AddMasked" | "MulDiv" | "lstrcpynW" => 3,

        // --- 4 args ---
        "GetModuleFileNameW" | "GetFullPathNameW" | "SetFilePointer" | "SetFileTime"
        | "GetTempFileNameW" | "WritePrivateProfileStringW" | "AppendMenuW" | "DefWindowProcW"
        | "FindWindowExW" | "GetDlgItemTextW" | "MessageBoxW" | "SendMessageW" | "GetMessageW"
        | "SetTimer" | "SystemParametersInfoW" | "DrawTextW" | "FillRect" | "RegEnumKeyW" => 4,

        // --- 5 args ---
        "ReadFile" | "WriteFile" | "GetDiskFreeSpaceW" | "CallWindowProcW" | "CreateDialogParamW"
        | "DialogBoxParamW" | "PeekMessageW" | "RegOpenKeyExW" | "SHGetFileInfoW"
        | "CoCreateInstance" | "ImageList_Create" => 5,

        // --- 6 args ---
        "GetPrivateProfileStringW" | "SearchPathW" | "MultiByteToWideChar" | "CreateThread"
        | "LoadImageW" | "AdjustTokenPrivileges" | "RegQueryValueExW" | "RegSetValueExW"
        | "ShellExecuteW" => 6,

        // --- 7 args ---
        "CreateFileW" | "SetWindowPos" | "SendMessageTimeoutW" | "TrackPopupMenu" => 7,

        // --- 8, 9, 10, 12 args ---
        "WideCharToMultiByte" | "RegEnumValueW" => 8,
        "RegCreateKeyExW" => 9,
        "CreateProcessW" => 10,
        "CreateWindowExW" => 12,

        _ => return None,
    };
    Some(n)
}

/// Windows TRUE / FALSE as BOOL return values.
const TRUE: u64 = 1;
const FALSE: u64 = 0;

/// A non-null sentinel returned by handle/pointer-returning stubs so callers
/// treat the operation as having succeeded and keep running.
pub(crate) const FAKE_HANDLE: u64 = 0x00CA_FE00;

// Synthetic window handles and the window messages the GUI shim understands.
const HWND_DIALOG: u64 = 0x00D1_A000;
const HWND_CONTROL: u64 = 0x00C0_0000; // control handle = HWND_CONTROL | id
const WM_SETTEXT: u32 = 0x000C;
const WM_GETTEXT: u32 = 0x000D;
const WM_GETTEXTLENGTH: u32 = 0x000E;
const WM_INITDIALOG: u64 = 0x0110;
const WM_COMMAND: u64 = 0x0111;
const IDOK: u32 = 1;
const IDCANCEL: u32 = 2;
// Progress-bar (msctls_progress32) messages.
const PBM_SETRANGE: u32 = 0x0401;
const PBM_SETPOS: u32 = 0x0402;
const PBM_DELTAPOS: u32 = 0x0403;
const PBM_SETRANGE32: u32 = 0x0406;

/// Recover the control id from a synthetic control handle, if it is one.
fn control_id(hwnd: u64) -> Option<u32> {
    if (HWND_CONTROL..HWND_CONTROL + 0x1_0000).contains(&hwnd) {
        Some((hwnd - HWND_CONTROL) as u32)
    } else {
        None
    }
}

/// Read a NUL-terminated UTF-16 string as code units (no terminator).
fn read_wstr_units(mem: &dyn Memory, addr: u64) -> Result<Vec<u16>> {
    let mut v = Vec::new();
    if addr == 0 {
        return Ok(v);
    }
    let mut i = 0u64;
    loop {
        let w = mem.read_u16(addr + i * 2)?;
        if w == 0 || i > (1 << 16) {
            break;
        }
        v.push(w);
        i += 1;
    }
    Ok(v)
}

/// Write UTF-16 code units + NUL into a guest buffer bounded by `max` units.
/// Returns the number of units written (excluding the terminator).
fn write_wstr_units(mem: &mut dyn Memory, addr: u64, units: &[u16], max: usize) -> Result<u64> {
    if addr == 0 || max == 0 {
        return Ok(0);
    }
    let n = units.len().min(max - 1);
    for (i, u) in units.iter().take(n).enumerate() {
        mem.write_u16(addr + (i as u64) * 2, *u)?;
    }
    mem.write_u16(addr + (n as u64) * 2, 0)?;
    Ok(n as u64)
}

/// Read a NUL-terminated UTF-16 string from guest memory into a `String`.
pub(crate) fn read_wstr(mem: &dyn Memory, addr: u64) -> Result<String> {
    if addr == 0 {
        return Ok(String::new());
    }
    let mut units = Vec::new();
    let mut i = 0u64;
    loop {
        let w = mem.read_u16(addr + i * 2)?;
        if w == 0 || i > (1 << 16) {
            break;
        }
        units.push(w);
        i += 1;
    }
    Ok(String::from_utf16_lossy(&units))
}

/// Length of a NUL-terminated UTF-16 string in code units.
fn wstrlen(mem: &dyn Memory, addr: u64) -> Result<usize> {
    let mut n = 0usize;
    while mem.read_u16(addr + (n as u64) * 2)? != 0 {
        n += 1;
        if n > (1 << 20) {
            break;
        }
    }
    Ok(n)
}

/// Compare two NUL-terminated UTF-16 strings, optionally case-folding ASCII.
fn wstrcmp(mem: &dyn Memory, a: u64, b: u64, fold: bool) -> Result<i32> {
    let f = |c: u16| if fold && (b'A' as u16..=b'Z' as u16).contains(&c) { c + 32 } else { c };
    let mut i = 0u64;
    loop {
        let x = f(mem.read_u16(a + i * 2)?);
        let y = f(mem.read_u16(b + i * 2)?);
        if x != y {
            return Ok(if x < y { -1 } else { 1 });
        }
        if x == 0 {
            return Ok(0);
        }
        i += 1;
    }
}

impl WinOs {
    pub(crate) fn dispatch(
        &mut self,
        api: &Api,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<Outcome> {
        let ret = |v: u64| Ok(Outcome::Return(v));
        match api {
            Api::ExitProcess => {
                let code = self.arg(cpu, mem, 0)? as u32 as i32;
                Ok(Outcome::Exit(code))
            }
            Api::ReturnExit => {
                // The entry function returned; its exit code is in EAX.
                let code = cpu.gpr_read(0, 4) as u32 as i32;
                Ok(Outcome::Exit(code))
            }
            Api::TerminateProcess => {
                let code = self.arg(cpu, mem, 1)? as u32 as i32;
                Ok(Outcome::Exit(code))
            }

            Api::GetStdHandle => {
                let which = self.arg(cpu, mem, 0)? as u32 as i32;
                ret(match which {
                    -10 => HANDLE_STDIN,
                    -11 => HANDLE_STDOUT,
                    -12 => HANDLE_STDERR,
                    _ => 0,
                })
            }

            Api::WriteFile => {
                // WriteFile(hFile, lpBuffer, nBytes, lpWritten, lpOverlapped)
                let handle = self.arg(cpu, mem, 0)?;
                let buf = self.arg(cpu, mem, 1)?;
                let n = self.arg(cpu, mem, 2)? as usize;
                let written_ptr = self.arg(cpu, mem, 3)?;
                let written = if self.is_file_handle(handle) {
                    let mut data = vec![0u8; n];
                    mem.read(buf, &mut data)?;
                    self.write_file_handle(handle, &data).unwrap_or(0)
                } else {
                    self.write_stream(handle, buf, n, mem)?;
                    n
                };
                if written_ptr != 0 {
                    mem.write_u32(written_ptr, written as u32)?;
                }
                ret(TRUE)
            }
            Api::WriteConsoleA => {
                // WriteConsoleA(hConsole, lpBuffer, nChars, lpWritten, lpReserved)
                let handle = self.arg(cpu, mem, 0)?;
                let buf = self.arg(cpu, mem, 1)?;
                let n = self.arg(cpu, mem, 2)? as usize;
                let written_ptr = self.arg(cpu, mem, 3)?;
                self.write_stream(handle, buf, n, mem)?;
                if written_ptr != 0 {
                    mem.write_u32(written_ptr, n as u32)?;
                }
                ret(TRUE)
            }
            Api::WriteConsoleW => {
                let handle = self.arg(cpu, mem, 0)?;
                let buf = self.arg(cpu, mem, 1)?;
                let n = self.arg(cpu, mem, 2)? as usize;
                let written_ptr = self.arg(cpu, mem, 3)?;
                let mut units = Vec::with_capacity(n);
                for i in 0..n {
                    units.push(mem.read_u16(buf + (i as u64) * 2)?);
                }
                let text = String::from_utf16_lossy(&units);
                let is_err = handle == HANDLE_STDERR;
                self.emit(is_err, text.as_bytes());
                if written_ptr != 0 {
                    mem.write_u32(written_ptr, n as u32)?;
                }
                ret(TRUE)
            }

            Api::GetCommandLineA => ret(self.cfg.cmdline_ptr_a),
            Api::GetCommandLineW => ret(self.cfg.cmdline_ptr_w),

            Api::GetModuleHandleA | Api::GetModuleHandleW => {
                // Only the "this module" (NULL name) case is supported.
                ret(self.cfg.image_base)
            }

            Api::GetProcessHeap => ret(HANDLE_PROCESS_HEAP),
            Api::HeapAlloc => {
                // HeapAlloc(hHeap, dwFlags, dwBytes)
                let size = self.arg(cpu, mem, 2)?;
                ret(self.heap_alloc(size))
            }
            Api::HeapReAlloc => {
                // HeapReAlloc(hHeap, dwFlags, lpMem, dwBytes)
                let old = self.arg(cpu, mem, 2)?;
                let size = self.arg(cpu, mem, 3)?;
                let new = self.heap_alloc(size);
                if new != 0 && old != 0 {
                    // Best-effort copy; we do not track the old size.
                    for i in 0..size {
                        let b = mem.read_u8(old + i)?;
                        mem.write_u8(new + i, b)?;
                    }
                }
                ret(new)
            }
            Api::HeapFree => ret(TRUE),

            Api::VirtualAlloc => {
                // VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
                let size = self.arg(cpu, mem, 1)?;
                ret(self.heap_alloc(size))
            }
            Api::VirtualFree => ret(TRUE),

            Api::GetLastError => ret(self.last_error as u64),
            Api::SetLastError => {
                self.last_error = self.arg(cpu, mem, 0)? as u32;
                Ok(Outcome::Return(0))
            }

            Api::GetCurrentProcessId => ret(0x1000),
            Api::GetCurrentThreadId => ret(0x1001),
            Api::GetCurrentProcess => ret(u64::MAX), // pseudo-handle (HANDLE)-1
            Api::IsDebuggerPresent => ret(FALSE),
            Api::Sleep => Ok(Outcome::Return(0)),

            Api::QueryPerformanceCounter => {
                let ptr = self.arg(cpu, mem, 0)?;
                if ptr != 0 {
                    mem.write_u64(ptr, 0)?;
                }
                ret(TRUE)
            }
            Api::QueryPerformanceFrequency => {
                let ptr = self.arg(cpu, mem, 0)?;
                if ptr != 0 {
                    mem.write_u64(ptr, 1_000_000)?;
                }
                ret(TRUE)
            }
            Api::GetSystemTimeAsFileTime => {
                let ptr = self.arg(cpu, mem, 0)?;
                if ptr != 0 {
                    mem.write_u64(ptr, 0)?;
                }
                Ok(Outcome::Return(0))
            }
            Api::GetTickCount => ret(0),
            Api::GetACP => ret(65001), // UTF-8 code page

            Api::SetConsoleCP | Api::SetConsoleOutputCP => ret(TRUE),
            Api::GetConsoleMode => {
                // GetConsoleMode(hConsole, lpMode): report a plausible mode.
                let ptr = self.arg(cpu, mem, 1)?;
                if ptr != 0 {
                    mem.write_u32(ptr, 0x0003)?; // ENABLE_PROCESSED_OUTPUT | WRAP
                }
                ret(TRUE)
            }
            Api::SetConsoleMode => ret(TRUE),

            Api::GetStartupInfoA | Api::GetStartupInfoW => {
                // Zero-fill a STARTUPINFO and set its cb field.
                let ptr = self.arg(cpu, mem, 0)?;
                if ptr != 0 {
                    for i in 0..104u64 {
                        mem.write_u8(ptr + i, 0)?;
                    }
                    mem.write_u32(ptr, 104)?; // cb
                }
                Ok(Outcome::Return(0))
            }
            Api::GetEnvironmentStringsW => {
                // Return an empty environment block (double NUL).
                let ptr = self.heap_alloc(8);
                ret(ptr)
            }
            Api::FreeEnvironmentStringsW => ret(TRUE),

            Api::LoadLibraryA => ret(0), // pretend the DLL could not be loaded
            Api::FreeLibrary => ret(TRUE),
            Api::GetProcAddress => ret(0),

            // --- msvcrt C runtime --------------------------------------------
            Api::Malloc => {
                let size = self.arg(cpu, mem, 0)?;
                ret(self.heap_alloc(size))
            }
            Api::Calloc => {
                // calloc(num, size): the arena is already zeroed.
                let num = self.arg(cpu, mem, 0)?;
                let size = self.arg(cpu, mem, 1)?;
                ret(self.heap_alloc(num.saturating_mul(size)))
            }
            Api::Realloc => {
                let old = self.arg(cpu, mem, 0)?;
                let size = self.arg(cpu, mem, 1)?;
                let new = self.heap_alloc(size);
                if new != 0 && old != 0 {
                    for i in 0..size {
                        let b = mem.read_u8(old + i)?;
                        mem.write_u8(new + i, b)?;
                    }
                }
                ret(new)
            }
            Api::Free => ret(0),

            Api::Memcpy => {
                // memcpy/memmove(dest, src, n) — return dest, overlap-safe.
                let dest = self.arg(cpu, mem, 0)?;
                let src = self.arg(cpu, mem, 1)?;
                let n = self.arg(cpu, mem, 2)? as usize;
                let mut tmp = vec![0u8; n];
                mem.read(src, &mut tmp)?;
                mem.write(dest, &tmp)?;
                ret(dest)
            }
            Api::Memset => {
                // memset(dest, c, n) — return dest.
                let dest = self.arg(cpu, mem, 0)?;
                let c = self.arg(cpu, mem, 1)? as u8;
                let n = self.arg(cpu, mem, 2)? as usize;
                mem.write(dest, &vec![c; n])?;
                ret(dest)
            }
            Api::Memcmp => {
                let a = self.arg(cpu, mem, 0)?;
                let b = self.arg(cpu, mem, 1)?;
                let n = self.arg(cpu, mem, 2)?;
                let mut result: u64 = 0;
                for i in 0..n {
                    let (x, y) = (mem.read_u8(a + i)?, mem.read_u8(b + i)?);
                    if x != y {
                        // Sign-extend the byte difference into the return.
                        result = (x as i32 - y as i32) as i64 as u64;
                        break;
                    }
                }
                ret(result)
            }
            Api::Strlen => {
                let s = self.arg(cpu, mem, 0)?;
                let bytes = mem.read_cstr(s, 1 << 20)?;
                ret(bytes.len() as u64)
            }

            Api::CrtExit => {
                let code = self.arg(cpu, mem, 0)? as u32 as i32;
                Ok(Outcome::Exit(code))
            }

            Api::GetMainArgs => {
                // int __getmainargs(int* argc, char*** argv, char*** env,
                //                   int doWildCard, _startupinfo* startInfo)
                // Populate a one-element argv from the command line pointer.
                let argc_ptr = self.arg(cpu, mem, 0)?;
                let argv_ptr = self.arg(cpu, mem, 1)?;
                let env_ptr = self.arg(cpu, mem, 2)?;
                let argv_arr = self.heap_alloc(16); // [arg0, NULL]
                if argv_arr != 0 {
                    mem.write_u64(argv_arr, self.cfg.cmdline_ptr_a)?;
                    mem.write_u64(argv_arr + 8, 0)?;
                }
                if argc_ptr != 0 {
                    mem.write_u32(argc_ptr, 1)?;
                }
                if argv_ptr != 0 {
                    mem.write_u64(argv_ptr, argv_arr)?;
                }
                if env_ptr != 0 {
                    let env_arr = self.heap_alloc(8); // just a NULL terminator
                    mem.write_u64(env_ptr, env_arr)?;
                }
                ret(0)
            }

            // _initterm(first, last): call each non-null function pointer in
            // [first, last). We drive them as real guest calls (so C++ static
            // constructors actually run) via the InittermDriver thunk.
            Api::Initterm => {
                let first = self.arg(cpu, mem, 0)?;
                let last = self.arg(cpu, mem, 1)?;
                let saved_rsp = cpu.rsp();
                let ret_addr = mem.read_u64(saved_rsp)?;

                let mut fns = VecDeque::new();
                let mut p = first;
                while p < last {
                    let f = mem.read_u64(p)?;
                    if f != 0 {
                        fns.push_back(f);
                    }
                    p += 8;
                }

                match fns.pop_front() {
                    None => Ok(Outcome::Return(0)), // nothing to initialize
                    Some(first_fn) => {
                        self.initterm_stack.push(InittermFrame { remaining: fns, ret: ret_addr, saved_rsp });
                        let driver = self.initterm_driver;
                        setup_call(cpu, mem, first_fn, driver, saved_rsp)?;
                        Ok(Outcome::Resume)
                    }
                }
            }
            // A constructor just returned to the driver thunk: run the next
            // one, or return to _initterm's original caller when done.
            Api::InittermDriver => self.initterm_advance(cpu, mem),
            // A guest callback (window/dialog proc) returned: advance the queue.
            Api::CallbackDriver => self.cb_advance(cpu, mem),

            // --- GUI: drive the dialog procedure ---------------------------
            Api::CreateDialogParam { modal } => {
                // CreateDialogParamW(hInst, lpTemplate, hWndParent, lpDlgProc,
                //                    dwInitParam) / DialogBoxParamW(same).
                let template_id = self.arg(cpu, mem, 1)?;
                let dlgproc = self.arg(cpu, mem, 3)?;
                let init_param = self.arg(cpu, mem, 4)?;
                let hwnd = HWND_DIALOG;
                self.dlgproc = dlgproc;
                self.dialog_hwnd = hwnd;
                if dlgproc == 0 {
                    return ret(hwnd);
                }

                // Try to show a real window for any dialog whose template we
                // parsed. `lpTemplate` is a MAKEINTRESOURCE id.
                let mut interactive = false;
                if template_id < 0x1_0000 {
                    if let Some(tpl) = self.dialogs.get(&(template_id as u32)).cloned() {
                        self.gui.open(&tpl);
                        interactive = self.gui.is_open();
                    }
                }

                if interactive {
                    // Run WM_INITDIALOG. A modeless dialog then returns its
                    // hwnd and the app's own message loop drives it; a modal
                    // dialog enters its own pump loop (see cb_advance) and
                    // returns the EndDialog value.
                    self.dialog_result = None;
                    let calls = vec![(dlgproc, vec![hwnd, WM_INITDIALOG, 0, init_param])];
                    let result = if *modal { IDCANCEL as u64 } else { hwnd };
                    self.invoke_callbacks(cpu, mem, calls, result, 5, *modal)
                } else {
                    // Headless: WM_INITDIALOG then a synthetic click on the
                    // default (IDOK) button so a dialog that gates work on it
                    // proceeds without a user.
                    let result = if *modal { IDOK as u64 } else { hwnd };
                    let calls = vec![
                        (dlgproc, vec![hwnd, WM_INITDIALOG, 0, init_param]),
                        (dlgproc, vec![hwnd, WM_COMMAND, IDOK as u64, 0]),
                    ];
                    self.invoke_callbacks(cpu, mem, calls, result, 5, false)
                }
            }

            Api::SetDlgItemTextW => {
                let id = self.arg(cpu, mem, 1)? as u32;
                let units = read_wstr_units(mem, self.arg(cpu, mem, 2)?)?;
                self.gui.set_text(id, &String::from_utf16_lossy(&units));
                self.controls.insert(id, units);
                ret(TRUE)
            }
            Api::GetDlgItemTextW => {
                let id = self.arg(cpu, mem, 1)? as u32;
                let buf = self.arg(cpu, mem, 2)?;
                let max = self.arg(cpu, mem, 3)? as usize;
                // Prefer any text the user edited in the real window.
                let text = self
                    .gui
                    .get_text(id)
                    .map(|s| s.encode_utf16().collect::<Vec<u16>>())
                    .or_else(|| self.controls.get(&id).cloned())
                    .unwrap_or_default();
                ret(write_wstr_units(mem, buf, &text, max)?)
            }
            Api::GetDlgItemApi => {
                // Return a synthetic control handle encoding the id.
                let id = self.arg(cpu, mem, 1)? as u32;
                ret(HWND_CONTROL | id as u64)
            }
            Api::SetWindowTextApi => {
                let hwnd = self.arg(cpu, mem, 0)?;
                if let Some(id) = control_id(hwnd) {
                    let text = read_wstr_units(mem, self.arg(cpu, mem, 1)?)?;
                    self.controls.insert(id, text);
                }
                ret(TRUE)
            }
            Api::GetWindowTextApi => {
                let hwnd = self.arg(cpu, mem, 0)?;
                let buf = self.arg(cpu, mem, 1)?;
                let max = self.arg(cpu, mem, 2)? as usize;
                let text = control_id(hwnd)
                    .and_then(|id| self.controls.get(&id).cloned())
                    .unwrap_or_default();
                ret(write_wstr_units(mem, buf, &text, max)?)
            }
            // GetMessageW(lpMsg, hWnd, min, max): hand back a WM_NULL message
            // (return 1) a bounded number of times so a message loop's body
            // runs (many installers defer real work to a loop iteration), then
            // report WM_QUIT (return 0) to end the loop.
            Api::GetMessageApi => {
                let lp = self.arg(cpu, mem, 0)?;
                if self.quit_posted {
                    self.quit_posted = false;
                    return ret(0);
                }
                // A custom (GDI-drawn) window: deliver WM_PAINT, then mouse
                // input, as real messages the app dispatches to its WndProc.
                if self.is_custom_window() {
                    if self.gdi.paint_pending {
                        self.gdi.paint_pending = false;
                        self.write_msg_full(mem, lp, crate::gdi::HWND_CUSTOM, crate::gdi::WM_PAINT, 0, 0)?;
                        return ret(1);
                    }
                    return match self.gui.pump(true) {
                        Some(exemu_core::GuiEvent::MouseDown(x, y)) => {
                            let lparam = (((y as u32 & 0xffff) << 16) | (x as u32 & 0xffff)) as u64;
                            self.write_msg_full(mem, lp, crate::gdi::HWND_CUSTOM, crate::gdi::WM_LBUTTONDOWN, 0, lparam)?;
                            ret(1)
                        }
                        _ => ret(0), // Close / nothing → WM_QUIT
                    };
                }
                if self.gui_active() {
                    // Block on the window until the user acts.
                    return match self.gui.pump(true) {
                        Some(exemu_core::GuiEvent::Command(id)) => {
                            self.write_msg(mem, lp)?;
                            let (dlgproc, hwnd) = (self.dlgproc, self.dialog_hwnd);
                            self.invoke_callbacks(cpu, mem, vec![(dlgproc, vec![hwnd, WM_COMMAND, id as u64, 0])], 1, 4, false)
                        }
                        None => {
                            self.write_msg(mem, lp)?;
                            ret(1)
                        }
                        _ => ret(0), // Close → WM_QUIT
                    };
                }
                if self.msg_pumps > 0 {
                    self.msg_pumps -= 1;
                    self.write_msg(mem, lp)?;
                    ret(1)
                } else {
                    ret(0)
                }
            }
            // PeekMessageW(lpMsg, hWnd, min, max, wRemoveMsg): same budget.
            Api::PeekMessageApi => {
                let lp = self.arg(cpu, mem, 0)?;
                if self.gui_active() {
                    return match self.gui.pump(false) {
                        Some(exemu_core::GuiEvent::Command(id)) => {
                            self.write_msg(mem, lp)?;
                            let (dlgproc, hwnd) = (self.dlgproc, self.dialog_hwnd);
                            self.invoke_callbacks(cpu, mem, vec![(dlgproc, vec![hwnd, WM_COMMAND, id as u64, 0])], TRUE, 5, false)
                        }
                        Some(exemu_core::GuiEvent::Close) => {
                            self.quit_posted = true;
                            ret(FALSE)
                        }
                        _ => ret(FALSE),
                    };
                }
                if self.msg_pumps > 0 {
                    self.msg_pumps -= 1;
                    self.write_msg(mem, lp)?;
                    ret(TRUE)
                } else {
                    ret(FALSE)
                }
            }
            // IsDialogMessageW: claim the message was handled so the loop
            // skips Translate/Dispatch and proceeds to its own logic.
            Api::IsDialogMessageApi => ret(TRUE),

            // CoCreateInstance(rclsid, pUnkOuter, ctx, riid, ppv): no COM, so
            // null the out-pointer and return REGDB_E_CLASSNOTREG. Callers
            // then take their failure path instead of dereferencing null.
            Api::CoCreateInstanceApi => {
                let ppv = self.arg(cpu, mem, 4)?;
                if ppv != 0 {
                    if self.cfg.is_64bit {
                        mem.write_u64(ppv, 0)?;
                    } else {
                        mem.write_u32(ppv, 0)?;
                    }
                }
                ret(0x8004_0154) // REGDB_E_CLASSNOTREG
            }
            Api::DestroyWindowApi => {
                self.gui.close();
                ret(TRUE)
            }
            Api::PostQuitMessageApi => {
                self.quit_posted = true;
                ret(0)
            }
            Api::EndDialogApi => {
                // Ends a modal dialog with the given result; closes the window.
                let result = self.arg(cpu, mem, 1)?;
                self.dialog_result = Some(result);
                self.gui.close();
                self.quit_posted = true;
                ret(TRUE)
            }

            // --- custom (CreateWindowEx) windows + GDI ---------------------
            Api::RegisterClassApi { ex } => {
                let wc = self.arg(cpu, mem, 0)?;
                ret(self.register_class(mem, wc, *ex)?)
            }
            Api::CreateWindowExApi => {
                let class_ptr = self.arg(cpu, mem, 1)?;
                let name_ptr = self.arg(cpu, mem, 2)?;
                let w = self.arg(cpu, mem, 6)? as u32 as i64;
                let h = self.arg(cpu, mem, 7)? as u32 as i64;
                let lp_param = self.arg(cpu, mem, 11)?;
                let hwnd = self.create_window(mem, class_ptr, name_ptr, w, h)?;
                if hwnd != crate::gdi::HWND_CUSTOM {
                    return ret(hwnd);
                }
                // Deliver WM_CREATE with a minimal CREATESTRUCT (lpCreateParams).
                let cs = self.heap_alloc(80);
                if cs != 0 {
                    mem.write_u64(cs, lp_param)?;
                }
                let wndproc = self.gdi.wndproc;
                self.invoke_callbacks(cpu, mem, vec![(wndproc, vec![hwnd, crate::gdi::WM_CREATE, 0, cs])], hwnd, 12, false)
            }
            Api::DefWindowProcApi => {
                let msg = self.arg(cpu, mem, 1)?;
                if msg == crate::gdi::WM_DESTROY {
                    self.quit_posted = true;
                } else if msg == crate::gdi::WM_CLOSE {
                    self.gui.close();
                    self.quit_posted = true;
                }
                ret(0)
            }
            Api::DispatchMessageApi => {
                let lp = self.arg(cpu, mem, 0)?;
                let (hwnd, message, wparam, lparam) = self.read_msg(mem, lp)?;
                let wndproc = self.gdi.wndproc;
                if wndproc == 0 {
                    return ret(0);
                }
                self.invoke_callbacks(cpu, mem, vec![(wndproc, vec![hwnd, message, wparam, lparam])], 0, 1, false)
            }
            Api::BeginPaintApi => {
                let ps = self.arg(cpu, mem, 1)?;
                ret(self.begin_paint(mem, ps)?)
            }
            Api::EndPaintApi => {
                self.end_paint();
                ret(TRUE)
            }
            Api::GetClientRectApi => {
                let rect = self.arg(cpu, mem, 1)?;
                self.get_client_rect(mem, rect)?;
                ret(TRUE)
            }
            Api::FillRectApi => {
                let rect = self.arg(cpu, mem, 1)?;
                let brush = self.arg(cpu, mem, 2)?;
                self.gdi_fill_rect(mem, rect, brush)?;
                ret(TRUE)
            }
            Api::RectangleApi => {
                let (l, t, r, b) = (
                    self.arg(cpu, mem, 1)? as i32,
                    self.arg(cpu, mem, 2)? as i32,
                    self.arg(cpu, mem, 3)? as i32,
                    self.arg(cpu, mem, 4)? as i32,
                );
                self.gdi_rectangle(l, t, r, b);
                ret(TRUE)
            }
            Api::TextOutApi => {
                let (x, y) = (self.arg(cpu, mem, 1)? as i32, self.arg(cpu, mem, 2)? as i32);
                let s = self.arg(cpu, mem, 3)?;
                let count = self.arg(cpu, mem, 4)? as usize;
                let mut units = read_wstr_units(mem, s)?;
                if count < units.len() {
                    units.truncate(count);
                }
                self.gdi_text_out(x, y, &String::from_utf16_lossy(&units));
                ret(TRUE)
            }
            Api::SetTextColorApi => {
                let c = self.arg(cpu, mem, 1)? as u32;
                ret(self.set_text_color(c))
            }
            Api::CreateSolidBrushApi => {
                let c = self.arg(cpu, mem, 0)? as u32;
                ret(self.create_solid_brush(c))
            }
            Api::CreatePenApi => {
                let c = self.arg(cpu, mem, 2)? as u32;
                ret(self.create_pen(c))
            }
            Api::GetStockObjectApi => {
                let i = self.arg(cpu, mem, 0)?;
                ret(self.get_stock_object(i))
            }
            Api::SelectObjectApi => {
                let obj = self.arg(cpu, mem, 1)?;
                ret(self.select_object(obj))
            }
            Api::MoveToExApi => {
                let (x, y) = (self.arg(cpu, mem, 1)? as i32, self.arg(cpu, mem, 2)? as i32);
                self.gdi_move_to(x, y);
                ret(TRUE)
            }
            Api::LineToApi => {
                let (x, y) = (self.arg(cpu, mem, 1)? as i32, self.arg(cpu, mem, 2)? as i32);
                self.gdi_line_to(x, y);
                ret(TRUE)
            }
            Api::SetPixelApi => {
                let (x, y) = (self.arg(cpu, mem, 1)? as i32, self.arg(cpu, mem, 2)? as i32);
                let c = self.arg(cpu, mem, 3)? as u32;
                self.gdi_set_pixel(x, y, c);
                ret(c as u64)
            }
            Api::WinStub { r, .. } => ret(*r),

            Api::SendMessageApi => {
                // Handle the text messages against a control's store; else 0.
                let hwnd = self.arg(cpu, mem, 0)?;
                let msg = self.arg(cpu, mem, 1)? as u32;
                let wparam = self.arg(cpu, mem, 2)?;
                let lparam = self.arg(cpu, mem, 3)?;
                let id = control_id(hwnd);
                match (msg, id) {
                    (WM_SETTEXT, Some(id)) => {
                        let t = read_wstr_units(mem, lparam)?;
                        self.controls.insert(id, t);
                        ret(TRUE)
                    }
                    (WM_GETTEXT, Some(id)) => {
                        let t = self.controls.get(&id).cloned().unwrap_or_default();
                        ret(write_wstr_units(mem, lparam, &t, wparam as usize)?)
                    }
                    (WM_GETTEXTLENGTH, Some(id)) => {
                        ret(self.controls.get(&id).map(|t| t.len()).unwrap_or(0) as u64)
                    }
                    // Progress-bar updates → drive the rendered bar.
                    (PBM_SETRANGE, Some(id)) => {
                        let (min, max) = (lparam as u16 as i64, (lparam >> 16) as u16 as i64);
                        self.progress.entry(id).or_insert((0, 100, 0));
                        if let Some(p) = self.progress.get_mut(&id) {
                            *p = (min, max.max(min + 1), p.2);
                        }
                        self.sync_progress(id);
                        ret(0)
                    }
                    (PBM_SETRANGE32, Some(id)) => {
                        let (min, max) = (wparam as u32 as i32 as i64, lparam as u32 as i32 as i64);
                        let cur = self.progress.get(&id).map(|p| p.2).unwrap_or(0);
                        self.progress.insert(id, (min, max.max(min + 1), cur));
                        self.sync_progress(id);
                        ret(0)
                    }
                    (PBM_SETPOS, Some(id)) => {
                        let e = self.progress.entry(id).or_insert((0, 100, 0));
                        let prev = e.2;
                        e.2 = wparam as i64;
                        self.sync_progress(id);
                        ret(prev as u64)
                    }
                    (PBM_DELTAPOS, Some(id)) => {
                        let e = self.progress.entry(id).or_insert((0, 100, 0));
                        let prev = e.2;
                        e.2 = prev + wparam as i64;
                        self.sync_progress(id);
                        ret(prev as u64)
                    }
                    _ => ret(0),
                }
            }

            Api::CrtNoop => ret(0),

            // --- C stdio output → host console ------------------------------
            // The FILE* stream (last arg) is opaque to us; route to stdout.
            Api::Fputs => {
                let s = self.arg(cpu, mem, 0)?;
                let bytes = mem.read_cstr(s, 1 << 20)?;
                self.emit(false, &bytes);
                ret(0)
            }
            Api::Fputc => {
                let c = self.arg(cpu, mem, 0)? as u8;
                self.emit(false, &[c]);
                ret(c as u64)
            }
            Api::Fwrite => {
                // fwrite(ptr, size, count, stream)
                let ptr = self.arg(cpu, mem, 0)?;
                let size = self.arg(cpu, mem, 1)?;
                let count = self.arg(cpu, mem, 2)?;
                let n = (size * count) as usize;
                let mut buf = vec![0u8; n];
                mem.read(ptr, &mut buf)?;
                self.emit(false, &buf);
                ret(count)
            }
            Api::Puts => {
                let s = self.arg(cpu, mem, 0)?;
                let mut bytes = mem.read_cstr(s, 1 << 20)?;
                bytes.push(b'\n');
                self.emit(false, &bytes);
                ret(0)
            }

            // --- Win32 string helpers ---------------------------------------
            Api::CharNextA => {
                let p = self.arg(cpu, mem, 0)?;
                ret(if mem.read_u8(p)? == 0 { p } else { p + 1 })
            }
            Api::CharNextW => {
                let p = self.arg(cpu, mem, 0)?;
                ret(if mem.read_u16(p)? == 0 { p } else { p + 2 })
            }
            Api::CharPrevW => {
                let start = self.arg(cpu, mem, 0)?;
                let p = self.arg(cpu, mem, 1)?;
                ret(if p <= start { start } else { p - 2 })
            }
            Api::LstrlenA => {
                let p = self.arg(cpu, mem, 0)?;
                ret(if p == 0 { 0 } else { mem.read_cstr(p, 1 << 20)?.len() as u64 })
            }
            Api::LstrlenW => {
                let p = self.arg(cpu, mem, 0)?;
                ret(if p == 0 { 0 } else { wstrlen(mem, p)? as u64 })
            }
            Api::LstrcpyW => {
                let dst = self.arg(cpu, mem, 0)?;
                let src = self.arg(cpu, mem, 1)?;
                let n = wstrlen(mem, src)?;
                for i in 0..=n {
                    let w = mem.read_u16(src + (i as u64) * 2)?;
                    mem.write_u16(dst + (i as u64) * 2, w)?;
                }
                ret(dst)
            }
            Api::LstrcpynW => {
                // lstrcpynW(dst, src, count): copy up to count-1 wchars, NUL-terminate.
                let dst = self.arg(cpu, mem, 0)?;
                let src = self.arg(cpu, mem, 1)?;
                let count = self.arg(cpu, mem, 2)? as usize;
                if count > 0 {
                    let mut i = 0usize;
                    while i + 1 < count {
                        let w = mem.read_u16(src + (i as u64) * 2)?;
                        mem.write_u16(dst + (i as u64) * 2, w)?;
                        if w == 0 {
                            break;
                        }
                        i += 1;
                    }
                    // Ensure NUL termination at the last written slot.
                    let last = if i + 1 >= count { count - 1 } else { i };
                    if mem.read_u16(dst + (last as u64) * 2).unwrap_or(1) != 0 {
                        mem.write_u16(dst + (last as u64) * 2, 0)?;
                    }
                }
                ret(dst)
            }
            Api::LstrcatW => {
                let dst = self.arg(cpu, mem, 0)?;
                let src = self.arg(cpu, mem, 1)?;
                let dlen = wstrlen(mem, dst)?;
                let slen = wstrlen(mem, src)?;
                for i in 0..=slen {
                    let w = mem.read_u16(src + (i as u64) * 2)?;
                    mem.write_u16(dst + ((dlen + i) as u64) * 2, w)?;
                }
                ret(dst)
            }
            Api::LstrcmpW | Api::LstrcmpiW => {
                let a = self.arg(cpu, mem, 0)?;
                let b = self.arg(cpu, mem, 1)?;
                let fold = matches!(api, Api::LstrcmpiW);
                ret(wstrcmp(mem, a, b, fold)? as u64)
            }

            // --- Filesystem -------------------------------------------------
            Api::CreateFileW => {
                let name = read_wstr(mem, self.arg(cpu, mem, 0)?)?;
                let access = self.arg(cpu, mem, 1)?;
                let disposition = self.arg(cpu, mem, 4)?;
                ret(self.create_file(&name, access, disposition))
            }
            Api::ReadFileApi => {
                let handle = self.arg(cpu, mem, 0)?;
                let buf = self.arg(cpu, mem, 1)?;
                let n = self.arg(cpu, mem, 2)? as usize;
                let read_ptr = self.arg(cpu, mem, 3)?;
                let mut tmp = vec![0u8; n];
                let got = self.read_file(handle, &mut tmp).unwrap_or(0);
                mem.write(buf, &tmp[..got])?;
                if read_ptr != 0 {
                    mem.write_u32(read_ptr, got as u32)?;
                }
                ret(TRUE)
            }
            Api::CloseHandle => {
                let handle = self.arg(cpu, mem, 0)?;
                self.close_handle(handle);
                ret(TRUE)
            }
            Api::CreateDirectoryW => {
                let name = read_wstr(mem, self.arg(cpu, mem, 0)?)?;
                ret(self.create_directory(&name) as u64)
            }
            Api::GetTempPathW => {
                // Report a guest temp directory that maps into the sandbox.
                let len = self.arg(cpu, mem, 0)? as usize;
                let buf = self.arg(cpu, mem, 1)?;
                let n = WinOs::write_wstr(mem, buf, "C:\\Temp\\", len)?;
                ret(n)
            }
            Api::GetTempFileNameW => {
                let dir = read_wstr(mem, self.arg(cpu, mem, 0)?)?;
                let prefix = read_wstr(mem, self.arg(cpu, mem, 1)?)?;
                let unique = self.arg(cpu, mem, 2)? as u32;
                let buf = self.arg(cpu, mem, 3)?;
                let (name, u) = self.temp_file_name(&dir, &prefix, unique);
                WinOs::write_wstr(mem, buf, &name, 260)?;
                ret(u as u64)
            }
            Api::GetFileSizeApi => {
                let handle = self.arg(cpu, mem, 0)?;
                let high_ptr = self.arg(cpu, mem, 1)?;
                let size = self.file_size(handle).unwrap_or(0);
                if high_ptr != 0 {
                    mem.write_u32(high_ptr, (size >> 32) as u32)?;
                }
                ret(size & 0xFFFF_FFFF)
            }
            Api::SetFilePointerApi => {
                let handle = self.arg(cpu, mem, 0)?;
                let dist = self.arg(cpu, mem, 1)? as u32 as i32 as i64;
                let method = self.arg(cpu, mem, 3)?;
                ret(self.set_file_pointer(handle, dist, method))
            }
            Api::GetFileAttributesW => {
                let name = read_wstr(mem, self.arg(cpu, mem, 0)?)?;
                ret(self.file_attributes(&name))
            }
            Api::DeleteFileW => {
                let name = read_wstr(mem, self.arg(cpu, mem, 0)?)?;
                ret(self.delete_file(&name) as u64)
            }
            Api::GetModuleFileNameW => {
                let buf = self.arg(cpu, mem, 1)?;
                let size = self.arg(cpu, mem, 2)? as usize;
                let path = self.cfg.module_path_w.clone();
                let n = WinOs::write_wstr(mem, buf, &path, size)?;
                ret(n)
            }

            // Global/Local memory: back it with the heap arena. Since we use
            // GMEM_FIXED semantics, the "handle" is the pointer itself and
            // GlobalLock is the identity.
            Api::GlobalAlloc => {
                let size = self.arg(cpu, mem, 1)?;
                ret(self.heap_alloc(size))
            }
            Api::GlobalLock => {
                let h = self.arg(cpu, mem, 0)?;
                ret(h)
            }
            Api::GlobalFreeUnlock => ret(0),

            // --- Environment / version -------------------------------------
            // Report Windows 6.2 (build 9200): LOWORD = minor<<8 | major,
            // HIWORD = build (top bit clear ⇒ build present).
            Api::GetVersion => ret(0x23F0_0206),
            Api::GetVersionEx => {
                // Fill an OSVERSIONINFO(EX)W: major/minor/build/platform.
                let p = self.arg(cpu, mem, 0)?;
                if p != 0 {
                    mem.write_u32(p + 4, 6)?; // dwMajorVersion
                    mem.write_u32(p + 8, 2)?; // dwMinorVersion
                    mem.write_u32(p + 12, 9200)?; // dwBuildNumber
                    mem.write_u32(p + 16, 2)?; // VER_PLATFORM_WIN32_NT
                    mem.write_u16(p + 20, 0)?; // szCSDVersion[0] = NUL
                }
                ret(TRUE)
            }
            Api::GetSystemDirectoryW => {
                let buf = self.arg(cpu, mem, 0)?;
                let size = self.arg(cpu, mem, 1)? as usize;
                ret(WinOs::write_wstr(mem, buf, "C:\\Windows\\System32", size)?)
            }
            Api::GetWindowsDirectoryW => {
                let buf = self.arg(cpu, mem, 0)?;
                let size = self.arg(cpu, mem, 1)? as usize;
                ret(WinOs::write_wstr(mem, buf, "C:\\Windows", size)?)
            }

            Api::FakeHandle { .. } => ret(FAKE_HANDLE),

            Api::Unsupported { sym, .. } => {
                if self.cfg.trace {
                    eprintln!("[exemu] unimplemented API {sym} -> returning 0");
                }
                ret(0)
            }
        }
    }

    /// Route a byte buffer to the appropriate host stream based on the
    /// Windows handle value.
    fn write_stream(&mut self, handle: u64, buf: u64, n: usize, mem: &dyn Memory) -> Result<()> {
        let mut bytes = vec![0u8; n];
        mem.read(buf, &mut bytes)?;
        let is_err = handle == HANDLE_STDERR;
        self.emit(is_err, &bytes);
        Ok(())
    }

    /// Invoke a sequence of guest callbacks, then return `result` to the
    /// current API's caller. `argc` is the API's own stdcall footprint (for
    /// 32-bit stack cleanup on the final return). Returns `Outcome::Resume`
    /// once the first callback is set up, or `Return(result)` if empty.
    pub(crate) fn invoke_callbacks(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
        calls: Vec<(u64, Vec<u64>)>,
        result: u64,
        argc: u32,
        modal: bool,
    ) -> Result<Outcome> {
        let mut q: VecDeque<(u64, Vec<u64>)> = calls.into();
        let Some((func, args)) = q.pop_front() else {
            return Ok(Outcome::Return(result));
        };
        let saved_rsp = cpu.rsp();
        let (ret_addr, ret_slot) = if self.cfg.is_64bit {
            (mem.read_u64(saved_rsp)?, 8u64)
        } else {
            (mem.read_u32(saved_rsp)? as u64, 4u64)
        };
        let cleanup = if self.cfg.is_64bit { 0 } else { argc as u64 * 4 };
        let final_rsp = saved_rsp + ret_slot + cleanup;
        self.cb_stack.push(CbFrame { remaining: q, ret_addr, final_rsp, result, modal });
        let driver = self.cb_driver;
        self.setup_call_args(cpu, mem, func, &args, driver, saved_rsp)?;
        Ok(Outcome::Resume)
    }

    /// Called when a guest callback returns to the callback driver thunk. Runs
    /// the next queued callback, drives a modal dialog loop, or returns to the
    /// original API's caller.
    fn cb_advance(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let next = self.cb_stack.last_mut().and_then(|f| f.remaining.pop_front());
        if let Some((func, args)) = next {
            let base = self.cb_stack.last().unwrap().final_rsp - if self.cfg.is_64bit { 8 } else { 4 };
            let driver = self.cb_driver;
            self.setup_call_args(cpu, mem, func, &args, driver, base)?;
            return Ok(Outcome::Resume);
        }

        // Queue drained. If this is a modal dialog loop that has not ended,
        // pump the window for the next user action and dispatch it.
        let modal = self.cb_stack.last().map(|f| f.modal).unwrap_or(false);
        if modal && self.dialog_result.is_none() {
            match self.gui.pump(true) {
                Some(exemu_core::GuiEvent::Command(id)) => {
                    let (dlgproc, hwnd) = (self.dlgproc, self.dialog_hwnd);
                    let base =
                        self.cb_stack.last().unwrap().final_rsp - if self.cfg.is_64bit { 8 } else { 4 };
                    let driver = self.cb_driver;
                    self.setup_call_args(cpu, mem, dlgproc, &[hwnd, WM_COMMAND, id as u64, 0], driver, base)?;
                    return Ok(Outcome::Resume);
                }
                _ => {
                    // Close / no event → cancel the modal dialog.
                    self.dialog_result = Some(IDCANCEL as u64);
                }
            }
        }

        // Return to the API's caller. A modal dialog returns its EndDialog value.
        let f = self.cb_stack.pop().expect("cb driver without frame");
        let result = if f.modal { self.dialog_result.take().unwrap_or(IDCANCEL as u64) } else { f.result };
        cpu.set_rsp(f.final_rsp);
        cpu.rip = f.ret_addr;
        if self.cfg.is_64bit {
            cpu.set_reg(Reg::Rax, result);
        } else {
            cpu.gpr_write(0, 4, result);
        }
        Ok(Outcome::Resume)
    }

    /// Push a progress control's current percentage to the GUI (rendered as
    /// the bar fill).
    fn sync_progress(&mut self, id: u32) {
        if let Some(&(min, max, pos)) = self.progress.get(&id) {
            let span = (max - min).max(1) as f64;
            let pct = (((pos - min).max(0) as f64 / span) * 100.0).round() as u32;
            self.gui.set_text(id, &pct.min(100).to_string());
        }
    }

    /// Write a `WM_NULL` MSG struct (targeting the dialog) into a guest
    /// buffer, for GetMessage/PeekMessage. Layout differs by bitness.
    fn write_msg(&self, mem: &mut dyn Memory, lp: u64) -> Result<()> {
        // hwnd = the dialog; message = WM_NULL.
        self.write_msg_full(mem, lp, HWND_DIALOG, 0, 0, 0)
    }

    /// Write a full MSG (hwnd, message, wParam, lParam) into a guest buffer.
    fn write_msg_full(&self, mem: &mut dyn Memory, lp: u64, hwnd: u64, message: u64, wparam: u64, lparam: u64) -> Result<()> {
        if lp == 0 {
            return Ok(());
        }
        let n = if self.cfg.is_64bit { 48 } else { 28 };
        for i in 0..n {
            mem.write_u8(lp + i, 0)?;
        }
        if self.cfg.is_64bit {
            mem.write_u64(lp, hwnd)?;
            mem.write_u32(lp + 8, message as u32)?;
            mem.write_u64(lp + 16, wparam)?;
            mem.write_u64(lp + 24, lparam)?;
        } else {
            mem.write_u32(lp, hwnd as u32)?;
            mem.write_u32(lp + 4, message as u32)?;
            mem.write_u32(lp + 8, wparam as u32)?;
            mem.write_u32(lp + 12, lparam as u32)?;
        }
        Ok(())
    }

    /// Read a MSG (hwnd, message, wParam, lParam) from a guest buffer.
    fn read_msg(&self, mem: &dyn Memory, lp: u64) -> Result<(u64, u64, u64, u64)> {
        if self.cfg.is_64bit {
            Ok((mem.read_u64(lp)?, mem.read_u32(lp + 8)? as u64, mem.read_u64(lp + 16)?, mem.read_u64(lp + 24)?))
        } else {
            Ok((
                mem.read_u32(lp)? as u64,
                mem.read_u32(lp + 4)? as u64,
                mem.read_u32(lp + 8)? as u64,
                mem.read_u32(lp + 12)? as u64,
            ))
        }
    }

    /// Set up a guest call to `func` with `args`, returning to `ret_thunk`.
    /// 64-bit: first four args in RCX/RDX/R8/R9 over a 32-byte shadow.
    /// 32-bit: args pushed right-to-left (stdcall; the callee cleans them).
    fn setup_call_args(
        &self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
        func: u64,
        args: &[u64],
        ret_thunk: u64,
        base_rsp: u64,
    ) -> Result<()> {
        if self.cfg.is_64bit {
            for (i, &a) in args.iter().take(4).enumerate() {
                cpu.set_reg([Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9][i], a);
            }
            let sp = (base_rsp & !0xf) - 0x20 - 8;
            mem.write_u64(sp, ret_thunk)?;
            cpu.set_rsp(sp);
        } else {
            let mut sp = base_rsp & !0xf;
            for &a in args.iter().rev() {
                sp -= 4;
                mem.write_u32(sp, a as u32)?;
            }
            sp -= 4;
            mem.write_u32(sp, ret_thunk as u32)?;
            cpu.set_rsp(sp);
        }
        cpu.rip = func;
        Ok(())
    }

    /// Called when a `_initterm` callback returns to the driver thunk. Runs
    /// the next callback, or unwinds back to `_initterm`'s original caller.
    fn initterm_advance(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let next = self
            .initterm_stack
            .last_mut()
            .and_then(|f| f.remaining.pop_front());

        match next {
            Some(func) => {
                let base = self.initterm_stack.last().unwrap().saved_rsp;
                let driver = self.initterm_driver;
                setup_call(cpu, mem, func, driver, base)?;
                Ok(Outcome::Resume)
            }
            None => {
                // All callbacks done: return to _initterm's caller with 0.
                let frame = self.initterm_stack.pop().expect("driver without frame");
                cpu.set_rsp(frame.saved_rsp + 8);
                cpu.rip = frame.ret;
                cpu.set_reg(Reg::Rax, 0);
                Ok(Outcome::Resume)
            }
        }
    }
}

/// Set up a Windows x64 call frame below `base_rsp` and point the CPU at
/// `func` with `ret_addr` as its return address. Reserves the 32-byte shadow
/// space and leaves `rsp % 16 == 8`, exactly as a real `call` would.
fn setup_call(
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
    func: u64,
    ret_addr: u64,
    base_rsp: u64,
) -> Result<()> {
    let sp = (base_rsp & !0xf) - 0x20 - 8;
    mem.write_u64(sp, ret_addr)?;
    cpu.set_rsp(sp);
    cpu.rip = func;
    Ok(())
}
