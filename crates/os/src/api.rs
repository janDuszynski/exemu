use std::collections::VecDeque;

use exemu_core::{CpuState, Memory, Reg, Result};

use crate::sync::{SignalOp, SyncKind};
use crate::{WinOs, HANDLE_PROCESS_HEAP, HANDLE_STDERR, HANDLE_STDIN, HANDLE_STDOUT};

pub(crate) enum Outcome {
    Return(u64),
    Exit(i32),
    Resume,
}

pub(crate) struct InittermFrame {
    pub remaining: VecDeque<u64>,
    pub ret: u64,
    pub saved_rsp: u64,
}

pub(crate) struct CbFrame {
    pub remaining: VecDeque<(u64, Vec<u64>)>,
    pub ret_addr: u64,
    pub final_rsp: u64,
    pub result: u64,
    pub modal: bool,
}

pub(crate) struct Win32kCbFrame {
    pub resume_rip: u64,
    pub resume_rsp: u64,
    pub resume_flags: u64,
    pub remaining: VecDeque<(u64, Vec<u64>)>,
    pub call_base: u64,
    pub result: Option<u64>,
    pub then: Option<crate::win32k::PendingHitTest>,
    pub client: Option<Box<ClientCbState>>,
}

pub(crate) struct ClientCbState {
    gpr: [u64; 8],
    xmm: [u128; 10],
}

const CLIENT_CB_GPRS: [Reg; 8] =
    [Reg::Rbx, Reg::Rbp, Reg::Rsi, Reg::Rdi, Reg::R12, Reg::R13, Reg::R14, Reg::R15];
const CLIENT_CB_XMM_FIRST: u8 = 6;

const WOW64_CB_SCRATCH_BLOCK: u64 = 0x400;
const WOW64_CB_SCRATCH_DEPTH: u64 = 16;

pub(crate) fn ssdt_nt_callback_return(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    let ret_ptr = os.syscall_arg(cpu, mem, 0)?;
    let ret_len = os.syscall_arg(cpu, mem, 1)? as u32;
    let status = os.syscall_arg(cpu, mem, 2)? as u32;
    os.client_callback_return(cpu, mem, ret_ptr, ret_len, status)
}

impl ClientCbState {
    fn capture(cpu: &CpuState) -> Self {
        let mut gpr = [0u64; 8];
        for (slot, r) in gpr.iter_mut().zip(CLIENT_CB_GPRS) {
            *slot = cpu.reg(r);
        }
        let mut xmm = [0u128; 10];
        for (slot, n) in xmm.iter_mut().zip(CLIENT_CB_XMM_FIRST..) {
            *slot = cpu.xmm(n);
        }
        Self { gpr, xmm }
    }

    fn restore(&self, cpu: &mut CpuState) {
        for (v, r) in self.gpr.iter().zip(CLIENT_CB_GPRS) {
            cpu.set_reg(r, *v);
        }
        for (v, n) in self.xmm.iter().zip(CLIENT_CB_XMM_FIRST..) {
            cpu.set_xmm_keep_upper(n, *v);
        }
    }
}

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
    VirtualProtect,
    VirtualQuery,
    CreateSync { kind: crate::sync::SyncKind, ex: bool, wide: bool },
    OpenSync { wide: bool },
    SignalSync { op: crate::sync::SignalOp },
    WaitSingle { ex: bool },
    WaitMultiple { ex: bool },
    CreateThread,
    ExitThread,
    ThreadExit,
    ResumeThread,
    SuspendThread,
    TerminateThread,
    GetExitCodeThread,
    CreateProcessApi { wide: bool },
    GetExitCodeProcessApi,
    SwitchToThread,
    SleepApi { ex: bool },
    PostMessageApi,
    PostThreadMessageApi,
    TranslateMessageApi,
    EncodeDecodePointer,
    GetLastError,
    SetLastError,
    GetCurrentProcessId,
    GetCurrentThreadId,
    GetCurrentProcess,
    IsDebuggerPresent,
    QueryPerformanceCounter,
    QueryPerformanceFrequency,
    GetSystemTimeAsFileTime,
    GetSystemTime,
    GetTickCount,
    GetACP,
    SetConsoleCP,
    SetConsoleOutputCP,
    GetConsoleMode,
    SetConsoleMode,
    GetStartupInfoA,
    GetStartupInfoW,
    GetEnvironmentStrings { wide: bool },
    FreeEnvironmentStrings,
    GetEnvironmentVariable { wide: bool },
    SetEnvironmentVariable { wide: bool },
    ExpandEnvironmentStrings { wide: bool },
    WideCharToMultiByte,
    MultiByteToWideChar,
    FreeLibrary,
    DisableThreadLibraryCalls,
    GetProcAddress,

    TlsAlloc { fiber: bool },
    TlsSetValue { fiber: bool },
    TlsGetValue { fiber: bool },
    TlsFree { fiber: bool },

    Malloc,
    Calloc,
    Realloc,
    Free,
    Memcpy,
    Memset,
    Memcmp,
    Strlen,
    CrtExit,
    GetMainArgs,
    Initterm,
    InittermDriver,
    EhProlog,
    CrtNoop,
    CrtGlobalPtr { name: String },
    Fputs,
    Fputc,
    Fwrite,
    Puts,

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
    FakeHandle { sym: String, argc: u32 },

    CreateFile { wide: bool },
    ReadFileApi,
    CloseHandle,
    CreateDirectory { wide: bool },
    GetTempPathW,
    GetTempFileNameW,
    GetFileSizeApi,
    SetFilePointerApi,
    GetFileAttributes { wide: bool },
    DeleteFile { wide: bool },
    GetModuleFileNameW,
    FindFirstFile { ex: bool, wide: bool },
    FindNextFile { wide: bool },
    FindClose,
    GetFullPathName { wide: bool },
    MoveFile { wide: bool, ex: bool },
    CopyFile { wide: bool },
    SetFileTimeApi,
    GlobalAlloc,
    GlobalReAlloc,
    GlobalLock,
    GlobalFreeUnlock,
    GetVersion,
    GetVersionEx,
    GetSystemDirectoryW,
    GetWindowsDirectoryW,

    CallbackDriver,
    Win32kCbDriver,
    CreateDialogParam { modal: bool },
    SetDlgItemTextW,
    GetDlgItemTextW,
    GetDlgItemApi,
    SendMessageApi,
    SetWindowTextApi,
    GetWindowTextApi,
    WindowLong { set: bool },
    IsWindowApi,
    GetWindowRectApi,
    ShowWindowApi,
    GetClassNameApi { wide: bool },
    SetPropApi { wide: bool },
    GetPropApi { wide: bool },
    RemovePropApi { wide: bool },
    InvalidateRectApi,
    ValidateRectApi,
    GetUpdateRectApi,
    GetDCApi,
    ReleaseDCApi,
    SetFocusApi,
    GetFocusApi,
    SetCaptureApi,
    GetCaptureApi,
    ReleaseCaptureApi,
    GetKeyStateApi,
    GetCursorPosApi,
    MoveWindowApi,
    SetWindowPosApi,
    GetMessageApi,
    PeekMessageApi,
    IsDialogMessageApi,
    CoCreateInstanceApi,
    DestroyWindowApi,
    PostQuitMessageApi,
    EndDialogApi,

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
    CreateFontApi,
    GetObjectApi { wide: bool },
    SaveDCApi,
    RestoreDCApi,
    SetBkColorApi,
    SetBkModeApi,
    GetStockObjectApi,
    SelectObjectApi,
    MoveToExApi,
    LineToApi,
    SetPixelApi,
    WinStub { r: u64, argc: u32 },
    WsprintfApi { wide: bool },
    MessageBoxApi { wide: bool },
    GetUserObjectInfoApi,
    LoadLibraryApi { wide: bool, argc: u32 },

    RtlCaptureContext,
    RtlLookupFunctionEntry,
    RtlVirtualUnwind,
    RtlPcToFileHeader,
    LdrGetDllHandle,
    LdrLoadDll,
    RaiseException,
    RtlUnwindEx,
    SetUnhandledExceptionFilter,
    UnhandledExceptionFilter,
    ExceptionDriver,

    RegCreate { wide: bool },
    RegOpen { wide: bool },
    RegSet { wide: bool },
    RegQuery { wide: bool },
    RegClose,
    RegDeleteValue { wide: bool },
    RegDeleteKey { wide: bool },
    RegEnumKey { wide: bool },
    RegEnumValue { wide: bool },
    RegQueryInfoKey,

    WineUnixCall,

    ReturnExit,
    ThreadTlsAttach,
    ThreadStartEntry,
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
            "VirtualProtect" => Api::VirtualProtect,
            "VirtualQuery" => Api::VirtualQuery,
            "EncodePointer" | "DecodePointer" | "EncodeSystemPointer"
            | "DecodeSystemPointer" | "RtlEncodePointer" | "RtlDecodePointer" => {
                Api::EncodeDecodePointer
            }

            "RtlCaptureContext" => Api::RtlCaptureContext,
            "RtlLookupFunctionEntry" => Api::RtlLookupFunctionEntry,
            "RtlVirtualUnwind" => Api::RtlVirtualUnwind,
            "RtlPcToFileHeader" => Api::RtlPcToFileHeader,
            "LdrGetDllHandle" => Api::LdrGetDllHandle,
            "LdrLoadDll" => Api::LdrLoadDll,
            "RaiseException" | "RtlRaiseException" => Api::RaiseException,
            "RtlUnwindEx" | "RtlUnwind" => Api::RtlUnwindEx,
            "SetUnhandledExceptionFilter" => Api::SetUnhandledExceptionFilter,
            "UnhandledExceptionFilter" => Api::UnhandledExceptionFilter,
            "GetLastError" => Api::GetLastError,
            "SetLastError" => Api::SetLastError,
            "GetCurrentProcessId" => Api::GetCurrentProcessId,
            "GetCurrentThreadId" => Api::GetCurrentThreadId,
            "GetCurrentProcess" => Api::GetCurrentProcess,
            "IsDebuggerPresent" => Api::IsDebuggerPresent,
            "Sleep" => Api::SleepApi { ex: false },
            "SleepEx" => Api::SleepApi { ex: true },
            "CreateThread" | "_beginthreadex" => Api::CreateThread,
            "ExitThread" | "_endthreadex" => Api::ExitThread,
            "ResumeThread" => Api::ResumeThread,
            "SuspendThread" => Api::SuspendThread,
            "TerminateThread" => Api::TerminateThread,
            "GetExitCodeThread" => Api::GetExitCodeThread,
            "CreateProcessW" => Api::CreateProcessApi { wide: true },
            "CreateProcessA" => Api::CreateProcessApi { wide: false },
            "GetExitCodeProcess" => Api::GetExitCodeProcessApi,
            "SwitchToThread" => Api::SwitchToThread,
            "QueryPerformanceCounter" => Api::QueryPerformanceCounter,
            "QueryPerformanceFrequency" => Api::QueryPerformanceFrequency,
            "GetSystemTimeAsFileTime" | "GetSystemTimePreciseAsFileTime" => Api::GetSystemTimeAsFileTime,
            "GetSystemTime" | "GetLocalTime" => Api::GetSystemTime,
            "GetTickCount" | "GetTickCount64" => Api::GetTickCount,
            "GetACP" => Api::GetACP,
            "SetConsoleCP" => Api::SetConsoleCP,
            "SetConsoleOutputCP" => Api::SetConsoleOutputCP,
            "GetConsoleMode" => Api::GetConsoleMode,
            "SetConsoleMode" => Api::SetConsoleMode,
            "GetStartupInfoA" => Api::GetStartupInfoA,
            "GetStartupInfoW" => Api::GetStartupInfoW,
            "GetEnvironmentStringsW" => Api::GetEnvironmentStrings { wide: true },
            "GetEnvironmentStrings" | "GetEnvironmentStringsA" => {
                Api::GetEnvironmentStrings { wide: false }
            }
            "FreeEnvironmentStringsW" | "FreeEnvironmentStringsA" => Api::FreeEnvironmentStrings,
            "GetEnvironmentVariableW" => Api::GetEnvironmentVariable { wide: true },
            "GetEnvironmentVariableA" => Api::GetEnvironmentVariable { wide: false },
            "SetEnvironmentVariableW" => Api::SetEnvironmentVariable { wide: true },
            "SetEnvironmentVariableA" => Api::SetEnvironmentVariable { wide: false },
            "ExpandEnvironmentStringsW" => Api::ExpandEnvironmentStrings { wide: true },
            "ExpandEnvironmentStringsA" => Api::ExpandEnvironmentStrings { wide: false },
            "WideCharToMultiByte" => Api::WideCharToMultiByte,
            "MultiByteToWideChar" => Api::MultiByteToWideChar,
            "LoadLibraryW" => Api::LoadLibraryApi { wide: true, argc: 1 },
            "LoadLibraryExW" => Api::LoadLibraryApi { wide: true, argc: 3 },
            "LoadLibraryA" => Api::LoadLibraryApi { wide: false, argc: 1 },
            "LoadLibraryExA" => Api::LoadLibraryApi { wide: false, argc: 3 },
            "FreeLibrary" => Api::FreeLibrary,
            "DisableThreadLibraryCalls" => Api::DisableThreadLibraryCalls,
            "GetProcAddress" => Api::GetProcAddress,

            "TlsAlloc" => Api::TlsAlloc { fiber: false },
            "TlsSetValue" => Api::TlsSetValue { fiber: false },
            "TlsGetValue" => Api::TlsGetValue { fiber: false },
            "TlsFree" => Api::TlsFree { fiber: false },
            "FlsAlloc" => Api::TlsAlloc { fiber: true },
            "FlsSetValue" => Api::TlsSetValue { fiber: true },
            "FlsGetValue" => Api::TlsGetValue { fiber: true },
            "FlsFree" => Api::TlsFree { fiber: true },

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

            "_EH_prolog" | "__EH_prolog" => Api::EhProlog,
            "fputs" => Api::Fputs,
            "fputc" | "putc" | "putchar" => Api::Fputc,
            "fwrite" => Api::Fwrite,
            "puts" => Api::Puts,

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

            "CreateFileW" => Api::CreateFile { wide: true },
            "CreateFileA" => Api::CreateFile { wide: false },
            "ReadFile" => Api::ReadFileApi,
            "CloseHandle" => Api::CloseHandle,
            "CreateDirectoryW" => Api::CreateDirectory { wide: true },
            "CreateDirectoryA" => Api::CreateDirectory { wide: false },
            "GetTempPathW" => Api::GetTempPathW,
            "GetTempFileNameW" => Api::GetTempFileNameW,
            "GetFileSize" => Api::GetFileSizeApi,
            "SetFilePointer" => Api::SetFilePointerApi,
            "GetFileAttributesW" => Api::GetFileAttributes { wide: true },
            "GetFileAttributesA" => Api::GetFileAttributes { wide: false },
            "DeleteFileW" => Api::DeleteFile { wide: true },
            "DeleteFileA" => Api::DeleteFile { wide: false },
            "GetFullPathNameW" => Api::GetFullPathName { wide: true },
            "GetFullPathNameA" => Api::GetFullPathName { wide: false },
            "MoveFileW" => Api::MoveFile { wide: true, ex: false },
            "MoveFileA" => Api::MoveFile { wide: false, ex: false },
            "MoveFileExW" => Api::MoveFile { wide: true, ex: true },
            "MoveFileExA" => Api::MoveFile { wide: false, ex: true },
            "CopyFileW" => Api::CopyFile { wide: true },
            "CopyFileA" => Api::CopyFile { wide: false },
            "SetFileTime" => Api::SetFileTimeApi,
            "GetModuleFileNameW" | "GetModuleFileNameA" => Api::GetModuleFileNameW,
            "GetVersion" => Api::GetVersion,
            "GetVersionExW" | "GetVersionExA" => Api::GetVersionEx,
            "GetSystemDirectoryW" => Api::GetSystemDirectoryW,
            "GetWindowsDirectoryW" | "GetSystemWindowsDirectoryW" => Api::GetWindowsDirectoryW,

            "CreateDialogParamW" => Api::CreateDialogParam { modal: false },
            "DialogBoxParamW" => Api::CreateDialogParam { modal: true },
            "SetDlgItemTextW" => Api::SetDlgItemTextW,
            "GetDlgItemTextW" => Api::GetDlgItemTextW,
            "GetDlgItem" => Api::GetDlgItemApi,
            "SendMessageW" | "SendMessageA" => Api::SendMessageApi,
            "PostMessageW" | "PostMessageA" => Api::PostMessageApi,
            "PostThreadMessageW" | "PostThreadMessageA" => Api::PostThreadMessageApi,
            "TranslateMessage" => Api::TranslateMessageApi,
            "SetWindowTextW" => Api::SetWindowTextApi,
            "GetWindowTextW" => Api::GetWindowTextApi,
            "GetWindowLongW" | "GetWindowLongA" | "GetWindowLongPtrW" | "GetWindowLongPtrA" => {
                Api::WindowLong { set: false }
            }
            "SetWindowLongW" | "SetWindowLongA" | "SetWindowLongPtrW" | "SetWindowLongPtrA" => {
                Api::WindowLong { set: true }
            }
            "IsWindow" => Api::IsWindowApi,
            "GetWindowRect" => Api::GetWindowRectApi,
            "ShowWindow" => Api::ShowWindowApi,
            "GetClassNameW" => Api::GetClassNameApi { wide: true },
            "GetClassNameA" => Api::GetClassNameApi { wide: false },
            "SetPropW" => Api::SetPropApi { wide: true },
            "SetPropA" => Api::SetPropApi { wide: false },
            "GetPropW" => Api::GetPropApi { wide: true },
            "GetPropA" => Api::GetPropApi { wide: false },
            "RemovePropW" => Api::RemovePropApi { wide: true },
            "RemovePropA" => Api::RemovePropApi { wide: false },
            "InvalidateRect" => Api::InvalidateRectApi,
            "ValidateRect" => Api::ValidateRectApi,
            "GetUpdateRect" => Api::GetUpdateRectApi,
            "GetDC" | "GetWindowDC" => Api::GetDCApi,
            "ReleaseDC" => Api::ReleaseDCApi,
            "SetFocus" => Api::SetFocusApi,
            "GetFocus" => Api::GetFocusApi,
            "SetCapture" => Api::SetCaptureApi,
            "GetCapture" => Api::GetCaptureApi,
            "ReleaseCapture" => Api::ReleaseCaptureApi,
            "GetKeyState" | "GetAsyncKeyState" => Api::GetKeyStateApi,
            "GetCursorPos" => Api::GetCursorPosApi,
            "MoveWindow" => Api::MoveWindowApi,
            "SetWindowPos" => Api::SetWindowPosApi,
            "GetMessageW" | "GetMessageA" => Api::GetMessageApi,
            "PeekMessageW" | "PeekMessageA" => Api::PeekMessageApi,
            "IsDialogMessageW" | "IsDialogMessage" => Api::IsDialogMessageApi,
            "CoCreateInstance" | "CoGetClassObject" => Api::CoCreateInstanceApi,
            "DestroyWindow" => Api::DestroyWindowApi,
            "PostQuitMessage" => Api::PostQuitMessageApi,
            "EndDialog" => Api::EndDialogApi,
            "GlobalAlloc" | "LocalAlloc" => Api::GlobalAlloc,
            "GlobalReAlloc" | "LocalReAlloc" => Api::GlobalReAlloc,
            "GlobalLock" | "LocalLock" | "GlobalHandle" => Api::GlobalLock,
            "GlobalFree" | "GlobalUnlock" | "LocalFree" | "LocalUnlock" => Api::GlobalFreeUnlock,
            "__set_app_type" | "_set_fmode" | "_get_fmode" | "__setusermatherr"
            | "_configthreadlocale" | "_controlfp" | "_controlfp_s"
            | "__C_specific_handler" | "_XcptFilter" | "_amsg_exit"
            | "signal" | "_lock" | "_unlock" | "_onexit" | "atexit" | "__dllonexit"
            | "_setmode" | "setlocale" | "_set_new_mode"
            | "_configure_narrow_argv" | "_initialize_narrow_environment"
            | "_get_initial_narrow_environment" | "_set_app_type" => Api::CrtNoop,

            n if n.starts_with("__p_") => Api::CrtGlobalPtr { name: n.to_string() },

            "HeapCreate"
            | "SetConsoleCtrlHandler" | "SetConsoleTitleW" | "SetConsoleTitleA"
            | "FlushConsoleInputBuffer"
            | "SetHandleCount" | "SetThreadPriority"
            | "LoadCursorW" | "LoadCursorA" | "LoadIconW" | "LoadIconA"
            | "LoadImageW" | "LoadImageA"
            | "LoadBitmapW" | "GetSystemMenu" | "CreatePopupMenu" | "CreateBrushIndirect"
            | "FindWindowExW" | "SetTimer" | "GetModuleHandleExW"
            | "GetProcessWindowStation" | "GetThreadDesktop" | "OpenDesktopW"
            | "OpenInputDesktopW" | "GetDesktopWindow" | "GetActiveWindow"
            | "GetForegroundWindow" | "GetShellWindow" | "GetCurrentThread"
            | "GetConsoleWindow" => {
                Api::FakeHandle { sym: format!("{dll}!{name}"), argc: win32_argc(dll, name).unwrap_or(0) }
            }

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
            "CreatePen" | "CreatePenIndirect" => Api::CreatePenApi,
            "CreateFontIndirectW" | "CreateFontIndirectA" => Api::CreateFontApi,
            "GetObjectW" => Api::GetObjectApi { wide: true },
            "GetObjectA" => Api::GetObjectApi { wide: false },
            "SaveDC" => Api::SaveDCApi,
            "RestoreDC" => Api::RestoreDCApi,
            "SetBkColor" => Api::SetBkColorApi,
            "SetBkMode" => Api::SetBkModeApi,
            "GetStockObject" => Api::GetStockObjectApi,
            "SelectObject" => Api::SelectObjectApi,
            "MoveToEx" => Api::MoveToExApi,
            "LineTo" => Api::LineToApi,
            "SetPixel" | "SetPixelV" => Api::SetPixelApi,
            "UpdateWindow" | "DeleteObject"
            | "GetSysColor" | "GetSystemMetrics" => {
                let r = match name {
                    "GetSysColor" => 0x00C0_C0C0,
                    "GetSystemMetrics" => 0,
                    _ => TRUE,
                };
                Api::WinStub { r, argc: win32_argc(dll, name).unwrap_or(0) }
            }

            "HeapDestroy" | "HeapValidate" | "HeapSetInformation" | "HeapCompact" => {
                Api::WinStub { r: TRUE, argc: win32_argc(dll, name).unwrap_or(0) }
            }

            "SetDefaultDllDirectories" | "SetDllDirectoryW" | "SetDllDirectoryA" => {
                Api::WinStub { r: TRUE, argc: win32_argc(dll, name).unwrap_or(0) }
            }

            "InitializeCriticalSection" | "InitializeCriticalSectionEx"
            | "InitializeCriticalSectionAndSpinCount" | "EnterCriticalSection"
            | "LeaveCriticalSection" | "DeleteCriticalSection" | "TryEnterCriticalSection"
            | "SetCriticalSectionSpinCount" | "InitializeSListHead" => {
                Api::WinStub { r: TRUE, argc: win32_argc(dll, name).unwrap_or(0) }
            }

            "CreateActCtxA" | "CreateActCtxW" => {
                Api::FakeHandle {
                    sym: format!("{dll}!{name}"),
                    argc: win32_argc(dll, name).unwrap_or(0),
                }
            }
            "ActivateActCtx" | "DeactivateActCtx"
            | "AddRefActCtx" | "ZombifyActCtx" | "ReleaseActCtx" => {
                Api::WinStub { r: TRUE, argc: win32_argc(dll, name).unwrap_or(0) }
            }
            "GetCurrentActCtx"
            | "FindActCtxSectionStringW" | "FindActCtxSectionStringA"
            | "FindActCtxSectionGuidW"
            | "QueryActCtxW" => {
                Api::WinStub { r: FALSE, argc: win32_argc(dll, name).unwrap_or(0) }
            }

            "CreateEventA" | "CreateEventW" => Api::CreateSync { kind: SyncKind::Event, ex: false, wide: name.ends_with('W') },
            "CreateEventExA" | "CreateEventExW" => Api::CreateSync { kind: SyncKind::Event, ex: true, wide: name.ends_with('W') },
            "CreateMutexA" | "CreateMutexW" => Api::CreateSync { kind: SyncKind::Mutex, ex: false, wide: name.ends_with('W') },
            "CreateMutexExA" | "CreateMutexExW" => Api::CreateSync { kind: SyncKind::Mutex, ex: true, wide: name.ends_with('W') },
            "CreateSemaphoreA" | "CreateSemaphoreW" => Api::CreateSync { kind: SyncKind::Semaphore, ex: false, wide: name.ends_with('W') },
            "CreateSemaphoreExA" | "CreateSemaphoreExW" => Api::CreateSync { kind: SyncKind::Semaphore, ex: true, wide: name.ends_with('W') },
            "CreateWaitableTimerA" | "CreateWaitableTimerW" => Api::CreateSync { kind: SyncKind::Timer, ex: false, wide: name.ends_with('W') },
            "CreateWaitableTimerExA" | "CreateWaitableTimerExW" => Api::CreateSync { kind: SyncKind::Timer, ex: true, wide: name.ends_with('W') },
            "OpenEventA" | "OpenEventW" | "OpenMutexA" | "OpenMutexW" | "OpenSemaphoreA" | "OpenSemaphoreW"
            | "OpenWaitableTimerA" | "OpenWaitableTimerW" => Api::OpenSync { wide: name.ends_with('W') },
            "SetEvent" => Api::SignalSync { op: SignalOp::SetEvent },
            "ResetEvent" => Api::SignalSync { op: SignalOp::ResetEvent },
            "PulseEvent" => Api::SignalSync { op: SignalOp::PulseEvent },
            "ReleaseMutex" => Api::SignalSync { op: SignalOp::ReleaseMutex },
            "ReleaseSemaphore" => Api::SignalSync { op: SignalOp::ReleaseSemaphore },
            "WaitForSingleObject" => Api::WaitSingle { ex: false },
            "WaitForSingleObjectEx" => Api::WaitSingle { ex: true },
            "WaitForMultipleObjects" => Api::WaitMultiple { ex: false },
            "WaitForMultipleObjectsEx" => Api::WaitMultiple { ex: true },

            "wsprintfW" | "wsprintfA" => Api::WsprintfApi { wide: name.ends_with('W') },
            "MessageBoxW" | "MessageBoxA" => Api::MessageBoxApi { wide: name.ends_with('W') },
            "GetUserObjectInformationW" | "GetUserObjectInformationA" => Api::GetUserObjectInfoApi,

            "RegCreateKeyExW" | "RegCreateKeyW" => Api::RegCreate { wide: true },
            "RegCreateKeyExA" | "RegCreateKeyA" => Api::RegCreate { wide: false },
            "RegOpenKeyExW" | "RegOpenKeyW" => Api::RegOpen { wide: true },
            "RegOpenKeyExA" | "RegOpenKeyA" => Api::RegOpen { wide: false },
            "RegSetValueExW" => Api::RegSet { wide: true },
            "RegSetValueExA" => Api::RegSet { wide: false },
            "RegQueryValueExW" => Api::RegQuery { wide: true },
            "RegQueryValueExA" => Api::RegQuery { wide: false },
            "RegCloseKey" => Api::RegClose,
            "RegDeleteValueW" => Api::RegDeleteValue { wide: true },
            "RegDeleteValueA" => Api::RegDeleteValue { wide: false },
            "RegDeleteKeyW" | "RegDeleteKeyExW" => Api::RegDeleteKey { wide: true },
            "RegDeleteKeyA" | "RegDeleteKeyExA" => Api::RegDeleteKey { wide: false },
            "RegEnumKeyExW" => Api::RegEnumKey { wide: true },
            "RegEnumKeyExA" => Api::RegEnumKey { wide: false },
            "RegEnumValueW" => Api::RegEnumValue { wide: true },
            "RegEnumValueA" => Api::RegEnumValue { wide: false },
            "RegQueryInfoKeyW" | "RegQueryInfoKeyA" => Api::RegQueryInfoKey,
            "RegFlushKey" | "RegNotifyChangeKeyValue" => {
                Api::WinStub { r: 0, argc: win32_argc(dll, name).unwrap_or(0) }
            }

            "FindFirstFileW" => Api::FindFirstFile { ex: false, wide: true },
            "FindFirstFileExW" => Api::FindFirstFile { ex: true, wide: true },
            "FindFirstFileA" => Api::FindFirstFile { ex: false, wide: false },
            "FindFirstFileExA" => Api::FindFirstFile { ex: true, wide: false },
            "FindNextFileW" => Api::FindNextFile { wide: true },
            "FindNextFileA" => Api::FindNextFile { wide: false },
            "FindClose" => Api::FindClose,

            _ => Api::Unsupported {
                sym: format!("{dll}!{name}"),
                argc: win32_argc(dll, name).unwrap_or(0),
            },
        }
    }

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
            Api::VirtualProtect => 4,
            Api::VirtualQuery => 3,
            Api::CreateSync { kind, ex, .. } => match (kind, ex) {
                (SyncKind::Event, _) => 4,
                (SyncKind::Mutex, false) => 3,
                (SyncKind::Mutex, true) => 4,
                (SyncKind::Semaphore, false) => 4,
                (SyncKind::Semaphore, true) => 6,
                (SyncKind::Timer, false) => 3,
                (SyncKind::Timer, true) => 4,
            },
            Api::OpenSync { .. } => 3,
            Api::SignalSync { op } => match op {
                SignalOp::ReleaseSemaphore => 3,
                _ => 1,
            },
            Api::WaitSingle { ex } => if *ex { 3 } else { 2 },
            Api::WaitMultiple { ex } => if *ex { 5 } else { 4 },
            Api::CreateThread => 6,
            Api::ExitThread => 1,
            Api::ThreadExit => 0,
            Api::ResumeThread | Api::SuspendThread => 1,
            Api::TerminateThread | Api::GetExitCodeThread | Api::GetExitCodeProcessApi => 2,
            Api::CreateProcessApi { .. } => 10,
            Api::SwitchToThread => 0,
            Api::SleepApi { ex } => if *ex { 2 } else { 1 },
            Api::PostMessageApi | Api::PostThreadMessageApi => 4,
            Api::TranslateMessageApi => 1,
            Api::IsWindowApi => 1,
            Api::WindowLong { set: false } | Api::GetWindowRectApi | Api::ShowWindowApi
            | Api::GetPropApi { .. } | Api::RemovePropApi { .. } => 2,
            Api::WindowLong { set: true } | Api::SetPropApi { .. } | Api::GetClassNameApi { .. } => 3,
            Api::GetDCApi => 1,
            Api::ValidateRectApi | Api::ReleaseDCApi => 2,
            Api::InvalidateRectApi | Api::GetUpdateRectApi => 3,
            Api::GetFocusApi | Api::GetCaptureApi | Api::ReleaseCaptureApi => 0,
            Api::SetFocusApi | Api::SetCaptureApi | Api::GetKeyStateApi | Api::GetCursorPosApi => 1,
            Api::MoveWindowApi => 6,
            Api::SetWindowPosApi => 7,
            Api::EncodeDecodePointer => 1,
            Api::GetLastError => 0,
            Api::SetLastError => 1,
            Api::GetCurrentProcessId | Api::GetCurrentThreadId | Api::GetCurrentProcess => 0,
            Api::IsDebuggerPresent => 0,
            Api::QueryPerformanceCounter => 1,
            Api::QueryPerformanceFrequency => 1,
            Api::GetSystemTimeAsFileTime | Api::GetSystemTime => 1,
            Api::GetTickCount => 0,
            Api::GetACP => 0,
            Api::SetConsoleCP | Api::SetConsoleOutputCP => 1,
            Api::GetConsoleMode => 2,
            Api::SetConsoleMode => 2,
            Api::GetStartupInfoA | Api::GetStartupInfoW => 1,
            Api::GetEnvironmentStrings { .. } => 0,
            Api::FreeEnvironmentStrings => 1,
            Api::SetEnvironmentVariable { .. } => 2,
            Api::GetEnvironmentVariable { .. } | Api::ExpandEnvironmentStrings { .. } => 3,
            Api::MultiByteToWideChar => 6,
            Api::WideCharToMultiByte => 8,
            Api::LoadLibraryApi { argc, .. } => *argc,
            Api::FreeLibrary => 1,
            Api::DisableThreadLibraryCalls => 1,
            Api::GetProcAddress => 2,
            Api::TlsAlloc { fiber } => *fiber as u32,
            Api::TlsGetValue { .. } | Api::TlsFree { .. } => 1,
            Api::TlsSetValue { .. } => 2,
            Api::Malloc | Api::Calloc | Api::Realloc | Api::Free | Api::Memcpy | Api::Memset
            | Api::Memcmp | Api::Strlen | Api::CrtExit | Api::GetMainArgs | Api::Initterm
            | Api::CrtNoop | Api::CrtGlobalPtr { .. } | Api::InittermDriver | Api::ReturnExit
            | Api::WineUnixCall | Api::ThreadTlsAttach | Api::ThreadStartEntry
            | Api::Fputs | Api::Fputc | Api::Fwrite | Api::Puts | Api::EhProlog => 0,
            Api::CharNextA | Api::CharNextW | Api::LstrlenA | Api::LstrlenW => 1,
            Api::CharPrevW | Api::LstrcpyW | Api::LstrcatW | Api::LstrcmpW | Api::LstrcmpiW => 2,
            Api::LstrcpynW => 3,
            Api::CloseHandle | Api::DeleteFile { .. } | Api::GetFileAttributes { .. } | Api::GlobalLock
            | Api::GlobalFreeUnlock | Api::FindClose => 1,
            Api::FindFirstFile { ex: false, .. } | Api::FindNextFile { .. } | Api::MoveFile { ex: false, .. } => 2,
            Api::FindFirstFile { ex: true, .. } => 6,
            Api::MoveFile { ex: true, .. } | Api::CopyFile { .. } => 3,
            Api::GetFullPathName { .. } | Api::SetFileTimeApi => 4,
            Api::GetVersion => 0,
            Api::GetVersionEx => 1,
            Api::CallbackDriver | Api::Win32kCbDriver => 0,
            Api::GetDlgItemApi | Api::GetWindowTextApi => 2,
            Api::SetWindowTextApi | Api::IsDialogMessageApi | Api::EndDialogApi => 2,
            Api::DestroyWindowApi | Api::PostQuitMessageApi => 1,
            Api::SetDlgItemTextW => 3,
            Api::GetDlgItemTextW | Api::SendMessageApi | Api::GetMessageApi => 4,
            Api::PeekMessageApi => 5,
            Api::CreateDialogParam { .. } | Api::CoCreateInstanceApi => 5,
            Api::CreateDirectory { .. } | Api::GetTempPathW | Api::GetFileSizeApi | Api::GlobalAlloc
            | Api::GetSystemDirectoryW | Api::GetWindowsDirectoryW => 2,
            Api::GlobalReAlloc => 3,
            Api::GetModuleFileNameW => 3,
            Api::SetFilePointerApi | Api::GetTempFileNameW => 4,
            Api::ReadFileApi => 5,
            Api::CreateFile { .. } => 7,
            Api::RegisterClassApi { .. } | Api::CreateSolidBrushApi | Api::GetStockObjectApi
            | Api::DispatchMessageApi | Api::CreateFontApi | Api::SaveDCApi => 1,
            Api::BeginPaintApi | Api::EndPaintApi | Api::GetClientRectApi | Api::SetTextColorApi
            | Api::SelectObjectApi | Api::RestoreDCApi | Api::SetBkColorApi | Api::SetBkModeApi => 2,
            Api::FillRectApi | Api::CreatePenApi | Api::LineToApi | Api::GetObjectApi { .. } => 3,
            Api::DefWindowProcApi | Api::MoveToExApi | Api::SetPixelApi => 4,
            Api::RectangleApi | Api::TextOutApi => 5,
            Api::CreateWindowExApi => 12,
            Api::WsprintfApi { .. } => 0,
            Api::MessageBoxApi { .. } => 4,
            Api::GetUserObjectInfoApi => 5,
            Api::RtlCaptureContext | Api::RtlLookupFunctionEntry | Api::RtlVirtualUnwind
            | Api::RtlPcToFileHeader | Api::RaiseException | Api::RtlUnwindEx
            | Api::ExceptionDriver | Api::LdrGetDllHandle | Api::LdrLoadDll => 0,
            Api::SetUnhandledExceptionFilter | Api::UnhandledExceptionFilter => 1,
            Api::RegClose => 1,
            Api::RegDeleteValue { .. } | Api::RegDeleteKey { .. } => 2,
            Api::RegOpen { .. } => 5,
            Api::RegSet { .. } | Api::RegQuery { .. } => 6,
            Api::RegEnumKey { .. } | Api::RegEnumValue { .. } => 8,
            Api::RegCreate { .. } => 9,
            Api::RegQueryInfoKey => 12,
            Api::WinStub { argc, .. }
            | Api::FakeHandle { argc, .. }
            | Api::Unsupported { argc, .. } => *argc,
        }
    }
}

pub(crate) fn win32_argc(dll: &str, name: &str) -> Option<u32> {
    if let Some(ord) = name.strip_prefix("#ord") {
        return match (dll, ord) {
            ("comctl32.dll", "17") => Some(0),
            _ => None,
        };
    }
    let n = match name {
        "GetCommandLineW" | "GetLastError" | "GetTickCount" | "GetVersion" | "GetCurrentProcess"
        | "CloseClipboard" | "CreatePopupMenu" | "EmptyClipboard" | "GetMessagePos"
        | "OleUninitialize" | "wsprintfW" | "wsprintfA"
        | "GetProcessWindowStation" | "GetDesktopWindow" | "GetActiveWindow"
        | "GetForegroundWindow" | "GetShellWindow" | "GetCurrentThread"
        | "GetConsoleWindow" | "SetConsoleTitleA" => 0,

        "SetConsoleTitleW" | "FlushConsoleInputBuffer" | "SetHandleCount"
        | "InitializeCriticalSection" | "DeleteCriticalSection" | "EnterCriticalSection"
        | "LeaveCriticalSection" | "TryEnterCriticalSection" | "InitializeSListHead"
        | "SetEvent" | "ResetEvent" | "PulseEvent" | "ReleaseMutex"
        | "CloseHandle" | "FindClose" | "FreeLibrary" | "GetFileAttributesW" | "DeleteFileW"
        | "GlobalFree" | "GlobalLock" | "GlobalUnlock" | "RemoveDirectoryW"
        | "SetCurrentDirectoryW" | "GetModuleHandleA" | "GetModuleHandleW" | "Sleep"
        | "SetErrorMode" | "lstrlenA" | "lstrlenW" | "DestroyWindow" | "GetDC" | "IsWindow"
        | "IsWindowEnabled" | "IsWindowVisible" | "OpenClipboard" | "PostQuitMessage"
        | "RegisterClassW" | "SetCursor" | "SetForegroundWindow" | "GetSysColor"
        | "GetSystemMetrics" | "TranslateMessage" | "DispatchMessageW" | "MessageBoxIndirectW"
        | "DeleteObject" | "CreateBrushIndirect" | "CreateFontIndirectW" | "RegCloseKey"
        | "SHBrowseForFolderW" | "SHFileOperationW" | "OleInitialize" | "CoTaskMemFree"
        | "ImageList_Destroy" | "GetThreadDesktop" | "LoadCursorA" | "LoadIconA"
        | "HeapDestroy"
        | "SetDefaultDllDirectories" | "SetDllDirectoryW" | "SetDllDirectoryA"
        | "CreateActCtxA" | "CreateActCtxW"
        | "ReleaseActCtx" | "AddRefActCtx" | "ZombifyActCtx"
        | "GetCurrentActCtx" => 1,

        "SetConsoleCtrlHandler" | "SetThreadPriority"
        | "CompareFileTime" | "CreateDirectoryW" | "GetFileSize" | "GlobalAlloc" | "MoveFileW"
        | "SetEnvironmentVariableW" | "SetFileAttributesW" | "WaitForSingleObject"
        | "GetTempPathW" | "GetSystemDirectoryW" | "GetWindowsDirectoryW"
        | "HeapCompact" | "InitializeCriticalSectionAndSpinCount" | "SetCriticalSectionSpinCount"
        | "EnableWindow" | "EndDialog" | "EndPaint" | "ExitWindowsEx" | "GetClientRect"
        | "GetDlgItem" | "GetSystemMenu" | "GetWindowLongW" | "GetWindowRect" | "LoadBitmapW"
        | "LoadCursorW" | "ReleaseDC" | "ScreenToClient" | "SetClipboardData" | "SetWindowTextW"
        | "ShowWindow" | "BeginPaint" | "GetDeviceCaps" | "SelectObject" | "SetBkColor"
        | "SetBkMode" | "SetTextColor" | "RegDeleteKeyW" | "RegDeleteValueW"
        | "SHGetPathFromIDListW" | "lstrcatW" | "lstrcmpW" | "lstrcmpiA" | "lstrcmpiW"
        | "lstrcpyA" | "lstrcpyW" | "FindFirstFileW" | "FindFirstFileA" | "FindNextFileW"
        | "FindNextFileA" | "RegNotifyChangeKeyValue"
        | "GetPropW" | "GetPropA" | "RemovePropW" | "RemovePropA"
        | "ActivateActCtx" | "DeactivateActCtx" => 2,

        "ReleaseSemaphore" | "CreateMutexA" | "CreateMutexW"
        | "WaitForSingleObjectEx"
        | "ExpandEnvironmentStringsW" | "CopyFileW" | "SetFileSecurityW" | "LoadLibraryExW"
        | "GetShortPathNameW" | "MoveFileExW" | "CheckDlgButton" | "EnableMenuItem"
        | "InvalidateRect" | "SetClassLongW" | "SetDlgItemTextW" | "SetWindowLongW"
        | "GetClassInfoW" | "OpenProcessToken" | "LookupPrivilegeValueW"
        | "SHGetSpecialFolderLocation" | "ImageList_AddMasked" | "MulDiv" | "lstrcpynW"
        | "OpenInputDesktopW" | "HeapCreate" | "HeapValidate"
        | "InitializeCriticalSectionEx" | "SetPropW" | "SetPropA" => 3,

        "CreateEventA" | "CreateEventW" | "CreateEventExA" | "CreateEventExW"
        | "CreateMutexExA" | "CreateMutexExW"
        | "CreateSemaphoreA" | "CreateSemaphoreW"
        | "WaitForMultipleObjects"
        | "GetModuleFileNameW" | "GetFullPathNameW" | "SetFilePointer" | "SetFileTime"
        | "GetTempFileNameW" | "WritePrivateProfileStringW" | "AppendMenuW" | "DefWindowProcW"
        | "FindWindowExW" | "GetDlgItemTextW" | "MessageBoxW" | "SendMessageW" | "GetMessageW"
        | "SetTimer" | "SystemParametersInfoW" | "DrawTextW" | "FillRect" | "RegEnumKeyW"
        | "OpenDesktopW" | "HeapSetInformation" | "MapWindowPoints" => 4,

        "WaitForMultipleObjectsEx"
        | "ReadFile" | "WriteFile" | "GetDiskFreeSpaceW" | "CallWindowProcW" | "CreateDialogParamW"
        | "DialogBoxParamW" | "PeekMessageW" | "RegOpenKeyExW" | "SHGetFileInfoW"
        | "CoCreateInstance" | "ImageList_Create"
        | "FindActCtxSectionStringW" | "FindActCtxSectionStringA"
        | "FindActCtxSectionGuidW" => 5,

        "GetPrivateProfileStringW" | "SearchPathW" | "MultiByteToWideChar" | "CreateThread"
        | "LoadImageW" | "LoadImageA" | "AdjustTokenPrivileges" | "RegQueryValueExW"
        | "RegSetValueExW" | "ShellExecuteW" | "FindFirstFileExW" => 6,

        "CreateFileW" | "CreateFileA" | "SetWindowPos" | "SendMessageTimeoutW" | "TrackPopupMenu"
        | "RegGetValueW"
        | "QueryActCtxW" => 7,

        "WideCharToMultiByte" | "RegEnumValueW" | "RegEnumKeyExW" => 8,
        "RegCreateKeyExW" => 9,
        "CreateWindowExW" | "RegQueryInfoKeyW" => 12,

        _ => return None,
    };
    Some(n)
}

const TRUE: u64 = 1;
const FALSE: u64 = 0;

pub(crate) const FAKE_HANDLE: u64 = 0x00CA_FE00;

const HWND_DIALOG: u64 = 0x00D1_A000;
const HWND_CONTROL: u64 = 0x00C0_0000;
const WM_SETTEXT: u32 = 0x000C;
const WM_GETTEXT: u32 = 0x000D;
const WM_GETTEXTLENGTH: u32 = 0x000E;
const WM_INITDIALOG: u64 = 0x0110;
const WM_COMMAND: u64 = 0x0111;
const IDOK: u32 = 1;
const IDCANCEL: u32 = 2;
const PBM_SETRANGE: u32 = 0x0401;
const PBM_SETPOS: u32 = 0x0402;
const PBM_DELTAPOS: u32 = 0x0403;
const PBM_SETRANGE32: u32 = 0x0406;

fn control_id(hwnd: u64) -> Option<u32> {
    if (HWND_CONTROL..HWND_CONTROL + 0x1_0000).contains(&hwnd) {
        Some((hwnd - HWND_CONTROL) as u32)
    } else {
        None
    }
}

fn read_unicode_string_base_name(mem: &dyn Memory, us: u64) -> Result<Option<String>> {
    if us == 0 {
        return Ok(None);
    }
    let len = mem.read_u16(us)? as u64;
    let buf = mem.read_u64(us + 8)?;
    if buf == 0 {
        return Ok(None);
    }
    let mut units = Vec::with_capacity((len / 2) as usize);
    for i in 0..len / 2 {
        units.push(mem.read_u16(buf + i * 2)?);
    }
    let name = String::from_utf16_lossy(&units).to_ascii_lowercase();
    Ok(Some(name.rsplit(['\\', '/']).next().unwrap_or(&name).to_string()))
}

pub(crate) fn read_wstr_units(mem: &dyn Memory, addr: u64) -> Result<Vec<u16>> {
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

pub(crate) fn read_astr(mem: &dyn Memory, addr: u64) -> Result<String> {
    if addr == 0 {
        return Ok(String::new());
    }
    let mut bytes = Vec::new();
    let mut i = 0u64;
    loop {
        let b = mem.read_u8(addr + i)?;
        if b == 0 || i > (1 << 20) {
            break;
        }
        bytes.push(b);
        i += 1;
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub(crate) fn read_path(mem: &dyn Memory, addr: u64, wide: bool) -> Result<String> {
    if wide {
        read_wstr(mem, addr)
    } else {
        read_astr(mem, addr)
    }
}

pub(crate) fn write_astr(mem: &mut dyn Memory, addr: u64, s: &str, max: usize) -> Result<u64> {
    if addr == 0 || max == 0 {
        return Ok(0);
    }
    let bytes = s.as_bytes();
    let n = bytes.len().min(max - 1);
    mem.write(addr, &bytes[..n])?;
    mem.write_u8(addr + n as u64, 0)?;
    Ok(n as u64)
}

fn write_path(mem: &mut dyn Memory, addr: u64, s: &str, max: usize, wide: bool) -> Result<u64> {
    if wide {
        WinOs::write_wstr(mem, addr, s, max)
    } else {
        write_astr(mem, addr, s, max)
    }
}

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
                self.begin_process_exit(cpu, mem, code)
            }
            Api::ReturnExit => {
                let code = cpu.gpr_read(0, 4) as u32 as i32;
                self.begin_process_exit(cpu, mem, code)
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
                let name_ptr = self.arg(cpu, mem, 0)?;
                if name_ptr == 0 {
                    return ret(self.cfg.image_base);
                }
                let name = if matches!(api, Api::GetModuleHandleW) {
                    read_wstr(mem, name_ptr)?
                } else {
                    read_astr(mem, name_ptr)?
                };
                ret(self.module_handle(&name))
            }

            Api::LoadLibraryApi { wide, argc } => {
                let name_ptr = self.arg(cpu, mem, 0)?;
                let name = if *wide { read_wstr(mem, name_ptr)? } else { read_astr(mem, name_ptr)? };
                let argc = *argc;
                self.enter_loader_lock(mem)?;
                let handle = self.load_library(mem, &name)?;
                let pending = std::mem::take(&mut self.dll.pending_dllmain);
                self.leave_loader_lock(mem)?;
                if !pending.is_empty() {
                    let bases: Vec<u64> = pending.iter().map(|&(_, b)| b).collect();
                    self.mark_attached(&bases);
                    let calls: Vec<(u64, Vec<u64>)> = pending
                        .into_iter()
                        .map(|(entry, base)| (entry, vec![base, 1 , 0]))
                        .collect();
                    return self.invoke_callbacks(cpu, mem, calls, handle, argc, false);
                }
                ret(handle)
            }

            Api::GetProcessHeap => ret(HANDLE_PROCESS_HEAP),
            Api::HeapAlloc => {
                let size = self.arg(cpu, mem, 2)?;
                ret(self.heap_alloc(size))
            }
            Api::HeapReAlloc => {
                let old = self.arg(cpu, mem, 2)?;
                let new_size = self.arg(cpu, mem, 3)?;
                let new = self.heap_alloc(new_size);
                if new != 0 && old != 0 {
                    let old_size = self.heap_sizes.get(&old).copied().unwrap_or(new_size);
                    let copy_len = old_size.min(new_size);
                    for i in 0..copy_len {
                        let b = mem.read_u8(old + i)?;
                        mem.write_u8(new + i, b)?;
                    }
                }
                ret(new)
            }
            Api::HeapFree => {
                let ptr = self.arg(cpu, mem, 2)?;
                if ptr != 0 {
                    if let Some(sz) = self.heap_sizes.remove(&ptr) {
                        if self.heap_next == ptr + sz {
                            self.heap_next = ptr;
                        }
                    }
                }
                ret(TRUE)
            }

            Api::VirtualAlloc => self.virtual_alloc(cpu, mem),
            Api::VirtualFree => self.virtual_free(cpu, mem),
            Api::VirtualProtect => self.virtual_protect(cpu, mem),
            Api::VirtualQuery => self.virtual_query(cpu, mem),

            Api::CreateSync { kind, ex, wide } => self.create_sync(cpu, mem, *kind, *ex, *wide),
            Api::OpenSync { wide } => self.open_sync(cpu, mem, *wide),
            Api::SignalSync { op } => self.signal_sync(cpu, mem, *op),
            Api::WaitSingle { .. } => self.wait_single(cpu, mem),
            Api::WaitMultiple { .. } => self.wait_multiple(cpu, mem),
            Api::EncodeDecodePointer => {
                let p = self.arg(cpu, mem, 0)?;
                ret(p)
            }

            Api::RtlCaptureContext => {
                let ctx_ptr = self.arg(cpu, mem, 0)?;
                let ret_addr = mem.read_u64(cpu.rsp())?;
                let mut snap = cpu.clone();
                snap.rip = ret_addr;
                snap.set_rsp(cpu.rsp() + 8);
                crate::exc::write_context(mem, ctx_ptr, &snap)?;
                ret(0)
            }
            Api::RtlLookupFunctionEntry => {
                let pc = self.arg(cpu, mem, 0)?;
                let base_out = self.arg(cpu, mem, 1)?;
                let image_base = self.cfg.image_base;
                let entry = pc
                    .checked_sub(image_base)
                    .and_then(|off| u32::try_from(off).ok())
                    .and_then(|rva| exemu_core::unwind::lookup(&self.function_table, rva));
                match entry {
                    Some(e) => {
                        if base_out != 0 {
                            mem.write_u64(base_out, image_base)?;
                        }
                        ret(image_base + e.record_rva as u64)
                    }
                    None => {
                        if base_out != 0 {
                            mem.write_u64(base_out, 0)?;
                        }
                        ret(0)
                    }
                }
            }
            Api::RtlVirtualUnwind => {
                let handler_type = self.arg(cpu, mem, 0)? as u32;
                let control_pc = self.arg(cpu, mem, 2)?;
                let ctx_ptr = self.arg(cpu, mem, 4)?;
                let handler_data_out = self.arg(cpu, mem, 5)?;
                let frame_out = self.arg(cpu, mem, 6)?;
                let image_base = self.cfg.image_base;

                let mut state = crate::exc::read_context(mem, ctx_ptr)?;
                state.rip = control_pc;
                let fu = exemu_core::unwind::virtual_unwind_typed(
                    &self.function_table,
                    image_base,
                    &mut state,
                    mem,
                    exemu_core::HandlerType(handler_type),
                )?;
                crate::exc::write_context(mem, ctx_ptr, &state)?;
                if frame_out != 0 {
                    mem.write_u64(frame_out, fu.establisher_frame)?;
                }
                if handler_data_out != 0 {
                    let hd = fu
                        .handler_data_rva
                        .map(|rva| image_base + rva as u64)
                        .unwrap_or(0);
                    mem.write_u64(handler_data_out, hd)?;
                }
                ret(fu.handler_rva.map(|rva| image_base + rva as u64).unwrap_or(0))
            }
            Api::RtlPcToFileHeader => {
                let pc = self.arg(cpu, mem, 0)?;
                let base_out = self.arg(cpu, mem, 1)?;
                let image_base = self.cfg.image_base;
                let in_image = pc
                    .checked_sub(image_base)
                    .and_then(|off| u32::try_from(off).ok())
                    .is_some_and(|rva| exemu_core::unwind::lookup(&self.function_table, rva).is_some());
                let base = if in_image { image_base } else { 0 };
                if base_out != 0 {
                    mem.write_u64(base_out, base)?;
                }
                ret(base)
            }

            Api::LdrGetDllHandle | Api::LdrLoadDll => {
                let name_us = self.arg(cpu, mem, 2)?;
                let handle_out = self.arg(cpu, mem, 3)?;
                const STATUS_DLL_NOT_FOUND: u64 = 0xC000_0135;
                let mut status = STATUS_DLL_NOT_FOUND;
                if let Some(name) = read_unicode_string_base_name(mem, name_us)? {
                    if let Some(base) = self.wow64_module(&name).or_else(|| self.module_base(&name)) {
                        if handle_out != 0 {
                            mem.write_u64(handle_out, base)?;
                        }
                        status = 0;
                    }
                }
                ret(status)
            }

            Api::RaiseException => self.raise_exception(cpu, mem),
            Api::RtlUnwindEx => self.rtl_unwind_ex(cpu, mem),
            Api::ExceptionDriver => self.exc_advance(cpu, mem),

            Api::WineUnixCall => {
                let status = self.wine_unix_call(cpu, mem)?;
                if self.unix_call_blocked {
                    Ok(Outcome::Resume)
                } else {
                    ret(status as u64)
                }
            }
            Api::SetUnhandledExceptionFilter => {
                let old = self.unhandled_filter;
                self.unhandled_filter = self.arg(cpu, mem, 0)?;
                ret(old)
            }
            Api::UnhandledExceptionFilter => ret(1),

            Api::GetLastError => ret(self.last_error as u64),
            Api::SetLastError => {
                self.last_error = self.arg(cpu, mem, 0)? as u32;
                Ok(Outcome::Return(0))
            }

            Api::GetCurrentProcessId => ret(0x1000),
            Api::GetCurrentThreadId => ret(self.current_tid as u64),
            Api::GetCurrentProcess => ret(u64::MAX),
            Api::IsDebuggerPresent => ret(FALSE),
            Api::CreateThread => self.create_thread(cpu, mem),
            Api::ExitThread => self.api_exit_thread(cpu, mem),
            Api::ThreadExit => self.thread_start_returned(cpu, mem),
            Api::ThreadTlsAttach => self.thread_tls_attach(cpu, mem),
            Api::ThreadStartEntry => self.thread_start_entry(cpu, mem),
            Api::ResumeThread => self.resume_thread(cpu, mem),
            Api::SuspendThread => self.suspend_thread(cpu, mem),
            Api::TerminateThread => self.terminate_thread(cpu, mem),
            Api::GetExitCodeThread => self.get_exit_code_thread(cpu, mem),
            Api::CreateProcessApi { wide } => self.win32_create_process(cpu, mem, *wide),
            Api::GetExitCodeProcessApi => self.win32_get_exit_code_process(cpu, mem),
            Api::SwitchToThread => self.switch_to_thread(cpu, mem),
            Api::SleepApi { ex } => self.sleep(cpu, mem, if *ex { 2 } else { 1 }),

            Api::PostMessageApi => self.post_message(cpu, mem),
            Api::PostThreadMessageApi => self.post_thread_message(cpu, mem),
            Api::TranslateMessageApi => self.translate_message(cpu, mem),

            Api::WindowLong { set } => self.window_long(cpu, mem, *set),
            Api::IsWindowApi => self.is_window(cpu, mem),
            Api::GetWindowRectApi => self.get_window_rect(cpu, mem),
            Api::ShowWindowApi => self.show_window(cpu, mem),
            Api::GetClassNameApi { wide } => self.get_class_name(cpu, mem, *wide),
            Api::SetPropApi { wide } => self.set_prop(cpu, mem, *wide),
            Api::GetPropApi { wide } => self.get_prop(cpu, mem, *wide),
            Api::RemovePropApi { wide } => self.remove_prop(cpu, mem, *wide),

            Api::QueryPerformanceCounter => self.query_performance_counter(cpu, mem),
            Api::QueryPerformanceFrequency => self.query_performance_frequency(cpu, mem),
            Api::GetSystemTimeAsFileTime => self.get_system_time_as_filetime(cpu, mem),
            Api::GetSystemTime => self.get_system_time(cpu, mem),
            Api::GetTickCount => self.get_tick_count(),
            Api::GetACP => ret(65001),

            Api::SetConsoleCP | Api::SetConsoleOutputCP => ret(TRUE),
            Api::GetConsoleMode => {
                let ptr = self.arg(cpu, mem, 1)?;
                if ptr != 0 {
                    mem.write_u32(ptr, 0x0003)?;
                }
                ret(TRUE)
            }
            Api::SetConsoleMode => ret(TRUE),

            Api::GetStartupInfoA | Api::GetStartupInfoW => {
                let ptr = self.arg(cpu, mem, 0)?;
                if ptr != 0 {
                    for i in 0..104u64 {
                        mem.write_u8(ptr + i, 0)?;
                    }
                    mem.write_u32(ptr, 104)?;
                }
                Ok(Outcome::Return(0))
            }
            Api::GetEnvironmentStrings { wide } => {
                if *wide {
                    let units = self.env_block_utf16();
                    let ptr = self.heap_alloc(units.len() as u64 * 2);
                    if ptr != 0 {
                        for (i, u) in units.iter().enumerate() {
                            mem.write_u16(ptr + i as u64 * 2, *u)?;
                        }
                    }
                    ret(ptr)
                } else {
                    let bytes = self.env_block_ansi();
                    let ptr = self.heap_alloc(bytes.len() as u64);
                    if ptr != 0 {
                        mem.write(ptr, &bytes)?;
                    }
                    ret(ptr)
                }
            }
            Api::FreeEnvironmentStrings => ret(TRUE),
            Api::GetEnvironmentVariable { wide } => {
                let name_ptr = self.arg(cpu, mem, 0)?;
                let buf = self.arg(cpu, mem, 1)?;
                let size = self.arg(cpu, mem, 2)? as usize;
                let name = if *wide { read_wstr(mem, name_ptr)? } else { read_astr(mem, name_ptr)? };
                match self.env_get(&name).map(str::to_owned) {
                    None => {
                        self.last_error = 203;
                        ret(0)
                    }
                    Some(value) => {
                        if *wide {
                            let units: Vec<u16> = value.encode_utf16().collect();
                            if units.len() + 1 > size {
                                ret(units.len() as u64 + 1)
                            } else {
                                write_wstr_units(mem, buf, &units, size)?;
                                ret(units.len() as u64)
                            }
                        } else {
                            let bytes = value.as_bytes();
                            if bytes.len() + 1 > size {
                                ret(bytes.len() as u64 + 1)
                            } else {
                                mem.write(buf, bytes)?;
                                mem.write_u8(buf + bytes.len() as u64, 0)?;
                                ret(bytes.len() as u64)
                            }
                        }
                    }
                }
            }
            Api::SetEnvironmentVariable { wide } => {
                let name_ptr = self.arg(cpu, mem, 0)?;
                let value_ptr = self.arg(cpu, mem, 1)?;
                let name = if *wide { read_wstr(mem, name_ptr)? } else { read_astr(mem, name_ptr)? };
                if name.is_empty() {
                    return ret(FALSE);
                }
                let value = if value_ptr == 0 {
                    None
                } else if *wide {
                    Some(read_wstr(mem, value_ptr)?)
                } else {
                    Some(read_astr(mem, value_ptr)?)
                };
                self.env_set(&name, value.as_deref());
                ret(TRUE)
            }
            Api::ExpandEnvironmentStrings { wide } => {
                let src_ptr = self.arg(cpu, mem, 0)?;
                let dst = self.arg(cpu, mem, 1)?;
                let size = self.arg(cpu, mem, 2)? as usize;
                let src = if *wide { read_wstr(mem, src_ptr)? } else { read_astr(mem, src_ptr)? };
                let expanded = self.expand_env(&src);
                if *wide {
                    let units: Vec<u16> = expanded.encode_utf16().collect();
                    let needed = units.len() + 1;
                    if needed <= size {
                        write_wstr_units(mem, dst, &units, size)?;
                    }
                    ret(needed as u64)
                } else {
                    let bytes = expanded.as_bytes();
                    let needed = bytes.len() + 1;
                    if needed <= size && dst != 0 {
                        mem.write(dst, bytes)?;
                        mem.write_u8(dst + bytes.len() as u64, 0)?;
                    }
                    ret(needed as u64)
                }
            }
            Api::WideCharToMultiByte => {
                let cp = self.arg(cpu, mem, 0)? as u32;
                let wstr = self.arg(cpu, mem, 2)?;
                let cch = self.arg(cpu, mem, 3)? as i32;
                let mbstr = self.arg(cpu, mem, 4)?;
                let cb = self.arg(cpu, mem, 5)? as i32;
                let used_default = self.arg(cpu, mem, 7)?;

                let units: Vec<u16> = if cch < 0 {
                    read_wstr_units(mem, wstr)?
                } else {
                    let mut v = Vec::with_capacity(cch as usize);
                    for i in 0..cch as u64 {
                        v.push(mem.read_u16(wstr + i * 2)?);
                    }
                    v
                };
                let (mut bytes, lossy) = match crate::nls::sbcs_encode(cp, &units) {
                    Some(pair) => pair,
                    None => (String::from_utf16_lossy(&units).into_bytes(), false),
                };
                if cch < 0 {
                    bytes.push(0);
                }
                if used_default != 0 {
                    mem.write_u8(used_default, u8::from(lossy))?;
                }
                if cb == 0 {
                    return ret(bytes.len() as u64);
                }
                if bytes.len() > cb as usize {
                    self.last_error = 122;
                    return ret(0);
                }
                mem.write(mbstr, &bytes)?;
                ret(bytes.len() as u64)
            }
            Api::MultiByteToWideChar => {
                let cp = self.arg(cpu, mem, 0)? as u32;
                let mbstr = self.arg(cpu, mem, 2)?;
                let cb = self.arg(cpu, mem, 3)? as i32;
                let wstr = self.arg(cpu, mem, 4)?;
                let cch = self.arg(cpu, mem, 5)? as i32;

                let bytes: Vec<u8> = if cb < 0 {
                    mem.read_cstr(mbstr, 1 << 20)?
                } else {
                    let mut v = vec![0u8; cb as usize];
                    mem.read(mbstr, &mut v)?;
                    v
                };
                let mut units: Vec<u16> = crate::nls::sbcs_decode(cp, &bytes)
                    .unwrap_or_else(|| String::from_utf8_lossy(&bytes).encode_utf16().collect());
                if cb < 0 {
                    units.push(0);
                }
                if cch == 0 {
                    return ret(units.len() as u64);
                }
                if units.len() > cch as usize {
                    self.last_error = 122;
                    return ret(0);
                }
                for (i, u) in units.iter().enumerate() {
                    mem.write_u16(wstr + i as u64 * 2, *u)?;
                }
                ret(units.len() as u64)
            }

            Api::FreeLibrary => {
                let hmodule = self.arg(cpu, mem, 0)?;
                self.enter_loader_lock(mem)?;
                let ok = self.free_library(hmodule);
                let pending = std::mem::take(&mut self.dll.pending_detach);
                self.leave_loader_lock(mem)?;
                let result = if ok { TRUE } else { FALSE };
                if !pending.is_empty() {
                    let calls: Vec<(u64, Vec<u64>)> = pending
                        .into_iter()
                        .map(|(entry, base)| (entry, vec![base, 0 , 0]))
                        .collect();
                    return self.invoke_callbacks(cpu, mem, calls, result, 1, false);
                }
                ret(result)
            }
            Api::DisableThreadLibraryCalls => {
                let hmodule = self.arg(cpu, mem, 0)?;
                ret(if self.disable_thread_library_calls(hmodule) { TRUE } else { FALSE })
            }
            Api::GetProcAddress => {
                let hmodule = self.arg(cpu, mem, 0)?;
                let name_ptr = self.arg(cpu, mem, 1)?;
                let addr = self.get_proc_address(mem, hmodule, name_ptr)?;
                if self.cfg.trace {
                    let what = if name_ptr < 0x1_0000 {
                        format!("#{name_ptr}")
                    } else {
                        read_astr(mem, name_ptr).unwrap_or_default()
                    };
                    eprintln!("[exemu]   GetProcAddress({hmodule:#x}, \"{what}\") -> {addr:#x}");
                }
                ret(addr)
            }

            Api::TlsAlloc { fiber } => ret(self.tls_alloc(*fiber)),
            Api::TlsSetValue { fiber } => {
                let index = self.arg(cpu, mem, 0)?;
                let value = self.arg(cpu, mem, 1)?;
                ret(self.tls_set(*fiber, index, value) as u64)
            }
            Api::TlsGetValue { fiber } => {
                let index = self.arg(cpu, mem, 0)?;
                self.last_error = 0;
                ret(self.tls_get(*fiber, index))
            }
            Api::TlsFree { fiber } => {
                let index = self.arg(cpu, mem, 0)?;
                ret(self.tls_free(*fiber, index) as u64)
            }

            Api::Malloc => {
                let size = self.arg(cpu, mem, 0)?;
                ret(self.heap_alloc(size))
            }
            Api::Calloc => {
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
                let dest = self.arg(cpu, mem, 0)?;
                let src = self.arg(cpu, mem, 1)?;
                let n = self.arg(cpu, mem, 2)? as usize;
                let mut tmp = vec![0u8; n];
                mem.read(src, &mut tmp)?;
                mem.write(dest, &tmp)?;
                ret(dest)
            }
            Api::Memset => {
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
                let argc_ptr = self.arg(cpu, mem, 0)?;
                let argv_ptr = self.arg(cpu, mem, 1)?;
                let env_ptr = self.arg(cpu, mem, 2)?;
                let argv_arr = self.heap_alloc(16);
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
                    let env_arr = self.heap_alloc(8);
                    mem.write_u64(env_ptr, env_arr)?;
                }
                ret(0)
            }

            Api::Initterm => {
                let first = self.arg(cpu, mem, 0)?;
                let last = self.arg(cpu, mem, 1)?;
                let saved_rsp = cpu.rsp();
                let ptr = if self.cfg.is_64bit { 8u64 } else { 4 };
                let ret_addr = self.read_ptr(mem, saved_rsp)?;

                let mut fns = VecDeque::new();
                let mut p = first;
                while p < last {
                    let f = self.read_ptr(mem, p)?;
                    if f != 0 {
                        fns.push_back(f);
                    }
                    p += ptr;
                }

                match fns.pop_front() {
                    None => Ok(Outcome::Return(0)),
                    Some(first_fn) => {
                        self.initterm_stack.push(InittermFrame { remaining: fns, ret: ret_addr, saved_rsp });
                        let driver = self.initterm_driver;
                        self.setup_call_args(cpu, mem, first_fn, &[], driver, saved_rsp)?;
                        Ok(Outcome::Resume)
                    }
                }
            }
            Api::EhProlog => self.eh_prolog(cpu, mem),

            Api::InittermDriver => self.initterm_advance(cpu, mem),
            Api::CallbackDriver => self.cb_advance(cpu, mem),
            Api::Win32kCbDriver => self.win32k_cb_advance(cpu, mem),

            Api::CreateDialogParam { modal } => {
                let template_id = self.arg(cpu, mem, 1)?;
                let dlgproc = self.arg(cpu, mem, 3)?;
                let init_param = self.arg(cpu, mem, 4)?;
                let hwnd = HWND_DIALOG;
                self.dlgproc = dlgproc;
                self.dialog_hwnd = hwnd;
                if dlgproc == 0 {
                    return ret(hwnd);
                }

                let mut interactive = false;
                if template_id < 0x1_0000 {
                    if let Some(tpl) = self.dialogs.get(&(template_id as u32)).cloned() {
                        self.gui.open(&tpl);
                        interactive = self.gui.is_open();
                    }
                }

                if interactive {
                    self.dialog_result = None;
                    let calls = vec![(dlgproc, vec![hwnd, WM_INITDIALOG, 0, init_param])];
                    let result = if *modal { IDCANCEL as u64 } else { hwnd };
                    self.invoke_callbacks(cpu, mem, calls, result, 5, *modal)
                } else {
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
                let text = self
                    .gui
                    .get_text(id)
                    .map(|s| s.encode_utf16().collect::<Vec<u16>>())
                    .or_else(|| self.controls.get(&id).cloned())
                    .unwrap_or_default();
                ret(write_wstr_units(mem, buf, &text, max)?)
            }
            Api::GetDlgItemApi => {
                let id = self.arg(cpu, mem, 1)? as u32;
                ret(HWND_CONTROL | id as u64)
            }
            Api::SetWindowTextApi => {
                let hwnd = self.arg(cpu, mem, 0)?;
                let text = read_wstr_units(mem, self.arg(cpu, mem, 1)?)?;
                if let Some(w) = self.gdi.windows.get_mut(&hwnd) {
                    w.title = text;
                } else if let Some(id) = control_id(hwnd) {
                    self.controls.insert(id, text);
                }
                ret(TRUE)
            }
            Api::GetWindowTextApi => {
                let hwnd = self.arg(cpu, mem, 0)?;
                let buf = self.arg(cpu, mem, 1)?;
                let max = self.arg(cpu, mem, 2)? as usize;
                let text = self
                    .gdi
                    .windows
                    .get(&hwnd)
                    .map(|w| w.title.clone())
                    .or_else(|| control_id(hwnd).and_then(|id| self.controls.get(&id).cloned()))
                    .unwrap_or_default();
                ret(write_wstr_units(mem, buf, &text, max)?)
            }
            Api::GetMessageApi => {
                let lp = self.arg(cpu, mem, 0)?;
                if let Some(m) = self.msg_next() {
                    self.write_msg_full(mem, lp, m.hwnd, m.message as u64, m.wparam, m.lparam)?;
                    return ret((m.message != crate::msg::WM_QUIT) as u64);
                }
                if self.quit_posted {
                    self.quit_posted = false;
                    return ret(0);
                }
                if self.is_custom_window() {
                    let hwnd = self.gdi.active_hwnd;
                    if self.gdi.paint_pending {
                        self.gdi.paint_pending = false;
                        self.write_msg_full(mem, lp, hwnd, crate::gdi::WM_PAINT, 0, 0)?;
                        return ret(1);
                    }
                    return match self.gui.pump(true) {
                        Some(exemu_core::GuiEvent::MouseDown(x, y)) => {
                            let lparam = (((y as u32 & 0xffff) << 16) | (x as u32 & 0xffff)) as u64;
                            self.write_msg_full(mem, lp, hwnd, crate::gdi::WM_LBUTTONDOWN, 0, lparam)?;
                            ret(1)
                        }
                        _ => ret(0),
                    };
                }
                if self.gui_active() {
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
                        _ => ret(0),
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
            Api::PeekMessageApi => {
                let lp = self.arg(cpu, mem, 0)?;
                let remove = self.arg(cpu, mem, 4)? & 1 != 0;
                if let Some(m) = self.msg_peek(remove) {
                    self.write_msg_full(mem, lp, m.hwnd, m.message as u64, m.wparam, m.lparam)?;
                    return ret(TRUE);
                }
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
            Api::IsDialogMessageApi => ret(TRUE),

            Api::CoCreateInstanceApi => {
                let ppv = self.arg(cpu, mem, 4)?;
                if ppv != 0 {
                    if self.cfg.is_64bit {
                        mem.write_u64(ppv, 0)?;
                    } else {
                        mem.write_u32(ppv, 0)?;
                    }
                }
                ret(0x8004_0154)
            }
            Api::DestroyWindowApi => {
                self.gui.close();
                ret(TRUE)
            }
            Api::PostQuitMessageApi => self.post_quit_message(cpu, mem),
            Api::EndDialogApi => {
                let result = self.arg(cpu, mem, 1)?;
                self.dialog_result = Some(result);
                self.gui.close();
                self.quit_posted = true;
                ret(TRUE)
            }

            Api::RegisterClassApi { ex } => {
                let wc = self.arg(cpu, mem, 0)?;
                ret(self.register_class(mem, wc, *ex)?)
            }
            Api::CreateWindowExApi => {
                let ex_style = self.arg(cpu, mem, 0)? as u32;
                let class_ptr = self.arg(cpu, mem, 1)?;
                let name_ptr = self.arg(cpu, mem, 2)?;
                let style = self.arg(cpu, mem, 3)? as u32;
                let x = self.arg(cpu, mem, 4)? as i32;
                let y = self.arg(cpu, mem, 5)? as i32;
                let w = self.arg(cpu, mem, 6)? as u32 as i64;
                let h = self.arg(cpu, mem, 7)? as u32 as i64;
                let parent = self.arg(cpu, mem, 8)?;
                let lp_param = self.arg(cpu, mem, 11)?;
                let hwnd = self.create_window(mem, class_ptr, name_ptr, style, ex_style, x, y, w, h, parent)?;
                if !self.gdi.windows.contains_key(&hwnd) {
                    return ret(hwnd);
                }
                let cs = self.heap_alloc(80);
                if cs != 0 {
                    mem.write_u64(cs, lp_param)?;
                }
                let wndproc = self.gdi.windows.get(&hwnd).map(|w| w.wndproc).unwrap_or(0);
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
                let wndproc = self.gdi.windows.get(&hwnd).map(|w| w.wndproc).unwrap_or(self.gdi.wndproc);
                if wndproc == 0 {
                    return ret(0);
                }
                self.invoke_callbacks(cpu, mem, vec![(wndproc, vec![hwnd, message, wparam, lparam])], 0, 1, false)
            }
            Api::BeginPaintApi => {
                let hwnd = self.arg(cpu, mem, 0)?;
                let ps = self.arg(cpu, mem, 1)?;
                ret(self.begin_paint(mem, hwnd, ps)?)
            }
            Api::InvalidateRectApi => {
                let hwnd = self.arg(cpu, mem, 0)?;
                let lprect = self.arg(cpu, mem, 1)?;
                ret(self.invalidate_rect(mem, hwnd, lprect)?)
            }
            Api::ValidateRectApi => {
                let hwnd = self.arg(cpu, mem, 0)?;
                ret(self.validate_rect(hwnd))
            }
            Api::GetUpdateRectApi => {
                let hwnd = self.arg(cpu, mem, 0)?;
                let lprect = self.arg(cpu, mem, 1)?;
                ret(self.get_update_rect(mem, hwnd, lprect)?)
            }
            Api::GetDCApi => {
                let hwnd = self.arg(cpu, mem, 0)?;
                ret(self.get_dc(hwnd))
            }
            Api::ReleaseDCApi => ret(TRUE),

            Api::SetFocusApi => self.set_focus(cpu, mem),
            Api::GetFocusApi => self.get_focus(),
            Api::SetCaptureApi => self.set_capture(cpu, mem),
            Api::GetCaptureApi => self.get_capture(),
            Api::ReleaseCaptureApi => self.release_capture(),
            Api::GetKeyStateApi => self.get_key_state(cpu, mem),
            Api::GetCursorPosApi => self.get_cursor_pos(cpu, mem),
            Api::MoveWindowApi => self.move_window(cpu, mem),
            Api::SetWindowPosApi => self.set_window_pos(cpu, mem),
            Api::EndPaintApi => {
                self.end_paint();
                ret(TRUE)
            }
            Api::GetClientRectApi => self.get_client_rect_win(cpu, mem),
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
            Api::CreateFontApi => {
                let lplf = self.arg(cpu, mem, 0)?;
                ret(self.create_font_indirect(mem, lplf)?)
            }
            Api::GetObjectApi { wide } => {
                let hobj = self.arg(cpu, mem, 0)?;
                let cb = self.arg(cpu, mem, 1)?;
                let out = self.arg(cpu, mem, 2)?;
                ret(self.get_object(mem, hobj, cb, out, *wide)?)
            }
            Api::SaveDCApi => ret(self.save_dc()),
            Api::RestoreDCApi => {
                let level = self.arg(cpu, mem, 1)? as i32 as i64;
                ret(self.restore_dc(level))
            }
            Api::SetBkColorApi => {
                let c = self.arg(cpu, mem, 1)? as u32;
                ret(self.set_bk_color(c))
            }
            Api::SetBkModeApi => {
                let m = self.arg(cpu, mem, 1)? as u32;
                ret(self.set_bk_mode(m))
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
            Api::RegCreate { wide } => self.reg_create(cpu, mem, *wide),
            Api::RegOpen { wide } => self.reg_open(cpu, mem, *wide),
            Api::RegSet { wide } => self.reg_set(cpu, mem, *wide),
            Api::RegQuery { wide } => self.reg_query(cpu, mem, *wide),
            Api::RegClose => self.reg_close(cpu, mem),
            Api::RegDeleteValue { wide } => self.reg_delete_value(cpu, mem, *wide),
            Api::RegDeleteKey { wide } => self.reg_delete_key(cpu, mem, *wide),
            Api::RegEnumKey { wide } => self.reg_enum_key(cpu, mem, *wide),
            Api::RegEnumValue { wide } => self.reg_enum_value(cpu, mem, *wide),
            Api::RegQueryInfoKey => self.reg_query_info(cpu, mem),

            Api::WinStub { r, .. } => ret(*r),
            Api::WsprintfApi { wide } => {
                let out = self.arg(cpu, mem, 0)?;
                let fmt_ptr = self.arg(cpu, mem, 1)?;
                let n = self.wsprintf(cpu, mem, out, fmt_ptr, *wide)?;
                ret(n as u64)
            }
            Api::MessageBoxApi { wide } => {
                let text_ptr = self.arg(cpu, mem, 1)?;
                let caption_ptr = self.arg(cpu, mem, 2)?;
                let text = if *wide { read_wstr(mem, text_ptr)? } else { read_astr(mem, text_ptr)? };
                let caption =
                    if *wide { read_wstr(mem, caption_ptr)? } else { read_astr(mem, caption_ptr)? };
                let caption = if caption.is_empty() { "Message".to_string() } else { caption };
                self.emit(true, format!("[MessageBox] {caption}: {text}\n").as_bytes());
                ret(IDOK as u64)
            }
            Api::GetUserObjectInfoApi => {
                const UOI_FLAGS: u64 = 1;
                const WSF_VISIBLE: u32 = 0x0001;
                let nindex = self.arg(cpu, mem, 1)?;
                let pv = self.arg(cpu, mem, 2)?;
                let nlen = self.arg(cpu, mem, 3)?;
                let needed = self.arg(cpu, mem, 4)?;
                if nindex == UOI_FLAGS {
                    if pv != 0 && nlen >= 12 {
                        mem.write_u32(pv, 0)?;
                        mem.write_u32(pv + 4, 0)?;
                        mem.write_u32(pv + 8, WSF_VISIBLE)?;
                    }
                    if needed != 0 {
                        mem.write_u32(needed, 12)?;
                    }
                } else if needed != 0 {
                    mem.write_u32(needed, 0)?;
                }
                ret(TRUE)
            }

            Api::SendMessageApi => {
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
            Api::CrtGlobalPtr { name } => {
                let name = name.clone();
                let cell = self.crt_global(mem, &name)?;
                ret(cell)
            }

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

            Api::CreateFile { wide } => {
                let name = read_path(mem, self.arg(cpu, mem, 0)?, *wide)?;
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
            Api::CreateDirectory { wide } => {
                let name = read_path(mem, self.arg(cpu, mem, 0)?, *wide)?;
                ret(self.create_directory(&name) as u64)
            }
            Api::GetTempPathW => {
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
            Api::GetFileAttributes { wide } => {
                let name = read_path(mem, self.arg(cpu, mem, 0)?, *wide)?;
                ret(self.file_attributes(&name))
            }
            Api::DeleteFile { wide } => {
                let name = read_path(mem, self.arg(cpu, mem, 0)?, *wide)?;
                ret(self.delete_file(&name) as u64)
            }
            Api::FindFirstFile { ex, wide } => {
                let pattern = read_path(mem, self.arg(cpu, mem, 0)?, *wide)?;
                let buf_arg = if *ex { 2 } else { 1 };
                let data_ptr = self.arg(cpu, mem, buf_arg)?;
                ret(self.find_first_file(mem, &pattern, data_ptr, *wide)?)
            }
            Api::FindNextFile { .. } => {
                let handle = self.arg(cpu, mem, 0)?;
                let data_ptr = self.arg(cpu, mem, 1)?;
                ret(self.find_next_file(mem, handle, data_ptr)?)
            }
            Api::FindClose => {
                let handle = self.arg(cpu, mem, 0)?;
                ret(self.find_close(handle))
            }
            Api::GetFullPathName { wide } => {
                let name = read_path(mem, self.arg(cpu, mem, 0)?, *wide)?;
                let len = self.arg(cpu, mem, 1)? as usize;
                let buf = self.arg(cpu, mem, 2)?;
                let part_ptr = self.arg(cpu, mem, 3)?;
                let full = self.full_path_name(&name);
                let written = write_path(mem, buf, &full, len, *wide)?;
                if part_ptr != 0 {
                    let part = match full.rfind('\\') {
                        Some(pos) if buf != 0 => buf + (pos as u64 + 1) * if *wide { 2 } else { 1 },
                        _ => 0,
                    };
                    self.write_ptr(mem, part_ptr, part)?;
                }
                ret(written)
            }
            Api::MoveFile { wide, .. } => {
                let src = read_path(mem, self.arg(cpu, mem, 0)?, *wide)?;
                let dst = read_path(mem, self.arg(cpu, mem, 1)?, *wide)?;
                ret(self.move_file(&src, &dst) as u64)
            }
            Api::CopyFile { wide } => {
                let src = read_path(mem, self.arg(cpu, mem, 0)?, *wide)?;
                let dst = read_path(mem, self.arg(cpu, mem, 1)?, *wide)?;
                let fail_if_exists = self.arg(cpu, mem, 2)? != 0;
                ret(self.copy_file(&src, &dst, fail_if_exists) as u64)
            }
            Api::SetFileTimeApi => ret(TRUE),
            Api::GetModuleFileNameW => {
                let buf = self.arg(cpu, mem, 1)?;
                let size = self.arg(cpu, mem, 2)? as usize;
                let path = self.cfg.module_path_w.clone();
                let n = WinOs::write_wstr(mem, buf, &path, size)?;
                ret(n)
            }

            Api::GlobalAlloc => {
                let size = self.arg(cpu, mem, 1)?;
                ret(self.heap_alloc(size))
            }
            Api::GlobalReAlloc => {
                let old = self.arg(cpu, mem, 0)?;
                let size = self.arg(cpu, mem, 1)?;
                let new = self.heap_alloc(size);
                if new != 0 && old != 0 {
                    let mut tmp = vec![0u8; size as usize];
                    mem.read(old, &mut tmp)?;
                    mem.write(new, &tmp)?;
                }
                ret(new)
            }
            Api::GlobalLock => {
                let h = self.arg(cpu, mem, 0)?;
                ret(h)
            }
            Api::GlobalFreeUnlock => ret(0),

            Api::GetVersion => ret(0x23F0_0206),
            Api::GetVersionEx => {
                let p = self.arg(cpu, mem, 0)?;
                if p != 0 {
                    mem.write_u32(p + 4, 6)?;
                    mem.write_u32(p + 8, 2)?;
                    mem.write_u32(p + 12, 9200)?;
                    mem.write_u32(p + 16, 2)?;
                    mem.write_u16(p + 20, 0)?;
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
                self.note_zero_returning_stub(sym);
                ret(0)
            }
        }
    }

    fn write_stream(&mut self, handle: u64, buf: u64, n: usize, mem: &dyn Memory) -> Result<()> {
        let mut bytes = vec![0u8; n];
        mem.read(buf, &mut bytes)?;
        let is_err = handle == HANDLE_STDERR;
        self.emit(is_err, &bytes);
        Ok(())
    }

    fn begin_process_exit(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, code: i32) -> Result<Outcome> {
        if !self.cb_stack.is_empty() {
            return Ok(Outcome::Exit(code));
        }
        self.enter_loader_lock(mem)?;
        let targets = self.take_process_detach_targets();
        self.leave_loader_lock(mem)?;
        if targets.is_empty() {
            return Ok(Outcome::Exit(code));
        }
        let ptr = if self.cfg.is_64bit { 8u64 } else { 4 };
        let sp = cpu.rsp() - ptr;
        if self.cfg.is_64bit {
            mem.write_u64(sp, self.exit_thunk())?;
        } else {
            mem.write_u32(sp, self.exit_thunk() as u32)?;
        }
        cpu.set_rsp(sp);
        self.pending_process_exit = Some(code);
        let calls: Vec<(u64, Vec<u64>)> = targets
            .into_iter()
            .map(|(entry, base)| (entry, vec![base, 0 , 0]))
            .collect();
        self.invoke_callbacks(cpu, mem, calls, code as u64, 0, false)
    }

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

    fn cb_advance(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let next = self.cb_stack.last_mut().and_then(|f| f.remaining.pop_front());
        if let Some((func, args)) = next {
            let base = self.cb_stack.last().unwrap().final_rsp - if self.cfg.is_64bit { 8 } else { 4 };
            let driver = self.cb_driver;
            self.setup_call_args(cpu, mem, func, &args, driver, base)?;
            return Ok(Outcome::Resume);
        }

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
                    self.dialog_result = Some(IDCANCEL as u64);
                }
            }
        }

        let f = self.cb_stack.pop().expect("cb driver without frame");
        if self.cb_stack.is_empty() {
            if let Some(code) = self.pending_process_exit.take() {
                return Ok(Outcome::Exit(code));
            }
        }
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

    pub(crate) fn call_hit_test_from_syscall(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
        wndproc: u64,
        args: Vec<u64>,
        pending: crate::win32k::PendingHitTest,
    ) -> Result<()> {
        self.call_wndprocs_from_syscall(cpu, mem, vec![(wndproc, args)], None, 0)?;
        if let Some(frame) = self.win32k_cb.last_mut() {
            frame.then = Some(pending);
        }
        Ok(())
    }

    pub(crate) fn win32k_cb_queue(&mut self, func: u64, args: Vec<u64>) {
        if let Some(frame) = self.win32k_cb.last_mut() {
            frame.remaining.push_back((func, args));
        }
    }

    pub(crate) fn win32k_cb_set_then(&mut self, pending: crate::win32k::PendingHitTest) {
        if let Some(frame) = self.win32k_cb.last_mut() {
            frame.then = Some(pending);
        }
    }

    pub(crate) fn win32k_cb_set_result(&mut self, result: u64) {
        if let Some(frame) = self.win32k_cb.last_mut() {
            frame.result = Some(result);
        }
    }

    pub(crate) fn can_call_client(&self) -> bool {
        !self.is_wow64() || self.client_cb_dispatcher != 0
    }

    pub(crate) fn is_wow64(&self) -> bool {
        self.wow64_peb32 != 0
    }

    pub(crate) fn wow64_peb32(&self) -> u64 {
        self.wow64_peb32
    }

    pub(crate) fn call_wndprocs_from_syscall(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
        calls: Vec<(u64, Vec<u64>)>,
        result: Option<u64>,
        stack_reserve: u64,
    ) -> Result<bool> {
        if !self.can_call_client() {
            return Ok(false);
        }
        let mut remaining: VecDeque<(u64, Vec<u64>)> = calls.into();
        let Some((func, args)) = remaining.pop_front() else {
            return Ok(false);
        };
        let resume_rsp = self.syscall_guest_rsp;
        let call_base = resume_rsp.wrapping_sub(stack_reserve);
        let client = self.is_wow64().then(|| Box::new(ClientCbState::capture(cpu)));
        self.win32k_cb.push(Win32kCbFrame {
            resume_rip: cpu.reg(Reg::Rcx),
            resume_rsp,
            resume_flags: cpu.reg(Reg::R11),
            remaining,
            call_base,
            result,
            then: None,
            client,
        });
        if let Err(e) = self.seat_win32k_callback(cpu, mem, func, &args, call_base) {
            self.win32k_cb.pop();
            return Err(e);
        }
        self.syscall_resume_as_is = true;
        Ok(true)
    }

    pub(crate) fn wow64_callback_scratch(&mut self, mem: &mut dyn Memory, size: u64) -> Option<u64> {
        if self.wow64_cb_scratch == 0 {
            let bytes = WOW64_CB_SCRATCH_DEPTH * WOW64_CB_SCRATCH_BLOCK;
            self.wow64_cb_scratch =
                self.map_anywhere_low(mem, bytes, exemu_core::Perm::RW, "wow64-callback-scratch")?;
        }
        let depth = self.win32k_cb.len() as u64;
        (depth < WOW64_CB_SCRATCH_DEPTH && size <= WOW64_CB_SCRATCH_BLOCK)
            .then(|| self.wow64_cb_scratch + depth * WOW64_CB_SCRATCH_BLOCK)
    }

    fn seat_win32k_callback(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
        func: u64,
        args: &[u64],
        call_base: u64,
    ) -> Result<()> {
        if self.win32k_cb.last().is_some_and(|f| f.client.is_some()) {
            return self.seat_client_win_proc(cpu, mem, func, args, call_base);
        }
        let driver = self.win32k_cb_driver;
        self.setup_call_args(cpu, mem, func, args, driver, call_base)
    }

    fn seat_client_win_proc(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
        func: u64,
        args: &[u64],
        call_base: u64,
    ) -> Result<()> {
        use crate::wow64::{cb_frame, win_proc_params as p};
        let dispatcher = self.client_cb_dispatcher;
        if dispatcher == 0 {
            return Err(exemu_core::EmuError::Os(
                "a client callback needs ntdll!KiUserCallbackDispatcher, which this boot did not publish"
                    .into(),
            ));
        }
        let (hwnd, msg) = (args.first().copied().unwrap_or(0), args.get(1).copied().unwrap_or(0));
        let (wparam, lparam) = (args.get(2).copied().unwrap_or(0), args.get(3).copied().unwrap_or(0));

        let params = (call_base - 0x100) & !0xf;
        mem.write_u64(params + p::FUNC, func)?;
        mem.write_u64(params + p::HWND, hwnd)?;
        mem.write_u32(params + p::MSG, msg as u32)?;
        mem.write_u64(params + p::WPARAM, wparam)?;
        mem.write_u64(params + p::LPARAM, lparam)?;
        mem.write_u32(params + p::SIZE, 0)?;
        mem.write_u32(params + p::ANSI, 0)?;
        mem.write_u32(params + p::MAPPING, 0)?;
        mem.write_u32(params + p::DPI_CONTEXT, crate::wow64::NTUSER_DPI_UNAWARE)?;
        mem.write_u64(params + p::PROC_A, 0)?;
        mem.write_u64(params + p::PROC_W, func)?;
        mem.write_u64(params + p::RESULT, 0)?;

        let frame = (params - cb_frame::SIZE) & !0xf;
        mem.write_u64(frame + cb_frame::ARGS, params)?;
        mem.write_u32(frame + cb_frame::LEN, p::CALL_LEN)?;
        mem.write_u32(frame + cb_frame::ID, crate::wow64::NT_USER_CALL_WIN_PROC)?;
        cpu.set_rsp(frame);
        cpu.rip = dispatcher;
        Ok(())
    }

    pub(crate) fn client_callback_return(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
        ret_ptr: u64,
        ret_len: u32,
        _status: u32,
    ) -> Result<u32> {
        const STATUS_NO_CALLBACK_ACTIVE: u32 = 0xC000_0258;
        if !self.win32k_cb.last().is_some_and(|f| f.client.is_some()) {
            return Ok(STATUS_NO_CALLBACK_ACTIVE);
        }
        let lresult = match ret_len {
            0 => 0,
            n if n >= 8 => mem.read_u64(ret_ptr)?,
            _ => mem.read_u32(ret_ptr)? as i32 as i64 as u64,
        };
        if let Some(state) = self.win32k_cb.last().and_then(|f| f.client.as_deref()) {
            state.restore(cpu);
        }
        cpu.set_reg(Reg::Rax, lresult);
        self.win32k_cb_advance(cpu, mem)?;
        self.syscall_resume_as_is = true;
        Ok(0)
    }

    fn win32k_cb_advance(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let drained =
            self.win32k_cb.last().is_some_and(|f| f.remaining.is_empty() && f.then.is_some());
        if drained {
            let pending = self.win32k_cb.last_mut().and_then(|f| f.then.take());
            if let Some(pending) = pending {
                let lresult = cpu.reg(Reg::Rax);
                crate::win32k::finish_hit_test(self, cpu, mem, pending, lresult)?;
            }
        }
        let next = self.win32k_cb.last_mut().and_then(|f| f.remaining.pop_front());
        if let Some((func, args)) = next {
            let base = self.win32k_cb.last().expect("frame just read").call_base;
            self.seat_win32k_callback(cpu, mem, func, &args, base)?;
            return Ok(Outcome::Resume);
        }
        let f = self.win32k_cb.pop().expect("win32k cb driver without frame");
        cpu.rip = f.resume_rip;
        cpu.set_rsp(f.resume_rsp);
        cpu.rflags = f.resume_flags;
        if let Some(result) = f.result {
            cpu.set_reg(Reg::Rax, result);
        }
        Ok(Outcome::Resume)
    }

    fn wsprintf(&self, cpu: &CpuState, mem: &mut dyn Memory, out: u64, fmt_ptr: u64, wide: bool) -> Result<usize> {
        let fmt = if wide { read_wstr(mem, fmt_ptr)? } else { read_astr(mem, fmt_ptr)? };
        let mut result = String::new();
        let mut argi = 2usize;
        let mut chars = fmt.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '%' {
                result.push(c);
                continue;
            }
            let (mut left, mut zero) = (false, false);
            while let Some(f) = chars.peek() {
                match f {
                    '-' => left = true,
                    '0' => zero = true,
                    '+' | ' ' | '#' => {}
                    _ => break,
                }
                chars.next();
            }
            let mut width = 0usize;
            while let Some(d) = chars.peek().and_then(|c| c.to_digit(10)) {
                width = width * 10 + d as usize;
                chars.next();
            }
            if chars.peek() == Some(&'.') {
                chars.next();
                while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
                    chars.next();
                }
            }
            while matches!(chars.peek(), Some('l' | 'h' | 'w' | 'I' | 'L')) {
                chars.next();
            }
            let conv = chars.next().unwrap_or('%');
            let mut next = |s: &Self| -> Result<u64> {
                let v = s.arg(cpu, mem, argi);
                argi += 1;
                v
            };
            let is_num = matches!(conv, 'd' | 'i' | 'u' | 'x' | 'X' | 'p');
            let text = match conv {
                '%' => "%".to_string(),
                'd' | 'i' => (next(self)? as i32 as i64).to_string(),
                'u' => (next(self)? as u32).to_string(),
                'x' => format!("{:x}", next(self)? as u32),
                'X' => format!("{:X}", next(self)? as u32),
                'p' => format!("{:08X}", next(self)? as u32),
                'c' => char::from_u32(next(self)? as u32 & 0xffff).unwrap_or('?').to_string(),
                's' => {
                    let p = next(self)?;
                    if wide { read_wstr(mem, p)? } else { read_astr(mem, p)? }
                }
                'S' => {
                    let p = next(self)?;
                    if wide { read_astr(mem, p)? } else { read_wstr(mem, p)? }
                }
                other => {
                    result.push('%');
                    other.to_string()
                }
            };
            let pad = width.saturating_sub(text.chars().count());
            if pad > 0 && !left {
                result.push_str(&(if zero && is_num { "0" } else { " " }).repeat(pad));
            }
            result.push_str(&text);
            if pad > 0 && left {
                result.push_str(&" ".repeat(pad));
            }
        }
        if wide {
            let units: Vec<u16> = result.encode_utf16().collect();
            for (i, u) in units.iter().enumerate() {
                mem.write_u16(out + i as u64 * 2, *u)?;
            }
            mem.write_u16(out + units.len() as u64 * 2, 0)?;
            Ok(units.len())
        } else {
            let bytes = result.as_bytes();
            mem.write(out, bytes)?;
            mem.write_u8(out + bytes.len() as u64, 0)?;
            Ok(bytes.len())
        }
    }

    fn sync_progress(&mut self, id: u32) {
        if let Some(&(min, max, pos)) = self.progress.get(&id) {
            let span = (max - min).max(1) as f64;
            let pct = (((pos - min).max(0) as f64 / span) * 100.0).round() as u32;
            self.gui.set_text(id, &pct.min(100).to_string());
        }
    }

    fn write_msg(&self, mem: &mut dyn Memory, lp: u64) -> Result<()> {
        self.write_msg_full(mem, lp, HWND_DIALOG, 0, 0, 0)
    }

    pub(crate) fn write_msg_full(&self, mem: &mut dyn Memory, lp: u64, hwnd: u64, message: u64, wparam: u64, lparam: u64) -> Result<()> {
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

    pub(crate) fn read_msg(&self, mem: &dyn Memory, lp: u64) -> Result<(u64, u64, u64, u64)> {
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

    pub(crate) fn setup_call_args(
        &self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
        func: u64,
        args: &[u64],
        ret_thunk: u64,
        base_rsp: u64,
    ) -> Result<()> {
        if std::env::var_os("EXEMU_DBG").is_some() {
            eprintln!(
                "[dbg] setup_call func={func:#x} ret_thunk={ret_thunk:#x} (cb={:#x} w32k={:#x} initterm={:#x})",
                self.cb_driver, self.win32k_cb_driver, self.initterm_driver
            );
        }
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

    fn eh_prolog(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        if self.cfg.is_64bit {
            return Ok(Outcome::Return(0));
        }
        let s = cpu.rsp() & 0xFFFF_FFFF;
        let retaddr = mem.read_u32(s)? as u64;
        let scopetable = cpu.gpr_read(Reg::Rax as u8, 4) as u32;
        let caller_ebp = cpu.gpr_read(Reg::Rbp as u8, 4) as u32;
        let fs0 = cpu.fs_base & 0xFFFF_FFFF;
        let old_head = mem.read_u32(fs0)?;

        let m4 = s.wrapping_sub(4) & 0xFFFF_FFFF;
        let m8 = s.wrapping_sub(8) & 0xFFFF_FFFF;
        let m12 = s.wrapping_sub(12) & 0xFFFF_FFFF;
        mem.write_u32(m4, 0xFFFF_FFFF)?;
        mem.write_u32(m8, scopetable)?;
        mem.write_u32(m12, old_head)?;
        mem.write_u32(s, caller_ebp)?;
        mem.write_u32(fs0, m12 as u32)?;

        cpu.gpr_write(Reg::Rbp as u8, 4, s);
        cpu.set_rsp(m12);
        cpu.rip = retaddr;
        Ok(Outcome::Resume)
    }

    fn initterm_advance(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Outcome> {
        let next = self
            .initterm_stack
            .last_mut()
            .and_then(|f| f.remaining.pop_front());

        match next {
            Some(func) => {
                let base = self.initterm_stack.last().unwrap().saved_rsp;
                let driver = self.initterm_driver;
                self.setup_call_args(cpu, mem, func, &[], driver, base)?;
                Ok(Outcome::Resume)
            }
            None => {
                let ptr = if self.cfg.is_64bit { 8 } else { 4 };
                let frame = self.initterm_stack.pop().expect("driver without frame");
                cpu.set_rsp(frame.saved_rsp + ptr);
                cpu.rip = frame.ret;
                cpu.set_reg(Reg::Rax, 0);
                Ok(Outcome::Resume)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dll_directory_setters_pop_one_arg_and_return_true() {
        for name in ["SetDefaultDllDirectories", "SetDllDirectoryW", "SetDllDirectoryA"] {
            assert_eq!(win32_argc("kernel32", name), Some(1), "{name} argc");
            let api = Api::classify("kernel32", name);
            assert_eq!(api.argc(), 1, "{name} classified argc");
            assert!(
                matches!(api, Api::WinStub { r: TRUE, argc: 1 }),
                "{name} must be a success-returning stub that pops 1 arg, got {api:?}"
            );
        }
    }

    #[test]
    fn unimplemented_stubs_that_return_zero_are_remembered() {
        use exemu_memory::VirtualMemory;
        let mut os = WinOs::new(crate::WinConfig { is_64bit: true, echo: false, ..Default::default() });
        let mut mem = VirtualMemory::new();
        let mut cpu = CpuState::default();
        let mut call = |os: &mut WinOs, sym: &str| {
            let api = Api::Unsupported { sym: sym.to_string(), argc: 0 };
            let out = os.dispatch(&api, &mut cpu, &mut mem).expect("stub dispatch");
            assert!(matches!(out, Outcome::Return(0)), "an unimplemented stub returns 0");
        };

        call(&mut os, "kernel32.dll!Alpha");
        call(&mut os, "kernel32.dll!Beta");
        assert_eq!(os.zero_returning_stubs(), ["kernel32.dll!Beta", "kernel32.dll!Alpha"], "newest first");

        call(&mut os, "kernel32.dll!Alpha");
        assert_eq!(os.zero_returning_stubs(), ["kernel32.dll!Alpha", "kernel32.dll!Beta"]);

        for i in 0..crate::ZERO_STUB_TRAIL + 5 {
            call(&mut os, &format!("kernel32.dll!Fill{i}"));
        }
        let trail = os.zero_returning_stubs();
        assert_eq!(trail.len(), crate::ZERO_STUB_TRAIL, "bounded");
        assert_eq!(trail[0], format!("kernel32.dll!Fill{}", crate::ZERO_STUB_TRAIL + 4), "newest kept");
        assert!(!trail.iter().any(|s| s == "kernel32.dll!Beta"), "the oldest is dropped");
    }
}
