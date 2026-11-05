#![forbid(unsafe_code)]

mod api;
mod apiset;
pub mod audio;
mod boot;
mod crypt32;
mod dll;
mod exc;
pub mod folders;
mod fs;
mod gdi;
mod msg;
pub mod net;
mod nls;
pub mod process;
mod reg;
mod section;
mod server;
mod syscall;
mod sync;
mod thread;
mod time;
pub mod token;
mod unixlib;
mod vm;
mod win;
mod win32k;
mod wndclass;
pub use win32k::abi as win32k_abi;
pub mod winedebug;
pub mod wow64;

use std::collections::HashMap;

use exemu_core::{CpuState, Exit, Hooks, ImportSymbol, Memory, Reg, Result};

pub use api::Api;
pub use apiset::{api_set_hash, build_populated_namespace, ApiSetNamespace, HASH_FACTOR};
pub use boot::{RVA_LDR_INITIALIZE_THUNK, RVA_RTL_USER_THREAD_START, RVA_WINE_UNIX_CALL_DISPATCHER};
pub use exc::{
    Trap, TrapMode, UnhandledException, EXC_FRAME_BYTES, RVA_KI_USER_EXCEPTION_DISPATCHER,
};
pub use syscall::SyscallHandler;
pub use sync::{SignalOp, SyncKind};
pub use unixlib::{UnixEntry, Unixlib};

#[derive(Debug, Clone)]
pub struct WinConfig {
    pub api_base: u64,
    pub heap_base: u64,
    pub heap_size: u64,
    pub image_base: u64,
    pub cmdline_ptr_a: u64,
    pub cmdline_ptr_w: u64,
    pub echo: bool,
    pub trace: bool,
    pub is_64bit: bool,
    pub sandbox: String,
    pub module_path_w: String,
    pub dll_base: u64,
    pub dll_size: u64,
    pub valloc_base: u64,
    pub peb_addr: u64,
    pub teb_base: u64,
    pub peb_ldr_off: u64,
    pub peb_loaderlock_off: u64,
    pub image_size: u64,
    pub image_entry: u64,
    pub image_name: String,
    pub wine_dll_dir: Option<String>,
    pub dpi: u32,
    pub file_dialog_pick: Option<String>,
}

impl Default for WinConfig {
    fn default() -> Self {
        WinConfig {
            api_base: 0x0000_7EFF_0000_0000,
            heap_base: 0x0000_0002_0000_0000,
            heap_size: 0x0400_0000,
            image_base: 0x1_4000_0000,
            cmdline_ptr_a: 0,
            cmdline_ptr_w: 0,
            echo: true,
            trace: false,
            is_64bit: true,
            sandbox: String::new(),
            module_path_w: "C:\\program.exe".into(),
            dll_base: 0x0000_0006_0000_0000,
            dll_size: 0x0800_0000,
            valloc_base: 0x0000_0040_0000_0000,
            peb_addr: 0,
            teb_base: 0,
            peb_ldr_off: 0x18,
            peb_loaderlock_off: 0x110,
            image_size: 0,
            image_entry: 0,
            image_name: String::new(),
            wine_dll_dir: None,
            dpi: 96,
            file_dialog_pick: None,
        }
    }
}

pub struct WinOs {
    cfg: WinConfig,
    thunks: HashMap<u64, Api>,
    interned: HashMap<(String, String), u64>,
    next_thunk: u64,
    heap_next: u64,
    heap_sizes: HashMap<u64, u64>,
    last_error: u32,

    zero_stubs: Vec<String>,

    vm_allocs: Vec<vm::VmAlloc>,
    valloc_next: u64,

    initterm_driver: u64,
    initterm_stack: Vec<api::InittermFrame>,

    cb_driver: u64,
    cb_stack: Vec<api::CbFrame>,
    win32k_cb_driver: u64,
    win32k_cb: Vec<api::Win32kCbFrame>,
    controls: std::collections::HashMap<u32, Vec<u16>>,
    msg_pumps: u32,

    audio: audio::AudioState,
    audio_sink: Box<dyn exemu_core::AudioSink>,

    gui: Box<dyn exemu_core::Gui>,
    driver: Box<dyn exemu_core::UserDriver>,
    input: Option<std::sync::mpsc::Receiver<exemu_core::InputEvent>>,
    dialogs: std::collections::HashMap<u32, exemu_core::DialogTemplate>,
    dlgproc: u64,
    dialog_hwnd: u64,
    quit_posted: bool,
    dialog_result: Option<u64>,
    progress: std::collections::HashMap<u32, (i64, i64, i64)>,
    gdi: gdi::Gdi,
    dll: dll::Loader,

    files: std::collections::HashMap<u64, fs::OpenFile>,
    file_dirs: std::collections::HashMap<u64, String>,
    find_handles: std::collections::HashMap<u64, fs::FindState>,
    sections: HashMap<u64, section::Section>,
    sockets: HashMap<u64, net::Socket>,
    next_handle: u64,
    temp_counter: u32,
    crt_globals: std::collections::HashMap<String, u64>,

    env: Vec<(String, String)>,

    tls_alloc: Vec<bool>,
    fls_alloc: Vec<bool>,
    tls_callbacks: Vec<u64>,

    reg_hive: HashMap<String, HashMap<String, (u32, Vec<u8>)>>,
    reg_handles: HashMap<u64, String>,

    kobjects: HashMap<u64, sync::KObject>,
    named_kobjects: HashMap<String, u64>,
    current_tid: u32,

    threads: Vec<thread::Thread>,
    current: usize,
    next_tid: u32,
    thread_exit_thunk: u64,
    thread_tls_thunk: u64,
    thread_entry_thunk: u64,
    sched_ticks: u64,

    start_time: std::time::Instant,

    clock: exemu_core::GuestClock,

    stdout_buf: Vec<u8>,
    stderr_buf: Vec<u8>,

    function_table: Vec<exemu_core::UnwindEntry>,
    exc_driver: u64,
    exc_stack: Vec<exc::DispatchFrame>,
    unhandled_filter: u64,

    ssdt: syscall::Ssdt,
    win32k: syscall::Ssdt,
    win32k_state: win32k::Win32kState,
    nls_locale_base: Option<(u64, u64)>,
    nls_section_bases: Vec<(u32, u32, u64, u64)>,
    unix_stack_top: u64,
    syscall_guest_rsp: u64,
    syscall_resume_as_is: bool,
    syscall_result64: Option<u64>,

    unixlibs: Vec<unixlib::Unixlib>,
    unixlib_of_module: HashMap<u64, u64>,
    wine_unix_call_thunk: u64,
    unix_call_blocked: bool,
    pub(crate) unix_call_wow64: bool,

    pending_process_exit: Option<i32>,

    exc_chain: exc::ExcChain,

    unhandled_exception: Option<exc::UnhandledException>,

    pending_syscall_exit: Option<i32>,

    children: Vec<process::ChildProcess>,
    next_pid: u32,
    spawner: Box<dyn exemu_core::ProcessSpawner>,
    images: Box<dyn exemu_core::ImageLoader>,
    spawn_depth: u32,
    child_failure: Option<String>,
    children_created: u32,
    wow64_peb32: u64,
    wow64_modules: HashMap<String, u64>,
    client_cb_dispatcher: u64,
    guest_mode32: bool,
    pending_mode_switch: Option<bool>,
    wow64_threading: Option<wow64::Wow64Threading>,
    wow64_cb_scratch: u64,
}

const ZERO_STUB_TRAIL: usize = 12;

const HANDLE_STDIN: u64 = 0x0C;
const HANDLE_STDOUT: u64 = 0x10;
const HANDLE_STDERR: u64 = 0x14;
const HANDLE_PROCESS_HEAP: u64 = 0x00AB_0000;

pub(crate) const CURRENT_PROCESS_ID: u64 = 0x1000;
const FIRST_CHILD_PROCESS_ID: u32 = 0x2000;

impl WinOs {
    pub fn new(cfg: WinConfig) -> Self {
        let (api_base, heap_base, valloc_base) = (cfg.api_base, cfg.heap_base, cfg.valloc_base);
        let mut os = WinOs {
            cfg,
            thunks: HashMap::new(),
            interned: HashMap::new(),
            next_thunk: api_base,
            heap_next: heap_base,
            heap_sizes: HashMap::new(),
            last_error: 0,
            zero_stubs: Vec::new(),
            vm_allocs: Vec::new(),
            valloc_next: valloc_base,
            initterm_driver: 0,
            initterm_stack: Vec::new(),
            cb_driver: 0,
            cb_stack: Vec::new(),
            win32k_cb_driver: 0,
            win32k_cb: Vec::new(),
            controls: std::collections::HashMap::new(),
            msg_pumps: 8,
            audio: audio::AudioState::default(),
            audio_sink: Box::new(exemu_core::NoAudio),
            gui: Box::new(exemu_core::NoGui),
            driver: Box::new(exemu_core::NoDriver),
            input: None,
            dialogs: std::collections::HashMap::new(),
            dlgproc: 0,
            dialog_hwnd: 0,
            quit_posted: false,
            dialog_result: None,
            progress: std::collections::HashMap::new(),
            gdi: gdi::Gdi::default(),
            dll: dll::Loader::default(),
            files: std::collections::HashMap::new(),
            file_dirs: std::collections::HashMap::new(),
            find_handles: std::collections::HashMap::new(),
            sections: HashMap::new(),
            sockets: HashMap::new(),
            next_handle: 0x0000_1000,
            temp_counter: 0,
            crt_globals: std::collections::HashMap::new(),
            env: default_environment(),
            tls_alloc: Vec::new(),
            fls_alloc: Vec::new(),
            tls_callbacks: Vec::new(),
            reg_hive: HashMap::new(),
            reg_handles: HashMap::new(),
            kobjects: HashMap::new(),
            named_kobjects: HashMap::new(),
            current_tid: 0x1001,
            threads: Vec::new(),
            current: 0,
            next_tid: 0x1002,
            thread_exit_thunk: 0,
            thread_tls_thunk: 0,
            thread_entry_thunk: 0,
            sched_ticks: 0,
            start_time: std::time::Instant::now(),
            clock: exemu_core::GuestClock::host(),
            stdout_buf: Vec::new(),
            stderr_buf: Vec::new(),
            function_table: Vec::new(),
            exc_driver: 0,
            exc_stack: Vec::new(),
            unhandled_filter: 0,
            ssdt: syscall::Ssdt::new(),
            win32k: syscall::Ssdt::new_win32k(),
            win32k_state: win32k::Win32kState::default(),
            nls_locale_base: None,
            nls_section_bases: Vec::new(),
            unix_stack_top: 0,
            syscall_guest_rsp: 0,
            syscall_resume_as_is: false,
            syscall_result64: None,
            unixlibs: Vec::new(),
            unixlib_of_module: HashMap::new(),
            wine_unix_call_thunk: 0,
            unix_call_blocked: false,
            unix_call_wow64: false,
            pending_process_exit: None,
            pending_syscall_exit: None,
            exc_chain: exc::ExcChain::default(),
            unhandled_exception: None,
            children: Vec::new(),
            next_pid: FIRST_CHILD_PROCESS_ID,
            spawner: Box::new(exemu_core::NoSpawner),
            images: Box::new(exemu_core::NoImageLoader),
            spawn_depth: 0,
            child_failure: None,
            children_created: 0,
            wow64_peb32: 0,
            wow64_modules: HashMap::new(),
            client_cb_dispatcher: 0,
            guest_mode32: false,
            pending_mode_switch: None,
            wow64_threading: None,
            wow64_cb_scratch: 0,
        };
        os.initterm_driver = os.alloc_thunk(Api::InittermDriver);
        os.cb_driver = os.alloc_thunk(Api::CallbackDriver);
        os.win32k_cb_driver = os.alloc_thunk(Api::Win32kCbDriver);
        os.exc_driver = os.alloc_thunk(Api::ExceptionDriver);
        os.thread_exit_thunk = os.alloc_thunk(Api::ThreadExit);
        os.thread_tls_thunk = os.alloc_thunk(Api::ThreadTlsAttach);
        os.thread_entry_thunk = os.alloc_thunk(Api::ThreadStartEntry);
        let mut main_thread = thread::Thread::main(0x1001);
        main_thread.teb_base = os.cfg.teb_base;
        os.threads.push(main_thread);
        os.reg_seed();
        os.set_syscall_handler(
            unixlib::SSDT_NT_QUERY_VIRTUAL_MEMORY,
            unixlib::ssdt_nt_query_virtual_memory,
        );
        os.set_syscall_handler(wow64::SSDT_NT_CALLBACK_RETURN, api::ssdt_nt_callback_return);
        os.set_syscall_handler(vm::SSDT_NT_ALLOCATE_VIRTUAL_MEMORY, vm::ssdt_nt_allocate_virtual_memory);
        os.set_syscall_handler(vm::SSDT_NT_FREE_VIRTUAL_MEMORY, vm::ssdt_nt_free_virtual_memory);
        os.set_syscall_handler(vm::SSDT_NT_PROTECT_VIRTUAL_MEMORY, vm::ssdt_nt_protect_virtual_memory);
        os.set_syscall_handler(section::SSDT_NT_CREATE_SECTION, section::ssdt_nt_create_section);
        os.set_syscall_handler(section::SSDT_NT_QUERY_SECTION, section::ssdt_nt_query_section);
        os.set_syscall_handler(section::SSDT_NT_MAP_VIEW_OF_SECTION, section::ssdt_nt_map_view_of_section);
        os.set_syscall_handler(section::SSDT_NT_UNMAP_VIEW_OF_SECTION, section::ssdt_nt_unmap_view_of_section);
        os.set_syscall_handler(fs::SSDT_NT_CREATE_FILE, fs::ssdt_nt_create_file);
        os.set_syscall_handler(fs::SSDT_NT_READ_FILE, fs::ssdt_nt_read_file);
        os.set_syscall_handler(fs::SSDT_NT_WRITE_FILE, fs::ssdt_nt_write_file);
        os.set_syscall_handler(fs::SSDT_NT_QUERY_INFORMATION_FILE, fs::ssdt_nt_query_information_file);
        os.set_syscall_handler(fs::SSDT_NT_SET_INFORMATION_FILE, fs::ssdt_nt_set_information_file);
        os.set_syscall_handler(fs::SSDT_NT_QUERY_DIRECTORY_FILE, fs::ssdt_nt_query_directory_file);
        os.set_syscall_handler(
            fs::SSDT_NT_QUERY_VOLUME_INFORMATION_FILE,
            fs::ssdt_nt_query_volume_information_file,
        );
        os.set_syscall_handler(fs::SSDT_NT_OPEN_FILE, fs::ssdt_nt_open_file);
        os.set_syscall_handler(fs::SSDT_NT_QUERY_ATTRIBUTES_FILE, fs::ssdt_nt_query_attributes_file);
        os.set_syscall_handler(fs::SSDT_NT_FS_CONTROL_FILE, fs::ssdt_nt_fs_control_file);
        os.set_syscall_handler(fs::SSDT_NT_CLOSE, fs::ssdt_nt_close);
        os.set_syscall_handler(net::SSDT_NT_DEVICE_IO_CONTROL_FILE, net::ssdt_nt_device_io_control_file);
        os.set_syscall_handler(thread::SSDT_NT_CREATE_THREAD_EX, thread::ssdt_nt_create_thread_ex);
        os.set_syscall_handler(thread::SSDT_NT_TERMINATE_THREAD, thread::ssdt_nt_terminate_thread);
        os.set_syscall_handler(thread::SSDT_NT_TERMINATE_PROCESS, thread::ssdt_nt_terminate_process);
        os.set_syscall_handler(thread::SSDT_NT_SUSPEND_THREAD, thread::ssdt_nt_suspend_thread);
        os.set_syscall_handler(thread::SSDT_NT_RESUME_THREAD, thread::ssdt_nt_resume_thread);
        os.set_syscall_handler(
            thread::SSDT_NT_QUERY_INFORMATION_THREAD,
            thread::ssdt_nt_query_information_thread,
        );
        os.set_syscall_handler(
            process::SSDT_NT_CREATE_USER_PROCESS,
            process::ssdt_nt_create_user_process,
        );
        os.set_syscall_handler(
            process::SSDT_NT_QUERY_INFORMATION_PROCESS,
            process::ssdt_nt_query_information_process,
        );
        os.set_syscall_handler(
            thread::SSDT_NT_SET_INFORMATION_THREAD,
            thread::ssdt_nt_set_information_thread,
        );
        os.set_syscall_handler(
            thread::SSDT_NT_QUERY_SYSTEM_INFORMATION_EX,
            thread::ssdt_nt_query_system_information_ex,
        );
        os.set_syscall_handler(
            thread::SSDT_NT_QUERY_SYSTEM_INFORMATION,
            thread::ssdt_nt_query_system_information,
        );
        os.set_syscall_handler(sync::SSDT_NT_CREATE_EVENT, sync::ssdt_nt_create_event);
        os.set_syscall_handler(sync::SSDT_NT_OPEN_EVENT, sync::ssdt_nt_open_event);
        os.set_syscall_handler(sync::SSDT_NT_SET_EVENT, sync::ssdt_nt_set_event);
        os.set_syscall_handler(sync::SSDT_NT_CREATE_MUTANT, sync::ssdt_nt_create_mutant);
        os.set_syscall_handler(sync::SSDT_NT_CREATE_SEMAPHORE, sync::ssdt_nt_create_semaphore);
        os.set_syscall_handler(sync::SSDT_NT_RELEASE_SEMAPHORE, sync::ssdt_nt_release_semaphore);
        os.set_syscall_handler(sync::SSDT_NT_WAIT_FOR_SINGLE_OBJECT, sync::ssdt_nt_wait_for_single_object);
        os.set_syscall_handler(
            sync::SSDT_NT_WAIT_FOR_MULTIPLE_OBJECTS,
            sync::ssdt_nt_wait_for_multiple_objects,
        );
        os.set_syscall_handler(reg::SSDT_NT_CREATE_KEY, reg::ssdt_nt_create_key);
        os.set_syscall_handler(reg::SSDT_NT_OPEN_KEY, reg::ssdt_nt_open_key);
        os.set_syscall_handler(reg::SSDT_NT_QUERY_VALUE_KEY, reg::ssdt_nt_query_value_key);
        os.set_syscall_handler(reg::SSDT_NT_SET_VALUE_KEY, reg::ssdt_nt_set_value_key);
        os.set_syscall_handler(reg::SSDT_NT_ENUMERATE_KEY, reg::ssdt_nt_enumerate_key);
        os.set_syscall_handler(reg::SSDT_NT_QUERY_KEY, reg::ssdt_nt_query_key);
        os.set_syscall_handler(reg::SSDT_NT_OPEN_KEY_EX, reg::ssdt_nt_open_key_ex);
        os.set_syscall_handler(reg::SSDT_NT_ENUMERATE_VALUE_KEY, reg::ssdt_nt_enumerate_value_key);
        os.set_syscall_handler(reg::SSDT_NT_DELETE_KEY, reg::ssdt_nt_delete_key);
        os.set_syscall_handler(reg::SSDT_NT_DELETE_VALUE_KEY, reg::ssdt_nt_delete_value_key);
        os.set_syscall_handler(reg::SSDT_NT_FLUSH_KEY, reg::ssdt_nt_flush_key);
        os.set_syscall_handler(time::SSDT_NT_QUERY_SYSTEM_TIME, time::ssdt_nt_query_system_time);
        os.set_syscall_handler(time::SSDT_NT_QUERY_PERFORMANCE_COUNTER, time::ssdt_nt_query_performance_counter);
        os.set_syscall_handler(token::SSDT_NT_OPEN_PROCESS_TOKEN, token::ssdt_nt_open_process_token);
        os.set_syscall_handler(token::SSDT_NT_OPEN_PROCESS_TOKEN_EX, token::ssdt_nt_open_process_token_ex);
        os.set_syscall_handler(token::SSDT_NT_OPEN_THREAD_TOKEN, token::ssdt_nt_open_thread_token);
        os.set_syscall_handler(token::SSDT_NT_OPEN_THREAD_TOKEN_EX, token::ssdt_nt_open_thread_token_ex);
        os.set_syscall_handler(token::SSDT_NT_QUERY_INFORMATION_TOKEN, token::ssdt_nt_query_information_token);
        os.set_syscall_handler(nls::SSDT_NT_INITIALIZE_NLS_FILES, nls::ssdt_nt_initialize_nls_files);
        os.set_syscall_handler(nls::SSDT_NT_GET_NLS_SECTION_PTR, nls::ssdt_nt_get_nls_section_ptr);
        os.set_syscall_handler(boot::SSDT_NT_CONTINUE, boot::ssdt_nt_continue);
        os.set_syscall_handler(exc::SSDT_NT_RAISE_EXCEPTION, exc::ssdt_nt_raise_exception);
        win32k::register(&mut os);
        os
    }

    pub fn set_wow64_peb32(&mut self, peb32: u64) {
        self.wow64_peb32 = peb32;
    }

    pub fn set_guest_mode32(&mut self, mode32: bool) {
        self.guest_mode32 = mode32;
    }

    pub fn take_thread_mode_switch(&mut self) -> Option<bool> {
        self.pending_mode_switch.take()
    }

    pub fn set_wow64_threading(&mut self, t: wow64::Wow64Threading) {
        self.wow64_threading = Some(t);
    }

    pub fn set_client_callback_dispatcher(&mut self, entry: u64) {
        self.client_cb_dispatcher = entry;
    }

    pub fn register_wow64_module(&mut self, name: &str, base: u64) {
        self.wow64_modules.insert(name.to_ascii_lowercase(), base);
    }

    pub(crate) fn wow64_module(&self, name: &str) -> Option<u64> {
        self.wow64_modules.get(&name.to_ascii_lowercase()).copied()
    }

    pub fn set_clock(&mut self, clock: exemu_core::GuestClock) {
        self.clock = clock;
    }

    pub fn clock(&self) -> &exemu_core::GuestClock {
        &self.clock
    }

    pub fn set_unwind_table(&mut self, table: Vec<exemu_core::UnwindEntry>) {
        self.function_table = table;
    }

    pub fn unwind_table(&self) -> &[exemu_core::UnwindEntry] {
        &self.function_table
    }

    pub fn set_tls_callbacks(&mut self, callbacks: Vec<u64>) {
        self.tls_callbacks = callbacks;
    }

    pub fn alloc_tls_index(&mut self) -> u32 {
        self.tls_alloc(false) as u32
    }

    pub fn start_process(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, entry: u64) -> Result<()> {
        if self.tls_callbacks.is_empty() {
            cpu.rip = entry;
            return Ok(());
        }
        let module = self.cfg.image_base;
        let calls: Vec<(u64, Vec<u64>)> = self
            .tls_callbacks
            .iter()
            .map(|&cb| (cb, vec![module, 1 , 0]))
            .collect();
        let ptr = if self.cfg.is_64bit { 8u64 } else { 4 };
        let sp = cpu.rsp() - ptr;
        if self.cfg.is_64bit {
            mem.write_u64(sp, entry)?;
        } else {
            mem.write_u32(sp, entry as u32)?;
        }
        cpu.set_rsp(sp);
        self.invoke_callbacks(cpu, mem, calls, 0, 0, false)?;
        Ok(())
    }

    pub fn set_gui(
        &mut self,
        gui: Box<dyn exemu_core::Gui>,
        dialogs: std::collections::HashMap<u32, exemu_core::DialogTemplate>,
    ) {
        self.gui = gui;
        self.dialogs = dialogs;
    }

    pub fn set_driver(&mut self, d: Box<dyn exemu_core::UserDriver>) {
        self.driver = d;
    }

    pub fn set_audio_sink(&mut self, sink: Box<dyn exemu_core::AudioSink>) {
        self.audio_sink = sink;
    }

    pub fn set_input(&mut self, rx: std::sync::mpsc::Receiver<exemu_core::InputEvent>) {
        self.input = Some(rx);
    }

    fn has_input(&self) -> bool {
        self.input.is_some()
    }

    fn drain_input(&mut self) -> bool {
        use std::sync::mpsc::TryRecvError;
        let Some(rx) = &self.input else { return false };
        let mut pending = Vec::new();
        let mut quit = false;
        loop {
            match rx.try_recv() {
                Ok(exemu_core::InputEvent::Close) => quit = true,
                Ok(ev) => pending.push(ev),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    quit = true;
                    break;
                }
            }
        }
        if quit {
            self.threads[self.current].quit_code.get_or_insert(0);
        }
        for ev in pending {
            self.post_input_event(ev);
        }
        true
    }

    fn wait_for_input(&mut self, timeout: std::time::Duration) {
        use std::sync::mpsc::RecvTimeoutError;
        let Some(rx) = &self.input else { return };
        match rx.recv_timeout(timeout) {
            Ok(exemu_core::InputEvent::Close) => {
                self.threads[self.current].quit_code.get_or_insert(0);
            }
            Ok(ev) => self.post_input_event(ev),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                self.threads[self.current].quit_code.get_or_insert(0);
            }
        }
    }

    fn gui_active(&self) -> bool {
        self.gui.is_open()
    }

    fn alloc_thunk(&mut self, api: Api) -> u64 {
        let addr = self.next_thunk;
        self.next_thunk += 8;
        self.thunks.insert(addr, api);
        addr
    }

    pub fn resolve_import(&mut self, dll: &str, symbol: &ImportSymbol) -> u64 {
        let dll_cow: std::borrow::Cow<str> = match self.images.api_set_host(dll) {
            Some(host) => std::borrow::Cow::Borrowed(host),
            None => std::borrow::Cow::Borrowed(dll),
        };
        let dll = dll_cow.as_ref();

        let name = match symbol {
            ImportSymbol::Named(n) => n.clone(),
            ImportSymbol::Ordinal(o) => format!("#ord{o}"),
        };
        let key = (dll.to_string(), name.clone());
        if let Some(&addr) = self.interned.get(&key) {
            return addr;
        }
        let addr = self.next_thunk;
        self.next_thunk += 8;
        let api = Api::classify(dll, &name);
        self.thunks.insert(addr, api);
        self.interned.insert(key, addr);
        addr
    }

    pub fn exit_thunk(&mut self) -> u64 {
        self.alloc_thunk(Api::ReturnExit)
    }

    pub fn wine_unix_call_thunk(&mut self) -> u64 {
        if self.wine_unix_call_thunk == 0 {
            self.wine_unix_call_thunk = self.alloc_thunk(Api::WineUnixCall);
        }
        self.wine_unix_call_thunk
    }

    pub(crate) fn note_zero_returning_stub(&mut self, sym: &str) {
        if let Some(i) = self.zero_stubs.iter().position(|s| s == sym) {
            self.zero_stubs.remove(i);
        }
        self.zero_stubs.insert(0, sym.to_string());
        self.zero_stubs.truncate(ZERO_STUB_TRAIL);
    }

    pub fn zero_returning_stubs(&self) -> &[String] {
        &self.zero_stubs
    }

    pub fn thunk_range(&self) -> (u64, u64) {
        (self.cfg.api_base, self.next_thunk)
    }

    pub fn symbol_for_thunk(&self, addr: u64) -> Option<String> {
        self.interned
            .iter()
            .find(|(_, &a)| a == addr)
            .map(|((dll, name), _)| format!("{dll}!{name}"))
    }

    pub fn captured_stdout(&self) -> &[u8] {
        &self.stdout_buf
    }
    pub fn captured_stderr(&self) -> &[u8] {
        &self.stderr_buf
    }

    fn arg(&self, cpu: &CpuState, mem: &dyn Memory, i: usize) -> Result<u64> {
        if self.cfg.is_64bit {
            Ok(match i {
                0 => cpu.reg(Reg::Rcx),
                1 => cpu.reg(Reg::Rdx),
                2 => cpu.reg(Reg::R8),
                3 => cpu.reg(Reg::R9),
                n => mem.read_u64(cpu.rsp() + 0x28 + (n as u64 - 4) * 8)?,
            })
        } else {
            Ok(mem.read_u32(cpu.rsp() + 4 + (i as u64) * 4)? as u64)
        }
    }

    pub(crate) fn read_ptr(&self, mem: &dyn Memory, addr: u64) -> Result<u64> {
        if self.cfg.is_64bit {
            mem.read_u64(addr)
        } else {
            Ok(mem.read_u32(addr)? as u64)
        }
    }

    pub(crate) fn write_ptr(&self, mem: &mut dyn Memory, addr: u64, val: u64) -> Result<()> {
        if self.cfg.is_64bit {
            mem.write_u64(addr, val)
        } else {
            mem.write_u32(addr, val as u32)
        }
    }

    fn ret(&self, cpu: &mut CpuState, mem: &dyn Memory, stack_args: u32) -> Result<()> {
        let sp = cpu.rsp();
        if self.cfg.is_64bit {
            cpu.rip = mem.read_u64(sp)?;
            cpu.set_rsp(sp + 8);
        } else {
            cpu.rip = mem.read_u32(sp)? as u64;
            cpu.set_rsp((sp + 4 + stack_args as u64 * 4) & 0xFFFF_FFFF);
        }
        Ok(())
    }

    pub fn set_environment(&mut self, env: Vec<(String, String)>) {
        if !env.is_empty() {
            self.env = env;
        }
    }

    pub(crate) fn emit_bytes(&mut self, is_err: bool, bytes: &[u8]) {
        self.emit(is_err, bytes);
    }

    fn emit(&mut self, is_err: bool, bytes: &[u8]) {
        use std::io::Write;
        if is_err {
            self.stderr_buf.extend_from_slice(bytes);
        } else {
            self.stdout_buf.extend_from_slice(bytes);
        }
        if self.cfg.echo {
            if is_err {
                let _ = std::io::stderr().write_all(bytes);
            } else {
                let _ = std::io::stdout().write_all(bytes);
            }
        }
    }

    fn heap_alloc(&mut self, size: u64) -> u64 {
        let align = 16u64;
        let ptr = (self.heap_next + align - 1) & !(align - 1);
        let stored = size.max(1);
        let end = ptr.checked_add(stored);
        match end {
            Some(end) if end <= self.cfg.heap_base + self.cfg.heap_size => {
                self.heap_next = end;
                self.heap_sizes.insert(ptr, stored);
                ptr
            }
            _ => {
                self.last_error = 8;
                0
            }
        }
    }

    pub(crate) fn crt_global(&mut self, mem: &mut dyn Memory, name: &str) -> Result<u64> {
        if let Some(&cell) = self.crt_globals.get(name) {
            return Ok(cell);
        }
        let cell = self.heap_alloc(8);
        let seed = match name {
            "__p__acmdln" => self.cfg.cmdline_ptr_a,
            "__p__wcmdln" => self.cfg.cmdline_ptr_w,
            _ => 0,
        };
        if seed != 0 && cell != 0 {
            if self.cfg.is_64bit {
                mem.write_u64(cell, seed)?;
            } else {
                mem.write_u32(cell, seed as u32)?;
            }
        }
        self.crt_globals.insert(name.to_string(), cell);
        Ok(cell)
    }

    fn tls_alloc_map(&mut self, fiber: bool) -> &mut Vec<bool> {
        if fiber {
            &mut self.fls_alloc
        } else {
            &mut self.tls_alloc
        }
    }

    fn tls_alloc(&mut self, fiber: bool) -> u64 {
        let map = self.tls_alloc_map(fiber);
        let idx = match map.iter().position(|used| !*used) {
            Some(i) => i,
            None => {
                map.push(false);
                map.len() - 1
            }
        };
        map[idx] = true;
        for t in &mut self.threads {
            t.tls_values(fiber).remove(&(idx as u64));
        }
        idx as u64
    }

    fn tls_set(&mut self, fiber: bool, index: u64, value: u64) -> bool {
        let cur = self.current;
        self.threads[cur].tls_values(fiber).insert(index, value);
        true
    }

    fn tls_get(&self, fiber: bool, index: u64) -> u64 {
        self.threads[self.current].tls_values_ref(fiber).get(&index).copied().unwrap_or(0)
    }

    fn tls_free(&mut self, fiber: bool, index: u64) -> bool {
        if let Some(used) = self.tls_alloc_map(fiber).get_mut(index as usize) {
            *used = false;
        }
        for t in &mut self.threads {
            t.tls_values(fiber).remove(&index);
        }
        true
    }

    fn reg_hkey_root(hkey: u64) -> Option<&'static str> {
        match hkey {
            0x8000_0000 => Some(Self::CLASSES_ROOT),
            0x8000_0001 => Some("HKCU"),
            0x8000_0002 => Some("HKLM"),
            0x8000_0003 => Some("HKU"),
            0x8000_0005 => Some("HKCC"),
            _ => None,
        }
    }

    pub(crate) fn reg_resolve(&self, hkey: u64) -> Option<String> {
        if let Some(root) = Self::reg_hkey_root(hkey) {
            return Some(root.to_string());
        }
        self.reg_handles.get(&hkey).cloned()
    }

    pub(crate) fn env_get(&self, name: &str) -> Option<&str> {
        self.env
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn env_set(&mut self, name: &str, value: Option<&str>) {
        let pos = self.env.iter().position(|(k, _)| k.eq_ignore_ascii_case(name));
        match (pos, value) {
            (Some(i), Some(v)) => self.env[i].1 = v.to_string(),
            (Some(i), None) => {
                self.env.remove(i);
            }
            (None, Some(v)) => self.env.push((name.to_string(), v.to_string())),
            (None, None) => {}
        }
    }

    pub(crate) fn env_block_utf16(&self) -> Vec<u16> {
        let mut out = Vec::new();
        for (k, v) in &self.env {
            out.extend(k.encode_utf16());
            out.push(b'=' as u16);
            out.extend(v.encode_utf16());
            out.push(0);
        }
        out.push(0);
        out
    }

    pub(crate) fn expand_env(&self, src: &str) -> String {
        let mut out = String::new();
        let mut rest = src;
        while let Some(open) = rest.find('%') {
            out.push_str(&rest[..open]);
            let after = &rest[open + 1..];
            match after.find('%') {
                Some(close) => {
                    let name = &after[..close];
                    match self.env_get(name) {
                        Some(v) => out.push_str(v),
                        None => {
                            out.push('%');
                            out.push_str(name);
                            out.push('%');
                        }
                    }
                    rest = &after[close + 1..];
                }
                None => {
                    out.push('%');
                    out.push_str(after);
                    rest = "";
                }
            }
        }
        out.push_str(rest);
        out
    }

    pub(crate) fn env_block_ansi(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (k, v) in &self.env {
            out.extend_from_slice(k.as_bytes());
            out.push(b'=');
            out.extend_from_slice(v.as_bytes());
            out.push(0);
        }
        out.push(0);
        out
    }
}

fn default_environment() -> Vec<(String, String)> {
    [
        ("ALLUSERSPROFILE", "C:\\ProgramData"),
        ("APPDATA", "C:\\Users\\exemu\\AppData\\Roaming"),
        ("CommonProgramFiles", "C:\\Program Files\\Common Files"),
        ("COMPUTERNAME", "EXEMU"),
        ("ComSpec", "C:\\Windows\\system32\\cmd.exe"),
        ("HOMEDRIVE", "C:"),
        ("HOMEPATH", "\\Users\\exemu"),
        ("LOCALAPPDATA", "C:\\Users\\exemu\\AppData\\Local"),
        ("NUMBER_OF_PROCESSORS", "8"),
        ("OS", "Windows_NT"),
        ("Path", "C:\\Windows;C:\\Windows\\system32;C:\\Windows\\System32\\Wbem"),
        ("PATHEXT", ".COM;.EXE;.BAT;.CMD;.VBS;.JS"),
        ("PROCESSOR_ARCHITECTURE", "AMD64"),
        ("ProgramData", "C:\\ProgramData"),
        ("ProgramFiles", "C:\\Program Files"),
        ("ProgramFiles(x86)", "C:\\Program Files (x86)"),
        ("SystemDrive", "C:"),
        ("SystemRoot", "C:\\Windows"),
        ("TEMP", "C:\\Temp"),
        ("TMP", "C:\\Temp"),
        ("USERDOMAIN", "EXEMU"),
        ("USERNAME", "exemu"),
        ("USERPROFILE", "C:\\Users\\exemu"),
        ("windir", "C:\\Windows"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

impl Hooks for WinOs {
    fn retire(&mut self, n: u64, cpu: &mut CpuState, _mem: &mut dyn Memory) -> Result<Option<Exit>> {
        if self.preempt_by(cpu, n) {
            return Ok(Some(Exit::Continue));
        }
        Ok(None)
    }

    fn retire_budget(&self) -> u64 {
        self.ticks_left()
    }

    fn intercept(&mut self, rip: u64, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Option<Exit>> {
        if self.preempt(cpu) {
            return Ok(Some(Exit::Continue));
        }
        if rip < self.cfg.api_base || rip >= self.next_thunk {
            return Ok(None);
        }
        let Some(api) = self.thunks.get(&rip).cloned() else {
            return Ok(None);
        };
        if self.cfg.trace && !matches!(api, Api::CallbackDriver | Api::InittermDriver) {
            eprintln!("[exemu] call {api:?}  (thunk {rip:#x})");
        }
        let argc = api.argc();
        match self.dispatch(&api, cpu, mem)? {
            api::Outcome::Return(value) => {
                if self.cfg.is_64bit {
                    cpu.set_reg(Reg::Rax, value);
                } else {
                    cpu.gpr_write(0, 4, value);
                }
                self.ret(cpu, mem, argc)?;
                Ok(Some(Exit::Continue))
            }
            api::Outcome::Exit(code) => Ok(Some(Exit::ProcessExit(code))),
            api::Outcome::Resume => Ok(Some(Exit::Continue)),
        }
    }

    fn syscall(&mut self, index: u32, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<Exit> {
        self.dispatch_syscall(index, cpu, mem)
    }
}
