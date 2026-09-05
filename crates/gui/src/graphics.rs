//! W7.3 — the macOS **OpenGL and Vulkan backends** behind Wine's `opengl32`
//! and `winevulkan`.
//!
//! # What the roadmap assumed, and what the binaries actually say
//!
//! The W7.3 roadmap line reads *"register the Vulkan/OpenGL driver-init members
//! (`pVulkanInit`/`pOpenGLInit`) so Wine's opengl32/wined3d have a backend"*.
//! Recovering the boundary from the pinned Wine 11.0 bytes shows those members
//! **do not exist anywhere a guest can see**, for the same structural reason
//! W4 found for the display driver: `pVulkanInit`/`pOpenGLInit` are members of
//! `win32u.so`'s internal driver vtable, and `win32u.so` is the Unix half exemu
//! *replaces* — it never loads it. `win32u.dll`, the PE half exemu does load,
//! exports **1290 `NtUser*`/`NtGdi*` syscall stubs and not one `wgl*` or `vk*`
//! entry point**.
//!
//! What actually exists in the pinned PE set is the pattern W7.1 (ws2_32) and
//! W7.2 (mmdevapi) already hit: **`opengl32.dll` and `winevulkan.dll` are PE
//! *halves* of unixlibs.** Each imports the unixlib bootstrap trio
//! (`ntdll!NtQueryVirtualMemory`, `LdrGetDllHandle`,
//! `RtlFindExportedRoutineByName`), resolves ntdll's exported
//! `__wine_unix_call_dispatcher` **data** export on first use, and then routes
//! *every* GL / Vulkan entry point through `__wine_unix_call(handle, code,
//! args)`. The "driver-init member" the roadmap is reaching for is therefore
//! **unixlib call code 0** in each DLL. Registering it means pairing a unixlib
//! with the PE builtin at the moment its PE half asks — exactly what exemu
//! already does for `ws2_32` and `mmdevapi` — not filling in a function-pointer
//! table.
//!
//! The recovered codes and argument layouts live in [`wine_abi`]; the
//! `wine_gl_vk_abi` integration test re-derives every one of them from the
//! pinned binaries on each run, so a Wine bump that renumbers a slot fails
//! there by name instead of silently drawing nothing.
//!
//! # What this module provides
//!
//! The **host side** of that pairing: real macOS graphics backends, shaped to
//! answer exactly what the recovered unixlib codes ask for.
//!
//! * [`OpenGlBackend`] — a real, headless **CGL** context out of
//!   `OpenGL.framework` (Apple's Metal-backed OpenGL). It answers
//!   `glGetString` (unixlib code 130) from the host driver and renders into an
//!   FBO, reading back **top-down BGRA32** — byte-for-byte the surface format
//!   exemu's win32k present path already uses, so a GL frame drops straight
//!   into [`crate::Presenter::flush`].
//! * [`VulkanBackend`] — loads an ICD (MoltenVK, or a Vulkan loader in front of
//!   it) by `dlopen`, resolves `vkGetInstanceProcAddr`, and answers the
//!   instance-level version / extension / physical-device queries that
//!   `winevulkan`'s codes 427 / 426 / 343 / 432 / 548 need.
//!
//! # Honest scope (read this before believing anything)
//!
//! * **OpenGL: real and verified.** A context is created, the version strings
//!   come from the host driver, and a cleared surface plus a triangle read back
//!   from the GPU is asserted pixel-wise by `graphics_backend.rs`.
//! * **Vulkan: loader implemented, unverified on the development host.** No
//!   MoltenVK is installed on the machine this was written on, so
//!   [`VulkanBackend::init`] returns [`GraphicsError::LibraryMissing`] there and
//!   the query path has never executed against a live ICD. The absence is a
//!   clean, reported failure — never a crash — and the tests assert *that*,
//!   not a fictional success.
//! * **Nothing is wired to the guest yet.** Pairing these backends with
//!   `opengl32.dll` / `winevulkan.dll` at the `MemoryWineUnixFuncs` query, and
//!   dispatching the recovered codes, is `crates/os` work and is still open.
//!   No guest has called into this module.
//!
//! No dependency was added for any of it: `dlopen`/`dlsym` come from `libSystem`
//! and every entry point is resolved by name at run time, so a missing
//! framework is a `Result`, not a link error.

#![allow(clippy::missing_safety_doc)]

use std::fmt;

// ===========================================================================
// The recovered Wine 11.0 unixlib ABI
// ===========================================================================

/// The `opengl32` / `winevulkan` unixlib ABI, recovered from the pinned Wine
/// 11.0 binaries in `example_exe/wine-dlls/x86_64-windows/`.
///
/// Every constant here is re-derived from those bytes by the `wine_gl_vk_abi`
/// integration test on each run. Provenance for each is the disassembly of the
/// named routine; nothing was read from Wine source.
///
/// ## How a code reaches the Unix side
///
/// Both DLLs share one bootstrap, in `unix_call_init`: the `.data` slot
/// `__wine_unix_call_dispatcher` initially points at `unix_call_init` itself,
/// which calls `LdrGetDllHandle(NULL, 0, &U"ntdll.dll", &ntdll)` (a
/// `UNICODE_STRING` with `Length` 0x12 / `MaximumLength` 0x14),
/// `RtlFindExportedRoutineByName(ntdll, "__wine_unix_call_dispatcher")`,
/// **dereferences the returned pointer** (the export is a data slot holding a
/// function pointer), `xchg`es it into the local slot and tail-jumps to it with
/// the original `(rcx = unixlib handle, edx = code, r8 = args)`. The handle
/// itself comes from `__wine_init_unix_call` →
/// `NtQueryVirtualMemory(.., MemoryWineUnixFuncs, ..)`.
pub mod wine_abi {
    // -- opengl32.dll ------------------------------------------------------

    /// `opengl32` unixlib slot count — the table is dense `0..=3101`.
    ///
    /// 3101 of the 3102 slots have a call site in the PE half; slot
    /// [`OPENGL32_UNUSED_SLOT`] is the sole exception.
    pub const OPENGL32_UNIX_CALL_COUNT: u32 = 3102;

    /// The one `opengl32` slot the PE half never calls:
    /// `wglGetPixelFormatAttribfvARB` widens the integer results of
    /// `wglGetPixelFormatAttribivARB` in PE code instead of crossing over.
    pub const OPENGL32_UNUSED_SLOT: u32 = 3088;

    /// `DllMain(DLL_PROCESS_ATTACH)` — **the OpenGL "driver init"**.
    ///
    /// Args are one pointer: `{ void *call_gl_debug_message_callback; }`, the
    /// PE-side thunk the Unix side uses to deliver `GL_ARB_debug_output`
    /// messages back to guest code. The call is made straight after
    /// `__wine_init_unix_call`, and **a nonzero NTSTATUS makes `DllMain` return
    /// FALSE** — without a registered Unix side `opengl32.dll` does not load at
    /// all, exactly like `ws2_32` in W7.1.
    pub const OPENGL32_PROCESS_ATTACH: u32 = 0;

    /// `DllMain(DLL_PROCESS_ATTACH | DLL_THREAD_ATTACH)` — per-thread init.
    /// Args are the raw `TEB *` (`gs:[0x30]`), passed by value in `r8`, not a
    /// struct. A nonzero status fails the attach.
    pub const OPENGL32_THREAD_ATTACH: u32 = 1;

    /// `DllMain(DLL_PROCESS_DETACH)` with `reserved == NULL`. Args are `NULL`.
    pub const OPENGL32_PROCESS_DETACH: u32 = 2;

    /// `get_pixel_formats` — the pixel-format enumeration behind
    /// `wglGetPixelFormat`/`DescribePixelFormat`.
    ///
    /// Args: `{ TEB *teb @0; HDC hdc @8; wgl_pixel_format *formats @0x10;
    /// UINT max_formats @0x18; UINT num_formats @0x1c; UINT num_onscreen @0x20 }`.
    /// Called twice — once with `formats == NULL` to size, then with a
    /// `calloc(num, 0x8c)` buffer. The PE half caches the answer in the TEB's
    /// GL slots (see [`TEB_GL_HDC`]).
    pub const OPENGL32_GET_PIXEL_FORMATS: u32 = 3;

    /// `wglCopyContext`.
    pub const OPENGL32_WGL_COPY_CONTEXT: u32 = 4;
    /// `wglCreateContext`. Args: `{ TEB *teb @0; HDC hdc @8; HGLRC ret @0x10 }`.
    pub const OPENGL32_WGL_CREATE_CONTEXT: u32 = 5;
    /// `wglDeleteContext`.
    pub const OPENGL32_WGL_DELETE_CONTEXT: u32 = 6;
    /// `wglGetPixelFormat`.
    pub const OPENGL32_WGL_GET_PIXEL_FORMAT: u32 = 7;
    /// `wglGetProcAddress`.
    pub const OPENGL32_WGL_GET_PROC_ADDRESS: u32 = 8;
    /// `wglMakeCurrent`. Args:
    /// `{ TEB *teb @0; HDC hdc @8; HGLRC ctx @0x10; BOOL ret @0x18 }`.
    pub const OPENGL32_WGL_MAKE_CURRENT: u32 = 9;
    /// `wglSetPixelFormat`.
    pub const OPENGL32_WGL_SET_PIXEL_FORMAT: u32 = 10;
    /// `wglShareLists`.
    pub const OPENGL32_WGL_SHARE_LISTS: u32 = 11;
    /// `wglSwapBuffers` — the GL present point.
    pub const OPENGL32_WGL_SWAP_BUFFERS: u32 = 12;

    /// `glClear` — the first slot of the alphabetical `gl*` block that starts
    /// at 13 and runs to [`OPENGL32_UNIX_CALL_COUNT`] − 1.
    pub const OPENGL32_GL_CLEAR: u32 = 23;
    /// `glClearColor`.
    pub const OPENGL32_GL_CLEAR_COLOR: u32 = 25;
    /// `glGetString` — the version/vendor/extension query this module answers
    /// from the real host driver.
    pub const OPENGL32_GL_GET_STRING: u32 = 130;
    /// `glReadPixels`.
    pub const OPENGL32_GL_READ_PIXELS: u32 = 250;
    /// `glViewport`.
    pub const OPENGL32_GL_VIEWPORT: u32 = 348;

    /// `sizeof(struct wgl_pixel_format)` — from the
    /// `calloc(count, 0x8c)` in `get_pixel_formats`.
    pub const WGL_PIXEL_FORMAT_SIZE: usize = 0x8c;

    /// TEB offset of the HDC `get_pixel_formats` caches its answer against
    /// (the 64-bit TEB's GL reserved block).
    pub const TEB_GL_HDC: usize = 0x1148;
    /// TEB offset of the cached `wgl_pixel_format` array — `free`d on thread
    /// detach.
    pub const TEB_GL_FORMATS: usize = 0x1150;
    /// TEB offset of the cached format count.
    pub const TEB_GL_NUM_FORMATS: usize = 0x1158;
    /// TEB offset of the cached on-screen format count.
    pub const TEB_GL_NUM_ONSCREEN_FORMATS: usize = 0x1160;

    // -- winevulkan.dll ----------------------------------------------------

    /// `winevulkan` unixlib slot count — the table is dense `0..=673`.
    pub const WINEVULKAN_UNIX_CALL_COUNT: u32 = 674;

    /// `wine_vk_init` — **the Vulkan "driver init"**.
    ///
    /// Reached lazily through `InitOnceExecuteOnce(&init_once, wine_vk_init)`
    /// from every public entry point, not from `DllMain`. Args are 24 bytes:
    /// `{ void *call_vulkan_debug_report_callback @0;
    ///    void *call_vulkan_debug_utils_callback @8;
    ///    unsigned char *instance_extensions @0x10 }` — two PE-side callback
    /// thunks in, and an **out** pointer to a byte-per-extension flag array the
    /// Unix side fills so the PE half knows which instance extensions are
    /// available (`movzbl`/`testb $1` against it all over the wrappers).
    ///
    /// The code is `0` because the register still holds the zero NTSTATUS from
    /// the `__wine_init_unix_call` that precedes it.
    ///
    /// **Failure is soft, unlike opengl32's:** if this returns nonzero,
    /// `vkEnumerateInstanceVersion` reports `VK_API_VERSION_1_0` (0x400000) and
    /// extension enumeration reports zero extensions, rather than the DLL
    /// failing to load.
    pub const WINEVULKAN_INIT: u32 = 0;

    /// `vkGetInstanceProcAddr` (also reached from
    /// `vk_icdGetPhysicalDeviceProcAddr`).
    pub const WINEVULKAN_GET_INSTANCE_PROC_ADDR: u32 = 1;
    /// `vkGetDeviceProcAddr`.
    pub const WINEVULKAN_GET_DEVICE_PROC_ADDR: u32 = 2;
    /// `vkCreateInstance`.
    pub const WINEVULKAN_CREATE_INSTANCE: u32 = 343;
    /// `vkDestroyInstance`.
    pub const WINEVULKAN_DESTROY_INSTANCE: u32 = 398;
    /// `vkEnumerateInstanceExtensionProperties`. Rejects a non-NULL
    /// `pLayerName` in PE code before ever crossing over.
    pub const WINEVULKAN_ENUMERATE_INSTANCE_EXTENSION_PROPERTIES: u32 = 426;
    /// `vkEnumerateInstanceVersion`. Args: `{ uint32_t *pApiVersion @0;
    /// VkResult result @8 }` — the trailing result slot is the shape every
    /// `winevulkan` params struct ends with.
    pub const WINEVULKAN_ENUMERATE_INSTANCE_VERSION: u32 = 427;
    /// `vkEnumeratePhysicalDevices`.
    pub const WINEVULKAN_ENUMERATE_PHYSICAL_DEVICES: u32 = 432;
    /// `vkGetPhysicalDeviceProperties`.
    pub const WINEVULKAN_GET_PHYSICAL_DEVICE_PROPERTIES: u32 = 548;

    /// `sizeof` the `wine_vk_init` params struct (three pointers).
    pub const WINEVULKAN_INIT_PARAMS_SIZE: usize = 24;

    /// `VK_API_VERSION_1_0` — the version `vkEnumerateInstanceVersion` reports
    /// in PE code when the Unix side failed to initialise.
    pub const VK_API_VERSION_1_0: u32 = 0x0040_0000;

    /// The three ntdll imports that mark a PE builtin as one half of a unixlib.
    /// Present in both `opengl32.dll` and `winevulkan.dll`.
    pub const UNIXLIB_BOOTSTRAP_IMPORTS: [&str; 3] =
        ["NtQueryVirtualMemory", "LdrGetDllHandle", "RtlFindExportedRoutineByName"];
}

// ===========================================================================
// Errors
// ===========================================================================

/// Why a graphics backend could not be brought up, or a call into one failed.
///
/// Every variant is a *reported* failure: the callers in this module never
/// panic on a missing framework, a missing symbol or a driver error, so a host
/// without MoltenVK (or without a window server) degrades to a clean `Err`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphicsError {
    /// The backend is not implemented for this platform (non-macOS builds).
    Unsupported {
        /// Which backend was asked for.
        backend: &'static str,
    },
    /// No candidate library could be `dlopen`ed. `tried` lists the paths in the
    /// order they were attempted, so the failure names what was looked for.
    LibraryMissing {
        /// Human name of the library ("MoltenVK", "OpenGL.framework").
        name: &'static str,
        /// The candidate paths, in search order.
        tried: Vec<String>,
    },
    /// The library loaded but a required entry point was absent — a wrong or
    /// truncated library rather than a missing one.
    SymbolMissing {
        /// The library it was looked up in.
        library: String,
        /// The symbol name.
        symbol: String,
    },
    /// A backend call returned a failure status.
    Backend {
        /// The call that failed.
        call: &'static str,
        /// The driver's own status code (`CGLError`, `VkResult`, `GLenum`).
        code: i32,
    },
}

impl fmt::Display for GraphicsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GraphicsError::Unsupported { backend } => {
                write!(f, "{backend} is only implemented on macOS")
            }
            GraphicsError::LibraryMissing { name, tried } => {
                write!(f, "{name} not found; tried: {}", tried.join(", "))
            }
            GraphicsError::SymbolMissing { library, symbol } => {
                write!(f, "{library} does not export {symbol}")
            }
            GraphicsError::Backend { call, code } => {
                write!(f, "{call} failed with status {code}")
            }
        }
    }
}

impl std::error::Error for GraphicsError {}

// ===========================================================================
// Vulkan ICD search order (host-independent, so it is testable everywhere)
// ===========================================================================

/// Environment variable that overrides the Vulkan ICD search with an explicit
/// path — the escape hatch for a MoltenVK that lives inside an app bundle.
pub const VULKAN_LIBRARY_ENV: &str = "EXEMU_VULKAN_LIBRARY";

/// The Vulkan libraries [`VulkanBackend::init`] tries, in order.
///
/// `EXEMU_VULKAN_LIBRARY` wins outright when set. Otherwise a Vulkan *loader*
/// is preferred over a bare ICD (it applies the ICD manifests and layers the
/// user installed), then MoltenVK itself at the paths the LunarG SDK, Homebrew
/// and MoltenVK's own release archive install to. Bare sonames are included so
/// `dlopen` can also find one via `DYLD_LIBRARY_PATH` / `@rpath`.
pub fn vulkan_library_candidates() -> Vec<String> {
    let explicit = std::env::var_os(VULKAN_LIBRARY_ENV).map(|v| v.to_string_lossy().into_owned());
    vulkan_library_candidates_from(explicit.as_deref())
}

/// The pure half of [`vulkan_library_candidates`]: the same search order, with
/// the `EXEMU_VULKAN_LIBRARY` override passed in rather than read from the
/// process environment.
///
/// Separated so tests can pin the ordering without mutating a global that other
/// tests in the same process are concurrently reading.
pub fn vulkan_library_candidates_from(explicit: Option<&str>) -> Vec<String> {
    if let Some(explicit) = explicit {
        if !explicit.is_empty() {
            return vec![explicit.to_string()];
        }
    }
    let mut out: Vec<String> = Vec::new();
    // A loader first — it honours ICD manifests and explicit layers.
    for dir in ["/usr/local/lib", "/opt/homebrew/lib"] {
        out.push(format!("{dir}/libvulkan.1.dylib"));
        out.push(format!("{dir}/libvulkan.dylib"));
    }
    // Then MoltenVK directly.
    for dir in ["/usr/local/lib", "/opt/homebrew/lib"] {
        out.push(format!("{dir}/libMoltenVK.dylib"));
    }
    out.push(
        "/usr/local/share/vulkan/icd.d/../../../lib/libMoltenVK.dylib".to_string(),
    );
    // Finally bare sonames, resolved through the dynamic loader's own search.
    out.push("libvulkan.1.dylib".to_string());
    out.push("libMoltenVK.dylib".to_string());
    out
}

// ===========================================================================
// The real backends (macOS only)
// ===========================================================================

#[cfg(target_os = "macos")]
mod imp {
    use super::wine_abi;
    use super::{vulkan_library_candidates, GraphicsError};
    use std::ffi::{c_char, c_int, c_void, CStr, CString};

    // -- dlopen/dlsym ------------------------------------------------------

    extern "C" {
        fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
        fn dlclose(handle: *mut c_void) -> c_int;
    }

    const RTLD_NOW: c_int = 0x2;
    const RTLD_LOCAL: c_int = 0x4;

    /// A `dlopen`ed handle plus the path it came from, closed on drop.
    struct Library {
        handle: *mut c_void,
        path: String,
    }

    impl Library {
        fn open(path: &str) -> Option<Library> {
            let c = CString::new(path).ok()?;
            // SAFETY: `c` is a NUL-terminated path; `dlopen` returns null on
            // failure, which is the only thing we act on.
            let handle = unsafe { dlopen(c.as_ptr(), RTLD_NOW | RTLD_LOCAL) };
            if handle.is_null() {
                None
            } else {
                Some(Library { handle, path: path.to_string() })
            }
        }

        /// Look a symbol up, or report which library was missing it.
        fn sym(&self, name: &str) -> Result<*mut c_void, GraphicsError> {
            let c = CString::new(name).map_err(|_| GraphicsError::SymbolMissing {
                library: self.path.clone(),
                symbol: name.to_string(),
            })?;
            // SAFETY: `self.handle` is a live handle from `dlopen`, `c` is
            // NUL-terminated. A missing symbol yields null, handled below.
            let p = unsafe { dlsym(self.handle, c.as_ptr()) };
            if p.is_null() {
                Err(GraphicsError::SymbolMissing {
                    library: self.path.clone(),
                    symbol: name.to_string(),
                })
            } else {
                Ok(p)
            }
        }
    }

    impl Drop for Library {
        fn drop(&mut self) {
            // SAFETY: handle came from `dlopen` and is dropped exactly once.
            unsafe { dlclose(self.handle) };
        }
    }

    /// Read a NUL-terminated C string a backend returned, lossily.
    ///
    /// # Safety
    /// `p` must be null or point at a NUL-terminated string that outlives the
    /// call.
    unsafe fn cstr(p: *const c_char) -> String {
        if p.is_null() {
            String::new()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }

    // ======================================================================
    // OpenGL — CGL out of OpenGL.framework
    // ======================================================================

    /// Where `OpenGL.framework` lives. Absolute, because the framework is
    /// deprecated and must not be link-time resolved.
    const OPENGL_FRAMEWORK: &str = "/System/Library/Frameworks/OpenGL.framework/OpenGL";

    // CGL pixel-format attribute selectors (public `CGLTypes.h` values).
    const K_CGL_PFA_COLOR_SIZE: i32 = 8;
    const K_CGL_PFA_ALPHA_SIZE: i32 = 11;
    const K_CGL_PFA_DEPTH_SIZE: i32 = 12;
    const K_CGL_PFA_OPENGL_PROFILE: i32 = 99;
    /// `kCGLOGLPVersion_Legacy` — the 2.1 profile. Chosen deliberately: it is
    /// the profile Wine's `opengl32` surface (`glBegin`/`glVertex`, unixlib
    /// codes 17 and up) is written against, and macOS backs it with Metal.
    const K_CGL_OGLP_VERSION_LEGACY: i32 = 0x1000;

    // GL enums (public `gl.h` / `glext.h` values).
    const GL_NO_ERROR: u32 = 0;
    const GL_VENDOR: u32 = 0x1F00;
    const GL_RENDERER: u32 = 0x1F01;
    const GL_VERSION: u32 = 0x1F02;
    const GL_EXTENSIONS: u32 = 0x1F03;
    const GL_TRIANGLES: u32 = 0x0004;
    const GL_UNSIGNED_BYTE: u32 = 0x1401;
    const GL_DEPTH_BUFFER_BIT: u32 = 0x0000_0100;
    const GL_COLOR_BUFFER_BIT: u32 = 0x0000_4000;
    const GL_PACK_ALIGNMENT: u32 = 0x0D05;
    const GL_RGBA8: u32 = 0x8058;
    const GL_DEPTH_COMPONENT24: u32 = 0x81A6;
    const GL_BGRA: u32 = 0x80E1;
    const GL_FRAMEBUFFER_EXT: u32 = 0x8D40;
    const GL_RENDERBUFFER_EXT: u32 = 0x8D41;
    const GL_COLOR_ATTACHMENT0_EXT: u32 = 0x8CE0;
    const GL_DEPTH_ATTACHMENT_EXT: u32 = 0x8D00;
    const GL_FRAMEBUFFER_COMPLETE_EXT: u32 = 0x8CD5;

    type CglObj = *mut c_void;

    // Signature aliases: each is exactly what OpenGL.framework publishes for
    // the entry points that share it. They exist so every `dlsym` result is
    // transmuted to a *named, spelled-out* type rather than an inferred one.
    type CglChoose = unsafe extern "C" fn(*const i32, *mut CglObj, *mut i32) -> i32;
    type CglCreate = unsafe extern "C" fn(CglObj, CglObj, *mut CglObj) -> i32;
    type CglObjToErr = unsafe extern "C" fn(CglObj) -> i32;
    type GlEnumToStr = unsafe extern "C" fn(u32) -> *const c_char;
    type GlToEnum = unsafe extern "C" fn() -> u32;
    type GlEnumToEnum = unsafe extern "C" fn(u32) -> u32;
    type Gl4i = unsafe extern "C" fn(i32, i32, i32, i32);
    type Gl4f = unsafe extern "C" fn(f32, f32, f32, f32);
    type Gl3f = unsafe extern "C" fn(f32, f32, f32);
    type Gl2f = unsafe extern "C" fn(f32, f32);
    type Gl1u = unsafe extern "C" fn(u32);
    type Gl0 = unsafe extern "C" fn();
    type GlEnumI = unsafe extern "C" fn(u32, i32);
    type GlReadPixels = unsafe extern "C" fn(i32, i32, i32, i32, u32, u32, *mut c_void);
    type GlGenNames = unsafe extern "C" fn(i32, *mut u32);
    type GlDeleteNames = unsafe extern "C" fn(i32, *const u32);
    type Gl2u = unsafe extern "C" fn(u32, u32);
    type Gl2u2i = unsafe extern "C" fn(u32, u32, i32, i32);
    type Gl4u = unsafe extern "C" fn(u32, u32, u32, u32);

    /// The CGL + GL entry points the backend resolves by name.
    #[allow(non_snake_case)]
    struct Gl {
        CGLChoosePixelFormat: CglChoose,
        CGLDestroyPixelFormat: CglObjToErr,
        CGLCreateContext: CglCreate,
        CGLDestroyContext: CglObjToErr,
        CGLSetCurrentContext: CglObjToErr,

        glGetString: GlEnumToStr,
        glGetError: GlToEnum,
        glViewport: Gl4i,
        glClearColor: Gl4f,
        glClear: Gl1u,
        glFinish: Gl0,
        glPixelStorei: GlEnumI,
        glReadPixels: GlReadPixels,
        glBegin: Gl1u,
        glEnd: Gl0,
        glColor3f: Gl3f,
        glVertex2f: Gl2f,

        glGenFramebuffersEXT: GlGenNames,
        glBindFramebufferEXT: Gl2u,
        glDeleteFramebuffersEXT: GlDeleteNames,
        glGenRenderbuffersEXT: GlGenNames,
        glBindRenderbufferEXT: Gl2u,
        glDeleteRenderbuffersEXT: GlDeleteNames,
        glRenderbufferStorageEXT: Gl2u2i,
        glFramebufferRenderbufferEXT: Gl4u,
        glCheckFramebufferStatusEXT: GlEnumToEnum,
    }

    /// What the host GL driver reports about itself — the answer exemu's
    /// `glGetString` (unixlib code 130) handler will return to guest code.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GlInfo {
        /// `GL_VERSION`, e.g. `"2.1 Metal - 90.5"`.
        pub version: String,
        /// `GL_RENDERER`, e.g. `"Apple M5"`.
        pub renderer: String,
        /// `GL_VENDOR`, e.g. `"Apple"`.
        pub vendor: String,
        /// `GL_EXTENSIONS`, split on spaces.
        pub extensions: Vec<String>,
    }

    /// A flat-shaded triangle in normalised device coordinates, for
    /// [`OpenGlBackend::draw_frame`].
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct Triangle {
        /// The three vertices, each `[x, y]` in `[-1, 1]` NDC.
        pub verts: [[f32; 2]; 3],
        /// Flat RGB colour in `[0, 1]`.
        pub color: [f32; 3],
    }

    /// A frame read back off the GPU, in exemu's surface format.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GlFrame {
        /// Width in pixels.
        pub width: u32,
        /// Height in pixels.
        pub height: u32,
        /// Top-down BGRA32, `width * height * 4` bytes — the same layout
        /// [`crate::Presenter::flush`] takes, so a GL frame presents directly.
        pub bgra: Vec<u8>,
    }

    /// A real, headless OpenGL context on `OpenGL.framework`'s CGL.
    ///
    /// This is the host side of `opengl32`'s unixlib: what
    /// [`wine_abi::OPENGL32_PROCESS_ATTACH`] must have ready before
    /// `wglCreateContext` (code 5) can hand a guest an `HGLRC`.
    ///
    /// **Not `Send`** — a GL context is bound to the thread that made it
    /// current, and the raw CGL handles say so.
    pub struct OpenGlBackend {
        // Field order matters: the context must be destroyed before the
        // library it came from is `dlclose`d.
        ctx: CglObj,
        pixel_format: CglObj,
        info: GlInfo,
        gl: Gl,
        _lib: Library,
    }

    impl OpenGlBackend {
        /// Bring up a headless GL context — the work
        /// [`wine_abi::OPENGL32_PROCESS_ATTACH`] has to succeed at, or
        /// `opengl32.dll` refuses to load.
        ///
        /// Fails cleanly with [`GraphicsError::LibraryMissing`] when
        /// `OpenGL.framework` is absent and [`GraphicsError::Backend`] when the
        /// host cannot give out a context (no window server, no renderer).
        pub fn init() -> Result<OpenGlBackend, GraphicsError> {
            let lib = Library::open(OPENGL_FRAMEWORK).ok_or_else(|| {
                GraphicsError::LibraryMissing {
                    name: "OpenGL.framework",
                    tried: vec![OPENGL_FRAMEWORK.to_string()],
                }
            })?;

            // SAFETY: every `dlsym` result below is checked non-null by
            // `Library::sym`, and each is transmuted to the signature
            // OpenGL.framework publishes for that exact name.
            let gl = unsafe {
                macro_rules! sym {
                    ($n:literal, $t:ty) => {
                        std::mem::transmute::<*mut c_void, $t>(lib.sym($n)?)
                    };
                }
                Gl {
                    CGLChoosePixelFormat: sym!("CGLChoosePixelFormat", CglChoose),
                    CGLDestroyPixelFormat: sym!("CGLDestroyPixelFormat", CglObjToErr),
                    CGLCreateContext: sym!("CGLCreateContext", CglCreate),
                    CGLDestroyContext: sym!("CGLDestroyContext", CglObjToErr),
                    CGLSetCurrentContext: sym!("CGLSetCurrentContext", CglObjToErr),
                    glGetString: sym!("glGetString", GlEnumToStr),
                    glGetError: sym!("glGetError", GlToEnum),
                    glViewport: sym!("glViewport", Gl4i),
                    glClearColor: sym!("glClearColor", Gl4f),
                    glClear: sym!("glClear", Gl1u),
                    glFinish: sym!("glFinish", Gl0),
                    glPixelStorei: sym!("glPixelStorei", GlEnumI),
                    glReadPixels: sym!("glReadPixels", GlReadPixels),
                    glBegin: sym!("glBegin", Gl1u),
                    glEnd: sym!("glEnd", Gl0),
                    glColor3f: sym!("glColor3f", Gl3f),
                    glVertex2f: sym!("glVertex2f", Gl2f),
                    glGenFramebuffersEXT: sym!("glGenFramebuffersEXT", GlGenNames),
                    glBindFramebufferEXT: sym!("glBindFramebufferEXT", Gl2u),
                    glDeleteFramebuffersEXT: sym!("glDeleteFramebuffersEXT", GlDeleteNames),
                    glGenRenderbuffersEXT: sym!("glGenRenderbuffersEXT", GlGenNames),
                    glBindRenderbufferEXT: sym!("glBindRenderbufferEXT", Gl2u),
                    glDeleteRenderbuffersEXT: sym!("glDeleteRenderbuffersEXT", GlDeleteNames),
                    glRenderbufferStorageEXT: sym!("glRenderbufferStorageEXT", Gl2u2i),
                    glFramebufferRenderbufferEXT: sym!("glFramebufferRenderbufferEXT", Gl4u),
                    glCheckFramebufferStatusEXT: sym!("glCheckFramebufferStatusEXT", GlEnumToEnum),
                }
            };

            let attribs: [i32; 9] = [
                K_CGL_PFA_OPENGL_PROFILE,
                K_CGL_OGLP_VERSION_LEGACY,
                K_CGL_PFA_COLOR_SIZE,
                24,
                K_CGL_PFA_ALPHA_SIZE,
                8,
                K_CGL_PFA_DEPTH_SIZE,
                24,
                0,
            ];
            let mut pixel_format: CglObj = std::ptr::null_mut();
            let mut n: i32 = 0;
            // SAFETY: `attribs` is a 0-terminated CGL attribute list; both
            // out-pointers are live locals.
            let err = unsafe {
                (gl.CGLChoosePixelFormat)(attribs.as_ptr(), &mut pixel_format, &mut n)
            };
            if err != 0 || pixel_format.is_null() {
                return Err(GraphicsError::Backend { call: "CGLChoosePixelFormat", code: err });
            }

            let mut ctx: CglObj = std::ptr::null_mut();
            // SAFETY: `pixel_format` is a live CGL pixel format; no share group.
            let err =
                unsafe { (gl.CGLCreateContext)(pixel_format, std::ptr::null_mut(), &mut ctx) };
            if err != 0 || ctx.is_null() {
                // SAFETY: `pixel_format` is live and released exactly once here.
                unsafe { (gl.CGLDestroyPixelFormat)(pixel_format) };
                return Err(GraphicsError::Backend { call: "CGLCreateContext", code: err });
            }

            // SAFETY: `ctx` is a live context; making it current is what every
            // subsequent GL call below requires.
            let err = unsafe { (gl.CGLSetCurrentContext)(ctx) };
            if err != 0 {
                // SAFETY: both objects are live and released exactly once.
                unsafe {
                    (gl.CGLDestroyContext)(ctx);
                    (gl.CGLDestroyPixelFormat)(pixel_format);
                }
                return Err(GraphicsError::Backend { call: "CGLSetCurrentContext", code: err });
            }

            // SAFETY: a context is current, so `glGetString` is legal and
            // returns driver-owned static strings.
            let info = unsafe {
                GlInfo {
                    version: cstr((gl.glGetString)(GL_VERSION)),
                    renderer: cstr((gl.glGetString)(GL_RENDERER)),
                    vendor: cstr((gl.glGetString)(GL_VENDOR)),
                    extensions: cstr((gl.glGetString)(GL_EXTENSIONS))
                        .split_whitespace()
                        .map(str::to_string)
                        .collect(),
                }
            };

            Ok(OpenGlBackend { ctx, pixel_format, info, gl, _lib: lib })
        }

        /// What the host driver reports — the answer to `glGetString`
        /// (unixlib code [`wine_abi::OPENGL32_GL_GET_STRING`]).
        pub fn info(&self) -> &GlInfo {
            &self.info
        }

        /// Make this backend's context current on the calling thread.
        pub fn make_current(&self) -> Result<(), GraphicsError> {
            // SAFETY: `self.ctx` is live for the lifetime of `self`.
            let err = unsafe { (self.gl.CGLSetCurrentContext)(self.ctx) };
            if err == 0 {
                Ok(())
            } else {
                Err(GraphicsError::Backend { call: "CGLSetCurrentContext", code: err })
            }
        }

        /// Render one `width × height` frame on the GPU and read it back as
        /// **top-down BGRA32**.
        ///
        /// `clear` is RGBA in `[0, 1]`; `tri`, when given, is drawn flat-shaded
        /// on top. The readback is `GL_BGRA`/`GL_UNSIGNED_BYTE` — the exact
        /// byte order of exemu's window surfaces — and the rows are flipped,
        /// because GL's origin is bottom-left and a Windows top-down DIB's is
        /// top-left.
        pub fn draw_frame(
            &mut self,
            width: u32,
            height: u32,
            clear: [f32; 4],
            tri: Option<Triangle>,
        ) -> Result<GlFrame, GraphicsError> {
            self.make_current()?;
            let (w, h) = (width as i32, height as i32);
            let gl = &self.gl;

            let mut fbo: u32 = 0;
            let mut color: u32 = 0;
            let mut depth: u32 = 0;
            // SAFETY: a context is current; every name below is generated by
            // the driver and bound before use, and all are deleted at the end
            // of this function.
            let status = unsafe {
                (gl.glGenFramebuffersEXT)(1, &mut fbo);
                (gl.glBindFramebufferEXT)(GL_FRAMEBUFFER_EXT, fbo);

                (gl.glGenRenderbuffersEXT)(1, &mut color);
                (gl.glBindRenderbufferEXT)(GL_RENDERBUFFER_EXT, color);
                (gl.glRenderbufferStorageEXT)(GL_RENDERBUFFER_EXT, GL_RGBA8, w, h);
                (gl.glFramebufferRenderbufferEXT)(
                    GL_FRAMEBUFFER_EXT,
                    GL_COLOR_ATTACHMENT0_EXT,
                    GL_RENDERBUFFER_EXT,
                    color,
                );

                (gl.glGenRenderbuffersEXT)(1, &mut depth);
                (gl.glBindRenderbufferEXT)(GL_RENDERBUFFER_EXT, depth);
                (gl.glRenderbufferStorageEXT)(GL_RENDERBUFFER_EXT, GL_DEPTH_COMPONENT24, w, h);
                (gl.glFramebufferRenderbufferEXT)(
                    GL_FRAMEBUFFER_EXT,
                    GL_DEPTH_ATTACHMENT_EXT,
                    GL_RENDERBUFFER_EXT,
                    depth,
                );

                (gl.glCheckFramebufferStatusEXT)(GL_FRAMEBUFFER_EXT)
            };

            if status != GL_FRAMEBUFFER_COMPLETE_EXT {
                // SAFETY: all three names are live and deleted exactly once.
                unsafe {
                    (gl.glBindFramebufferEXT)(GL_FRAMEBUFFER_EXT, 0);
                    (gl.glDeleteRenderbuffersEXT)(1, &depth);
                    (gl.glDeleteRenderbuffersEXT)(1, &color);
                    (gl.glDeleteFramebuffersEXT)(1, &fbo);
                }
                return Err(GraphicsError::Backend {
                    call: "glCheckFramebufferStatusEXT",
                    code: status as i32,
                });
            }

            let mut bgra = vec![0u8; (width as usize) * (height as usize) * 4];
            // SAFETY: the FBO is complete and bound; `bgra` is exactly
            // `width * height * 4` bytes, which is what a tightly packed
            // (`GL_PACK_ALIGNMENT` 1) `GL_BGRA`/`GL_UNSIGNED_BYTE` readback of
            // that rectangle writes.
            let gl_err = unsafe {
                (gl.glViewport)(0, 0, w, h);
                (gl.glClearColor)(clear[0], clear[1], clear[2], clear[3]);
                (gl.glClear)(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
                if let Some(t) = tri {
                    (gl.glColor3f)(t.color[0], t.color[1], t.color[2]);
                    (gl.glBegin)(GL_TRIANGLES);
                    for v in t.verts {
                        (gl.glVertex2f)(v[0], v[1]);
                    }
                    (gl.glEnd)();
                }
                (gl.glFinish)();
                (gl.glPixelStorei)(GL_PACK_ALIGNMENT, 1);
                (gl.glReadPixels)(
                    0,
                    0,
                    w,
                    h,
                    GL_BGRA,
                    GL_UNSIGNED_BYTE,
                    bgra.as_mut_ptr().cast(),
                );
                (gl.glGetError)()
            };

            // SAFETY: all three names are live and deleted exactly once.
            unsafe {
                (gl.glBindFramebufferEXT)(GL_FRAMEBUFFER_EXT, 0);
                (gl.glDeleteRenderbuffersEXT)(1, &depth);
                (gl.glDeleteRenderbuffersEXT)(1, &color);
                (gl.glDeleteFramebuffersEXT)(1, &fbo);
            }

            if gl_err != GL_NO_ERROR {
                return Err(GraphicsError::Backend { call: "glReadPixels", code: gl_err as i32 });
            }

            // GL reads back bottom-up; exemu's surfaces are top-down DIBs.
            let stride = (width as usize) * 4;
            let mut top_down = vec![0u8; bgra.len()];
            for row in 0..height as usize {
                let src = (height as usize - 1 - row) * stride;
                top_down[row * stride..row * stride + stride]
                    .copy_from_slice(&bgra[src..src + stride]);
            }
            Ok(GlFrame { width, height, bgra: top_down })
        }
    }

    impl Drop for OpenGlBackend {
        fn drop(&mut self) {
            // SAFETY: both handles were produced by CGL in `init` and are
            // released exactly once, after clearing the current context so no
            // thread is left pointing at freed state.
            unsafe {
                (self.gl.CGLSetCurrentContext)(std::ptr::null_mut());
                (self.gl.CGLDestroyContext)(self.ctx);
                (self.gl.CGLDestroyPixelFormat)(self.pixel_format);
            }
        }
    }

    // ======================================================================
    // Vulkan — MoltenVK (or a loader in front of it)
    // ======================================================================

    const VK_SUCCESS: i32 = 0;
    const VK_INCOMPLETE: i32 = 5;
    const VK_STRUCTURE_TYPE_APPLICATION_INFO: u32 = 0;
    const VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO: u32 = 1;
    /// `VK_INSTANCE_CREATE_ENUMERATE_PORTABILITY_BIT_KHR` — required before a
    /// portability ICD (MoltenVK) will report its physical device.
    const VK_INSTANCE_CREATE_ENUMERATE_PORTABILITY_BIT_KHR: u32 = 0x0000_0001;
    const VK_PORTABILITY_ENUMERATION_EXTENSION: &str = "VK_KHR_portability_enumeration";
    /// `sizeof(VkExtensionProperties)` = `char[256]` + `uint32_t`.
    const VK_EXTENSION_PROPERTIES_SIZE: usize = 260;
    /// Offset of `deviceName` in `VkPhysicalDeviceProperties`
    /// (`apiVersion`, `driverVersion`, `vendorID`, `deviceID`, `deviceType`).
    const VK_PHYSICAL_DEVICE_PROPERTIES_NAME_OFFSET: usize = 20;
    /// A generous over-allocation for `VkPhysicalDeviceProperties` (824 bytes
    /// in Vulkan 1.3) — only the leading scalars and `deviceName` are read.
    const VK_PHYSICAL_DEVICE_PROPERTIES_SIZE: usize = 2048;

    type VkInstance = *mut c_void;
    type VkPhysicalDevice = *mut c_void;
    type PfnVoid = unsafe extern "C" fn();

    // Vulkan entry-point signatures, spelled out so every `dlsym`/`vkGetInstanceProcAddr`
    // result is transmuted to a named type. Each matches the Vulkan 1.x C ABI.
    type PfnGetInstanceProcAddr =
        unsafe extern "C" fn(VkInstance, *const c_char) -> Option<PfnVoid>;
    type PfnEnumerateInstanceVersion = unsafe extern "C" fn(*mut u32) -> i32;
    type PfnEnumerateInstanceExtensionProperties =
        unsafe extern "C" fn(*const c_char, *mut u32, *mut u8) -> i32;
    type PfnCreateInstance =
        unsafe extern "C" fn(*const u8, *const c_void, *mut VkInstance) -> i32;
    type PfnDestroyInstance = unsafe extern "C" fn(VkInstance, *const c_void);
    type PfnEnumeratePhysicalDevices =
        unsafe extern "C" fn(VkInstance, *mut u32, *mut VkPhysicalDevice) -> i32;
    type PfnGetPhysicalDeviceProperties = unsafe extern "C" fn(VkPhysicalDevice, *mut u8);

    /// A physical device the loaded ICD reports.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct VulkanDevice {
        /// `VkPhysicalDeviceProperties::deviceName`.
        pub name: String,
        /// `apiVersion` as `(major, minor, patch)`.
        pub api_version: (u32, u32, u32),
        /// `vendorID`.
        pub vendor_id: u32,
        /// `deviceID`.
        pub device_id: u32,
        /// `deviceType` (`VkPhysicalDeviceType`; MoltenVK reports 4 =
        /// integrated on Apple silicon).
        pub device_type: u32,
    }

    /// A loaded Vulkan ICD — the host side of `winevulkan`'s unixlib.
    ///
    /// [`init`](VulkanBackend::init) is the work
    /// [`wine_abi::WINEVULKAN_INIT`] has to do, and the queries below are what
    /// codes 427 / 426 / 343 / 432 / 548 need answered.
    ///
    /// **Unverified against a live ICD.** MoltenVK is not installed on the
    /// development host, so on that machine `init` reports
    /// [`GraphicsError::LibraryMissing`] and nothing past it has run.
    pub struct VulkanBackend {
        get_instance_proc_addr: PfnGetInstanceProcAddr,
        instance: VkInstance,
        destroy_instance: Option<PfnDestroyInstance>,
        path: String,
        _lib: Library,
    }

    impl VulkanBackend {
        /// Load the first Vulkan library in [`vulkan_library_candidates`] that
        /// `dlopen`s and exports `vkGetInstanceProcAddr`.
        ///
        /// Returns [`GraphicsError::LibraryMissing`], listing every path tried,
        /// when the host has no Vulkan at all — the expected outcome on a Mac
        /// without MoltenVK, and never a panic. A library that *did* load but
        /// is not a Vulkan ICD is reported as [`GraphicsError::SymbolMissing`]
        /// instead, so a wrong `EXEMU_VULKAN_LIBRARY` does not masquerade as an
        /// absent one.
        pub fn init() -> Result<VulkanBackend, GraphicsError> {
            Self::load(&vulkan_library_candidates())
        }

        /// Load the first of `candidates` that is a Vulkan ICD.
        ///
        /// The explicit-list form of [`init`](VulkanBackend::init), so a caller
        /// (or a test) can probe a specific library without going through the
        /// process environment.
        pub fn load(candidates: &[String]) -> Result<VulkanBackend, GraphicsError> {
            let mut not_an_icd: Option<GraphicsError> = None;
            for path in candidates {
                let Some(lib) = Library::open(path) else { continue };
                let p = match lib.sym("vkGetInstanceProcAddr") {
                    Ok(p) => p,
                    Err(e) => {
                        not_an_icd.get_or_insert(e);
                        continue;
                    }
                };
                // SAFETY: `p` is non-null and named `vkGetInstanceProcAddr`,
                // whose signature is fixed by the Vulkan ABI.
                    let get_instance_proc_addr =
                    unsafe { std::mem::transmute::<*mut c_void, PfnGetInstanceProcAddr>(p) };
                return Ok(VulkanBackend {
                    get_instance_proc_addr,
                    instance: std::ptr::null_mut(),
                    destroy_instance: None,
                    path: lib.path.clone(),
                    _lib: lib,
                });
            }
            Err(not_an_icd.unwrap_or_else(|| GraphicsError::LibraryMissing {
                name: "MoltenVK",
                tried: candidates.to_vec(),
            }))
        }

        /// The library this backend actually loaded.
        pub fn library(&self) -> &str {
            &self.path
        }

        /// Resolve a global or instance-level entry point through the ICD's
        /// own `vkGetInstanceProcAddr`.
        fn proc(&self, instance: VkInstance, name: &str) -> Result<PfnVoid, GraphicsError> {
            let c = CString::new(name).map_err(|_| GraphicsError::SymbolMissing {
                library: self.path.clone(),
                symbol: name.to_string(),
            })?;
            // SAFETY: `c` is NUL-terminated; a null instance is legal for the
            // global commands and required for them.
            let f = unsafe { (self.get_instance_proc_addr)(instance, c.as_ptr()) };
            f.ok_or_else(|| GraphicsError::SymbolMissing {
                library: self.path.clone(),
                symbol: name.to_string(),
            })
        }

        /// `vkEnumerateInstanceVersion` as `(major, minor, patch)` — what
        /// `winevulkan` code [`wine_abi::WINEVULKAN_ENUMERATE_INSTANCE_VERSION`]
        /// must fill in.
        ///
        /// A Vulkan 1.0 ICD does not export it; that is reported as version
        /// 1.0.0, matching what `winevulkan`'s PE half falls back to.
        pub fn instance_version(&self) -> Result<(u32, u32, u32), GraphicsError> {
            let Ok(f) = self.proc(std::ptr::null_mut(), "vkEnumerateInstanceVersion") else {
                return Ok(decode_vk_version(wine_abi::VK_API_VERSION_1_0));
            };
            // SAFETY: resolved under that exact name, whose signature is
            // `VkResult(uint32_t *)`; `v` is a live local.
            let f: PfnEnumerateInstanceVersion =
                unsafe { std::mem::transmute::<PfnVoid, PfnEnumerateInstanceVersion>(f) };
            let mut v: u32 = 0;
            // SAFETY: as above.
            let r = unsafe { f(&mut v) };
            if r != VK_SUCCESS {
                return Err(GraphicsError::Backend {
                    call: "vkEnumerateInstanceVersion",
                    code: r,
                });
            }
            Ok(decode_vk_version(v))
        }

        /// `vkEnumerateInstanceExtensionProperties(NULL, ..)` — the extension
        /// names `winevulkan` code
        /// [`wine_abi::WINEVULKAN_ENUMERATE_INSTANCE_EXTENSION_PROPERTIES`]
        /// reports, and the source of the per-extension flag bytes
        /// [`wine_abi::WINEVULKAN_INIT`] writes back through its third argument.
        pub fn instance_extensions(&self) -> Result<Vec<String>, GraphicsError> {
            let f = self.proc(std::ptr::null_mut(), "vkEnumerateInstanceExtensionProperties")?;
            // SAFETY: resolved under that exact name; its signature is
            // `VkResult(const char *, uint32_t *, VkExtensionProperties *)`.
            let f: PfnEnumerateInstanceExtensionProperties = unsafe {
                std::mem::transmute::<PfnVoid, PfnEnumerateInstanceExtensionProperties>(f)
            };

            let mut count: u32 = 0;
            // SAFETY: a null layer name asks for the implementation's own
            // extensions; a null property pointer asks only for the count.
            let r = unsafe { f(std::ptr::null(), &mut count, std::ptr::null_mut()) };
            if r != VK_SUCCESS {
                return Err(GraphicsError::Backend {
                    call: "vkEnumerateInstanceExtensionProperties",
                    code: r,
                });
            }
            let mut buf = vec![0u8; count as usize * VK_EXTENSION_PROPERTIES_SIZE];
            // SAFETY: `buf` holds exactly `count` `VkExtensionProperties`, and
            // `count` is passed by pointer as the array capacity.
            let r = unsafe { f(std::ptr::null(), &mut count, buf.as_mut_ptr()) };
            if r != VK_SUCCESS && r != VK_INCOMPLETE {
                return Err(GraphicsError::Backend {
                    call: "vkEnumerateInstanceExtensionProperties",
                    code: r,
                });
            }
            Ok(buf
                .chunks_exact(VK_EXTENSION_PROPERTIES_SIZE)
                .take(count as usize)
                .map(|c| fixed_cstr(&c[..256]))
                .collect())
        }

        /// Create the `VkInstance` `winevulkan` code
        /// [`wine_abi::WINEVULKAN_CREATE_INSTANCE`] hands back, enabling
        /// `VK_KHR_portability_enumeration` when the ICD offers it (MoltenVK
        /// hides its physical device without it).
        pub fn create_instance(&mut self) -> Result<(), GraphicsError> {
            if !self.instance.is_null() {
                return Ok(());
            }
            let portability = self
                .instance_extensions()
                .map(|e| e.iter().any(|x| x == VK_PORTABILITY_ENUMERATION_EXTENSION))
                .unwrap_or(false);

            let f = self.proc(std::ptr::null_mut(), "vkCreateInstance")?;
            // SAFETY: resolved under that exact name; its signature is
            // `VkResult(const VkInstanceCreateInfo *, const VkAllocationCallbacks *, VkInstance *)`.
            let create: PfnCreateInstance =
                unsafe { std::mem::transmute::<PfnVoid, PfnCreateInstance>(f) };

            let app_name = CString::new("exemu").expect("literal has no NUL");
            let ext_name =
                CString::new(VK_PORTABILITY_ENUMERATION_EXTENSION).expect("literal has no NUL");
            let ext_ptrs = [ext_name.as_ptr()];

            // VkApplicationInfo, laid out by hand (56 bytes) so no binding
            // crate is needed. Offsets are the Vulkan 1.x C ABI's.
            let mut app = [0u8; 56];
            write_u32(&mut app, 0, VK_STRUCTURE_TYPE_APPLICATION_INFO);
            write_ptr(&mut app, 16, app_name.as_ptr().cast());
            write_u32(&mut app, 48, wine_abi::VK_API_VERSION_1_0);

            // VkInstanceCreateInfo (64 bytes).
            let mut ci = [0u8; 64];
            write_u32(&mut ci, 0, VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO);
            if portability {
                write_u32(&mut ci, 16, VK_INSTANCE_CREATE_ENUMERATE_PORTABILITY_BIT_KHR);
            }
            write_ptr(&mut ci, 24, app.as_ptr().cast());
            if portability {
                write_u32(&mut ci, 48, 1);
                write_ptr(&mut ci, 56, ext_ptrs.as_ptr().cast());
            }

            let mut instance: VkInstance = std::ptr::null_mut();
            // SAFETY: `ci` and the structures it points at live across the
            // call; a null allocator is legal; `instance` is a live local.
            let r = unsafe { create(ci.as_ptr(), std::ptr::null(), &mut instance) };
            if r != VK_SUCCESS || instance.is_null() {
                return Err(GraphicsError::Backend { call: "vkCreateInstance", code: r });
            }
            self.instance = instance;
            if let Ok(f) = self.proc(instance, "vkDestroyInstance") {
                // SAFETY: resolved under that exact name; its signature is
                // `void(VkInstance, const VkAllocationCallbacks *)`.
                self.destroy_instance =
                    Some(unsafe { std::mem::transmute::<PfnVoid, PfnDestroyInstance>(f) });
            }
            Ok(())
        }

        /// The physical devices the ICD reports — `winevulkan` codes
        /// [`wine_abi::WINEVULKAN_ENUMERATE_PHYSICAL_DEVICES`] and
        /// [`wine_abi::WINEVULKAN_GET_PHYSICAL_DEVICE_PROPERTIES`].
        pub fn devices(&mut self) -> Result<Vec<VulkanDevice>, GraphicsError> {
            self.create_instance()?;
            let instance = self.instance;

            let f = self.proc(instance, "vkEnumeratePhysicalDevices")?;
            // SAFETY: resolved under that exact name; its signature is
            // `VkResult(VkInstance, uint32_t *, VkPhysicalDevice *)`.
            let enumerate: PfnEnumeratePhysicalDevices =
                unsafe { std::mem::transmute::<PfnVoid, PfnEnumeratePhysicalDevices>(f) };

            let mut count: u32 = 0;
            // SAFETY: a null array asks only for the count.
            let r = unsafe { enumerate(instance, &mut count, std::ptr::null_mut()) };
            if r != VK_SUCCESS {
                return Err(GraphicsError::Backend {
                    call: "vkEnumeratePhysicalDevices",
                    code: r,
                });
            }
            let mut handles: Vec<VkPhysicalDevice> = vec![std::ptr::null_mut(); count as usize];
            // SAFETY: `handles` has exactly `count` slots, which `count`
            // declares.
            let r = unsafe { enumerate(instance, &mut count, handles.as_mut_ptr()) };
            if r != VK_SUCCESS && r != VK_INCOMPLETE {
                return Err(GraphicsError::Backend {
                    call: "vkEnumeratePhysicalDevices",
                    code: r,
                });
            }
            handles.truncate(count as usize);

            let f = self.proc(instance, "vkGetPhysicalDeviceProperties")?;
            // SAFETY: resolved under that exact name; its signature is
            // `void(VkPhysicalDevice, VkPhysicalDeviceProperties *)`.
            let props: PfnGetPhysicalDeviceProperties =
                unsafe { std::mem::transmute::<PfnVoid, PfnGetPhysicalDeviceProperties>(f) };

            let mut out = Vec::with_capacity(handles.len());
            for dev in handles {
                let mut buf = vec![0u8; VK_PHYSICAL_DEVICE_PROPERTIES_SIZE];
                // SAFETY: `buf` is far larger than `VkPhysicalDeviceProperties`
                // in any published Vulkan version, so the driver's write fits.
                unsafe { props(dev, buf.as_mut_ptr()) };
                out.push(VulkanDevice {
                    api_version: decode_vk_version(read_u32(&buf, 0)),
                    vendor_id: read_u32(&buf, 8),
                    device_id: read_u32(&buf, 12),
                    device_type: read_u32(&buf, 16),
                    name: fixed_cstr(
                        &buf[VK_PHYSICAL_DEVICE_PROPERTIES_NAME_OFFSET
                            ..VK_PHYSICAL_DEVICE_PROPERTIES_NAME_OFFSET + 256],
                    ),
                });
            }
            Ok(out)
        }
    }

    impl Drop for VulkanBackend {
        fn drop(&mut self) {
            if let (Some(destroy), false) = (self.destroy_instance, self.instance.is_null()) {
                // SAFETY: `self.instance` came from `vkCreateInstance` and is
                // destroyed exactly once, with the null allocator it was made
                // with.
                unsafe { destroy(self.instance, std::ptr::null()) };
            }
        }
    }

    // -- small helpers -----------------------------------------------------

    /// Split a packed Vulkan version into `(major, minor, patch)`.
    pub fn decode_vk_version(v: u32) -> (u32, u32, u32) {
        (v >> 22, (v >> 12) & 0x3ff, v & 0xfff)
    }

    /// Read a NUL-padded fixed-size C char array (`deviceName`,
    /// `extensionName`) as a `String`.
    fn fixed_cstr(bytes: &[u8]) -> String {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    }

    fn write_u32(buf: &mut [u8], at: usize, v: u32) {
        buf[at..at + 4].copy_from_slice(&v.to_ne_bytes());
    }

    fn write_ptr(buf: &mut [u8], at: usize, v: *const c_void) {
        buf[at..at + 8].copy_from_slice(&(v as usize as u64).to_ne_bytes());
    }

    fn read_u32(buf: &[u8], at: usize) -> u32 {
        u32::from_ne_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
    }
}

#[cfg(target_os = "macos")]
pub use imp::{
    decode_vk_version, GlFrame, GlInfo, OpenGlBackend, Triangle, VulkanBackend, VulkanDevice,
};

// ---------------------------------------------------------------------------
// Non-macOS: the seam exists, and says so.
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "macos"))]
mod portable {
    use super::GraphicsError;

    /// Split a packed Vulkan version into `(major, minor, patch)`.
    pub fn decode_vk_version(v: u32) -> (u32, u32, u32) {
        (v >> 22, (v >> 12) & 0x3ff, v & 0xfff)
    }

    /// Placeholder for the CGL backend on non-macOS hosts.
    pub struct OpenGlBackend(());

    impl OpenGlBackend {
        /// Always [`GraphicsError::Unsupported`] — CGL is macOS-only.
        pub fn init() -> Result<OpenGlBackend, GraphicsError> {
            Err(GraphicsError::Unsupported { backend: "the CGL OpenGL backend" })
        }
    }

    /// Placeholder for the MoltenVK backend on non-macOS hosts.
    pub struct VulkanBackend(());

    impl VulkanBackend {
        /// Always [`GraphicsError::Unsupported`] — MoltenVK is macOS-only.
        pub fn init() -> Result<VulkanBackend, GraphicsError> {
            Err(GraphicsError::Unsupported { backend: "the MoltenVK Vulkan backend" })
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub use portable::{decode_vk_version, OpenGlBackend, VulkanBackend};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulkan_version_decodes_like_vk_make_version() {
        assert_eq!(decode_vk_version(wine_abi::VK_API_VERSION_1_0), (1, 0, 0));
        // VK_MAKE_API_VERSION(0, 1, 3, 280)
        assert_eq!(decode_vk_version((1 << 22) | (3 << 12) | 280), (1, 3, 280));
    }

    #[test]
    fn the_icd_search_order_prefers_a_loader_then_moltenvk() {
        let c = vulkan_library_candidates_from(None);
        let loader = c.iter().position(|p| p.contains("libvulkan")).expect("a loader is tried");
        let icd = c.iter().position(|p| p.contains("MoltenVK")).expect("MoltenVK is tried");
        assert!(loader < icd, "a Vulkan loader must be preferred over a bare ICD: {c:?}");
        assert!(
            c.iter().any(|p| p.starts_with("/opt/homebrew/")),
            "the Homebrew prefix must be searched: {c:?}"
        );
    }

    #[test]
    fn an_explicit_library_overrides_the_search() {
        assert_eq!(
            vulkan_library_candidates_from(Some("/tmp/exemu-fake-icd.dylib")),
            vec!["/tmp/exemu-fake-icd.dylib".to_string()]
        );
        // An empty override is ignored, not treated as "no candidates".
        assert_eq!(vulkan_library_candidates_from(Some("")), vulkan_library_candidates_from(None));
    }

    #[test]
    fn a_missing_library_formats_as_a_reported_failure_not_a_panic() {
        let e = GraphicsError::LibraryMissing {
            name: "MoltenVK",
            tried: vec!["/opt/homebrew/lib/libMoltenVK.dylib".into()],
        };
        assert_eq!(
            e.to_string(),
            "MoltenVK not found; tried: /opt/homebrew/lib/libMoltenVK.dylib"
        );
    }
}
