#![allow(clippy::missing_safety_doc)]

use std::fmt;

pub mod wine_abi {

    pub const OPENGL32_UNIX_CALL_COUNT: u32 = 3102;

    pub const OPENGL32_UNUSED_SLOT: u32 = 3088;

    pub const OPENGL32_PROCESS_ATTACH: u32 = 0;

    pub const OPENGL32_THREAD_ATTACH: u32 = 1;

    pub const OPENGL32_PROCESS_DETACH: u32 = 2;

    pub const OPENGL32_GET_PIXEL_FORMATS: u32 = 3;

    pub const OPENGL32_WGL_COPY_CONTEXT: u32 = 4;
    pub const OPENGL32_WGL_CREATE_CONTEXT: u32 = 5;
    pub const OPENGL32_WGL_DELETE_CONTEXT: u32 = 6;
    pub const OPENGL32_WGL_GET_PIXEL_FORMAT: u32 = 7;
    pub const OPENGL32_WGL_GET_PROC_ADDRESS: u32 = 8;
    pub const OPENGL32_WGL_MAKE_CURRENT: u32 = 9;
    pub const OPENGL32_WGL_SET_PIXEL_FORMAT: u32 = 10;
    pub const OPENGL32_WGL_SHARE_LISTS: u32 = 11;
    pub const OPENGL32_WGL_SWAP_BUFFERS: u32 = 12;

    pub const OPENGL32_GL_CLEAR: u32 = 23;
    pub const OPENGL32_GL_CLEAR_COLOR: u32 = 25;
    pub const OPENGL32_GL_GET_STRING: u32 = 130;
    pub const OPENGL32_GL_READ_PIXELS: u32 = 250;
    pub const OPENGL32_GL_VIEWPORT: u32 = 348;

    pub const WGL_PIXEL_FORMAT_SIZE: usize = 0x8c;

    pub const TEB_GL_HDC: usize = 0x1148;
    pub const TEB_GL_FORMATS: usize = 0x1150;
    pub const TEB_GL_NUM_FORMATS: usize = 0x1158;
    pub const TEB_GL_NUM_ONSCREEN_FORMATS: usize = 0x1160;

    pub const WINEVULKAN_UNIX_CALL_COUNT: u32 = 674;

    pub const WINEVULKAN_INIT: u32 = 0;

    pub const WINEVULKAN_GET_INSTANCE_PROC_ADDR: u32 = 1;
    pub const WINEVULKAN_GET_DEVICE_PROC_ADDR: u32 = 2;
    pub const WINEVULKAN_CREATE_INSTANCE: u32 = 343;
    pub const WINEVULKAN_DESTROY_INSTANCE: u32 = 398;
    pub const WINEVULKAN_ENUMERATE_INSTANCE_EXTENSION_PROPERTIES: u32 = 426;
    pub const WINEVULKAN_ENUMERATE_INSTANCE_VERSION: u32 = 427;
    pub const WINEVULKAN_ENUMERATE_PHYSICAL_DEVICES: u32 = 432;
    pub const WINEVULKAN_GET_PHYSICAL_DEVICE_PROPERTIES: u32 = 548;

    pub const WINEVULKAN_INIT_PARAMS_SIZE: usize = 24;

    pub const VK_API_VERSION_1_0: u32 = 0x0040_0000;

    pub const UNIXLIB_BOOTSTRAP_IMPORTS: [&str; 3] =
        ["NtQueryVirtualMemory", "LdrGetDllHandle", "RtlFindExportedRoutineByName"];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphicsError {
    Unsupported {
        backend: &'static str,
    },
    LibraryMissing {
        name: &'static str,
        tried: Vec<String>,
    },
    SymbolMissing {
        library: String,
        symbol: String,
    },
    Backend {
        call: &'static str,
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

pub const VULKAN_LIBRARY_ENV: &str = "EXEMU_VULKAN_LIBRARY";

pub fn vulkan_library_candidates() -> Vec<String> {
    let explicit = std::env::var_os(VULKAN_LIBRARY_ENV).map(|v| v.to_string_lossy().into_owned());
    vulkan_library_candidates_from(explicit.as_deref())
}

pub fn vulkan_library_candidates_from(explicit: Option<&str>) -> Vec<String> {
    if let Some(explicit) = explicit {
        if !explicit.is_empty() {
            return vec![explicit.to_string()];
        }
    }
    let mut out: Vec<String> = Vec::new();
    for dir in ["/usr/local/lib", "/opt/homebrew/lib"] {
        out.push(format!("{dir}/libvulkan.1.dylib"));
        out.push(format!("{dir}/libvulkan.dylib"));
    }
    for dir in ["/usr/local/lib", "/opt/homebrew/lib"] {
        out.push(format!("{dir}/libMoltenVK.dylib"));
    }
    out.push(
        "/usr/local/share/vulkan/icd.d/../../../lib/libMoltenVK.dylib".to_string(),
    );
    out.push("libvulkan.1.dylib".to_string());
    out.push("libMoltenVK.dylib".to_string());
    out
}

#[cfg(target_os = "macos")]
mod imp {
    use super::wine_abi;
    use super::{vulkan_library_candidates, GraphicsError};
    use std::ffi::{c_char, c_int, c_void, CStr, CString};

    extern "C" {
        fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
        fn dlclose(handle: *mut c_void) -> c_int;
    }

    const RTLD_NOW: c_int = 0x2;
    const RTLD_LOCAL: c_int = 0x4;

    struct Library {
        handle: *mut c_void,
        path: String,
    }

    impl Library {
        fn open(path: &str) -> Option<Library> {
            let c = CString::new(path).ok()?;
            let handle = unsafe { dlopen(c.as_ptr(), RTLD_NOW | RTLD_LOCAL) };
            if handle.is_null() {
                None
            } else {
                Some(Library { handle, path: path.to_string() })
            }
        }

        fn sym(&self, name: &str) -> Result<*mut c_void, GraphicsError> {
            let c = CString::new(name).map_err(|_| GraphicsError::SymbolMissing {
                library: self.path.clone(),
                symbol: name.to_string(),
            })?;
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
            unsafe { dlclose(self.handle) };
        }
    }

    unsafe fn cstr(p: *const c_char) -> String {
        if p.is_null() {
            String::new()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }

    const OPENGL_FRAMEWORK: &str = "/System/Library/Frameworks/OpenGL.framework/OpenGL";

    const K_CGL_PFA_COLOR_SIZE: i32 = 8;
    const K_CGL_PFA_ALPHA_SIZE: i32 = 11;
    const K_CGL_PFA_DEPTH_SIZE: i32 = 12;
    const K_CGL_PFA_OPENGL_PROFILE: i32 = 99;
    const K_CGL_OGLP_VERSION_LEGACY: i32 = 0x1000;

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

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GlInfo {
        pub version: String,
        pub renderer: String,
        pub vendor: String,
        pub extensions: Vec<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct Triangle {
        pub verts: [[f32; 2]; 3],
        pub color: [f32; 3],
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GlFrame {
        pub width: u32,
        pub height: u32,
        pub bgra: Vec<u8>,
    }

    pub struct OpenGlBackend {
        ctx: CglObj,
        pixel_format: CglObj,
        info: GlInfo,
        gl: Gl,
        _lib: Library,
    }

    impl OpenGlBackend {
        pub fn init() -> Result<OpenGlBackend, GraphicsError> {
            let lib = Library::open(OPENGL_FRAMEWORK).ok_or_else(|| {
                GraphicsError::LibraryMissing {
                    name: "OpenGL.framework",
                    tried: vec![OPENGL_FRAMEWORK.to_string()],
                }
            })?;

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
            let err = unsafe {
                (gl.CGLChoosePixelFormat)(attribs.as_ptr(), &mut pixel_format, &mut n)
            };
            if err != 0 || pixel_format.is_null() {
                return Err(GraphicsError::Backend { call: "CGLChoosePixelFormat", code: err });
            }

            let mut ctx: CglObj = std::ptr::null_mut();
            let err =
                unsafe { (gl.CGLCreateContext)(pixel_format, std::ptr::null_mut(), &mut ctx) };
            if err != 0 || ctx.is_null() {
                unsafe { (gl.CGLDestroyPixelFormat)(pixel_format) };
                return Err(GraphicsError::Backend { call: "CGLCreateContext", code: err });
            }

            let err = unsafe { (gl.CGLSetCurrentContext)(ctx) };
            if err != 0 {
                unsafe {
                    (gl.CGLDestroyContext)(ctx);
                    (gl.CGLDestroyPixelFormat)(pixel_format);
                }
                return Err(GraphicsError::Backend { call: "CGLSetCurrentContext", code: err });
            }

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

        pub fn info(&self) -> &GlInfo {
            &self.info
        }

        pub fn make_current(&self) -> Result<(), GraphicsError> {
            let err = unsafe { (self.gl.CGLSetCurrentContext)(self.ctx) };
            if err == 0 {
                Ok(())
            } else {
                Err(GraphicsError::Backend { call: "CGLSetCurrentContext", code: err })
            }
        }

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

            unsafe {
                (gl.glBindFramebufferEXT)(GL_FRAMEBUFFER_EXT, 0);
                (gl.glDeleteRenderbuffersEXT)(1, &depth);
                (gl.glDeleteRenderbuffersEXT)(1, &color);
                (gl.glDeleteFramebuffersEXT)(1, &fbo);
            }

            if gl_err != GL_NO_ERROR {
                return Err(GraphicsError::Backend { call: "glReadPixels", code: gl_err as i32 });
            }

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
            unsafe {
                (self.gl.CGLSetCurrentContext)(std::ptr::null_mut());
                (self.gl.CGLDestroyContext)(self.ctx);
                (self.gl.CGLDestroyPixelFormat)(self.pixel_format);
            }
        }
    }

    const VK_SUCCESS: i32 = 0;
    const VK_INCOMPLETE: i32 = 5;
    const VK_STRUCTURE_TYPE_APPLICATION_INFO: u32 = 0;
    const VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO: u32 = 1;
    const VK_INSTANCE_CREATE_ENUMERATE_PORTABILITY_BIT_KHR: u32 = 0x0000_0001;
    const VK_PORTABILITY_ENUMERATION_EXTENSION: &str = "VK_KHR_portability_enumeration";
    const VK_EXTENSION_PROPERTIES_SIZE: usize = 260;
    const VK_PHYSICAL_DEVICE_PROPERTIES_NAME_OFFSET: usize = 20;
    const VK_PHYSICAL_DEVICE_PROPERTIES_SIZE: usize = 2048;

    type VkInstance = *mut c_void;
    type VkPhysicalDevice = *mut c_void;
    type PfnVoid = unsafe extern "C" fn();

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

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct VulkanDevice {
        pub name: String,
        pub api_version: (u32, u32, u32),
        pub vendor_id: u32,
        pub device_id: u32,
        pub device_type: u32,
    }

    pub struct VulkanBackend {
        get_instance_proc_addr: PfnGetInstanceProcAddr,
        instance: VkInstance,
        destroy_instance: Option<PfnDestroyInstance>,
        path: String,
        _lib: Library,
    }

    impl VulkanBackend {
        pub fn init() -> Result<VulkanBackend, GraphicsError> {
            Self::load(&vulkan_library_candidates())
        }

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

        pub fn library(&self) -> &str {
            &self.path
        }

        fn proc(&self, instance: VkInstance, name: &str) -> Result<PfnVoid, GraphicsError> {
            let c = CString::new(name).map_err(|_| GraphicsError::SymbolMissing {
                library: self.path.clone(),
                symbol: name.to_string(),
            })?;
            let f = unsafe { (self.get_instance_proc_addr)(instance, c.as_ptr()) };
            f.ok_or_else(|| GraphicsError::SymbolMissing {
                library: self.path.clone(),
                symbol: name.to_string(),
            })
        }

        pub fn instance_version(&self) -> Result<(u32, u32, u32), GraphicsError> {
            let Ok(f) = self.proc(std::ptr::null_mut(), "vkEnumerateInstanceVersion") else {
                return Ok(decode_vk_version(wine_abi::VK_API_VERSION_1_0));
            };
            let f: PfnEnumerateInstanceVersion =
                unsafe { std::mem::transmute::<PfnVoid, PfnEnumerateInstanceVersion>(f) };
            let mut v: u32 = 0;
            let r = unsafe { f(&mut v) };
            if r != VK_SUCCESS {
                return Err(GraphicsError::Backend {
                    call: "vkEnumerateInstanceVersion",
                    code: r,
                });
            }
            Ok(decode_vk_version(v))
        }

        pub fn instance_extensions(&self) -> Result<Vec<String>, GraphicsError> {
            let f = self.proc(std::ptr::null_mut(), "vkEnumerateInstanceExtensionProperties")?;
            let f: PfnEnumerateInstanceExtensionProperties = unsafe {
                std::mem::transmute::<PfnVoid, PfnEnumerateInstanceExtensionProperties>(f)
            };

            let mut count: u32 = 0;
            let r = unsafe { f(std::ptr::null(), &mut count, std::ptr::null_mut()) };
            if r != VK_SUCCESS {
                return Err(GraphicsError::Backend {
                    call: "vkEnumerateInstanceExtensionProperties",
                    code: r,
                });
            }
            let mut buf = vec![0u8; count as usize * VK_EXTENSION_PROPERTIES_SIZE];
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

        pub fn create_instance(&mut self) -> Result<(), GraphicsError> {
            if !self.instance.is_null() {
                return Ok(());
            }
            let portability = self
                .instance_extensions()
                .map(|e| e.iter().any(|x| x == VK_PORTABILITY_ENUMERATION_EXTENSION))
                .unwrap_or(false);

            let f = self.proc(std::ptr::null_mut(), "vkCreateInstance")?;
            let create: PfnCreateInstance =
                unsafe { std::mem::transmute::<PfnVoid, PfnCreateInstance>(f) };

            let app_name = CString::new("exemu").expect("literal has no NUL");
            let ext_name =
                CString::new(VK_PORTABILITY_ENUMERATION_EXTENSION).expect("literal has no NUL");
            let ext_ptrs = [ext_name.as_ptr()];

            let mut app = [0u8; 56];
            write_u32(&mut app, 0, VK_STRUCTURE_TYPE_APPLICATION_INFO);
            write_ptr(&mut app, 16, app_name.as_ptr().cast());
            write_u32(&mut app, 48, wine_abi::VK_API_VERSION_1_0);

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
            let r = unsafe { create(ci.as_ptr(), std::ptr::null(), &mut instance) };
            if r != VK_SUCCESS || instance.is_null() {
                return Err(GraphicsError::Backend { call: "vkCreateInstance", code: r });
            }
            self.instance = instance;
            if let Ok(f) = self.proc(instance, "vkDestroyInstance") {
                self.destroy_instance =
                    Some(unsafe { std::mem::transmute::<PfnVoid, PfnDestroyInstance>(f) });
            }
            Ok(())
        }

        pub fn devices(&mut self) -> Result<Vec<VulkanDevice>, GraphicsError> {
            self.create_instance()?;
            let instance = self.instance;

            let f = self.proc(instance, "vkEnumeratePhysicalDevices")?;
            let enumerate: PfnEnumeratePhysicalDevices =
                unsafe { std::mem::transmute::<PfnVoid, PfnEnumeratePhysicalDevices>(f) };

            let mut count: u32 = 0;
            let r = unsafe { enumerate(instance, &mut count, std::ptr::null_mut()) };
            if r != VK_SUCCESS {
                return Err(GraphicsError::Backend {
                    call: "vkEnumeratePhysicalDevices",
                    code: r,
                });
            }
            let mut handles: Vec<VkPhysicalDevice> = vec![std::ptr::null_mut(); count as usize];
            let r = unsafe { enumerate(instance, &mut count, handles.as_mut_ptr()) };
            if r != VK_SUCCESS && r != VK_INCOMPLETE {
                return Err(GraphicsError::Backend {
                    call: "vkEnumeratePhysicalDevices",
                    code: r,
                });
            }
            handles.truncate(count as usize);

            let f = self.proc(instance, "vkGetPhysicalDeviceProperties")?;
            let props: PfnGetPhysicalDeviceProperties =
                unsafe { std::mem::transmute::<PfnVoid, PfnGetPhysicalDeviceProperties>(f) };

            let mut out = Vec::with_capacity(handles.len());
            for dev in handles {
                let mut buf = vec![0u8; VK_PHYSICAL_DEVICE_PROPERTIES_SIZE];
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
                unsafe { destroy(self.instance, std::ptr::null()) };
            }
        }
    }

    pub fn decode_vk_version(v: u32) -> (u32, u32, u32) {
        (v >> 22, (v >> 12) & 0x3ff, v & 0xfff)
    }

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

#[cfg(not(target_os = "macos"))]
mod portable {
    use super::GraphicsError;

    pub fn decode_vk_version(v: u32) -> (u32, u32, u32) {
        (v >> 22, (v >> 12) & 0x3ff, v & 0xfff)
    }

    pub struct OpenGlBackend(());

    impl OpenGlBackend {
        pub fn init() -> Result<OpenGlBackend, GraphicsError> {
            Err(GraphicsError::Unsupported { backend: "the CGL OpenGL backend" })
        }
    }

    pub struct VulkanBackend(());

    impl VulkanBackend {
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
