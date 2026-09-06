use exemu_gui::graphics::{GraphicsError, OpenGlBackend, Triangle, VulkanBackend};
use exemu_gui::{OffscreenPresenter, Presenter};

fn gl() -> Option<OpenGlBackend> {
    match OpenGlBackend::init() {
        Ok(b) => Some(b),
        Err(e @ GraphicsError::LibraryMissing { .. }) | Err(e @ GraphicsError::Backend { .. }) => {
            eprintln!("[skip] no host OpenGL context: {e}");
            None
        }
        Err(e) => panic!("OpenGlBackend::init failed unexpectedly: {e}"),
    }
}

fn px(frame: &[u8], w: u32, x: u32, y: u32) -> (u8, u8, u8, u8) {
    let i = ((y * w + x) * 4) as usize;
    (frame[i], frame[i + 1], frame[i + 2], frame[i + 3])
}

#[test]
fn the_opengl_driver_init_yields_a_context_that_answers_from_the_host() {
    let Some(backend) = gl() else { return };
    let info = backend.info();
    eprintln!(
        "[gl] GL_VERSION={:?} GL_RENDERER={:?} GL_VENDOR={:?} ({} extensions)",
        info.version,
        info.renderer,
        info.vendor,
        info.extensions.len()
    );

    assert!(
        info.version.starts_with(|c: char| c.is_ascii_digit()),
        "GL_VERSION must start with the version number, got {:?}",
        info.version
    );
    assert!(!info.renderer.is_empty(), "GL_RENDERER must name the host renderer");
    assert!(!info.vendor.is_empty(), "GL_VENDOR must name the host vendor");

    assert!(
        info.extensions.len() > 20,
        "a real driver publishes an extension list, got {}",
        info.extensions.len()
    );
    assert!(
        info.extensions.iter().any(|e| e == "GL_EXT_framebuffer_object"),
        "the FBO extension this backend renders through must be present"
    );
}

#[test]
fn opengl_renders_a_cleared_surface_and_a_triangle_into_a_bgra_frame() {
    let Some(mut backend) = gl() else { return };
    const W: u32 = 320;
    const H: u32 = 240;

    let clear = [0.0f32, 0.0, 1.0, 1.0];
    let tri =
        Triangle { verts: [[-0.6, -0.6], [0.6, -0.6], [0.0, 0.6]], color: [1.0, 0.0, 0.0] };

    let frame = match backend.draw_frame(W, H, clear, Some(tri)) {
        Ok(f) => f,
        Err(e @ GraphicsError::Backend { .. }) => {
            eprintln!("[skip] host GL cannot render offscreen: {e}");
            return;
        }
        Err(e) => panic!("draw_frame failed: {e}"),
    };

    assert_eq!(frame.width, W);
    assert_eq!(frame.height, H);
    assert_eq!(frame.bgra.len(), (W * H * 4) as usize, "top-down BGRA32, stride = w*4");

    for (x, y) in [(0, 0), (W - 1, 0), (0, H - 1), (W - 1, H - 1)] {
        assert_eq!(
            px(&frame.bgra, W, x, y),
            (255, 0, 0, 255),
            "({x},{y}) must be the opaque blue clear colour in BGRA order"
        );
    }

    assert_eq!(
        px(&frame.bgra, W, W / 2, H / 2),
        (0, 0, 255, 255),
        "the triangle interior must be opaque red in BGRA order"
    );

    let (b, g, r, _) = px(&frame.bgra, W, 0, 0);
    assert!(b == 255 && g == 0 && r == 0, "blue must live in byte 0 (BGRA), not byte 2");

    let dir = std::env::temp_dir().join(format!("exemu-w73-gl-{}", std::process::id()));
    let mut presenter = OffscreenPresenter::with_dir(Some(dir.clone()));
    presenter.flush(1, &frame.bgra, W, H);
    assert_eq!(presenter.frame_count(), 1);
    let png = dir.join("hwnd00000001-frame0001.png");
    let written = std::fs::metadata(&png).unwrap_or_else(|e| panic!("{}: {e}", png.display()));
    assert!(written.len() > 0, "the GL frame must reach a PNG snapshot");
    eprintln!("[gl] wrote {} ({} bytes)", png.display(), written.len());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn opengl_frames_are_reproducible_across_calls() {
    let Some(mut backend) = gl() else { return };
    let clear = [0.25f32, 0.5, 0.75, 1.0];
    let a = match backend.draw_frame(64, 48, clear, None) {
        Ok(f) => f,
        Err(e @ GraphicsError::Backend { .. }) => {
            eprintln!("[skip] host GL cannot render offscreen: {e}");
            return;
        }
        Err(e) => panic!("draw_frame failed: {e}"),
    };
    let b = backend.draw_frame(64, 48, clear, None).expect("second frame");
    assert_eq!(a, b, "the backend must be stateless between frames");

    assert_eq!(px(&a.bgra, 64, 10, 10), (191, 128, 64, 255));
}

#[test]
fn vulkan_either_answers_from_a_real_icd_or_fails_cleanly_by_name() {
    match VulkanBackend::init() {
        Ok(backend) => {
            eprintln!("[vk] loaded {}", backend.library());
            let version = backend.instance_version().expect("instance version");
            eprintln!("[vk] instance version {}.{}.{}", version.0, version.1, version.2);
            assert!(version.0 >= 1, "a Vulkan ICD reports at least 1.x, got {version:?}");

            let exts = backend.instance_extensions().expect("instance extensions");
            eprintln!("[vk] {} instance extensions", exts.len());
            assert!(!exts.is_empty(), "a real ICD publishes instance extensions");
            assert!(
                exts.iter().any(|e| e == "VK_KHR_surface"),
                "VK_KHR_surface is mandatory for any presentable ICD: {exts:?}"
            );

            let mut backend = backend;
            match backend.devices() {
                Ok(devs) => {
                    eprintln!("[vk] devices: {devs:?}");
                    assert!(!devs.is_empty(), "an ICD that loads must expose a device");
                    assert!(devs.iter().all(|d| !d.name.is_empty()), "every device is named");
                }
                Err(e) => panic!("device enumeration failed against a live ICD: {e}"),
            }
        }
        Err(GraphicsError::LibraryMissing { name, tried }) => {
            let e = GraphicsError::LibraryMissing { name, tried: tried.clone() };
            eprintln!("[skip] no Vulkan ICD on this host: {e}");
            assert!(
                tried.iter().any(|p| p.contains("MoltenVK")),
                "the failure must name MoltenVK among the paths tried: {tried:?}"
            );
            assert!(
                e.to_string().contains("not found; tried:"),
                "the failure must report what it looked for, got {e}"
            );
        }
        Err(e) => panic!("Vulkan init failed in an unexpected way: {e}"),
    }
}

#[test]
fn a_library_that_is_not_an_icd_is_reported_as_a_missing_symbol() {
    let probe = "/usr/lib/libSystem.B.dylib".to_string();
    if !std::path::Path::new("/usr/lib/dyld").exists() {
        eprintln!("[skip] not a macOS dyld host");
        return;
    }
    match VulkanBackend::load(std::slice::from_ref(&probe)) {
        Err(GraphicsError::SymbolMissing { library, symbol }) => {
            assert_eq!(library, probe);
            assert_eq!(symbol, "vkGetInstanceProcAddr");
        }
        Err(e) => panic!("expected a missing-symbol report, got {e}"),
        Ok(_) => panic!("libSystem must not pass as a Vulkan ICD"),
    }
}

#[test]
fn a_path_that_does_not_exist_is_reported_as_a_missing_library() {
    let probe = "/nonexistent/exemu-no-such-icd.dylib".to_string();
    match VulkanBackend::load(std::slice::from_ref(&probe)) {
        Err(GraphicsError::LibraryMissing { tried, .. }) => assert_eq!(tried, vec![probe]),
        Err(e) => panic!("expected a missing-library report, got {e}"),
        Ok(_) => panic!("a nonexistent path must not load"),
    }
}
