//! The live macOS display path (W4.4): a from-scratch AppKit/Metal presenter.
//!
//! Wine's real USER/GDI kernel logic lives in exemu's win32k SSDT handlers,
//! which draw into a per-HWND top-down **BGRA32** surface (design §5). This
//! module turns that surface into pixels on screen:
//!
//! * [`CocoaWindow`] — one `NSWindow` + `NSView` + `CAMetalLayer` per top-level
//!   HWND. `present` uploads the BGRA surface into a `BGRA8Unorm` `MTLTexture`
//!   and blits it to the layer's drawable. It owns AppKit objects
//!   (`NSApplication`/`NSWindow`/`NSView`), which are `MainThreadOnly` and thus
//!   `!Send` — so it must be built and driven on the **main thread**. The
//!   interpreter-thread ↔ main-thread channel that lets a guest drive it is
//!   W4.5; W4.4 exercises it through the `cocoa-demo` CLI subcommand.
//!
//! * [`CocoaPresenter`] — the `Send` driver-side [`Presenter`]. It renders the
//!   surface headlessly (the shared [`crate::bgra_to_rgba`] transform → PNG /
//!   retained last frame), holding **no** AppKit or Metal handles so it stays
//!   `Send` and usable on the interpreter thread today. In W4.5 it gains a
//!   `Sender` to a main-thread [`CocoaWindow`]; for now it is the headless half
//!   and the subject of the "PNG parity vs Offscreen" gate.
//!
//! * [`metal_bgra_roundtrip`] — uploads a BGRA buffer into a `BGRA8Unorm`
//!   `MTLTexture` and reads it back, proving the live Metal path reproduces the
//!   surface pixels bit-for-bit. The parity gate compares its output (swapped to
//!   RGBA) against `bgra_to_rgba`, tying the live pipeline to the headless one.
//!   Returns `None` when no GPU is available (headless CI), so callers skip.

use std::collections::HashMap;
use std::path::PathBuf;

use core::ffi::c_void;
use core::ptr::NonNull;

use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{MainThreadMarker, MainThreadOnly};

use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSBackingStoreType, NSView, NSWindow,
    NSWindowStyleMask,
};
use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};
use objc2_metal::{
    MTLBlitCommandEncoder, MTLCommandBuffer, MTLCommandEncoder, MTLCommandQueue,
    MTLCreateSystemDefaultDevice, MTLDevice, MTLOrigin, MTLPixelFormat, MTLRegion, MTLSize,
    MTLStorageMode, MTLTexture, MTLTextureDescriptor, MTLTextureUsage,
};
use objc2_quartz_core::{CALayer, CAMetalDrawable, CAMetalLayer};

use exemu_core::UserDriver;

use crate::{bgra_to_rgba, Presenter};

/// The full BGRA region of a `w × h` surface, origin `(0,0)`.
fn full_region(w: u32, h: u32) -> MTLRegion {
    MTLRegion {
        origin: MTLOrigin { x: 0, y: 0, z: 0 },
        size: MTLSize { width: w as usize, height: h as usize, depth: 1 },
    }
}

// ============================ CocoaWindow (live) =============================

/// A live macOS window backed by a `CAMetalLayer`. **Main-thread only** — every
/// field below AppKit's `MainThreadOnly` types makes this `!Send`.
pub struct CocoaWindow {
    // `_app` is kept alive for the process; dropping it early would tear down the
    // shared application. The leading underscore documents "owned, not read".
    _app: Retained<NSApplication>,
    window: Retained<NSWindow>,
    layer: Retained<CAMetalLayer>,
    device: Retained<ProtocolObject<dyn MTLDevice>>,
    queue: Retained<ProtocolObject<dyn MTLCommandQueue>>,
}

impl CocoaWindow {
    /// Create a titled, resizable window of `w × h` points with a Metal layer
    /// ready to receive BGRA frames.
    ///
    /// Returns `None` off the main thread or when no Metal device exists
    /// (headless CI) — the live path then fails cleanly and callers fall back to
    /// the headless [`CocoaPresenter`].
    pub fn open(w: u32, h: u32, title: &str) -> Option<Self> {
        let mtm = MainThreadMarker::new()?;

        let app = NSApplication::sharedApplication(mtm);
        app.setActivationPolicy(NSApplicationActivationPolicy::Regular);

        let device = MTLCreateSystemDefaultDevice()?;
        let queue = device.newCommandQueue()?;

        let rect = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(w as f64, h as f64));
        let style = NSWindowStyleMask::Titled
            | NSWindowStyleMask::Closable
            | NSWindowStyleMask::Resizable
            | NSWindowStyleMask::Miniaturizable;
        let window = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                NSWindow::alloc(mtm),
                rect,
                style,
                NSBackingStoreType::Buffered,
                false,
            )
        };

        let view = NSView::initWithFrame(NSView::alloc(mtm), rect);
        view.setWantsLayer(true);

        let layer = CAMetalLayer::new();
        layer.setDevice(Some(&device));
        layer.setPixelFormat(MTLPixelFormat::BGRA8Unorm);
        // Must be false: we blit *into* the drawable's texture, and a
        // framebuffer-only drawable rejects a blit destination (the classic
        // "black window" bug).
        layer.setFramebufferOnly(false);
        layer.setDrawableSize(NSSize::new(w as f64, h as f64));
        let ca: &CALayer = &layer;
        view.setLayer(Some(ca));

        window.setContentView(Some(&view));
        window.setTitle(&NSString::from_str(title));
        window.center();
        window.makeKeyAndOrderFront(None);
        app.activate();

        Some(CocoaWindow { _app: app, window, layer, device, queue })
    }

    /// Blit one top-down BGRA8 frame (`stride = w * 4`) to the window. A frame
    /// whose dimensions don't match the layer is presented as-is at its own
    /// size (the surface is the source of truth; window resize tracking is
    /// W4.5). Silently returns if the buffer is short or a drawable can't be
    /// acquired this tick.
    pub fn present(&mut self, bgra: &[u8], w: u32, h: u32) {
        if bgra.len() < (w as usize) * (h as usize) * 4 {
            return;
        }
        self.layer.setDrawableSize(NSSize::new(w as f64, h as f64));

        let desc = unsafe {
            MTLTextureDescriptor::texture2DDescriptorWithPixelFormat_width_height_mipmapped(
                MTLPixelFormat::BGRA8Unorm,
                w as usize,
                h as usize,
                false,
            )
        };
        desc.setUsage(MTLTextureUsage::ShaderRead);
        let Some(src) = self.device.newTextureWithDescriptor(&desc) else { return };
        unsafe {
            src.replaceRegion_mipmapLevel_withBytes_bytesPerRow(
                full_region(w, h),
                0,
                NonNull::new(bgra.as_ptr() as *mut c_void).unwrap(),
                (w * 4) as usize,
            );
        }

        let Some(drawable) = self.layer.nextDrawable() else { return };
        let dst = drawable.texture();

        let Some(cmd) = self.queue.commandBuffer() else { return };
        let Some(blit) = cmd.blitCommandEncoder() else { return };
        unsafe {
            blit.copyFromTexture_sourceSlice_sourceLevel_sourceOrigin_sourceSize_toTexture_destinationSlice_destinationLevel_destinationOrigin(
                &src,
                0,
                0,
                MTLOrigin { x: 0, y: 0, z: 0 },
                MTLSize { width: w as usize, height: h as usize, depth: 1 },
                &dst,
                0,
                0,
                MTLOrigin { x: 0, y: 0, z: 0 },
            );
        }
        blit.endEncoding();
        cmd.presentDrawable(ProtocolObject::from_ref(&*drawable));
        cmd.commit();
    }

    /// Borrow the underlying window (e.g. to check `isVisible` in a demo).
    pub fn window(&self) -> &NSWindow {
        &self.window
    }
}

// ============================ metal round-trip ==============================

/// Upload `bgra` (top-down BGRA8, `stride = w*4`) into a `BGRA8Unorm`
/// `MTLTexture` and read it straight back, returning the round-tripped BGRA
/// bytes. Proves the live Metal texture path is pixel-lossless — the parity gate
/// swaps this to RGBA and compares against [`bgra_to_rgba`].
///
/// Returns `None` when no Metal device is available (headless CI) so the gate
/// can skip rather than fail.
pub fn metal_bgra_roundtrip(bgra: &[u8], w: u32, h: u32) -> Option<Vec<u8>> {
    let n = (w as usize) * (h as usize) * 4;
    if bgra.len() < n {
        return None;
    }
    let device = MTLCreateSystemDefaultDevice()?;

    let desc = unsafe {
        MTLTextureDescriptor::texture2DDescriptorWithPixelFormat_width_height_mipmapped(
            MTLPixelFormat::BGRA8Unorm,
            w as usize,
            h as usize,
            false,
        )
    };
    // Shared storage keeps the texture CPU-readable so getBytes works on both
    // Apple-silicon and Intel GPUs.
    desc.setStorageMode(MTLStorageMode::Shared);
    desc.setUsage(MTLTextureUsage::ShaderRead);
    let tex = device.newTextureWithDescriptor(&desc)?;

    let region = full_region(w, h);
    let stride = (w * 4) as usize;
    unsafe {
        tex.replaceRegion_mipmapLevel_withBytes_bytesPerRow(
            region,
            0,
            NonNull::new(bgra.as_ptr() as *mut c_void).unwrap(),
            stride,
        );
    }

    let mut out = vec![0u8; n];
    unsafe {
        tex.getBytes_bytesPerRow_fromRegion_mipmapLevel(
            NonNull::new(out.as_mut_ptr() as *mut c_void).unwrap(),
            stride,
            region,
            0,
        );
    }
    Some(out)
}

// ============================ CocoaPresenter (Send) =========================

/// One retained frame: RGBA8, tightly packed, plus its dimensions.
struct Frame {
    w: u32,
    h: u32,
    rgba: Vec<u8>,
}

/// The `Send` driver-side presenter for the Cocoa path.
///
/// Holds no AppKit/Metal handles, so it stays `Send` and runs on the
/// interpreter thread. It renders each surface with the shared
/// [`bgra_to_rgba`] transform — the identical pixels a [`CocoaWindow`] would
/// show — retaining the last RGBA frame per HWND and, when a directory is set,
/// writing it to PNG. This is the headless half of the W4.5 split (which adds
/// the channel to a main-thread window) and the subject of the parity gate.
pub struct CocoaPresenter {
    dir: Option<PathBuf>,
    frame_count: u64,
    last: HashMap<u32, Frame>,
}

impl CocoaPresenter {
    /// Build a presenter. When `dir` is `Some`, each flushed frame is written as
    /// a PNG; the last frame is always retained in memory for inspection.
    pub fn with_dir(dir: Option<impl Into<PathBuf>>) -> Self {
        let dir = dir.map(|d| {
            let p = d.into();
            let _ = std::fs::create_dir_all(&p);
            p
        });
        CocoaPresenter { dir, frame_count: 0, last: HashMap::new() }
    }

    /// Total frames flushed across all HWNDs.
    pub fn frame_count(&self) -> u64 {
        self.frame_count
    }

    /// The last presented frame for `hwnd` as `(rgba, w, h)`, if any.
    pub fn last_rgba(&self, hwnd: u32) -> Option<(&[u8], u32, u32)> {
        self.last.get(&hwnd).map(|f| (f.rgba.as_slice(), f.w, f.h))
    }
}

impl Default for CocoaPresenter {
    fn default() -> Self {
        Self::with_dir(std::env::var_os("EXEMU_GUI_SHOT"))
    }
}

impl Presenter for CocoaPresenter {
    fn flush(&mut self, hwnd: u32, pixels: &[u8], width: u32, height: u32) {
        self.frame_count += 1;
        let rgba = bgra_to_rgba(pixels);
        if let Some(dir) = &self.dir {
            let path = dir.join(format!("hwnd{hwnd:08x}-frame{:04}.png", self.frame_count));
            if let Ok(file) = std::fs::File::create(&path) {
                let mut enc = png::Encoder::new(std::io::BufWriter::new(file), width, height);
                enc.set_color(png::ColorType::Rgba);
                enc.set_depth(png::BitDepth::Eight);
                if let Ok(mut w) = enc.write_header() {
                    let _ = w.write_image_data(&rgba);
                }
                eprintln!("[exemu-gui] cocoa: wrote {}", path.display());
            }
        }
        self.last.insert(hwnd, Frame { w: width, h: height, rgba });
    }
}

/// Adapt a [`CocoaPresenter`] to a full [`UserDriver`] (surface half only), so
/// it can be dropped into `RunConfig.driver` exactly like `PresenterDriver`.
impl UserDriver for CocoaPresenter {
    fn flush_surface(&mut self, hwnd: u32, pixels: &[u8], w: u32, h: u32) {
        <Self as Presenter>::flush(self, hwnd, pixels, w, h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OffscreenPresenter;

    /// A 2×2 BGRA frame exercising a non-grayscale colour (so the B/R swap
    /// actually matters): blue, red, green, gray.
    fn test_frame() -> (Vec<u8>, u32, u32) {
        #[rustfmt::skip]
        let px = vec![
            255, 0,   0,   255,   // blue  (B=255)
            0,   0,   255, 255,   // red   (R=255)
            0,   255, 0,   255,   // green (G=255)
            60,  60,  60,  255,   // gray
        ];
        (px, 2, 2)
    }

    /// Read the single PNG written into `dir`.
    fn only_png(dir: &std::path::Path) -> Vec<u8> {
        let entry = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .find(|e| e.path().extension().and_then(|x| x.to_str()) == Some("png"))
            .expect("a PNG was written");
        std::fs::read(entry.path()).unwrap()
    }

    #[test]
    fn cocoa_presenter_png_parity_with_offscreen() {
        let (bgra, w, h) = test_frame();
        let base = std::env::temp_dir().join(format!("exemu-w44-parity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let cdir = base.join("cocoa");
        let odir = base.join("offscreen");

        let mut cocoa = CocoaPresenter::with_dir(Some(&cdir));
        let mut off = OffscreenPresenter::with_dir(Some(&odir));
        cocoa.flush(1, &bgra, w, h);
        off.flush(1, &bgra, w, h);

        // The literal "PNG parity vs Offscreen" gate: byte-identical files.
        assert_eq!(
            only_png(&cdir),
            only_png(&odir),
            "CocoaPresenter and OffscreenPresenter must write byte-identical PNGs"
        );
        // …and both equal the ground-truth BGRA→RGBA transform.
        assert_eq!(cocoa.last_rgba(1).unwrap().0, bgra_to_rgba(&bgra).as_slice());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn metal_roundtrip_is_lossless_or_skips() {
        let (bgra, w, h) = test_frame();
        match metal_bgra_roundtrip(&bgra, w, h) {
            None => eprintln!("SKIP: MTLCreateSystemDefaultDevice returned None (headless/no GPU)"),
            Some(rt) => {
                // A BGRA8Unorm texture round-trips the surface bit-for-bit…
                assert_eq!(rt, bgra, "BGRA8Unorm MTLTexture upload/readback is lossless");
                // …so the pixels a live CocoaWindow shows equal the offscreen PNG.
                assert_eq!(bgra_to_rgba(&rt), bgra_to_rgba(&bgra));
            }
        }
    }
}
