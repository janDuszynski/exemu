use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::Sender;

use core::ffi::c_void;
use core::ptr::NonNull;

use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{MainThreadMarker, MainThreadOnly};

use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSBackingStoreType, NSEvent, NSEventMask,
    NSEventType, NSView, NSWindow, NSWindowStyleMask,
};
use objc2_foundation::{NSDate, NSDefaultRunLoopMode, NSPoint, NSRect, NSRunLoop, NSSize, NSString};
use objc2_core_foundation::{CFString, CGPoint, CGSize};
use objc2_core_graphics::{CGBitmapContextCreate, CGBitmapContextGetData, CGColorSpace, CGContext};
use objc2_core_text::{CTFont, CTFontOrientation};
use objc2_metal::{
    MTLBlitCommandEncoder, MTLCommandBuffer, MTLCommandEncoder, MTLCommandQueue,
    MTLCreateSystemDefaultDevice, MTLDevice, MTLOrigin, MTLPixelFormat, MTLRegion, MTLSize,
    MTLStorageMode, MTLTexture, MTLTextureDescriptor, MTLTextureUsage,
};
use objc2_quartz_core::{CALayer, CAMetalDrawable, CAMetalLayer};

use exemu_core::{InputEvent, MouseButton, TextBitmap, UserDriver, WindowParams};

use crate::{bgra_to_rgba, Presenter};

fn full_region(w: u32, h: u32) -> MTLRegion {
    MTLRegion {
        origin: MTLOrigin { x: 0, y: 0, z: 0 },
        size: MTLSize { width: w as usize, height: h as usize, depth: 1 },
    }
}

pub struct CocoaWindow {
    _app: Retained<NSApplication>,
    window: Retained<NSWindow>,
    layer: Retained<CAMetalLayer>,
    device: Retained<ProtocolObject<dyn MTLDevice>>,
    queue: Retained<ProtocolObject<dyn MTLCommandQueue>>,
}

impl CocoaWindow {
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
        layer.setFramebufferOnly(false);
        layer.setDrawableSize(NSSize::new(w as f64, h as f64));
        let ca: &CALayer = &layer;
        view.setLayer(Some(ca));

        window.setContentView(Some(&view));
        window.setTitle(&NSString::from_str(title));
        window.setAcceptsMouseMovedEvents(true);
        window.center();
        window.makeKeyAndOrderFront(None);
        app.activate();

        Some(CocoaWindow { _app: app, window, layer, device, queue })
    }

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

    pub fn window(&self) -> &NSWindow {
        &self.window
    }

    pub fn set_title(&self, title: &str) {
        self.window.setTitle(&NSString::from_str(title));
    }

    pub fn is_visible(&self) -> bool {
        self.window.isVisible()
    }

    pub fn pump(&self, seconds: f64) {
        pump_runloop(seconds);
    }
}

fn pump_runloop(seconds: f64) {
    let until = NSDate::dateWithTimeIntervalSinceNow(seconds);
    NSRunLoop::currentRunLoop().runUntilDate(&until);
}

pub fn run_demo(w: u32, h: u32, title: &str, bgra: &[u8], hold_secs: f64) -> Result<(), String> {
    let mut win = CocoaWindow::open(w, h, title)
        .ok_or("cannot open a Cocoa window (not the main thread, or no Metal device)")?;
    let start = std::time::Instant::now();
    while start.elapsed().as_secs_f64() < hold_secs.max(0.1) {
        win.present(bgra, w, h);
        win.pump(0.05);
    }
    Ok(())
}

fn event_client_pos(event: &NSEvent, mtm: MainThreadMarker) -> Option<(i32, i32)> {
    let win = event.window(mtm)?;
    let view = win.contentView()?;
    let loc = event.locationInWindow();
    let p = view.convertPoint_fromView(loc, None);
    let bounds = view.bounds();
    let x = p.x.round() as i32;
    let y = (bounds.size.height - p.y).round() as i32;
    Some((x, y))
}

fn event_vk(event: &NSEvent) -> Option<u32> {
    if let Some(s) = event.charactersIgnoringModifiers() {
        if let Some(c) = s.to_string().chars().next() {
            let up = c.to_ascii_uppercase();
            if up.is_ascii_alphanumeric() {
                return Some(up as u32);
            }
        }
    }
    let vk = match event.keyCode() {
        0x24 => 0x0D,
        0x30 => 0x09,
        0x31 => 0x20,
        0x33 => 0x08,
        0x35 => 0x1B,
        0x7B => 0x25,
        0x7C => 0x27,
        0x7D => 0x28,
        0x7E => 0x26,
        _ => return None,
    };
    Some(vk)
}

fn translate_event(event: &NSEvent, mtm: MainThreadMarker) -> Option<InputEvent> {
    let mouse = |button, down| {
        event_client_pos(event, mtm).map(|(x, y)| InputEvent::MouseButton { button, down, x, y })
    };
    match event.r#type() {
        NSEventType::LeftMouseDown => mouse(MouseButton::Left, true),
        NSEventType::LeftMouseUp => mouse(MouseButton::Left, false),
        NSEventType::RightMouseDown => mouse(MouseButton::Right, true),
        NSEventType::RightMouseUp => mouse(MouseButton::Right, false),
        NSEventType::MouseMoved | NSEventType::LeftMouseDragged | NSEventType::RightMouseDragged => {
            event_client_pos(event, mtm).map(|(x, y)| InputEvent::MouseMove { x, y })
        }
        NSEventType::KeyDown => event_vk(event).map(|vk| InputEvent::Key { vk, down: true }),
        NSEventType::KeyUp => event_vk(event).map(|vk| InputEvent::Key { vk, down: false }),
        _ => None,
    }
}

fn pump_events(input_tx: &Sender<InputEvent>, seconds: f64) {
    let Some(mtm) = MainThreadMarker::new() else {
        pump_runloop(seconds);
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    let mut until = NSDate::dateWithTimeIntervalSinceNow(seconds);
    loop {
        let event = unsafe {
            app.nextEventMatchingMask_untilDate_inMode_dequeue(
                NSEventMask::Any,
                Some(&until),
                NSDefaultRunLoopMode,
                true,
            )
        };
        let Some(event) = event else { break };
        if let Some(ev) = translate_event(&event, mtm) {
            let _ = input_tx.send(ev);
        }
        app.sendEvent(&event);
        until = NSDate::distantPast();
    }
}

#[derive(Default)]
pub struct WindowHost {
    windows: HashMap<u32, CocoaWindow>,
}

impl WindowHost {
    pub fn new() -> Self {
        WindowHost::default()
    }

    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }

    fn ensure(&mut self, hwnd: u32, w: u32, h: u32, title: &str) {
        if let std::collections::hash_map::Entry::Vacant(slot) = self.windows.entry(hwnd) {
            if let Some(win) = CocoaWindow::open(w.max(1), h.max(1), title) {
                slot.insert(win);
            }
        }
    }

    pub fn apply(&mut self, cmd: WindowCommand) {
        match cmd {
            WindowCommand::Create { hwnd, w, h, ref title, .. } => self.ensure(hwnd, w, h, title),
            WindowCommand::SetTitle { hwnd, ref title } => {
                if let Some(win) = self.windows.get(&hwnd) {
                    win.set_title(title);
                }
            }
            WindowCommand::Show { .. } | WindowCommand::Pos { .. } => {}
            WindowCommand::Present { hwnd, w, h, bgra } => {
                self.ensure(hwnd, w, h, "exemu");
                if let Some(win) = self.windows.get_mut(&hwnd) {
                    win.present(&bgra, w, h);
                }
            }
            WindowCommand::Destroy { hwnd } => {
                self.windows.remove(&hwnd);
            }
        }
    }

    pub fn reap_closed(&mut self, input_tx: &Sender<InputEvent>) {
        let closed: Vec<u32> =
            self.windows.iter().filter(|(_, w)| !w.is_visible()).map(|(h, _)| *h).collect();
        for hwnd in closed {
            self.windows.remove(&hwnd);
            let _ = input_tx.send(InputEvent::Close);
        }
    }
}

pub fn run_live(
    cmd_rx: std::sync::mpsc::Receiver<WindowCommand>,
    input_tx: Sender<InputEvent>,
    linger_secs: f64,
) {
    use std::sync::mpsc::TryRecvError;

    let auto_close_ms: Option<u128> =
        std::env::var("EXEMU_COCOA_MAX_MS").ok().and_then(|s| s.parse().ok());
    let start = std::time::Instant::now();
    let mut auto_close_sent = false;

    let mut host = WindowHost::new();
    loop {
        match cmd_rx.try_recv() {
            Ok(cmd) => host.apply(cmd),
            Err(TryRecvError::Empty) => {
                pump_events(&input_tx, 0.01);
                host.reap_closed(&input_tx);
                if let Some(ms) = auto_close_ms {
                    if !auto_close_sent && start.elapsed().as_millis() >= ms {
                        let _ = input_tx.send(InputEvent::Close);
                        auto_close_sent = true;
                    }
                }
            }
            Err(TryRecvError::Disconnected) => break,
        }
    }
    let linger_start = std::time::Instant::now();
    while !host.is_empty() && linger_start.elapsed().as_secs_f64() < linger_secs {
        pump_runloop(0.02);
    }
}

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

#[derive(Debug, Clone)]
pub enum WindowCommand {
    Create { hwnd: u32, x: i32, y: i32, w: u32, h: u32, title: String },
    SetTitle { hwnd: u32, title: String },
    Show { hwnd: u32, cmd: i32 },
    Pos { hwnd: u32, rect: [i32; 4] },
    Present { hwnd: u32, w: u32, h: u32, bgra: Vec<u8> },
    Destroy { hwnd: u32 },
}

struct Frame {
    w: u32,
    h: u32,
    rgba: Vec<u8>,
}

pub struct CocoaPresenter {
    dir: Option<PathBuf>,
    frame_count: u64,
    last: HashMap<u32, Frame>,
    tx: Option<Sender<WindowCommand>>,
}

impl CocoaPresenter {
    pub fn with_dir(dir: Option<impl Into<PathBuf>>) -> Self {
        let dir = dir.map(|d| {
            let p = d.into();
            let _ = std::fs::create_dir_all(&p);
            p
        });
        CocoaPresenter { dir, frame_count: 0, last: HashMap::new(), tx: None }
    }

    pub fn with_channel(tx: Sender<WindowCommand>) -> Self {
        CocoaPresenter { dir: None, frame_count: 0, last: HashMap::new(), tx: Some(tx) }
    }

    pub fn frame_count(&self) -> u64 {
        self.frame_count
    }

    pub fn last_rgba(&self, hwnd: u32) -> Option<(&[u8], u32, u32)> {
        self.last.get(&hwnd).map(|f| (f.rgba.as_slice(), f.w, f.h))
    }

    fn send(&self, cmd: WindowCommand) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(cmd);
        }
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

impl UserDriver for CocoaPresenter {
    fn create_window(&mut self, hwnd: u32, params: &WindowParams) {
        self.send(WindowCommand::Create {
            hwnd,
            x: params.x,
            y: params.y,
            w: params.cx.max(0) as u32,
            h: params.cy.max(0) as u32,
            title: params.title.clone(),
        });
    }

    fn destroy_window(&mut self, hwnd: u32) {
        self.send(WindowCommand::Destroy { hwnd });
    }

    fn window_pos_changed(&mut self, hwnd: u32, rect: [i32; 4]) {
        self.send(WindowCommand::Pos { hwnd, rect });
    }

    fn show_window(&mut self, hwnd: u32, cmd: i32) {
        self.send(WindowCommand::Show { hwnd, cmd });
    }

    fn set_window_text(&mut self, hwnd: u32, text: &str) {
        self.send(WindowCommand::SetTitle { hwnd, title: text.to_string() });
    }

    fn flush_surface(&mut self, hwnd: u32, pixels: &[u8], w: u32, h: u32) {
        if self.tx.is_some() {
            self.frame_count += 1;
            self.send(WindowCommand::Present { hwnd, w, h, bgra: pixels.to_vec() });
            self.last.insert(hwnd, Frame { w, h, rgba: bgra_to_rgba(pixels) });
        } else {
            <Self as Presenter>::flush(self, hwnd, pixels, w, h);
        }
    }

    fn rasterize_text(&self, text: &str, px: u32) -> Option<TextBitmap> {
        coretext_rasterize(text, px)
    }
}

fn coretext_rasterize(text: &str, px: u32) -> Option<TextBitmap> {
    if text.is_empty() || px == 0 {
        return None;
    }
    let utf16: Vec<u16> = text.encode_utf16().collect();
    let n = utf16.len();

    let name = CFString::from_static_str("Helvetica");
    let font = unsafe { CTFont::with_name(&name, px as f64, std::ptr::null()) };

    let mut glyphs = vec![0u16; n];
    unsafe {
        font.glyphs_for_characters(
            NonNull::new(utf16.as_ptr() as *mut u16)?,
            NonNull::new(glyphs.as_mut_ptr())?,
            n as isize,
        );
    }

    let mut advances = vec![CGSize { width: 0.0, height: 0.0 }; n];
    unsafe {
        font.advances_for_glyphs(
            CTFontOrientation::Default,
            NonNull::new(glyphs.as_mut_ptr())?,
            advances.as_mut_ptr(),
            n as isize,
        );
    }
    let ascent = unsafe { font.ascent() };
    let descent = unsafe { font.descent() };
    let total_w: f64 = advances.iter().map(|a| a.width).sum();
    let width = (total_w.ceil() as usize).max(1);
    let height = ((ascent + descent).ceil() as usize).max(1);

    let space = CGColorSpace::new_device_gray()?;
    let ctx = unsafe {
        CGBitmapContextCreate(std::ptr::null_mut(), width, height, 8, width, Some(&space), 0)
    }?;

    let mut positions = Vec::with_capacity(n);
    let mut pen = 0.0f64;
    for a in &advances {
        positions.push(CGPoint { x: pen, y: descent });
        pen += a.width;
    }

    CGContext::set_gray_fill_color(Some(&ctx), 1.0, 1.0);
    unsafe {
        font.draw_glyphs(
            NonNull::new(glyphs.as_mut_ptr())?,
            NonNull::new(positions.as_mut_ptr())?,
            n,
            &ctx,
        );
    }

    let data = CGBitmapContextGetData(Some(&ctx)) as *const u8;
    if data.is_null() {
        return None;
    }
    let coverage = unsafe { std::slice::from_raw_parts(data, width * height) }.to_vec();
    Some(TextBitmap { width: width as u32, height: height as u32, coverage })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OffscreenPresenter;

    #[test]
    fn coretext_rasterizes_a_run_to_coverage() {
        let tb = coretext_rasterize("Hi!", 16).expect("CoreText rasterizes on macOS");
        assert!(tb.width >= 8 && tb.width <= 200, "plausible run width: {}", tb.width);
        assert!(tb.height >= 8 && tb.height <= 64, "plausible cell height: {}", tb.height);
        assert_eq!(tb.coverage.len(), (tb.width * tb.height) as usize);
        let covered = tb.coverage.iter().filter(|&&a| a > 0).count();
        assert!(covered > 0, "the glyphs cover some pixels ({covered})");
        assert!(
            tb.coverage.iter().any(|&a| a > 0 && a < 255),
            "CoreText anti-aliases glyph edges"
        );
        assert!(coretext_rasterize("", 16).is_none());
        assert!(coretext_rasterize("x", 0).is_none());
    }

    fn test_frame() -> (Vec<u8>, u32, u32) {
        #[rustfmt::skip]
        let px = vec![
            255, 0,   0,   255,
            0,   0,   255, 255,
            0,   255, 0,   255,
            60,  60,  60,  255,
        ];
        (px, 2, 2)
    }

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

        assert_eq!(
            only_png(&cdir),
            only_png(&odir),
            "CocoaPresenter and OffscreenPresenter must write byte-identical PNGs"
        );
        assert_eq!(cocoa.last_rgba(1).unwrap().0, bgra_to_rgba(&bgra).as_slice());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn channel_presenter_emits_the_window_command_stream() {
        use crate::UserDriver;
        use exemu_core::WindowParams;

        let (tx, rx) = std::sync::mpsc::channel();
        let mut p = CocoaPresenter::with_channel(tx);

        let params = WindowParams {
            class_atom: 0xC001,
            class_name: String::new(),
            title: "hello".into(),
            x: 120,
            y: 130,
            cx: 480,
            cy: 260,
            style: 0,
            ex_style: 0,
            parent: 0,
        };
        p.create_window(7, &params);
        p.set_window_text(7, "world");
        p.show_window(7, 5);
        p.window_pos_changed(7, [120, 130, 480, 260]);
        let (bgra, w, h) = test_frame();
        p.flush_surface(7, &bgra, w, h);
        p.destroy_window(7);

        assert_eq!(p.last_rgba(7).unwrap().0, bgra_to_rgba(&bgra).as_slice());
        drop(p);

        let cmds: Vec<_> = rx.iter().collect();
        assert!(matches!(
            cmds[0],
            WindowCommand::Create { hwnd: 7, x: 120, y: 130, w: 480, h: 260, .. }
        ));
        assert!(matches!(&cmds[1], WindowCommand::SetTitle { hwnd: 7, title } if title == "world"));
        assert!(matches!(cmds[2], WindowCommand::Show { hwnd: 7, cmd: 5 }));
        assert!(matches!(cmds[3], WindowCommand::Pos { hwnd: 7, rect: [120, 130, 480, 260] }));
        match &cmds[4] {
            WindowCommand::Present { hwnd: 7, w: 2, h: 2, bgra } => assert_eq!(bgra, &test_frame().0),
            other => panic!("expected Present, got {other:?}"),
        }
        assert!(matches!(cmds[5], WindowCommand::Destroy { hwnd: 7 }));
        assert_eq!(cmds.len(), 6);
    }

    #[test]
    fn metal_roundtrip_is_lossless_or_skips() {
        let (bgra, w, h) = test_frame();
        match metal_bgra_roundtrip(&bgra, w, h) {
            None => eprintln!("SKIP: MTLCreateSystemDefaultDevice returned None (headless/no GPU)"),
            Some(rt) => {
                assert_eq!(rt, bgra, "BGRA8Unorm MTLTexture upload/readback is lossless");
                assert_eq!(bgra_to_rgba(&rt), bgra_to_rgba(&bgra));
            }
        }
    }
}
