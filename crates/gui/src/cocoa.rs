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
use objc2_metal::{
    MTLBlitCommandEncoder, MTLCommandBuffer, MTLCommandEncoder, MTLCommandQueue,
    MTLCreateSystemDefaultDevice, MTLDevice, MTLOrigin, MTLPixelFormat, MTLRegion, MTLSize,
    MTLStorageMode, MTLTexture, MTLTextureDescriptor, MTLTextureUsage,
};
use objc2_quartz_core::{CALayer, CAMetalDrawable, CAMetalLayer};

use exemu_core::{InputEvent, MouseButton, UserDriver, WindowParams};

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
        // Deliver WM_MOUSEMOVE-worthy moves even when no button is down (W4.6).
        window.setAcceptsMouseMovedEvents(true);
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

    /// Update the window's title-bar text.
    pub fn set_title(&self, title: &str) {
        self.window.setTitle(&NSString::from_str(title));
    }

    /// Whether the window is still on screen. Becomes `false` once the user
    /// clicks the close button (the host turns that into a guest `WM_QUIT`).
    pub fn is_visible(&self) -> bool {
        self.window.isVisible()
    }

    /// Run the current thread's run loop for `seconds`, letting the window draw
    /// and process events.
    pub fn pump(&self, seconds: f64) {
        pump_runloop(seconds);
    }
}

/// Run the current thread's run loop for `seconds` (must be the main thread).
/// The single place the AppKit run loop is ticked — used by the `cocoa-demo`
/// runner and by [`run_live`]'s window host.
fn pump_runloop(seconds: f64) {
    let until = NSDate::dateWithTimeIntervalSinceNow(seconds);
    NSRunLoop::currentRunLoop().runUntilDate(&until);
}

/// Open a live window, blit `bgra` (top-down BGRA8, `stride = w*4`) into it, and
/// keep it on screen for `hold_secs`, re-presenting as the run loop ticks. The
/// manual "window appears" runner for W4.4 (`exemu cocoa-demo`).
///
/// Errors when there is no main thread / no Metal device (headless), so the CLI
/// prints a clean message instead of silently doing nothing.
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

// ============================ native input tap (W4.6) =======================

/// The client-area point (top-left origin, pixels) of a mouse `NSEvent`, mapping
/// AppKit's bottom-left window coordinates into the guest's top-down space. `None`
/// when the event has no window (e.g. a system event).
fn event_client_pos(event: &NSEvent, mtm: MainThreadMarker) -> Option<(i32, i32)> {
    let win = event.window(mtm)?;
    let view = win.contentView()?;
    let loc = event.locationInWindow();
    let p = view.convertPoint_fromView(loc, None);
    let bounds = view.bounds();
    let x = p.x.round() as i32;
    let y = (bounds.size.height - p.y).round() as i32; // flip bottom-left → top-left
    Some((x, y))
}

/// The Windows virtual-key code for a key `NSEvent`, or `None` for a key exemu
/// does not map. Alphanumerics derive from the character (VK_A..VK_Z = 0x41..0x5A,
/// VK_0..VK_9 = 0x30..0x39 == the uppercase ASCII code); control/navigation keys
/// come from the macOS virtual keycode. Unmapped keys are dropped rather than
/// delivered with a wrong code.
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
        0x24 => 0x0D, // Return   → VK_RETURN
        0x30 => 0x09, // Tab      → VK_TAB
        0x31 => 0x20, // Space    → VK_SPACE
        0x33 => 0x08, // Delete   → VK_BACK
        0x35 => 0x1B, // Escape   → VK_ESCAPE
        0x7B => 0x25, // Left     → VK_LEFT
        0x7C => 0x27, // Right    → VK_RIGHT
        0x7D => 0x28, // Down     → VK_DOWN
        0x7E => 0x26, // Up       → VK_UP
        _ => return None,
    };
    Some(vk)
}

/// Translate one native `NSEvent` into the [`InputEvent`] the guest pump expects,
/// or `None` for events exemu does not forward (window drags, system events, …).
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

/// Pump native `NSEvent`s for up to `seconds`: block for the first event, then
/// drain the rest without blocking. Each is translated and forwarded to the guest
/// over `input_tx` (so its `NtUserGetMessage` wakes and its WndProc sees the
/// input) and then handed to AppKit via `sendEvent` so the window keeps its normal
/// behaviour (dragging, the close button, key focus). This *is* the run-loop tick
/// for the live host — it replaces a bare `runUntilDate` so no event slips past
/// the tap. Off the main thread (no `NSApplication`) it falls back to a plain
/// run-loop pump. (roadmap W4.6)
fn pump_events(input_tx: &Sender<InputEvent>, seconds: f64) {
    let Some(mtm) = MainThreadMarker::new() else {
        pump_runloop(seconds);
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    // Block up to `seconds` for the first event; poll (distantPast) thereafter.
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

// ============================ main → window host ============================

/// The main-thread consumer of [`WindowCommand`]s: it owns one [`CocoaWindow`]
/// per guest HWND and applies each command as it arrives. **Main-thread only**
/// (holds `CocoaWindow`s). This is the receiving half of the W4.5 split; the
/// interpreter thread produces commands via [`CocoaPresenter::with_channel`].
#[derive(Default)]
pub struct WindowHost {
    windows: HashMap<u32, CocoaWindow>,
}

impl WindowHost {
    /// A host owning no windows yet.
    pub fn new() -> Self {
        WindowHost::default()
    }

    /// True once every window has been destroyed (nothing left to keep alive).
    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }

    /// Ensure a window exists for `hwnd`, opening one of `w × h` if not.
    fn ensure(&mut self, hwnd: u32, w: u32, h: u32, title: &str) {
        if let std::collections::hash_map::Entry::Vacant(slot) = self.windows.entry(hwnd) {
            if let Some(win) = CocoaWindow::open(w.max(1), h.max(1), title) {
                slot.insert(win);
            }
        }
    }

    /// Apply one command to the live windows.
    pub fn apply(&mut self, cmd: WindowCommand) {
        match cmd {
            WindowCommand::Create { hwnd, w, h, ref title, .. } => self.ensure(hwnd, w, h, title),
            WindowCommand::SetTitle { hwnd, ref title } => {
                if let Some(win) = self.windows.get(&hwnd) {
                    win.set_title(title);
                }
            }
            // The window is ordered front on open; explicit resize/reposition is
            // W4.7. Show/Pos are accepted and inert for now.
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

    /// Drop any window the user has closed, sending a [`InputEvent::Close`] to
    /// the guest for each so its message pump can quit. Called each host tick.
    pub fn reap_closed(&mut self, input_tx: &Sender<InputEvent>) {
        let closed: Vec<u32> =
            self.windows.iter().filter(|(_, w)| !w.is_visible()).map(|(h, _)| *h).collect();
        for hwnd in closed {
            self.windows.remove(&hwnd);
            let _ = input_tx.send(InputEvent::Close);
        }
    }
}

/// The main-thread window host loop (roadmap W4.5). Drain `cmd_rx`, applying
/// each [`WindowCommand`] to native windows, tick the AppKit run loop between
/// polls, and forward window-close back to the guest over `input_tx` (so a
/// blocking `NtUserGetMessage` wakes and the guest quits). Returns once the
/// command sender is dropped — the interpreter thread finished — after showing
/// any surviving window for up to `linger_secs`.
///
/// A live GUI guest blocks in its message loop until its window is closed, so
/// this loop runs for the lifetime of the on-screen window. Set
/// `EXEMU_COCOA_MAX_MS` to auto-close after that many milliseconds — a safety
/// valve for headless/CI runs where no one clicks the close button.
///
/// MUST be called on the main thread; `CocoaWindow::open` yields `None`
/// otherwise and the host quietly draws nothing.
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
            Err(TryRecvError::Disconnected) => break, // the guest exited
        }
    }
    // The guest has exited; keep its window(s) visible briefly.
    let linger_start = std::time::Instant::now();
    while !host.is_empty() && linger_start.elapsed().as_secs_f64() < linger_secs {
        pump_runloop(0.02);
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

// ============================ interp → main channel =========================

/// A window-lifecycle command sent from the interpreter thread (where the
/// win32k handlers run) to the main thread (which owns AppKit). This is the
/// `Send` half of the W4.5 split: [`CocoaPresenter`] emits these as a guest
/// drives windows; the main-thread window host (W4.5b) applies them to
/// [`CocoaWindow`]s. Every variant is plain data — no AppKit/Metal handle
/// crosses the channel.
#[derive(Debug, Clone)]
pub enum WindowCommand {
    /// A top-level window was created at `(x, y)` with a `w × h` window rect.
    Create { hwnd: u32, x: i32, y: i32, w: u32, h: u32, title: String },
    /// The window's title bar text changed.
    SetTitle { hwnd: u32, title: String },
    /// `ShowWindow(hwnd, cmd)` — `cmd` is the `SW_*` constant.
    Show { hwnd: u32, cmd: i32 },
    /// The window moved/resized to `rect` = `[x, y, cx, cy]`.
    Pos { hwnd: u32, rect: [i32; 4] },
    /// Present one top-down BGRA8 frame (`stride = w*4`) — fire-and-forget.
    Present { hwnd: u32, w: u32, h: u32, bgra: Vec<u8> },
    /// The window was destroyed; the host should drop its `CocoaWindow`.
    Destroy { hwnd: u32 },
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
    /// When set (the live W4.5 path), window-lifecycle calls are forwarded to
    /// the main-thread window host as [`WindowCommand`]s instead of, or in
    /// addition to, the headless PNG/last-frame behaviour.
    tx: Option<Sender<WindowCommand>>,
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
        CocoaPresenter { dir, frame_count: 0, last: HashMap::new(), tx: None }
    }

    /// Build a presenter that forwards every window-lifecycle event to a
    /// main-thread window host over `tx` (the W4.5 live path). No PNGs are
    /// written; the last RGBA frame is still retained for inspection.
    pub fn with_channel(tx: Sender<WindowCommand>) -> Self {
        CocoaPresenter { dir: None, frame_count: 0, last: HashMap::new(), tx: Some(tx) }
    }

    /// Total frames flushed across all HWNDs.
    pub fn frame_count(&self) -> u64 {
        self.frame_count
    }

    /// The last presented frame for `hwnd` as `(rgba, w, h)`, if any.
    pub fn last_rgba(&self, hwnd: u32) -> Option<(&[u8], u32, u32)> {
        self.last.get(&hwnd).map(|f| (f.rgba.as_slice(), f.w, f.h))
    }

    /// Forward a command to the main-thread host, ignoring a dropped receiver
    /// (the window host having gone away just means "nothing to draw to").
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

/// Adapt a [`CocoaPresenter`] to a full [`UserDriver`]. Headless (no channel):
/// only the surface half matters — `flush_surface` writes a PNG / retains the
/// frame. Live (with a channel): every window-lifecycle call is forwarded to
/// the main-thread host as a [`WindowCommand`].
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
            // Live path: hand the pixels to the main thread; fire-and-forget.
            self.frame_count += 1;
            self.send(WindowCommand::Present { hwnd, w, h, bgra: pixels.to_vec() });
            self.last.insert(hwnd, Frame { w, h, rgba: bgra_to_rgba(pixels) });
        } else {
            // Headless: Presenter::flush writes the PNG and bumps frame_count.
            <Self as Presenter>::flush(self, hwnd, pixels, w, h);
        }
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
        p.show_window(7, 5); // SW_SHOW
        p.window_pos_changed(7, [120, 130, 480, 260]);
        let (bgra, w, h) = test_frame();
        p.flush_surface(7, &bgra, w, h);
        p.destroy_window(7);

        // The live path still retains the last frame (as RGBA) for inspection.
        assert_eq!(p.last_rgba(7).unwrap().0, bgra_to_rgba(&bgra).as_slice());
        drop(p); // close the sender so the receiver iterator terminates

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
                // A BGRA8Unorm texture round-trips the surface bit-for-bit…
                assert_eq!(rt, bgra, "BGRA8Unorm MTLTexture upload/readback is lossless");
                // …so the pixels a live CocoaWindow shows equal the offscreen PNG.
                assert_eq!(bgra_to_rgba(&rt), bgra_to_rgba(&bgra));
            }
        }
    }
}
