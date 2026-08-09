//! W7.1 — **a socket exchange through Wine's `ws2_32.dll` as guest code**.
//!
//! The proof binary ([`exemu_app::socket_sample`]) statically imports
//! `ws2_32!WSAStartup`/`socket`/`connect`/`send`/`recv`/`closesocket`/
//! `WSACleanup`, so under the Wine boot the loader must map, relocate, bind and
//! `DllMain` **Wine's own ws2_32.dll** before the entry point runs. Every socket
//! call is then Wine's guest code, which reaches exemu only through the NT
//! surface recovered in `afd_abi.rs`: `NtOpenFile` on `\Device\Afd` and
//! `NtDeviceIoControlFile`.
//!
//! Two things make the result attributable to that path and nothing else:
//!
//! 1. **exemu has no Winsock of any kind, native or emulated.** On the emulated
//!    path every `ws2_32` import is an unimplemented thunk returning 0, so
//!    `socket()` hands back a zero SOCKET and nothing is sent or received. That
//!    is the control below, and it is what gives the Wine result its meaning.
//! 2. **The peer is a real loopback listener this test creates**, on an
//!    ephemeral port, and it asserts on the bytes it received. So the payload
//!    provably left the guest, crossed the host network stack, and came back —
//!    it cannot have been synthesised anywhere in between.
//!
//! **Hermetic.** The listener binds `127.0.0.1:0`; nothing outside the machine
//! is contacted and the test passes offline. The port is only known after the
//! bind, which is why the sample is generated *per run* with the port baked in.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::mpsc;

use exemu_app::{load_and_run, socket_sample, RunConfig};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

/// What the guest sends, and what the listener answers with. Both are printable
/// so they can be asserted straight out of stdout, and long enough that a stub
/// echoing a header could not produce them.
const REQUEST: &[u8] = b"exemu W7.1: this request left the guest through Wine's ws2_32";
const REPLY: &[u8] = b"and this reply came back through exemu's AFD backend";

/// Read a `LABEL=` line out of the sample's stdout.
fn line<'a>(stdout: &'a str, label: &str) -> &'a str {
    stdout
        .lines()
        .find(|l| l.starts_with(label))
        .unwrap_or_else(|| panic!("no {label:?} line in:\n{stdout}"))
        .split_at(label.len())
        .1
}

/// A loopback echo-ish peer on an ephemeral port: accept one connection, read
/// exactly [`REQUEST`], answer [`REPLY`], and report what it saw.
struct Peer {
    port: u16,
    saw: mpsc::Receiver<std::io::Result<Vec<u8>>>,
    join: std::thread::JoinHandle<()>,
}

impl Peer {
    fn start() -> Peer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback listener");
        let port = listener.local_addr().unwrap().port();
        let (tx, saw) = mpsc::channel();
        let join = std::thread::spawn(move || {
            let result = (|| -> std::io::Result<Vec<u8>> {
                let (mut s, _) = listener.accept()?;
                let mut got = vec![0u8; REQUEST.len()];
                s.read_exact(&mut got)?;
                s.write_all(REPLY)?;
                s.flush()?;
                // Hold the connection until the guest has read the reply; the
                // sample closes its socket, which ends this read.
                let mut sink = Vec::new();
                let _ = s.read_to_end(&mut sink);
                Ok(got)
            })();
            let _ = tx.send(result);
        });
        Peer { port, saw, join }
    }

    /// What the peer received, once the run is over.
    fn received(self) -> Vec<u8> {
        let got = self
            .saw
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the loopback peer should have finished")
            .expect("the loopback peer's own I/O should have succeeded");
        self.join.join().expect("peer thread");
        got
    }
}

/// The control: exemu implements no Winsock, so the sample cannot open a socket
/// and says so. Without this, a pass on the Wine path could just be an exemu
/// thunk being helpful.
#[test]
fn emulated_path_has_no_winsock_at_all() {
    // No listener: the emulated path must not reach one, and must not hang
    // trying. It also proves the sample fails *before* any network I/O.
    let exe = socket_sample::build(1, REQUEST, REPLY);
    let run = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 2_000_000,
            sandbox_root: Some(private_sandbox("emulated")),
            ..RunConfig::default()
        },
    )
    .expect("emulated run");

    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    assert_ne!(run.exit_code, socket_sample::SOCKET_OK_EXIT, "stdout:\n{stdout}");
    assert!(
        stdout.contains(socket_sample::FAIL_MESSAGE.trim_end()),
        "the sample should report failure without a Winsock implementation; stdout:\n{stdout}"
    );
    // Specifically: `socket()` produced no SOCKET, so nothing downstream could
    // have worked.
    assert_eq!(
        line(&stdout, socket_sample::LABEL_SOCKET),
        "0000000000000000",
        "exemu's ws2_32!socket is an unimplemented thunk; stdout:\n{stdout}"
    );
    assert_eq!(
        line(&stdout, socket_sample::LABEL_SENT),
        "0000000000000000",
        "…so nothing was sent; stdout:\n{stdout}"
    );
    assert_eq!(
        line(&stdout, socket_sample::LABEL_RECVD),
        "0000000000000000",
        "…and nothing received; stdout:\n{stdout}"
    );
}

/// The W7.1 gate: Wine's `ws2_32.dll`, running as guest code, exchanges bytes
/// with a real loopback peer over exemu's `\Device\Afd` backend.
#[test]
fn socket_sample_exchanges_bytes_through_wine_ws2_32() {
    if !Path::new(WINE_DLLS).join("ws2_32.dll").exists() {
        eprintln!("SKIP: {WINE_DLLS}/ws2_32.dll not present (Wine DLL set is git-ignored)");
        return;
    }

    let peer = Peer::start();
    let exe = socket_sample::build(peer.port, REQUEST, REPLY);
    let run = load_and_run(
        &exe,
        RunConfig {
            echo: false,
            max_steps: 400_000_000,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            sandbox_root: Some(private_sandbox("wine")),
            ..RunConfig::default()
        },
    )
    .expect("the socket sample should run on the Wine boot, not fault");

    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    eprintln!("socket sample on Wine: exit {} after {} steps\n{stdout}", run.exit_code, run.steps);

    // Wine's Winsock stack really booted: ws2_32 pulls in the full
    // kernel32/kernelbase/ntdll/ucrtbase set plus its own initialisation, which
    // the emulated control (a few tens of thousands of instructions) cannot
    // approach.
    assert!(run.steps > 500_000, "expected a real Wine boot, got {} steps", run.steps);

    // WSAStartup negotiated a version.
    assert_eq!(
        line(&stdout, socket_sample::LABEL_STARTUP),
        "0000000000000000",
        "WSAStartup should succeed; stdout:\n{stdout}"
    );
    // A live SOCKET came back — which, on this path, is an NT handle exemu
    // minted for `\Device\Afd`.
    let sock = line(&stdout, socket_sample::LABEL_SOCKET);
    assert_ne!(sock, "0000000000000000", "socket() returned nothing; stdout:\n{stdout}");
    assert_ne!(sock, "ffffffffffffffff", "socket() returned INVALID_SOCKET; stdout:\n{stdout}");
    assert_eq!(
        line(&stdout, socket_sample::LABEL_CONNECT),
        "0000000000000000",
        "connect() failed; stdout:\n{stdout}"
    );

    // THE CLAIM, from the guest's side: the exact byte counts, and the reply
    // byte for byte.
    assert_eq!(
        line(&stdout, socket_sample::LABEL_SENT),
        format!("{:016x}", REQUEST.len()),
        "send() reported the wrong count; stdout:\n{stdout}"
    );
    assert_eq!(
        line(&stdout, socket_sample::LABEL_RECVD),
        format!("{:016x}", REPLY.len()),
        "recv() reported the wrong count; stdout:\n{stdout}"
    );
    assert_eq!(
        line(&stdout, socket_sample::LABEL_DATA).as_bytes(),
        REPLY,
        "the reply bytes; stdout:\n{stdout}"
    );

    // The guest verified the same thing itself and said so with its
    // distinguishing exit code.
    assert!(stdout.contains(socket_sample::OK_MESSAGE.trim_end()), "stdout:\n{stdout}");
    assert_eq!(run.exit_code, socket_sample::SOCKET_OK_EXIT, "stdout:\n{stdout}");

    // THE CLAIM, from the other side of a real socket: the host peer received
    // exactly what the guest sent. Nothing in exemu synthesised these bytes.
    assert_eq!(peer.received(), REQUEST, "the loopback peer's view of the request");
}

/// A private sandbox per run, so nothing a previous run left behind can change
/// what this one observes (see `RunConfig::sandbox_root`).
fn private_sandbox(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("exemu-w71-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}
