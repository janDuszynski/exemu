use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use exemu_core::{Cpu, Exit, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::net;
use exemu_os::{WinConfig, WinOs};

const CODE: u64 = 0x0000_0000_0040_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const TEB_SIZE: u64 = 0x2000;

const NT_OPEN_FILE: u32 = 0x33;
const NT_CLOSE: u32 = 0x0f;

const STATUS_SUCCESS: u64 = 0;
const STATUS_NOT_IMPLEMENTED: u64 = 0xC000_0002;
const STATUS_INVALID_HANDLE: u64 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;
const STATUS_INVALID_CONNECTION: u64 = 0xC000_0140;

const AF_INET: u64 = 2;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const IPPROTO_TCP: u64 = 6;

const HANDLE_PTR: u64 = SCRATCH;
const IOSB_PTR: u64 = SCRATCH + 0x10;
const OA_PTR: u64 = SCRATCH + 0x100;
const IN_PTR: u64 = SCRATCH + 0x400;
const OUT_PTR: u64 = SCRATCH + 0x600;
const WSABUF_PTR: u64 = SCRATCH + 0x800;
const DATA_PTR: u64 = SCRATCH + 0x900;
const FLAGS_PTR: u64 = SCRATCH + 0xB00;

fn syscall(os: &mut WinOs, mem: &mut VirtualMemory, index: u32, args: &[u64]) -> u64 {
    let mut asm: Vec<u8> = Vec::new();
    asm.extend_from_slice(&[0x48, 0xB9]);
    asm.extend_from_slice(&args.first().copied().unwrap_or(0).to_le_bytes());
    asm.extend_from_slice(&[0x49, 0x89, 0xCA]);
    asm.extend_from_slice(&[0xB8]);
    asm.extend_from_slice(&index.to_le_bytes());
    asm.extend_from_slice(&[0x0F, 0x05]);
    asm.push(0xF4);
    mem.poke(CODE, &asm).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B64);
    let rsp = STACK_TOP - 0x100;
    {
        let s = cpu.state_mut();
        s.rip = CODE;
        s.set_rsp(rsp);
        let regs = [Reg::Rdx, Reg::R8, Reg::R9];
        for (i, &a) in args.iter().skip(1).take(3).enumerate() {
            s.set_reg(regs[i], a);
        }
    }
    for (n, &a) in args.iter().enumerate().skip(4) {
        mem.write_u64(rsp + 0x28 + (n as u64 - 4) * 8, a).unwrap();
    }
    loop {
        match cpu.step(mem, os).unwrap() {
            Exit::Continue => continue,
            Exit::Halted => break,
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    cpu.state().reg(Reg::Rax)
}

fn setup() -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("stack", STACK_TOP - 0x2000, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("scratch", SCRATCH, 0x4000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig {
        is_64bit: true,
        echo: false,
        teb_base: GS_BASE,
        ..WinConfig::default()
    });
    (os, mem)
}

fn write_unicode_string(mem: &mut VirtualMemory, us_ptr: u64, buf_ptr: u64, s: &str) {
    let units: Vec<u16> = s.encode_utf16().collect();
    for (i, u) in units.iter().enumerate() {
        mem.write_u16(buf_ptr + (i as u64) * 2, *u).unwrap();
    }
    let bytes = (units.len() * 2) as u16;
    mem.write_u16(us_ptr, bytes).unwrap();
    mem.write_u16(us_ptr + 2, bytes + 2).unwrap();
    mem.write_u32(us_ptr + 4, 0).unwrap();
    mem.write_u64(us_ptr + 8, buf_ptr).unwrap();
}

fn write_object_attributes(mem: &mut VirtualMemory, oa_ptr: u64, nt_path: &str) {
    let us_ptr = oa_ptr + 0x20;
    let buf_ptr = oa_ptr + 0x40;
    mem.write_u32(oa_ptr, 0x30).unwrap();
    mem.write_u64(oa_ptr + 8, 0).unwrap();
    mem.write_u64(oa_ptr + 0x10, us_ptr).unwrap();
    mem.write_u32(oa_ptr + 0x18, 0).unwrap();
    write_unicode_string(mem, us_ptr, buf_ptr, nt_path);
}

fn make_socket(os: &mut WinOs, mem: &mut VirtualMemory, family: u64, kind: u64, proto: u64) -> (u64, u64) {
    write_object_attributes(mem, OA_PTR, net::AFD_DEVICE_NAME);
    let st = syscall(
        os,
        mem,
        NT_OPEN_FILE,
        &[HANDLE_PTR, u64::from(net::AFD_DESIRED_ACCESS), OA_PTR, IOSB_PTR, 0, 0x20],
    );
    assert_eq!(st, STATUS_SUCCESS, "NtOpenFile(\\Device\\Afd)");
    let handle = mem.read_u64(HANDLE_PTR).unwrap();
    assert_ne!(handle, 0);

    mem.write_u32(IN_PTR, family as u32).unwrap();
    mem.write_u32(IN_PTR + 4, kind as u32).unwrap();
    mem.write_u32(IN_PTR + 8, proto as u32).unwrap();
    mem.write_u32(IN_PTR + 12, 0).unwrap();
    let st = ioctl(os, mem, handle, net::IOCTL_AFD_WINE_CREATE, IN_PTR, net::CREATE_PARAMS_LEN as u64, 0, 0);
    (handle, st)
}

#[allow(clippy::too_many_arguments)]
fn ioctl(
    os: &mut WinOs,
    mem: &mut VirtualMemory,
    handle: u64,
    code: u32,
    in_buf: u64,
    in_len: u64,
    out_buf: u64,
    out_len: u64,
) -> u64 {
    syscall(
        os,
        mem,
        net::SSDT_NT_DEVICE_IO_CONTROL_FILE,
        &[handle, 0, 0, 0, IOSB_PTR, u64::from(code), in_buf, in_len, out_buf, out_len],
    )
}

fn information(mem: &VirtualMemory) -> u64 {
    mem.read_u64(IOSB_PTR + 8).unwrap()
}

fn write_sockaddr_in(mem: &mut VirtualMemory, ptr: u64, addr: SocketAddr) {
    let SocketAddr::V4(v4) = addr else { panic!("the tests bind IPv4 loopback") };
    mem.write_u16(ptr, AF_INET as u16).unwrap();
    mem.write(ptr + 2, &v4.port().to_be_bytes()).unwrap();
    mem.write(ptr + 4, &v4.ip().octets()).unwrap();
    mem.write(ptr + 8, &[0u8; 8]).unwrap();
}

fn read_sockaddr_in(mem: &VirtualMemory, ptr: u64) -> (u16, [u8; 4]) {
    let mut port = [0u8; 2];
    mem.read(ptr + 2, &mut port).unwrap();
    let mut ip = [0u8; 4];
    mem.read(ptr + 4, &mut ip).unwrap();
    assert_eq!(mem.read_u16(ptr).unwrap() as u64, AF_INET, "sin_family");
    (u16::from_be_bytes(port), ip)
}

fn write_send_params(mem: &mut VirtualMemory, data: &[u8], to: Option<SocketAddr>) {
    mem.write(DATA_PTR, data).unwrap();
    mem.write_u32(WSABUF_PTR, data.len() as u32).unwrap();
    mem.write_u64(WSABUF_PTR + net::WSABUF_PTR_OFF, DATA_PTR).unwrap();

    let (addr_ptr, addr_len) = match to {
        Some(a) => {
            write_sockaddr_in(mem, OUT_PTR + 0x100, a);
            (OUT_PTR + 0x100, 16u32)
        }
        None => (0, 0),
    };
    mem.write_u64(IN_PTR + net::SENDMSG_ADDR_OFF, addr_ptr).unwrap();
    mem.write_u32(IN_PTR + net::SENDMSG_ADDR_LEN_OFF, addr_len).unwrap();
    mem.write_u32(IN_PTR + 0x0c, 0).unwrap();
    mem.write_u32(IN_PTR + 0x10, 0).unwrap();
    mem.write_u32(IN_PTR + net::SENDMSG_COUNT_OFF, 1).unwrap();
    mem.write_u64(IN_PTR + net::SENDMSG_BUFFERS_OFF, WSABUF_PTR).unwrap();
}

fn write_recv_params(mem: &mut VirtualMemory, cap: u32, want_addr: bool) {
    mem.write(DATA_PTR, &vec![0u8; cap as usize]).unwrap();
    mem.write_u32(WSABUF_PTR, cap).unwrap();
    mem.write_u64(WSABUF_PTR + net::WSABUF_PTR_OFF, DATA_PTR).unwrap();

    let (addr_ptr, addr_len_ptr) = if want_addr {
        mem.write_u32(OUT_PTR + 0x180, 16).unwrap();
        (OUT_PTR + 0x100, OUT_PTR + 0x180)
    } else {
        (0, 0)
    };
    mem.write_u64(IN_PTR, 0).unwrap();
    mem.write_u64(IN_PTR + net::RECVMSG_ADDR_OFF, addr_ptr).unwrap();
    mem.write_u64(IN_PTR + net::RECVMSG_ADDR_LEN_OFF, addr_len_ptr).unwrap();
    mem.write_u32(FLAGS_PTR, 0).unwrap();
    mem.write_u64(IN_PTR + net::RECVMSG_WS_FLAGS_OFF, FLAGS_PTR).unwrap();
    mem.write_u32(0x20 + IN_PTR, 0).unwrap();
    mem.write_u32(IN_PTR + net::RECVMSG_COUNT_OFF, 1).unwrap();
    mem.write_u64(IN_PTR + net::RECVMSG_BUFFERS_OFF, WSABUF_PTR).unwrap();
}

fn received(mem: &VirtualMemory, n: u64) -> Vec<u8> {
    let mut out = vec![0u8; n as usize];
    mem.read(DATA_PTR, &mut out).unwrap();
    out
}

fn connect(os: &mut WinOs, mem: &mut VirtualMemory, handle: u64, addr: SocketAddr) -> u64 {
    mem.write_u32(IN_PTR, 16).unwrap();
    mem.write_u32(IN_PTR + 4, 1).unwrap();
    write_sockaddr_in(mem, IN_PTR + net::CONNECT_PARAMS_HEADER, addr);
    ioctl(os, mem, handle, net::IOCTL_AFD_WINE_CONNECT, IN_PTR, 8 + 16, 0, 0)
}

#[test]
fn a_full_client_exchange_over_a_loopback_listener() {
    const REQUEST: &[u8] = b"exemu W7.1: guest bytes on a real socket";
    const REPLY: &[u8] = b"and the host answered";

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let (mut s, from) = listener.accept().unwrap();
        let mut got = vec![0u8; REQUEST.len()];
        s.read_exact(&mut got).unwrap();
        s.write_all(REPLY).unwrap();
        s.flush().unwrap();
        (got, from)
    });

    let (mut os, mut mem) = setup();
    let (sock, st) = make_socket(&mut os, &mut mem, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert_eq!(st, STATUS_SUCCESS, "IOCTL_AFD_WINE_CREATE");

    assert_eq!(connect(&mut os, &mut mem, sock, addr), STATUS_SUCCESS, "connect");

    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_WINE_GET_PEER_NAME, 0, 0, OUT_PTR, 16);
    assert_eq!(st, STATUS_SUCCESS, "getpeername");
    assert_eq!(information(&mem), 16, "a sockaddr_in is 16 bytes");
    assert_eq!(read_sockaddr_in(&mem, OUT_PTR), (addr.port(), [127, 0, 0, 1]));

    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_GET_SOCK_NAME, 0, 0, OUT_PTR, 16);
    assert_eq!(st, STATUS_SUCCESS, "getsockname");
    let (local_port, local_ip) = read_sockaddr_in(&mem, OUT_PTR);
    assert_eq!(local_ip, [127, 0, 0, 1]);
    assert_ne!(local_port, 0, "the host assigned an ephemeral port");

    write_send_params(&mut mem, REQUEST, None);
    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_WINE_SENDMSG, IN_PTR, net::SENDMSG_PARAMS_LEN as u64, 0, 0);
    assert_eq!(st, STATUS_SUCCESS, "send");
    assert_eq!(information(&mem), REQUEST.len() as u64, "IOSB.Information is the byte count");

    write_recv_params(&mut mem, 128, false);
    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_WINE_RECVMSG, IN_PTR, net::RECVMSG_PARAMS_LEN as u64, 0, 0);
    assert_eq!(st, STATUS_SUCCESS, "recv");
    let n = information(&mem);
    assert_eq!(received(&mem, n), REPLY, "the reply came back byte for byte");

    let (got, from) = peer.join().unwrap();
    assert_eq!(got, REQUEST);
    assert_eq!(from.port(), local_port, "getsockname matched the peer's view");

    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_WINE_GET_SOCKET_INFO, 0, 0, OUT_PTR, 12);
    assert_eq!(st, STATUS_SUCCESS);
    assert_eq!(mem.read_u32(OUT_PTR).unwrap() as u64, AF_INET);
    assert_eq!(mem.read_u32(OUT_PTR + 4).unwrap() as u64, SOCK_STREAM);
    assert_eq!(mem.read_u32(OUT_PTR + 8).unwrap() as u64, IPPROTO_TCP);

    assert_eq!(syscall(&mut os, &mut mem, NT_CLOSE, &[sock]), STATUS_SUCCESS, "closesocket");
}

#[test]
fn a_blocking_receive_waits_for_the_peer_instead_of_reporting_end_of_stream() {
    const DELAY: Duration = Duration::from_millis(300);
    const LATE: &[u8] = b"worth waiting for";

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        std::thread::sleep(DELAY);
        s.write_all(LATE).unwrap();
        s.flush().unwrap();
        std::thread::sleep(Duration::from_millis(200));
    });

    let (mut os, mut mem) = setup();
    let (sock, _) = make_socket(&mut os, &mut mem, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert_eq!(connect(&mut os, &mut mem, sock, addr), STATUS_SUCCESS);

    write_recv_params(&mut mem, 64, false);
    let start = Instant::now();
    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_WINE_RECVMSG, IN_PTR, net::RECVMSG_PARAMS_LEN as u64, 0, 0);
    let waited = start.elapsed();

    assert_eq!(st, STATUS_SUCCESS);
    let n = information(&mem);
    assert_eq!(received(&mem, n), LATE, "the bytes the peer actually sent");
    assert!(
        waited >= DELAY - Duration::from_millis(50),
        "the receive returned after only {waited:?} — it did not really block"
    );
    peer.join().unwrap();
    assert_eq!(syscall(&mut os, &mut mem, NT_CLOSE, &[sock]), STATUS_SUCCESS);
}

#[test]
fn a_closed_peer_reads_as_a_graceful_end_of_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        drop(s);
    });

    let (mut os, mut mem) = setup();
    let (sock, _) = make_socket(&mut os, &mut mem, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert_eq!(connect(&mut os, &mut mem, sock, addr), STATUS_SUCCESS);
    peer.join().unwrap();

    write_recv_params(&mut mem, 64, false);
    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_WINE_RECVMSG, IN_PTR, net::RECVMSG_PARAMS_LEN as u64, 0, 0);
    assert_eq!(st, STATUS_SUCCESS, "a graceful close is not an error");
    assert_eq!(information(&mem), 0, "…it is zero bytes transferred");
    assert_eq!(syscall(&mut os, &mut mem, NT_CLOSE, &[sock]), STATUS_SUCCESS);
}

#[test]
fn the_guest_can_be_the_server_and_accept_a_real_connection() {
    const GREETING: &[u8] = b"client speaking";

    let (mut os, mut mem) = setup();
    let (sock, _) = make_socket(&mut os, &mut mem, AF_INET, SOCK_STREAM, IPPROTO_TCP);

    mem.write_u32(IN_PTR, 0).unwrap();
    write_sockaddr_in(&mut mem, IN_PTR + net::BIND_PARAMS_HEADER, "127.0.0.1:0".parse().unwrap());
    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_BIND, IN_PTR, 4 + 16, OUT_PTR, 16);
    assert_eq!(st, STATUS_SUCCESS, "bind");
    let (port, ip) = read_sockaddr_in(&mem, OUT_PTR);
    assert_eq!(ip, [127, 0, 0, 1]);
    assert_ne!(port, 0, "bind reported the ephemeral port it was given");

    mem.write_u32(IN_PTR, 0).unwrap();
    mem.write_u32(IN_PTR + net::LISTEN_BACKLOG_OFF, 8).unwrap();
    mem.write_u32(IN_PTR + 8, 0).unwrap();
    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_START_LISTEN, IN_PTR, net::LISTEN_PARAMS_LEN as u64, 0, 0);
    assert_eq!(st, STATUS_SUCCESS, "listen");

    let client = std::thread::spawn(move || {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(GREETING).unwrap();
        s.flush().unwrap();
        s
    });

    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_WINE_ACCEPT, 0, 0, OUT_PTR, net::ACCEPT_OUT_LEN as u64);
    assert_eq!(st, STATUS_SUCCESS, "accept");
    assert_eq!(information(&mem), 4);
    let accepted = mem.read_u32(OUT_PTR).unwrap() as u64;
    assert_ne!(accepted, sock, "a distinct socket");
    assert_ne!(accepted, 0);

    write_recv_params(&mut mem, 64, false);
    let st = ioctl(&mut os, &mut mem, accepted, net::IOCTL_AFD_WINE_RECVMSG, IN_PTR, net::RECVMSG_PARAMS_LEN as u64, 0, 0);
    assert_eq!(st, STATUS_SUCCESS);
    let n = information(&mem);
    assert_eq!(received(&mem, n), GREETING);

    let _client = client.join().unwrap();
    assert_eq!(syscall(&mut os, &mut mem, NT_CLOSE, &[accepted]), STATUS_SUCCESS);
    assert_eq!(syscall(&mut os, &mut mem, NT_CLOSE, &[sock]), STATUS_SUCCESS);
}

#[test]
fn select_polls_and_then_reports_a_socket_that_becomes_readable() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(150));
        s.write_all(b"ready now").unwrap();
        s.flush().unwrap();
        std::thread::sleep(Duration::from_millis(200));
    });

    let (mut os, mut mem) = setup();
    let (sock, _) = make_socket(&mut os, &mut mem, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert_eq!(connect(&mut os, &mut mem, sock, addr), STATUS_SUCCESS);

    let poll = |mem: &mut VirtualMemory, timeout: i64, want: u32| {
        mem.write_u64(IN_PTR, timeout as u64).unwrap();
        mem.write_u32(IN_PTR + net::POLL_PARAMS_COUNT_OFF, 1).unwrap();
        mem.write_u32(IN_PTR + 0x0c, 0).unwrap();
        let e = IN_PTR + net::POLL_PARAMS_HEADER;
        mem.write_u64(e, sock).unwrap();
        mem.write_u32(e + net::POLL_ENTRY_FLAGS_OFF, want).unwrap();
        mem.write_u32(e + net::POLL_ENTRY_STATUS_OFF, 0).unwrap();
    };
    let params_len = net::POLL_PARAMS_HEADER + net::POLL_ENTRY_STRIDE;

    poll(&mut mem, 0, net::AFD_POLL_READ | net::AFD_POLL_ALWAYS);
    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_SELECT, IN_PTR, params_len, IN_PTR, params_len);
    assert_eq!(st, STATUS_SUCCESS, "a poll always succeeds");
    assert_eq!(
        mem.read_u32(IN_PTR + net::POLL_PARAMS_COUNT_OFF).unwrap(),
        0,
        "nothing readable yet"
    );

    poll(&mut mem, i64::MAX, net::AFD_POLL_READ | net::AFD_POLL_ALWAYS);
    let start = Instant::now();
    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_SELECT, IN_PTR, params_len, IN_PTR, params_len);
    assert_eq!(st, STATUS_SUCCESS);
    assert!(start.elapsed() >= Duration::from_millis(100), "the wait was real");
    assert_eq!(mem.read_u32(IN_PTR + net::POLL_PARAMS_COUNT_OFF).unwrap(), 1, "one socket ready");
    let e = IN_PTR + net::POLL_PARAMS_HEADER;
    assert_eq!(mem.read_u64(e).unwrap(), sock, "…and it is ours");
    assert!(
        mem.read_u32(e + net::POLL_ENTRY_FLAGS_OFF).unwrap() & net::AFD_POLL_READ != 0,
        "reported readable"
    );

    peer.join().unwrap();
    assert_eq!(syscall(&mut os, &mut mem, NT_CLOSE, &[sock]), STATUS_SUCCESS);
}

#[test]
fn a_select_timeout_reports_no_ready_sockets_on_the_callers_schedule() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(600));
        drop(s);
    });

    let (mut os, mut mem) = setup();
    let (sock, _) = make_socket(&mut os, &mut mem, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert_eq!(connect(&mut os, &mut mem, sock, addr), STATUS_SUCCESS);

    let timeout: i64 = -(150_000_000 / 100);
    mem.write_u64(IN_PTR, timeout as u64).unwrap();
    mem.write_u32(IN_PTR + net::POLL_PARAMS_COUNT_OFF, 1).unwrap();
    mem.write_u32(IN_PTR + 0x0c, 0).unwrap();
    let e = IN_PTR + net::POLL_PARAMS_HEADER;
    mem.write_u64(e, sock).unwrap();
    mem.write_u32(e + net::POLL_ENTRY_FLAGS_OFF, net::AFD_POLL_READ).unwrap();
    mem.write_u32(e + net::POLL_ENTRY_STATUS_OFF, 0).unwrap();
    let params_len = net::POLL_PARAMS_HEADER + net::POLL_ENTRY_STRIDE;

    let start = Instant::now();
    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_SELECT, IN_PTR, params_len, IN_PTR, params_len);
    let waited = start.elapsed();

    assert_eq!(st, STATUS_SUCCESS, "a select timeout is not an error");
    assert_eq!(
        mem.read_u32(IN_PTR + net::POLL_PARAMS_COUNT_OFF).unwrap(),
        0,
        "…it is zero ready sockets"
    );
    assert!(waited >= Duration::from_millis(140), "it waited the caller's timeout: {waited:?}");
    assert!(
        waited < Duration::from_secs(5),
        "it must honour the caller's 150ms, not the blocking safety limit: {waited:?}"
    );
    peer.join().unwrap();
    assert_eq!(syscall(&mut os, &mut mem, NT_CLOSE, &[sock]), STATUS_SUCCESS);
}

#[test]
fn a_datagram_socket_exchanges_with_a_host_peer() {
    const PING: &[u8] = b"udp ping";
    const PONG: &[u8] = b"udp pong";

    let host = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let host_addr = host.local_addr().unwrap();

    let (mut os, mut mem) = setup();
    let (sock, st) = make_socket(&mut os, &mut mem, AF_INET, SOCK_DGRAM, 17);
    assert_eq!(st, STATUS_SUCCESS);

    mem.write_u32(IN_PTR, 0).unwrap();
    write_sockaddr_in(&mut mem, IN_PTR + net::BIND_PARAMS_HEADER, "127.0.0.1:0".parse().unwrap());
    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_BIND, IN_PTR, 4 + 16, OUT_PTR, 16);
    assert_eq!(st, STATUS_SUCCESS, "bind a datagram socket");
    let (guest_port, _) = read_sockaddr_in(&mem, OUT_PTR);

    let peer = std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        let (n, from) = host.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], PING);
        host.send_to(PONG, from).unwrap();
        from
    });

    write_send_params(&mut mem, PING, Some(host_addr));
    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_WINE_SENDMSG, IN_PTR, net::SENDMSG_PARAMS_LEN as u64, 0, 0);
    assert_eq!(st, STATUS_SUCCESS, "sendto");
    assert_eq!(information(&mem), PING.len() as u64);

    write_recv_params(&mut mem, 64, true);
    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_WINE_RECVMSG, IN_PTR, net::RECVMSG_PARAMS_LEN as u64, 0, 0);
    assert_eq!(st, STATUS_SUCCESS, "recvfrom");
    let n = information(&mem);
    assert_eq!(received(&mem, n), PONG);
    assert_eq!(read_sockaddr_in(&mem, OUT_PTR + 0x100), (host_addr.port(), [127, 0, 0, 1]));
    assert_eq!(mem.read_u32(OUT_PTR + 0x180).unwrap(), 16, "addr_len updated");

    assert_eq!(peer.join().unwrap().port(), guest_port);
    assert_eq!(syscall(&mut os, &mut mem, NT_CLOSE, &[sock]), STATUS_SUCCESS);
}

#[test]
fn only_ordinary_ip_stream_and_datagram_sockets_are_served() {
    let (mut os, mut mem) = setup();
    let (_, st) = make_socket(&mut os, &mut mem, 1, SOCK_STREAM, 0);
    assert_eq!(st, STATUS_NOT_IMPLEMENTED, "AF_UNIX is refused");
    let (_, st) = make_socket(&mut os, &mut mem, AF_INET, 3, 1);
    assert_eq!(st, STATUS_NOT_IMPLEMENTED, "SOCK_RAW is refused");
    let (_, st) = make_socket(&mut os, &mut mem, 26, SOCK_STREAM, 0);
    assert_eq!(st, STATUS_NOT_IMPLEMENTED);
    let (_, st) = make_socket(&mut os, &mut mem, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert_eq!(st, STATUS_SUCCESS);
    let (_, st) = make_socket(&mut os, &mut mem, AF_INET, SOCK_DGRAM, 17);
    assert_eq!(st, STATUS_SUCCESS);
}

#[test]
fn failure_statuses_are_the_ones_ws2_32_can_translate() {
    let (mut os, mut mem) = setup();
    let (sock, _) = make_socket(&mut os, &mut mem, AF_INET, SOCK_STREAM, IPPROTO_TCP);

    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_WINE_GET_PEER_NAME, 0, 0, OUT_PTR, 16);
    assert_eq!(st, STATUS_INVALID_CONNECTION);

    mem.write(IN_PTR, &[0u8; 12]).unwrap();
    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_START_LISTEN, IN_PTR, net::LISTEN_PARAMS_LEN as u64, 0, 0);
    assert_eq!(st, STATUS_INVALID_PARAMETER);

    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_EVENT_SELECT, IN_PTR, 16, 0, 0);
    assert_eq!(st, STATUS_NOT_IMPLEMENTED);

    mem.write_u32(IN_PTR, 0).unwrap();
    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_WINE_OP_210, IN_PTR, 4, 0, 0);
    assert_eq!(st, STATUS_SUCCESS);

    assert_eq!(syscall(&mut os, &mut mem, NT_CLOSE, &[sock]), STATUS_SUCCESS);
    let st = ioctl(&mut os, &mut mem, sock, net::IOCTL_AFD_WINE_GET_SOCKET_INFO, 0, 0, OUT_PTR, 12);
    assert_eq!(st, STATUS_INVALID_HANDLE, "the handle is gone");
    assert_eq!(syscall(&mut os, &mut mem, NT_CLOSE, &[sock]), STATUS_INVALID_HANDLE);
}

#[test]
fn the_afd_device_does_not_shadow_the_filesystem() {
    let (mut os, mut mem) = setup();
    let (sock, _) = make_socket(&mut os, &mut mem, AF_INET, SOCK_STREAM, IPPROTO_TCP);

    write_object_attributes(&mut mem, OA_PTR, "\\Device\\NotAfd");
    let st = syscall(
        &mut os,
        &mut mem,
        NT_OPEN_FILE,
        &[HANDLE_PTR, u64::from(net::AFD_DESIRED_ACCESS), OA_PTR, IOSB_PTR, 0, 0x20],
    );
    assert_ne!(st, STATUS_SUCCESS, "only \\Device\\Afd mints a socket");

    const NT_READ_FILE: u32 = 0x06;
    let st = syscall(&mut os, &mut mem, NT_READ_FILE, &[sock, 0, 0, 0, IOSB_PTR, DATA_PTR, 16, 0, 0]);
    assert_eq!(st, STATUS_INVALID_HANDLE);
}
