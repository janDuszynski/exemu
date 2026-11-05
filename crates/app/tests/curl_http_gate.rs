use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use exemu_app::{load_and_run, RunConfig};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";
const CURL: &str = "../../example_exe/curl-8.21.0_2-win64-mingw/bin/curl.exe";

const BODY: &str = "exemu fetched this over http\nfrom a server on 127.0.0.1\n";
const CURL_EXIT_COULDNT_CONNECT: i32 = 7;
const MAX_STEPS: u64 = 300_000_000;
const REQUEST_LIMIT: usize = 16 * 1024;

fn inputs_present() -> bool {
    let present = Path::new(WINE_DLLS).join("ws2_32.dll").exists() && Path::new(CURL).exists();
    if !present {
        eprintln!("SKIP: the Wine DLL set or curl.exe is not present (both are git-ignored)");
    }
    present
}

struct Server {
    port: u16,
    request: mpsc::Receiver<Vec<u8>>,
    join: std::thread::JoinHandle<()>,
}

impl Server {
    fn start(body: &'static str) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback listener");
        let port = listener.local_addr().unwrap().port();
        let (tx, request) = mpsc::channel();
        let join = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().expect("curl should connect");
            s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
            let mut got = Vec::new();
            let mut chunk = [0u8; 1024];
            while !got.windows(4).any(|w| w == b"\r\n\r\n") && got.len() < REQUEST_LIMIT {
                let n = s.read(&mut chunk).expect("read the request");
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&chunk[..n]);
            }
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            s.write_all(reply.as_bytes()).expect("write the reply");
            s.flush().unwrap();
            let _ = tx.send(got);
        });
        Server { port, request, join }
    }

    fn request(self) -> String {
        let got = self.request.recv_timeout(Duration::from_secs(30)).expect("the server should have seen a request");
        self.join.join().expect("server thread");
        String::from_utf8(got).expect("an ASCII request")
    }
}

fn sandbox(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("exemu-curl-http-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn run_curl(tag: &str, args: &[String]) -> (i32, String) {
    let bytes = std::fs::read(CURL).expect("read curl.exe");
    let mut argv = vec!["curl.exe".to_string()];
    argv.extend(args.iter().cloned());
    let run = load_and_run(
        &bytes,
        RunConfig {
            args: argv,
            echo: false,
            max_steps: MAX_STEPS,
            virtual_clock: true,
            wine_boot_dir: Some(WINE_DLLS.to_string()),
            sandbox_root: Some(sandbox(tag)),
            ..RunConfig::default()
        },
    )
    .expect("curl should run to completion on the Wine boot");
    (run.exit_code as i32, String::from_utf8_lossy(&run.stdout).into_owned())
}

#[test]
fn curl_fetches_an_http_url_from_a_loopback_server() {
    if !inputs_present() {
        return;
    }
    let server = Server::start(BODY);
    let url = format!("http://127.0.0.1:{}/hello.txt", server.port);
    let (exit, stdout) = run_curl("fetch", &["-sS".to_string(), url]);

    let request = server.request();
    assert!(request.starts_with("GET /hello.txt HTTP/1.1\r\n"), "request line; got:\n{request}");
    assert!(request.contains("User-Agent: curl/8.21.0\r\n"), "curl's own request headers; got:\n{request}");
    assert!(request.contains("Host: 127.0.0.1:"), "a Host header; got:\n{request}");

    assert_eq!(exit, 0, "curl exits 0 on a 200; stdout:\n{stdout}");
    assert_eq!(stdout, BODY, "stdout is the response body byte for byte");
}

#[test]
fn curl_reports_a_refused_loopback_connection_with_its_own_exit_code() {
    if !inputs_present() {
        return;
    }
    let closed_port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let url = format!("http://127.0.0.1:{closed_port}/hello.txt");
    let (exit, stdout) = run_curl("refused", &["-sS".to_string(), url]);
    assert_eq!(exit, CURL_EXIT_COULDNT_CONNECT, "CURLE_COULDNT_CONNECT, not a hang and not 'unsupported protocol'");
    assert!(stdout.is_empty(), "nothing is written to stdout; got {stdout:?}");
}
