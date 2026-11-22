//! End-to-end shutdown of the real `basis_server` binary, the way `docker stop` drives it: a
//! fresh data directory, a tracker NFT that is not minted yet, a mock node on 127.0.0.1, then
//! SIGTERM. The process must exit 0 within the shutdown deadline (20 s from the signal), with
//! the note store closed, also when a client holds a connection open. The same harness checks
//! that the binary refuses to start with an all-zero tracker NFT id.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The server's shutdown deadline, counted from the signal.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(20);
/// How long a test waits for the server to come up (a debug build compiles the contracts).
const STARTUP_TIMEOUT: Duration = Duration::from_secs(120);

/// A minimal Ergo node: an empty chain at height 1000. Records every request line.
struct MockNode {
    url: String,
    seen: Arc<Mutex<Vec<String>>>,
}

impl MockNode {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock node");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_thread = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let seen = seen_by_thread.clone();
                std::thread::spawn(move || answer(stream, &seen));
            }
        });
        Self { url, seen }
    }

    fn saw(&self, prefix: &str) -> bool {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.starts_with(prefix))
    }
}

fn answer(mut stream: TcpStream, seen: &Mutex<Vec<String>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    while buf.len() < head_end + content_length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let mut request_line = head.lines().next().unwrap_or("").split_whitespace();
    let method = request_line.next().unwrap_or("").to_string();
    let target = request_line.next().unwrap_or("").to_string();
    seen.lock().unwrap().push(format!("{method} {target}"));

    let path = target.split('?').next().unwrap_or("");
    let (status, body) = match (method.as_str(), path) {
        ("GET", "/info") => (
            200,
            r#"{"fullHeight":1000,"headersHeight":1000}"#.to_string(),
        ),
        // No reserves and no tracker box: the NFT is not minted yet.
        (_, p) if p.starts_with("/blockchain/box/unspent/") => (200, "[]".to_string()),
        _ => (
            404,
            r#"{"error":404,"reason":"not-found","detail":"mock node"}"#.to_string(),
        ),
    };
    let response = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Write `config/basis.toml` for a loopback, unauthenticated server with a fresh tracker key.
fn write_config(dir: &Path, port: u16, node_url: &str) {
    write_config_with_nft(dir, port, node_url, &"11".repeat(32));
}

fn write_config_with_nft(dir: &Path, port: u16, node_url: &str, nft: &str) {
    let (secret, public) = basis_store::schnorr::generate_keypair();
    let reserve = basis_store::contract_compiler::get_basis_reserve_contract_p2s().unwrap();
    let token_reserve =
        basis_store::contract_compiler::get_basis_token_reserve_contract_p2s().unwrap();
    let data_dir = dir.join("data");
    std::fs::create_dir_all(dir.join("config")).unwrap();
    std::fs::write(
        dir.join("config/basis.toml"),
        format!(
            r#"[server]
host = "127.0.0.1"
port = {port}
data_dir = "{data_dir}"

[server.auth]
mode = "none"

[ergo]
basis_reserve_contract_p2s = "{reserve}"
basis_token_reserve_contract_p2s = "{token_reserve}"
tracker_nft_id = "{nft}"
tracker_public_key = "{public}"
tracker_secret_key = "{secret}"

[ergo.scanner]
node_url = "{node_url}"
start_height = 0
"#,
            data_dir = data_dir.display(),
            public = hex::encode(public),
            secret = hex::encode(secret),
        ),
    )
    .unwrap();
}

struct Server {
    child: Child,
    port: u16,
    log: std::path::PathBuf,
}

/// Run the binary in `dir` (which holds `config/basis.toml`), stdout and stderr to `server.log`.
fn spawn_server(dir: &Path) -> (Child, std::path::PathBuf) {
    spawn_server_with_env(dir, &[])
}

fn spawn_server_with_env(dir: &Path, env: &[(&str, &str)]) -> (Child, std::path::PathBuf) {
    let log = dir.join("server.log");
    let out = std::fs::File::create(&log).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_basis_server"))
        .current_dir(dir)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("RUST_LOG", "info")
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::from(out))
        .spawn()
        .expect("start basis_server");
    (child, log)
}

impl Server {
    fn start(dir: &Path, node: &MockNode) -> Self {
        let port = free_port();
        write_config(dir, port, &node.url);
        let (child, log) = spawn_server(dir);
        let mut server = Self { child, port, log };
        server.wait_until_serving(node);
        server
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The log from the signal on, printed by passing tests (visible with `--nocapture`).
    fn print_shutdown_log(&self) {
        let log = self.log();
        let from = log.find("SIGTERM received").unwrap_or(0);
        eprintln!("{}", &log[from..]);
    }

    /// Wait until `GET /` answers and the background loops have talked to the node.
    fn wait_until_serving(&mut self, node: &MockNode) {
        let started = Instant::now();
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!("server exited during startup: {status}\n{}", self.log());
            }
            let ready = get_root(self.port)
                && node.saw("POST /blockchain/box/unspent/byAddress")
                && node.saw("GET /blockchain/box/unspent/byTokenId/");
            if ready {
                return;
            }
            if started.elapsed() > STARTUP_TIMEOUT {
                let _ = self.child.kill();
                panic!("server did not come up\n{}", self.log());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn sigterm(&self) {
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!("kill -TERM {}", self.child.id()))
            .status()
            .unwrap();
        assert!(status.success(), "kill -TERM failed");
    }

    /// Wait for the process to exit, at most `limit`; kill it after that.
    fn wait_exit(&mut self, limit: Duration) -> Option<ExitStatus> {
        let started = Instant::now();
        while started.elapsed() < limit {
            if let Some(status) = self.child.try_wait().unwrap() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        None
    }
}

/// `GET /` with `Connection: close`, so the probe leaves no connection behind.
fn get_root(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    if stream
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response.starts_with("HTTP/1.1 200")
}

#[test]
fn sigterm_on_a_fresh_tracker_exits_0_well_within_the_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let node = MockNode::start();
    let mut server = Server::start(dir.path(), &node);

    server.sigterm();
    let signalled = Instant::now();
    let status = server.wait_exit(SHUTDOWN_DEADLINE + Duration::from_secs(10));
    let took = signalled.elapsed();
    let log = server.log();

    let status = status.unwrap_or_else(|| panic!("no exit {took:?} after SIGTERM\n{log}"));
    assert_eq!(status.code(), Some(0), "exit status {status}\n{log}");
    // Nothing is in flight, so no step may wait for the deadline.
    assert!(
        took < Duration::from_secs(10),
        "shutdown took {took:?}\n{log}"
    );
    assert!(log.contains("Shutdown complete"), "{log}");
    assert!(log.contains("Reserve scanner stopped"), "{log}");
    assert!(log.contains("note store closed"), "{log}");
    server.print_shutdown_log();
}

#[test]
fn sigterm_with_a_stuck_client_still_exits_0_by_the_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let node = MockNode::start();
    let mut server = Server::start(dir.path(), &node);

    // Half a request, then silence: the server cannot close this connection gracefully.
    let mut stuck = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    stuck
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n")
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));

    server.sigterm();
    let signalled = Instant::now();
    let status = server.wait_exit(SHUTDOWN_DEADLINE + Duration::from_secs(10));
    let took = signalled.elapsed();
    let log = server.log();
    drop(stuck);

    let status = status.unwrap_or_else(|| panic!("no exit {took:?} after SIGTERM\n{log}"));
    assert_eq!(status.code(), Some(0), "exit status {status}\n{log}");
    assert!(
        took <= SHUTDOWN_DEADLINE + Duration::from_secs(1),
        "shutdown took {took:?}\n{log}"
    );
    // The connection was waited for until its share of the deadline ran out, and the tracker
    // thread still closed the note store in the time kept for it.
    assert!(
        log.contains("without waiting longer for open HTTP connections"),
        "{log}"
    );
    assert!(log.contains("note store closed"), "{log}");
    server.print_shutdown_log();
}

/// Wait for a process that must exit during startup; its status and log.
fn wait_for_startup_exit(mut child: Child, log: &Path) -> (ExitStatus, String) {
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > STARTUP_TIMEOUT {
            let _ = child.kill();
            panic!(
                "still running\n{}",
                std::fs::read_to_string(log).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    (status, std::fs::read_to_string(log).unwrap_or_default())
}

/// An all-zero tracker NFT id is a placeholder, never a minted token: the binary exits 1 before
/// it serves anything, and says why on stderr (before tracing is set up).
#[test]
fn an_all_zero_tracker_nft_is_refused_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let node = MockNode::start();
    let port = free_port();
    write_config_with_nft(dir.path(), port, &node.url, &"00".repeat(32));
    let (child, log) = spawn_server(dir.path());
    let (status, log) = wait_for_startup_exit(child, &log);
    assert_eq!(status.code(), Some(1), "{log}");
    assert!(
        log.contains("basis_server: Tracker NFT ID is not properly configured"),
        "{log}"
    );
    assert!(log.contains("all zeros"), "{log}");
    assert!(!get_root(port), "nothing may listen");
}

/// An update interval of 0 used to panic the updater's timer after startup; the binary now
/// refuses it before it serves anything.
#[test]
fn an_update_interval_of_zero_is_refused_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let node = MockNode::start();
    let port = free_port();
    write_config(dir.path(), port, &node.url);
    let (child, log) = spawn_server_with_env(
        dir.path(),
        &[("BASIS_TRACKER_UPDATE_INTERVAL_SECONDS", "0")],
    );
    let (status, log) = wait_for_startup_exit(child, &log);
    assert_eq!(status.code(), Some(1), "{log}");
    assert!(
        log.contains("basis_server: BASIS_TRACKER_UPDATE_INTERVAL_SECONDS is 0"),
        "{log}"
    );
    assert!(!get_root(port), "nothing may listen");
}
