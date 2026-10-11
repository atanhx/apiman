use crate::security::{harden_process, lock_memory};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonRequest {
    GetMasterKey,
    Lock,
    Status,
    Ping,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonResponse {
    MasterKey(String), // hex encoded
    Locked,
    Status {
        unlocked: bool,
        remaining_seconds: u64,
        auto_lock_timeout: u64,
    },
    Pong,
    Error(String),
}

#[derive(Debug)]
pub enum DaemonClientError {
    NotRunning,
    Io(std::io::Error),
    Serialization(serde_json::Error),
    Protocol(String),
}

impl fmt::Display for DaemonClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRunning => write!(f, "Daemon is not running or socket is unavailable"),
            Self::Io(e) => write!(f, "Daemon connection error: {e}"),
            Self::Serialization(e) => write!(f, "Protocol serialization error: {e}"),
            Self::Protocol(e) => write!(f, "Daemon error: {e}"),
        }
    }
}

impl std::error::Error for DaemonClientError {}

impl From<std::io::Error> for DaemonClientError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for DaemonClientError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e)
    }
}

pub fn send_request(
    socket_path: &Path,
    req: &DaemonRequest,
) -> Result<DaemonResponse, DaemonClientError> {
    if !socket_path.exists() {
        return Err(DaemonClientError::NotRunning);
    }

    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;

    let mut msg = serde_json::to_string(req)?;
    msg.push('\n');
    stream.write_all(msg.as_bytes())?;

    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line)?;

    let resp: DaemonResponse = serde_json::from_str(&resp_line)?;
    Ok(resp)
}

pub fn get_cached_master_key(socket_path: &Path) -> Option<Zeroizing<[u8; 32]>> {
    match send_request(socket_path, &DaemonRequest::GetMasterKey) {
        Ok(DaemonResponse::MasterKey(hex_str)) => {
            let mut bytes = [0u8; 32];
            if hex_str.len() == 64 {
                if hex::decode_to_slice(&hex_str, &mut bytes).is_ok() {
                    return Some(Zeroizing::new(bytes));
                }
            }
            None
        }
        _ => None,
    }
}

pub fn lock_daemon(socket_path: &Path) -> Result<(), DaemonClientError> {
    if !socket_path.exists() {
        return Ok(());
    }
    let _ = send_request(socket_path, &DaemonRequest::Lock);
    if socket_path.exists() {
        let _ = fs::remove_file(socket_path);
    }
    Ok(())
}

pub fn check_daemon_status(
    socket_path: &Path,
) -> Option<(bool, u64, u64)> {
    match send_request(socket_path, &DaemonRequest::Status) {
        Ok(DaemonResponse::Status {
            unlocked,
            remaining_seconds,
            auto_lock_timeout,
        }) => Some((unlocked, remaining_seconds, auto_lock_timeout)),
        _ => None,
    }
}

pub fn spawn_daemon(
    key: &[u8; 32],
    timeout_secs: u64,
    socket_path: &Path,
) -> Result<(), std::io::Error> {
    // If socket exists and responds, nothing to do
    if let Ok(DaemonResponse::Pong) = send_request(socket_path, &DaemonRequest::Ping) {
        return Ok(());
    }

    let _ = fs::remove_file(socket_path);

    let current_exe = std::env::current_exe()?;
    let mut child = Command::new(current_exe)
        .arg("daemon")
        .arg("--run")
        .arg("--timeout")
        .arg(timeout_secs.to_string())
        .arg("--socket")
        .arg(socket_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        // Write raw 32-byte key over stdin pipe
        stdin.write_all(key)?;
        stdin.flush()?;
    }

    // Wait briefly for daemon to initialize socket
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(50));
        if socket_path.exists() {
            if let Ok(DaemonResponse::Pong) = send_request(socket_path, &DaemonRequest::Ping) {
                return Ok(());
            }
        }
    }

    Ok(())
}

pub fn run_daemon_loop(timeout_secs: u64, socket_path: PathBuf) -> Result<(), std::io::Error> {
    harden_process();

    // Read 32-byte key from stdin
    let mut key_bytes = [0u8; 32];
    let mut stdin = std::io::stdin();
    stdin.read_exact(&mut key_bytes)?;

    lock_memory(key_bytes.as_ptr(), key_bytes.len());
    let master_key = Arc::new(Mutex::new(Zeroizing::new(key_bytes)));

    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _ = fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        let _ = fs::set_permissions(&socket_path, perms);
    }

    listener.set_nonblocking(true)?;

    let last_accessed = Arc::new(Mutex::new(Instant::now()));
    let should_stop = Arc::new(AtomicBool::new(false));

    // Watcher thread for inactivity timeout
    let watcher_stop = Arc::clone(&should_stop);
    let watcher_accessed = Arc::clone(&last_accessed);
    let watcher_key = Arc::clone(&master_key);
    let watcher_socket = socket_path.clone();

    std::thread::spawn(move || {
        let timeout = Duration::from_secs(timeout_secs);
        while !watcher_stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(1));
            let elapsed = {
                let lock = watcher_accessed.lock().unwrap();
                lock.elapsed()
            };
            if elapsed >= timeout {
                // Auto-lock
                let mut key = watcher_key.lock().unwrap();
                key.zeroize();
                watcher_stop.store(true, Ordering::SeqCst);
                let _ = fs::remove_file(&watcher_socket);
                break;
            }
        }
    });

    while !should_stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                {
                    let mut lock = last_accessed.lock().unwrap();
                    *lock = Instant::now();
                }

                let mk = Arc::clone(&master_key);
                let stop = Arc::clone(&should_stop);
                let accessed = Arc::clone(&last_accessed);
                let sock_file = socket_path.clone();

                std::thread::spawn(move || {
                    let _ = handle_client(stream, mk, stop, accessed, timeout_secs, &sock_file);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                break;
            }
        }
    }

    let _ = fs::remove_file(&socket_path);
    let mut key = master_key.lock().unwrap();
    key.zeroize();

    Ok(())
}

fn handle_client(
    mut stream: UnixStream,
    master_key: Arc<Mutex<Zeroizing<[u8; 32]>>>,
    should_stop: Arc<AtomicBool>,
    last_accessed: Arc<Mutex<Instant>>,
    timeout_secs: u64,
    socket_path: &Path,
) -> Result<(), std::io::Error> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }

    let req: DaemonRequest = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            let resp = DaemonResponse::Error(e.to_string());
            let mut out = serde_json::to_string(&resp).unwrap();
            out.push('\n');
            let _ = stream.write_all(out.as_bytes());
            return Ok(());
        }
    };

    let response = match req {
        DaemonRequest::Ping => DaemonResponse::Pong,
        DaemonRequest::GetMasterKey => {
            let key_guard = master_key.lock().unwrap();
            let hex_key = hex::encode(key_guard.as_slice());
            DaemonResponse::MasterKey(hex_key)
        }
        DaemonRequest::Lock => {
            let mut key_guard = master_key.lock().unwrap();
            key_guard.zeroize();
            should_stop.store(true, Ordering::SeqCst);
            let _ = fs::remove_file(socket_path);
            DaemonResponse::Locked
        }
        DaemonRequest::Status => {
            let elapsed = {
                let lock = last_accessed.lock().unwrap();
                lock.elapsed().as_secs()
            };
            let remaining = timeout_secs.saturating_sub(elapsed);
            DaemonResponse::Status {
                unlocked: !should_stop.load(Ordering::SeqCst),
                remaining_seconds: remaining,
                auto_lock_timeout: timeout_secs,
            }
        }
    };

    let mut out = serde_json::to_string(&response).unwrap();
    out.push('\n');
    stream.write_all(out.as_bytes())?;
    Ok(())
}

// Minimal hex encode/decode to avoid extra dependencies
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }

    pub fn decode_to_slice(hex: &str, out: &mut [u8]) -> Result<(), ()> {
        if hex.len() != out.len() * 2 {
            return Err(());
        }
        for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            let high = val(chunk[0])?;
            let low = val(chunk[1])?;
            out[i] = (high << 4) | low;
        }
        Ok(())
    }

    fn val(c: u8) -> Result<u8, ()> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_roundtrip() {
        let original = [42u8; 32];
        let enc = hex::encode(&original);
        assert_eq!(enc.len(), 64);
        let mut decoded = [0u8; 32];
        hex::decode_to_slice(&enc, &mut decoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_daemon_ipc_flow() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("test_daemon.sock");
        let key = [99u8; 32];

        // Start listener manually in a thread
        let listener = UnixListener::bind(&socket_path).unwrap();
        let master_key = Arc::new(Mutex::new(Zeroizing::new(key)));
        let should_stop = Arc::new(AtomicBool::new(false));
        let last_accessed = Arc::new(Mutex::new(Instant::now()));

        let mk = Arc::clone(&master_key);
        let stop = Arc::clone(&should_stop);
        let accessed = Arc::clone(&last_accessed);
        let sock_path_clone = socket_path.clone();

        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_client(stream, mk, stop, accessed, 60, &sock_path_clone).unwrap();
        });

        // Test GetMasterKey
        let resp = send_request(&socket_path, &DaemonRequest::GetMasterKey).unwrap();
        match resp {
            DaemonResponse::MasterKey(hex_key) => {
                let mut decoded = [0u8; 32];
                hex::decode_to_slice(&hex_key, &mut decoded).unwrap();
                assert_eq!(decoded, key);
            }
            _ => panic!("Expected MasterKey response"),
        }

        handle.join().unwrap();
    }
}
