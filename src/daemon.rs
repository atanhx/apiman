use crate::security::{harden_process, lock_memory};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonRequest {
    GetMasterKey,
    UpdateMasterKey(String),
    UpdateTimeout(u64),
    Lock,
    Status,
    Ping,
    /// Resets the inactivity timer without transferring the key.
    Touch,
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

    let mut msg = Zeroizing::new(serde_json::to_string(req)?);
    msg.push('\n');
    stream.write_all(msg.as_bytes())?;

    let mut reader = BufReader::new(stream);
    let mut resp_line = Zeroizing::new(String::new());
    reader.read_line(&mut resp_line)?;

    let resp: DaemonResponse = serde_json::from_str(&resp_line)?;
    Ok(resp)
}

pub fn get_cached_master_key(socket_path: &Path) -> Option<Zeroizing<[u8; 32]>> {
    match send_request(socket_path, &DaemonRequest::GetMasterKey) {
        Ok(DaemonResponse::MasterKey(hex_str)) => {
            let hex_str = Zeroizing::new(hex_str);
            let mut bytes = Zeroizing::new([0u8; 32]);
            if hex::decode_to_slice(&hex_str, bytes.as_mut()).is_ok()
                && bytes.iter().any(|&b| b != 0)
            {
                return Some(bytes);
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

pub fn update_daemon_master_key(
    socket_path: &Path,
    new_key: &[u8; 32],
) -> Result<(), DaemonClientError> {
    if !socket_path.exists() {
        return Ok(());
    }
    let hex_key = Zeroizing::new(hex::encode(new_key));
    let _ = send_request(
        socket_path,
        &DaemonRequest::UpdateMasterKey(hex_key.to_string()),
    );
    Ok(())
}

pub fn update_daemon_timeout(
    socket_path: &Path,
    new_timeout: u64,
) -> Result<(), DaemonClientError> {
    if !socket_path.exists() {
        return Ok(());
    }
    let _ = send_request(socket_path, &DaemonRequest::UpdateTimeout(new_timeout));
    Ok(())
}

pub fn touch_daemon(socket_path: &Path) -> bool {
    matches!(
        send_request(socket_path, &DaemonRequest::Touch),
        Ok(DaemonResponse::Pong)
    )
}

pub fn check_daemon_status(socket_path: &Path) -> Option<(bool, u64, u64)> {
    match send_request(socket_path, &DaemonRequest::Status) {
        Ok(DaemonResponse::Status {
            unlocked,
            remaining_seconds,
            auto_lock_timeout,
        }) => Some((unlocked, remaining_seconds, auto_lock_timeout)),
        _ => None,
    }
}

/// Start a helper as its own session: no controlling terminal, so Ctrl+C in
/// the shell (or closing it) does not kill it, and it does not pin the cwd.
pub fn detached_command(program: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd
}

/// Reap a detached child in the background so long-lived parents (the TUI)
/// never accumulate zombies.
pub fn reap_in_background(mut child: std::process::Child) {
    std::thread::spawn(move || {
        let _ = child.wait();
    });
}

pub fn spawn_daemon(
    key: &[u8; 32],
    timeout_secs: u64,
    socket_path: &Path,
) -> Result<(), std::io::Error> {
    if let Ok(DaemonResponse::Pong) = send_request(socket_path, &DaemonRequest::Ping) {
        return Ok(());
    }

    let _ = fs::remove_file(socket_path);

    let current_exe = std::env::current_exe()?;
    let mut child = detached_command(&current_exe)
        .arg("daemon")
        .arg("--run")
        .arg("--timeout")
        .arg(timeout_secs.to_string())
        .arg("--socket")
        .arg(socket_path)
        .spawn()?;

    let written = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(key).and_then(|_| stdin.flush()),
        None => Ok(()),
    };
    reap_in_background(child);
    written?;

    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(50));
        if let Ok(DaemonResponse::Pong) = send_request(socket_path, &DaemonRequest::Ping) {
            return Ok(());
        }
    }

    Err(std::io::Error::other(format!(
        "session daemon did not start on '{}'",
        socket_path.display()
    )))
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0).then_some(cred.uid)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    (rc == 0).then_some(uid)
}

const IDLE_RECHECK: Duration = Duration::from_secs(30);

struct DaemonState {
    master_key: Mutex<Zeroizing<[u8; 32]>>,
    timeout_secs: AtomicU64,
    last_accessed: Mutex<Instant>,
    should_stop: AtomicBool,
    socket_path: PathBuf,
}

impl DaemonState {
    fn touch(&self) {
        *self.last_accessed.lock().unwrap() = Instant::now();
    }

    fn shutdown(&self) {
        self.master_key.lock().unwrap().zeroize();
        self.should_stop.store(true, Ordering::SeqCst);
        let _ = fs::remove_file(&self.socket_path);
    }
}

pub fn run_daemon_loop(timeout_secs: u64, socket_path: PathBuf) -> Result<(), std::io::Error> {
    harden_process();

    let state = Arc::new(DaemonState {
        master_key: Mutex::new(Zeroizing::new([0u8; 32])),
        timeout_secs: AtomicU64::new(timeout_secs),
        last_accessed: Mutex::new(Instant::now()),
        should_stop: AtomicBool::new(false),
        socket_path: socket_path.clone(),
    });

    {
        // Read straight into the long-lived (locked) buffer: no stray stack copy.
        let mut key = state.master_key.lock().unwrap();
        lock_memory(key.as_ptr(), key.len());
        std::io::stdin().read_exact(key.as_mut())?;
    }

    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _ = fs::remove_file(&socket_path);

    // Create the socket 0600 from the start instead of chmod-ing it afterwards.
    let old_umask = unsafe { libc::umask(0o177) };
    let bound = UnixListener::bind(&socket_path);
    unsafe { libc::umask(old_umask) };
    let listener = bound?;

    // The watcher sleeps until the inactivity deadline (re-checking at most
    // every 30s so timeout changes apply), so an idle daemon costs no CPU.
    let watcher = Arc::clone(&state);
    std::thread::spawn(move || {
        loop {
            let timeout = watcher.timeout_secs.load(Ordering::SeqCst);
            let wait = if timeout == 0 {
                IDLE_RECHECK
            } else {
                let elapsed = watcher.last_accessed.lock().unwrap().elapsed();
                let limit = Duration::from_secs(timeout);
                if elapsed >= limit {
                    watcher.shutdown();
                    std::process::exit(0);
                }
                (limit - elapsed).min(IDLE_RECHECK)
            };
            std::thread::sleep(wait);
        }
    });

    let my_uid = unsafe { libc::geteuid() };
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if peer_uid(&stream) != Some(my_uid) {
                    continue;
                }
                let st = Arc::clone(&state);
                std::thread::spawn(move || {
                    let _ = handle_client(stream, &st);
                    if st.should_stop.load(Ordering::SeqCst) {
                        std::process::exit(0);
                    }
                });
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::ConnectionAborted
                ) => {}
            Err(_) => break,
        }
    }

    state.shutdown();
    Ok(())
}

fn handle_client(stream: UnixStream, state: &DaemonState) -> Result<(), std::io::Error> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let mut line = Zeroizing::new(String::new());
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }

    let stopping = state.should_stop.load(Ordering::SeqCst);
    let response = match serde_json::from_str::<DaemonRequest>(&line) {
        Err(e) => DaemonResponse::Error(e.to_string()),
        Ok(DaemonRequest::Ping) => DaemonResponse::Pong,
        Ok(_) if stopping => DaemonResponse::Locked,
        Ok(DaemonRequest::Touch) => {
            state.touch();
            DaemonResponse::Pong
        }
        Ok(DaemonRequest::GetMasterKey) => {
            state.touch();
            let key = state.master_key.lock().unwrap();
            DaemonResponse::MasterKey(hex::encode(key.as_slice()))
        }
        Ok(DaemonRequest::UpdateMasterKey(hex_key)) => {
            let hex_key = Zeroizing::new(hex_key);
            let mut bytes = Zeroizing::new([0u8; 32]);
            if hex::decode_to_slice(&hex_key, bytes.as_mut()).is_ok() {
                state
                    .master_key
                    .lock()
                    .unwrap()
                    .copy_from_slice(bytes.as_ref());
                state.touch();
                DaemonResponse::Pong
            } else {
                DaemonResponse::Error("Invalid key format".to_string())
            }
        }
        Ok(DaemonRequest::UpdateTimeout(new_secs)) => {
            state.timeout_secs.store(new_secs, Ordering::SeqCst);
            state.touch();
            DaemonResponse::Pong
        }
        Ok(DaemonRequest::Lock) => {
            state.shutdown();
            DaemonResponse::Locked
        }
        Ok(DaemonRequest::Status) => {
            let timeout = state.timeout_secs.load(Ordering::SeqCst);
            let elapsed = state.last_accessed.lock().unwrap().elapsed().as_secs();
            DaemonResponse::Status {
                unlocked: true,
                remaining_seconds: if timeout == 0 {
                    0
                } else {
                    timeout.saturating_sub(elapsed)
                },
                auto_lock_timeout: timeout,
            }
        }
    };

    let mut out = Zeroizing::new(serde_json::to_string(&response).unwrap_or_default());
    out.push('\n');
    writer.write_all(out.as_bytes())?;
    if let DaemonResponse::MasterKey(mut hex_key) = response {
        hex_key.zeroize();
    }
    Ok(())
}

// Minimal hex encode/decode to avoid extra dependencies
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(DIGITS[(b >> 4) as usize] as char);
            s.push(DIGITS[(b & 0x0f) as usize] as char);
        }
        s
    }

    pub fn decode_to_slice(hex: &str, out: &mut [u8]) -> Result<(), ()> {
        if hex.len() != out.len() * 2 {
            return Err(());
        }
        for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            out[i] = (val(chunk[0])? << 4) | val(chunk[1])?;
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
