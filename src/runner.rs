use std::io::{self, Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Values shorter than this are not masked: they are too likely to collide
/// with ordinary output ("true", "8080") to be worth hiding.
pub const MIN_MASK_LEN: usize = 6;

/// Replaces secret values in a byte stream with `[REDACTED:NAME]`, including
/// values split across reads.
pub struct Masker {
    // (secret bytes, replacement), longest first so overlapping values mask fully
    secrets: Vec<(Zeroizing<Vec<u8>>, Vec<u8>)>,
}

impl Masker {
    pub fn new<'a, I: IntoIterator<Item = (&'a str, &'a str)>>(pairs: I) -> Self {
        let mut secrets: Vec<(Zeroizing<Vec<u8>>, Vec<u8>)> = Vec::new();
        for (name, value) in pairs {
            if value.len() < MIN_MASK_LEN
                || secrets
                    .iter()
                    .any(|(s, _)| s.as_slice() == value.as_bytes())
            {
                continue;
            }
            secrets.push((
                Zeroizing::new(value.as_bytes().to_vec()),
                format!("[REDACTED:{name}]").into_bytes(),
            ));
        }
        secrets.sort_by_key(|(s, _)| std::cmp::Reverse(s.len()));
        Self { secrets }
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Masks complete matches in `pending`, appends the safe prefix to `out`,
    /// and leaves only a possible partial secret at the end of `pending`.
    pub fn process(&self, pending: &mut Zeroizing<Vec<u8>>, out: &mut Vec<u8>, at_eof: bool) {
        let buf = pending.as_slice();
        let mut i = 0;
        let mut hold_from: Option<usize> = None;

        while i < buf.len() {
            let mut best: Option<(usize, usize)> = None;
            for (k, (secret, _)) in self.secrets.iter().enumerate() {
                if let Some(p) = find(&buf[i..], secret) {
                    let pos = i + p;
                    if best.is_none_or(|(bp, _)| pos < bp) {
                        best = Some((pos, k));
                    }
                }
            }
            let Some((pos, k)) = best else { break };
            // A longer secret may start here but not be complete yet.
            if !at_eof
                && self.secrets.iter().any(|(s, _)| {
                    s.len() > self.secrets[k].0.len() && is_proper_prefix(&buf[pos..], s)
                })
            {
                hold_from = Some(pos);
                break;
            }
            out.extend_from_slice(&buf[i..pos]);
            out.extend_from_slice(&self.secrets[k].1);
            i = pos + self.secrets[k].0.len();
        }

        let flush_end = match hold_from {
            Some(p) => p,
            None if at_eof => buf.len(),
            None => buf.len() - self.partial_suffix_len(&buf[i..]),
        };
        out.extend_from_slice(&buf[i..flush_end]);
        pending.drain(..flush_end);
    }

    fn partial_suffix_len(&self, rest: &[u8]) -> usize {
        let mut longest = 0;
        for (secret, _) in &self.secrets {
            let max = (secret.len() - 1).min(rest.len());
            for l in (longest + 1..=max).rev() {
                if rest[rest.len() - l..] == secret[..l] {
                    longest = l;
                    break;
                }
            }
        }
        longest
    }
}

fn is_proper_prefix(candidate: &[u8], secret: &[u8]) -> bool {
    candidate.len() < secret.len() && secret.starts_with(candidate)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    let first = needle[0];
    (0..=haystack.len() - needle.len())
        .find(|&i| haystack[i] == first && &haystack[i..i + needle.len()] == needle)
}

fn pump(mut from: impl Read, mut to: impl Write, masker: &Masker) {
    let mut pending = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new(vec![0u8; 8192]);
    let mut out = Vec::new();
    loop {
        let n = match from.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        pending.extend_from_slice(&chunk[..n]);
        out.clear();
        masker.process(&mut pending, &mut out, false);
        // Reader goes away on a closed pipe so the child sees SIGPIPE too.
        if to.write_all(&out).and_then(|_| to.flush()).is_err() {
            return;
        }
    }
    out.clear();
    masker.process(&mut pending, &mut out, true);
    let _ = to.write_all(&out).and_then(|_| to.flush());
}

static CHILD_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward_signal(sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

fn exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1)
}

/// Runs `cmd` with stdout/stderr piped through `masker`. Termination signals
/// sent to apiman are forwarded so the child decides how to exit, and the
/// child's exit status is returned unchanged.
pub fn run_masked(mut cmd: Command, masker: Masker) -> io::Result<i32> {
    use std::io::IsTerminal;
    use std::os::unix::process::CommandExt;

    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(target_os = "linux")]
    unsafe {
        // Never outlive apiman (e.g. when an agent tool SIGKILLs it on timeout).
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    CHILD_PID.store(child.id() as i32, Ordering::SeqCst);

    // A terminal already delivers Ctrl+C to the whole foreground group; only
    // relay SIGINT/SIGQUIT ourselves when there is no terminal (agents, CI).
    let interactive = io::stdin().is_terminal();
    unsafe {
        let handler = forward_signal as *const () as libc::sighandler_t;
        for sig in [libc::SIGTERM, libc::SIGHUP] {
            libc::signal(sig, handler);
        }
        for sig in [libc::SIGINT, libc::SIGQUIT] {
            libc::signal(sig, if interactive { libc::SIG_IGN } else { handler });
        }
    }

    let masker = Arc::new(masker);
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let (m1, tx1) = (Arc::clone(&masker), done_tx.clone());
    std::thread::spawn(move || {
        pump(stdout, io::stdout(), &m1);
        let _ = tx1.send(());
    });
    let (m2, tx2) = (Arc::clone(&masker), done_tx);
    std::thread::spawn(move || {
        pump(stderr, io::stderr(), &m2);
        let _ = tx2.send(());
    });

    let status = child.wait()?;
    // A backgrounded grandchild may keep the pipes open forever; drain what
    // is already there, then stop waiting.
    let deadline = Instant::now() + Duration::from_secs(2);
    for _ in 0..2 {
        if done_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .is_err()
        {
            break;
        }
    }
    CHILD_PID.store(0, Ordering::SeqCst);
    Ok(exit_code(status))
}
