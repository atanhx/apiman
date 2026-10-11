use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub fn harden_process() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
}

pub fn lock_memory(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        libc::mlock(ptr as *const libc::c_void, len);
    }
}

pub fn unlock_memory(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
}

pub fn read_secure_password(prompt: &str) -> std::io::Result<String> {
    use std::io::{self, IsTerminal, Write};
    if io::stdin().is_terminal() {
        if !prompt.is_empty() {
            eprint!("{prompt}");
            io::stderr().flush()?;
        }
        rpassword::prompt_password("")
    } else {
        if !prompt.is_empty() {
            eprint!("{prompt}");
            let _ = io::stderr().flush();
        }
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        Ok(line)
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretString {
    inner: String,
}

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            inner: value.into(),
        }
    }

    pub fn expose_secret(&self) -> &str {
        &self.inner
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl ZeroizeOnDrop for SecretString {}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.expose_secret())
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::new(s))
    }
}
