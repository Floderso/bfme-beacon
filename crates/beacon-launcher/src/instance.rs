//! One running launcher per data directory (i.e. per `--instance`): a named mutex
//! (`Local\BFME-Beacon-<hash of the data dir>`) plus `running.json` with the port
//! and token of a loopback handover listener. A second start finds the mutex taken,
//! reads the file and sends the running instance an [`Action`] ([`hand_over`]):
//! `Activate` (a plain second start: the running app publishes `Change::Activate`,
//! the UI opens the browser) or `Quit` (`Beacon.exe stop`: graceful shutdown, also
//! for scripts that cannot deliver Ctrl+C to a native Windows process).

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{debug, info};

use crate::paths::DataDirs;
use crate::sys::NamedMutex;
use crate::util;

/// Largest handover request line.
const MAX_LINE: u64 = 1024;
/// Handover I/O timeout.
const HANDOVER_TIMEOUT: Duration = Duration::from_secs(3);
/// Largest `running.json`.
const MAX_RUNNING_FILE: u64 = 4096;

/// Contents of `running.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunningInfo {
    /// Process id of the running launcher.
    pub pid: u32,
    /// Loopback port of its handover listener.
    pub port: u16,
    /// Secret the second start must present.
    pub token: String,
    /// Start time (ms since the Unix epoch).
    pub started_at_ms: u64,
}

/// What a second start asks the running instance to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Show yourself (open the UI).
    Activate,
    /// Shut down gracefully.
    Quit,
}

/// A handover request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Request {
    token: String,
    action: Action,
}

/// Result of [`acquire`].
#[derive(Debug)]
pub enum Acquire {
    /// This process is the instance.
    Acquired(InstanceLock),
    /// Another process runs this instance (its `running.json`, if readable).
    Running(Option<RunningInfo>),
}

/// The mutex, held while the app runs.
#[derive(Debug)]
pub struct InstanceLock {
    _mutex: NamedMutex,
    file: PathBuf,
}

/// Takes the instance mutex of `data`.
pub fn acquire(data: &DataDirs) -> io::Result<Acquire> {
    let (mutex, existed) = NamedMutex::create(&data.mutex_name())?;
    if existed {
        let info = util::read_bounded(&data.running_file(), MAX_RUNNING_FILE)
            .ok()
            .and_then(|t| serde_json::from_slice(&t).ok());
        return Ok(Acquire::Running(info));
    }
    Ok(Acquire::Acquired(InstanceLock {
        _mutex: mutex,
        file: data.running_file(),
    }))
}

/// The published instance: listener + `running.json` (removed on drop).
#[derive(Debug)]
pub struct InstanceGuard {
    _lock: InstanceLock,
    file: PathBuf,
    token: String,
    task: JoinHandle<()>,
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        self.task.abort();
        let ours = util::read_bounded(&self.file, MAX_RUNNING_FILE)
            .ok()
            .and_then(|t| serde_json::from_slice::<RunningInfo>(&t).ok())
            .is_some_and(|i| i.token == self.token);
        if ours {
            let _ = std::fs::remove_file(&self.file);
        }
    }
}

impl InstanceLock {
    /// Starts the handover listener on `127.0.0.1:0` and writes `running.json`;
    /// `on_request` runs (inside the runtime) for every valid request.
    pub async fn publish(self, on_request: impl Fn(Action) + Send + Sync + 'static) -> io::Result<InstanceGuard> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let port = listener.local_addr()?.port();
        let token = util::random_hex_token()?;
        let info = RunningInfo {
            pid: std::process::id(),
            port,
            token: token.clone(),
            started_at_ms: util::unix_ms(),
        };
        let json = serde_json::to_vec_pretty(&info).map_err(io::Error::other)?;
        util::write_atomic(&self.file, &json)?;
        let expected = token.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                // One request at a time; slow or bogus clients are cut off.
                match tokio::time::timeout(HANDOVER_TIMEOUT, serve(stream, &expected, &on_request)).await {
                    Ok(Ok(true)) => {}
                    Ok(Ok(false)) => debug!(%peer, "handover request refused"),
                    Ok(Err(e)) => debug!(%peer, "handover: {e}"),
                    Err(_) => debug!(%peer, "handover timeout"),
                }
            }
        });
        let file = self.file.clone();
        Ok(InstanceGuard {
            _lock: self,
            file,
            token,
            task,
        })
    }
}

async fn serve(stream: TcpStream, expected: &str, on_request: &(dyn Fn(Action) + Send + Sync)) -> io::Result<bool> {
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    BufReader::new(read.take(MAX_LINE)).read_line(&mut line).await?;
    let action = serde_json::from_str::<Request>(line.trim())
        .ok()
        .filter(|r| util::ct_eq(r.token.as_bytes(), expected.as_bytes()))
        .map(|r| r.action);
    let ok = action.is_some();
    if let Some(action) = action {
        info!("another start requested {action:?}");
        on_request(action);
    }
    write.write_all(if ok { b"ok\n" } else { b"no\n" }).await?;
    Ok(ok)
}

/// Sends `action` to the running instance.
pub async fn hand_over(info: &RunningInfo, action: Action) -> io::Result<()> {
    let attempt = async {
        let mut stream = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], info.port))).await?;
        let req = Request {
            token: info.token.clone(),
            action,
        };
        let mut line = serde_json::to_vec(&req).map_err(io::Error::other)?;
        line.push(b'\n');
        stream.write_all(&line).await?;
        let mut answer = Vec::new();
        stream.take(16).read_to_end(&mut answer).await?;
        if answer.starts_with(b"ok") {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "handover refused"))
        }
    };
    tokio::time::timeout(HANDOVER_TIMEOUT, attempt)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no answer from the running instance"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn second_start_hands_over() {
        let base = std::env::temp_dir().join(format!("beacon-instance-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let data = DataDirs::with_base(base.clone(), 1).unwrap();
        let Acquire::Acquired(lock) = acquire(&data).unwrap() else {
            panic!("first acquire must succeed");
        };
        let hits = Arc::new(AtomicU32::new(0));
        let quits = Arc::new(AtomicU32::new(0));
        let (h, q) = (Arc::clone(&hits), Arc::clone(&quits));
        let guard = lock.publish(move |action| {
            let counter = if action == Action::Quit { &q } else { &h };
            counter.fetch_add(1, Ordering::SeqCst);
        })
        .await
        .unwrap();
        #[cfg(windows)]
        {
            let Acquire::Running(Some(info)) = acquire(&data).unwrap() else {
                panic!("second acquire must see the running instance");
            };
            assert_eq!(info.pid, std::process::id());
            hand_over(&info, Action::Activate).await.unwrap();
            assert_eq!(hits.load(Ordering::SeqCst), 1);
            hand_over(&info, Action::Quit).await.unwrap();
            assert_eq!(quits.load(Ordering::SeqCst), 1);
            let wrong = RunningInfo {
                token: "0".repeat(32),
                ..info
            };
            assert!(hand_over(&wrong, Action::Quit).await.is_err());
            assert_eq!(quits.load(Ordering::SeqCst), 1);
            assert_eq!(hits.load(Ordering::SeqCst), 1);
            // Other instances are independent.
            let two = DataDirs::with_base(base.clone(), 2).unwrap();
            assert!(matches!(acquire(&two).unwrap(), Acquire::Acquired(_)));
        }
        let file = data.running_file();
        assert!(file.exists());
        drop(guard);
        assert!(!file.exists(), "running.json removed on exit");
        let _ = std::fs::remove_dir_all(&base);
    }
}
