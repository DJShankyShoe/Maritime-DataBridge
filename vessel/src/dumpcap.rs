//! # Dumpcap Supervisor
//!
//! dumpcap runs as a separate, prebuilt binary with raw-capture privileges
//! granted via `setcap`, keeping the parent daemon unprivileged.
//!
//! The daemon manages the child's entire lifecycle and derives its arguments 
//! directly from the daemon's own configuration as a single source of truth. 
//! During startup, the reader creates the FIFO and holds an `O_RDWR` end open, 
//! ensuring dumpcap's subsequent open call never blocks. It automatically 
//! restarts the process on exit using exponential backoff.
//!
//! Managing the process here rather than via a dedicated `systemd` unit introduces 
//! a trade-off: a daemon restart will also stop dumpcap, causing a brief capture 
//! gap and a fresh Section Header Block (SHB). `kill_on_drop` ensures that dropping 
//! the supervisor future tears down the child process cleanly.


use std::future::Future;
use std::time::Duration;

use noc_common::config::CaptureConfig;
use tokio::sync::watch;
use tokio::time::Instant;

/// Located via `PATH`; update the service's `PATH` or use a symlink if needed.
pub use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;

/// File descriptor assigned to the FIFO in the child process and used by
/// `-w /dev/fd/3`. Any descriptor above stdio can be used.
const CHILD_FIFO_FD: RawFd = 3;

const DUMPCAP_BIN: &str = "dumpcap";

/// Exponential-backoff restart policy.
#[derive(Debug, Clone, Copy)]
pub struct BackoffPolicy {
    pub initial: Duration,
    pub max: Duration,
    /// An instance that ran at least this long counts as healthy, resetting the
    /// backoff so a one-off crash after hours of uptime restarts promptly.
    pub reset_after: Duration,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(500),
            max: Duration::from_secs(30),
            reset_after: Duration::from_secs(60),
        }
    }
}

/// Builds dumpcap's arguments from the capture configuration.
///
/// Each interface gets its own `-i` and `-B` buffer size, producing a merged
/// pcapng stream with separate Interface Description Blocks (IDBs). `-q` suppresses 
/// dumpcap's output, as logging is handled by `tracing`.
///
/// `-w` uses an inherited file descriptor instead of `pipe_path`. When dumpcap 
/// fails to start (e.g., if a capture interface does not exist yet), it deletes its 
/// output path. This previously stranded the reader on a deleted pipe and silently 
/// stopped capture until the service restarted. Passing a descriptor avoids this 
/// entirely, as it has no path to delete.
///
/// pcapng is the default and required for multi-interface capture. `-P` (legacy pcap) 
/// is omitted because the downstream pipeline relies strictly on pcapng block structure.

pub fn build_argv(cfg: &CaptureConfig) -> Vec<String> {
    let mut argv = Vec::new();
    for iface in &cfg.interfaces {
        argv.push("-i".to_string());
        argv.push(iface.clone());
        argv.push("-B".to_string());
        argv.push(cfg.libpcap_buffer_size_mb.to_string());
    }
    argv.push("-w".to_string());
    argv.push(format!("/dev/fd/{CHILD_FIFO_FD}"));
    argv.push("-q".to_string());
    argv
}

/// Supervise dumpcap until shutdown flips, runs dumpcap for the lifetime of the daemon. 
///
/// Keeps the FIFO from [`crate::fifo::open_fifo`] open while supervising dumpcap
/// and passes it to each child as [`CHILD_FIFO_FD`].
///
/// A bump to `restart` replaces the running process. The reader uses this
/// after stream desynchronisation, as a fresh dumpcap provides the section
/// header needed to resume parsing.
pub async fn supervise(
    cfg: &CaptureConfig,
    fifo: std::fs::File,
    shutdown: watch::Receiver<bool>,
    restart: watch::Receiver<u64>,
) {
    let argv = build_argv(cfg);
    let fifo_fd = fifo.as_raw_fd();
    tracing::info!(bin = DUMPCAP_BIN, ?argv, pipe = %cfg.pipe_path.display(), "supervising dumpcap");
    supervise_with(
        move |attempt| run_dumpcap_once(argv.clone(), fifo_fd, attempt),
        BackoffPolicy::default(),
        shutdown,
        restart,
    )
    .await;
}

/// Spawn one instance and wait for it to exit. Dropping this future kills the
/// child.
async fn run_dumpcap_once(argv: Vec<String>, fifo_fd: RawFd, attempt: u64) {
    let mut cmd = tokio::process::Command::new(DUMPCAP_BIN);
    cmd.args(&argv).kill_on_drop(true);
    // Put the FIFO on CHILD_FIFO_FD for the child. Rust opens files close-on-exec, so
    // the descriptor only survives exec because dup2 produces a copy without that flag
    // (or, when it already sits on the right number, because we clear the flag).
    unsafe {
        cmd.as_std_mut().pre_exec(move || {
            let rc = if fifo_fd == CHILD_FIFO_FD {
                libc::fcntl(fifo_fd, libc::F_SETFD, 0)
            } else {
                libc::dup2(fifo_fd, CHILD_FIFO_FD)
            };
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let spawn_result = cmd.spawn();

    match spawn_result {
        Ok(mut child) => match child.wait().await {
            Ok(status) => {
                tracing::warn!(attempt, ?status, "dumpcap exited");
            }
            Err(e) => {
                tracing::error!(attempt, error = %e, "failed waiting on dumpcap");
            }
        },
        Err(e) => {
            tracing::error!(attempt, error = %e, "failed to spawn dumpcap");
        }
    }
}

/// Keeps the supervision loop separate from process spawning so restart and
/// backoff behaviour can be tested without launching real processes.
async fn supervise_with<Run, Fut>(
    mut run_once: Run,
    policy: BackoffPolicy,
    mut shutdown: watch::Receiver<bool>,
    mut restart: watch::Receiver<u64>,
) where
    Run: FnMut(u64) -> Fut,
    Fut: Future<Output = ()>,
{
    let mut backoff = policy.initial;
    let mut attempt: u64 = 0;
    // Guards the restart arm: a dropped sender makes `changed()` return immediately and
    // forever, which would otherwise spin the loop killing every new instance.
    let mut restart_open = true;

    loop {
        if *shutdown.borrow() {
            return;
        }

        let started = Instant::now();
        tokio::select! {
            _ = run_once(attempt) => {}
            // Dropping the run_once future kills the child in both arms below.
            r = restart.changed(), if restart_open => {
                match r {
                    Ok(()) => tracing::warn!("replacing dumpcap: the reader asked for a fresh capture stream"),
                    Err(_) => restart_open = false,
                }
            }
            _ = shutdown.changed() => return,
        }
        attempt += 1;

        // Reset after a healthy run, otherwise grow towards the cap.
        if started.elapsed() >= policy.reset_after {
            backoff = policy.initial;
        } else {
            backoff = (backoff * 2).min(policy.max);
        }

        tracing::info!(attempt, backoff_ms = backoff.as_millis() as u64, "restarting dumpcap after backoff");
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = shutdown.changed() => return,
        }
    }
}
