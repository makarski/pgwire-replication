use crate::config::ReplicationConfig;
use crate::error::{PgWireError, Result};
use crate::lsn::Lsn;

use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;

use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinError, JoinHandle};

use std::sync::Arc;
use std::time::Duration;

#[cfg(not(feature = "tls-rustls"))]
use crate::config::SslMode;

use super::metrics::ReplicationMetrics;
use super::worker::{ReplicationEvent, ReplicationEventReceiver, SharedProgress, WorkerState};

/// PostgreSQL logical replication client.
///
/// This client spawns a background worker task that maintains the replication
/// connection and streams events to the consumer via a bounded channel.
///
/// # Example
///
/// ```no_run
/// use pgwire_replication::client::{ReplicationClient, ReplicationEvent};
/// use pgwire_replication::config::ReplicationConfig;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = ReplicationConfig::new(
///         "localhost",
///         "postgres",
///         "password",
///         "mydb",
///         "my_slot",
///         "my_pub",
///     );
///
///     let mut client = ReplicationClient::connect(config).await?;
///
///     while let Some(ev) = client.recv().await? {
///         match ev {
///             ReplicationEvent::XLogData { data, wal_end, .. } => {
///                 process_change(&data);
///                 client.update_applied_lsn(wal_end);
///             }
///             ReplicationEvent::KeepAlive { .. } => {}
///             ReplicationEvent::StoppedAt { reached } => {
///                 println!("Reached stop LSN: {reached}");
///                 break;
///             }
///             _ => {}
///         }
///     }
///
///     Ok(())
/// }
///
/// fn process_change(_data: &bytes::Bytes) {
///     // user-defined
/// }
/// ```
pub struct ReplicationClient {
    rx: ReplicationEventReceiver,
    progress: Arc<SharedProgress>,
    stop_tx: watch::Sender<bool>,
    metrics: Arc<ReplicationMetrics>,
    join: Option<WorkerHandle>,
}

type WorkerHandle = JoinHandle<std::result::Result<(), PgWireError>>;

impl ReplicationClient {
    /// Connect to PostgreSQL and start streaming replication events.
    ///
    /// This establishes a TCP connection (optionally upgrading to TLS),
    /// authenticates, and starts the replication stream. It returns once the
    /// server has accepted `START_REPLICATION`, so a failure in any of those
    /// steps is returned here rather than from the first
    /// [`recv()`](Self::recv). Events are buffered in a channel of size
    /// `config.buffer_events`.
    ///
    /// `config.connect_timeout` bounds the whole wait.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - TCP connection fails
    /// - TLS handshake fails (when enabled)
    /// - Authentication fails
    /// - Replication slot doesn't exist
    /// - Publication doesn't exist
    /// - Unix socket does not exist (when host starts with `/`)
    /// - TLS requested with Unix socket connection
    /// - The stream did not start within `config.connect_timeout`
    pub async fn connect(cfg: ReplicationConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(cfg.buffer_events);

        // Progress is shared via atomics: cheap, monotonic, no async backpressure.
        let progress = Arc::new(SharedProgress::new(cfg.start_lsn));

        let (stop_tx, stop_rx) = watch::channel(false);
        let (ready_tx, ready_rx) = oneshot::channel();
        let connect_timeout = cfg.connect_timeout;

        let metrics = Arc::new(ReplicationMetrics::default());

        let progress_for_worker = Arc::clone(&progress);
        let metrics_for_worker = Arc::clone(&metrics);
        let cfg_for_worker = cfg.clone();

        let join = tokio::spawn(async move {
            let mut worker = WorkerState::new(
                cfg_for_worker,
                progress_for_worker,
                stop_rx,
                tx,
                metrics_for_worker,
            )
            .notify_ready(ready_tx);
            let res = run_worker(&mut worker, &cfg).await;
            if let Err(ref e) = res {
                tracing::error!("replication worker terminated with error: {e}");
            }
            res
        });
        let startup = AbortOnDrop(Some(join));
        let join = await_stream_start(ready_rx, startup, connect_timeout).await?;

        Ok(Self {
            rx,
            progress,
            stop_tx,
            metrics,
            join: Some(join),
        })
    }

    /// Receive the next replication event.
    ///
    /// - `Ok(Some(event))` => received an event
    /// - `Ok(None)`        => replication ended normally (stop requested or stop_at_lsn reached)
    /// - `Err(e)`          => replication ended abnormally
    pub async fn recv(&mut self) -> Result<Option<ReplicationEvent>> {
        match self.rx.recv().await {
            Some(Ok(ev)) => Ok(Some(ev)),
            Some(Err(e)) => Err(e),
            None => self.handle_worker_shutdown().await,
        }
    }

    async fn handle_worker_shutdown(&mut self) -> Result<Option<ReplicationEvent>> {
        let join = self
            .join
            .take()
            .ok_or_else(|| PgWireError::Internal("replication worker already joined".into()))?;

        match join.await {
            Ok(Ok(())) => Ok(None),
            Ok(Err(e)) => Err(e),
            Err(join_err) => Err(PgWireError::Task(format!(
                "replication worker panicked: {join_err}"
            ))),
        }
    }

    /// Update the applied/durable LSN reported to the server.
    ///
    /// Semantics: call this only once you have durably persisted all events up to `lsn`.
    /// This update is monotonic and cheap; wire feedback is still governed by the worker’s
    /// `status_interval` and keepalive reply requests.
    #[inline]
    pub fn update_applied_lsn(&self, lsn: Lsn) {
        self.progress.update_applied(lsn);
    }

    /// Returns a handle to the live replication metrics.
    ///
    /// The returned `Arc` shares the same counters the background worker
    /// updates, so reads reflect current progress. Cheap to clone and call
    /// repeatedly; nothing here blocks the worker.
    #[inline]
    pub fn metrics(&self) -> Arc<ReplicationMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Request the worker to stop gracefully.
    ///
    /// After calling this, [`recv()`](Self::recv) will return remaining buffered
    /// events, then `Ok(None)` once the worker exits cleanly.
    ///
    /// This sends a CopyDone message to the server to cleanly terminate
    /// the replication stream.
    #[inline]
    pub fn stop(&self) {
        let _ = self.stop_tx.send(true);
    }

    pub fn is_running(&self) -> bool {
        self.join
            .as_ref()
            .map(|j| !j.is_finished())
            .unwrap_or(false)
    }

    /// Wait for the worker task to complete and return its result.
    ///
    /// This consumes the client. Use this for diagnostics or to ensure
    /// clean shutdown after calling [`stop()`](Self::stop).
    pub async fn join(mut self) -> Result<()> {
        let join = self
            .join
            .take()
            .ok_or_else(|| PgWireError::Task("worker already joined".into()))?;

        match join.await {
            Ok(inner) => inner,
            Err(e) => Err(PgWireError::Task(format!("join error: {e}"))),
        }
    }

    /// Abort the worker task immediately.
    ///
    /// This is a hard cancel and does not send CopyDone.
    /// Prefer `stop()`/`shutdown()` for graceful termination.
    pub fn abort(&mut self) {
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }

    /// Request a graceful stop and wait for the worker to exit.
    pub async fn shutdown(&mut self) -> Result<()> {
        self.stop();

        // Drain events until the worker closes the channel.
        while let Some(msg) = self.rx.recv().await {
            match msg {
                Ok(_ev) => {} //discard; caller can drain themselves if they need events
                Err(e) => return Err(e),
            }
        }

        self.join_mut().await
    }

    /// Wait for the worker task to complete and return its result.
    async fn join_mut(&mut self) -> Result<()> {
        let join = self
            .join
            .take()
            .ok_or_else(|| PgWireError::Task("worker already joined".into()))?;

        match join.await {
            Ok(inner) => inner,
            Err(e) => Err(PgWireError::Task(format!("join error: {e}"))),
        }
    }
}

impl Drop for ReplicationClient {
    fn drop(&mut self) {
        let _ = self.stop_tx.send(true);

        // We cannot .await here. Prefer to detach a join in the background
        // so the worker can exit cleanly without being aborted.
        if let Some(join) = self.join.take() {
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    handle.spawn(async move {
                        let _ = join.await;
                    });
                }
                Err(_) => {
                    // No Tokio runtime available (dropping outside async context).
                    // Fall back to abort to avoid a potentially unbounded leaked task.
                    tracing::debug!(
                        "dropping ReplicationClient outside a Tokio runtime; aborting worker task"
                    );
                    join.abort();
                }
            }
        }
    }
}

/// Aborts the worker unless startup hands it over to the client, so a timed
/// out or cancelled `connect` does not leave the worker and its socket behind.
struct AbortOnDrop(Option<WorkerHandle>);

impl AbortOnDrop {
    fn disarm(mut self) -> WorkerHandle {
        self.0.take().expect("startup worker handle")
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(join) = self.0.take() {
            join.abort();
        }
    }
}

/// Wait until the worker has started streaming, or return why it has not.
async fn await_stream_start(
    ready: oneshot::Receiver<()>,
    startup: AbortOnDrop,
    timeout: Option<Duration>,
) -> Result<WorkerHandle> {
    let started = match timeout {
        Some(limit) => tokio::time::timeout(limit, ready).await.map_err(|_| {
            PgWireError::Io(Arc::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("replication stream did not start within {limit:?}"),
            )))
        })?,
        None => ready.await,
    };
    let join = startup.disarm();
    match started {
        Ok(()) => Ok(join),
        Err(_) => Err(startup_failure(join.await)),
    }
}

fn startup_failure(outcome: std::result::Result<Result<()>, JoinError>) -> PgWireError {
    match outcome {
        Ok(Err(e)) => e,
        Ok(Ok(())) => {
            PgWireError::Internal("replication worker exited before the stream started".into())
        }
        Err(e) => PgWireError::Task(format!("replication worker panicked: {e}")),
    }
}

async fn run_worker(worker: &mut WorkerState, cfg: &ReplicationConfig) -> Result<()> {
    #[cfg(unix)]
    if cfg.is_unix_socket() {
        if cfg.tls.mode.requires_tls() {
            return Err(PgWireError::Tls(
                "TLS is not supported over Unix domain sockets".into(),
            ));
        }

        let path = cfg.unix_socket_path();
        let mut stream = UnixStream::connect(&path).await.map_err(|e| {
            PgWireError::Io(std::sync::Arc::new(std::io::Error::new(
                e.kind(),
                format!("failed to connect to Unix socket {}: {e}", path.display()),
            )))
        })?;

        return worker.run_on_stream(&mut stream).await;
    }

    let tcp = TcpStream::connect((cfg.host.as_str(), cfg.port)).await?;
    tcp.set_nodelay(true)?;

    #[cfg(feature = "tls-rustls")]
    {
        use crate::tls::rustls::{maybe_upgrade_to_tls, MaybeTlsStream};
        let upgraded = maybe_upgrade_to_tls(tcp, &cfg.tls, &cfg.host).await?;
        match upgraded {
            MaybeTlsStream::Plain(mut s) => worker.run_on_stream(&mut s).await,
            MaybeTlsStream::Tls(mut s) => worker.run_on_stream(s.as_mut()).await,
        }
    }

    #[cfg(not(feature = "tls-rustls"))]
    {
        if !matches!(cfg.tls.mode, SslMode::Disable) {
            return Err(PgWireError::Tls("tls-rustls feature not enabled".into()));
        }
        let mut s = tcp;
        worker.run_on_stream(&mut s).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn local_server() -> (TcpListener, ReplicationConfig) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg =
            ReplicationConfig::new("127.0.0.1", "u", "p", "db", "slot", "pub").with_port(port);
        (listener, cfg)
    }

    /// Wait for the peer to close the connection; `false` if it stays open.
    async fn closed_by_peer(socket: &mut tokio::net::TcpStream) -> bool {
        use tokio::io::AsyncReadExt;

        let mut buf = [0u8; 1024];
        loop {
            match tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => return true,
                Ok(Ok(_)) => continue,
                Err(_) => return false,
            }
        }
    }

    #[tokio::test]
    async fn cancelled_connect_closes_the_startup_socket() {
        let (listener, cfg) = local_server().await;
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            accepted_tx.send(()).unwrap();
            closed_by_peer(&mut socket).await
        });

        let connecting = tokio::spawn(ReplicationClient::connect(cfg));
        accepted_rx.await.unwrap();
        connecting.abort();
        let _ = connecting.await;

        assert!(
            server.await.unwrap(),
            "cancelled connect left the startup socket open"
        );
    }

    #[tokio::test]
    async fn connect_times_out_when_the_server_never_answers() {
        let (listener, cfg) = local_server().await;
        let cfg = cfg.with_connect_timeout(Duration::from_millis(200));
        let _held = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(socket);
        });

        let err = ReplicationClient::connect(cfg)
            .await
            .err()
            .expect("timeout");
        match err {
            PgWireError::Io(io) => assert_eq!(io.kind(), std::io::ErrorKind::TimedOut),
            other => panic!("expected a timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connect_returns_the_error_when_the_server_closes_before_streaming() {
        let (listener, cfg) = local_server().await;
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            drop(socket);
        });

        let err = ReplicationClient::connect(cfg).await.err().expect("error");
        assert!(
            !matches!(&err, PgWireError::Io(io) if io.kind() == std::io::ErrorKind::TimedOut),
            "expected the startup failure, got {err:?}"
        );
    }
}
