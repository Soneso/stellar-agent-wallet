//! A loopback TCP listener that counts the connections it accepts.
//!
//! A plaintext HTTP mock cannot observe contact through an `https://` URL. A
//! TLS client's handshake never forms an HTTP request, so the mock records
//! nothing whether or not the client connected. [`ConnectionCounter`]
//! observes contact at the TCP level instead. Every accepted connection
//! counts, whatever protocol the client speaks, and each one is closed at once
//! so the client fails fast.

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long the accept worker, and a count waiting on its probe, wait between
/// polls of the listener.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// How long [`ConnectionCounter::accepted`] waits for its own probe
/// connection to reach the accept queue.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// A TCP listener on `127.0.0.1:0` that accepts, counts, and closes every
/// connection.
///
/// A background worker accepts connections as they arrive and closes each
/// one, so a client that connects fails at once.
/// [`ConnectionCounter::accepted`] counts every connection a client completed
/// before the call, including one the kernel has not yet queued for accept.
///
/// # Examples
///
/// ```
/// use stellar_agent_test_support::ConnectionCounter;
///
/// let counter = ConnectionCounter::start().expect("loopback listener");
/// assert!(counter.https_uri().starts_with("https://127.0.0.1:"));
/// assert_eq!(counter.accepted().expect("connection count"), 0);
///
/// drop(std::net::TcpStream::connect(counter.https_uri().trim_start_matches("https://")));
/// assert_eq!(counter.accepted().expect("connection count"), 1);
/// ```
pub struct ConnectionCounter {
    address: SocketAddr,
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
}

/// State shared by the counter and its accept worker.
struct Shared {
    listener: TcpListener,
    /// The number of client connections accepted so far. Every accept
    /// happens under this lock, so each connection is counted once, by
    /// whichever side accepted it, and a probe connection is never taken by
    /// the worker.
    accepted: Mutex<usize>,
    shutdown: AtomicBool,
}

/// What one non-blocking accept observed.
enum Accept {
    /// A connection from `peer`, closed on return.
    Connection(SocketAddr),
    /// A client aborted or reset its connection before the accept
    /// (`ConnectionAborted` or `ConnectionReset`); it still made contact.
    Aborted,
    /// No completed connection is queued.
    Empty,
}

/// The queue of completed connections a count accepts from.
///
/// The listener is the only production source. The unit tests script the
/// queue. A scripted connection can complete before the count begins and
/// reach the queue only after it, and a scripted accept can fail with a given
/// error kind.
trait AcceptSource {
    /// Holds the probe connection open while the count waits for it.
    type Probe;

    /// Opens a probe connection to the listener and returns it with the
    /// address the listener sees it from.
    fn open_probe(&self) -> std::io::Result<(Self::Probe, SocketAddr)>;

    /// Takes one completed connection off the queue, closing it at once, and
    /// returns the peer address.
    fn accept_raw(&self) -> std::io::Result<SocketAddr>;

    /// Accepts one queued connection and classifies the outcome.
    fn accept_one(&self) -> std::io::Result<Accept> {
        loop {
            match self.accept_raw() {
                Ok(peer) => return Ok(Accept::Connection(peer)),
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset
                    ) =>
                {
                    return Ok(Accept::Aborted);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(Accept::Empty),
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

impl AcceptSource for TcpListener {
    type Probe = TcpStream;

    fn open_probe(&self) -> std::io::Result<(TcpStream, SocketAddr)> {
        let probe = TcpStream::connect(self.local_addr()?)?;
        let address = probe.local_addr()?;
        Ok((probe, address))
    }

    fn accept_raw(&self) -> std::io::Result<SocketAddr> {
        // Dropping the stream closes the connection.
        self.accept().map(|(_stream, peer)| peer)
    }
}

/// Adds to `accepted` every connection queued ahead of a probe connection of
/// its own, and returns the new total.
///
/// The connections already queued are accepted first, so the probe never
/// connects into a backlog that only the locked-out worker would drain. A
/// client's `connect` can return before the listening side has queued the
/// connection, so draining the queue alone can miss it. The probe is opened
/// after every such client connection completed, and the queue is first in,
/// first out, so once the probe arrives every earlier connection has been
/// accepted. The probe itself is not counted.
fn count_through_probe<S: AcceptSource>(
    source: &S,
    accepted: &mut usize,
) -> std::io::Result<usize> {
    while let Accept::Connection(_) | Accept::Aborted = source.accept_one()? {
        *accepted += 1;
    }
    let (_probe, probe_address) = source.open_probe()?;
    let deadline = Instant::now() + PROBE_TIMEOUT;
    loop {
        match source.accept_one()? {
            Accept::Connection(peer) if peer == probe_address => return Ok(*accepted),
            Accept::Connection(_) | Accept::Aborted => *accepted += 1,
            Accept::Empty if Instant::now() >= deadline => {
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "the connection counter's probe never reached the accept queue",
                ));
            }
            Accept::Empty => std::thread::sleep(POLL_INTERVAL),
        }
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, usize> {
        self.accepted.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Accepts and counts every queued connection.
    fn drain(&self) {
        let mut accepted = self.lock();
        while let Ok(Accept::Connection(_) | Accept::Aborted) = self.listener.accept_one() {
            *accepted += 1;
        }
    }
}

impl ConnectionCounter {
    /// Binds a listener on `127.0.0.1:0` and starts the accept worker.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the loopback listener cannot be bound or set
    /// non-blocking, or when the worker thread cannot be spawned.
    pub fn start() -> std::io::Result<Self> {
        let mut counter = Self::bind()?;
        let worker_state = Arc::clone(&counter.shared);
        let worker = std::thread::Builder::new()
            .name("connection-counter".to_owned())
            .spawn(move || {
                while !worker_state.shutdown.load(Ordering::Acquire) {
                    worker_state.drain();
                    std::thread::sleep(POLL_INTERVAL);
                }
            })?;
        counter.worker = Some(worker);
        Ok(counter)
    }

    /// Binds the non-blocking listener on `127.0.0.1:0`, with no accept
    /// worker.
    fn bind() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        Ok(Self {
            address,
            shared: Arc::new(Shared {
                listener,
                accepted: Mutex::new(0),
                shutdown: AtomicBool::new(false),
            }),
            worker: None,
        })
    }

    /// The listener as an `https://` URL: `https://127.0.0.1:<port>`.
    #[must_use]
    pub fn https_uri(&self) -> String {
        format!("https://{}", self.address)
    }

    /// The number of client connections accepted so far.
    ///
    /// A client's `connect` can return before the listening side has queued
    /// the connection for accept, so the count cannot be read directly. The
    /// call accepts the connections already queued, then opens a probe
    /// connection of its own and accepts until the probe arrives. Loopback
    /// delivers segments in order and the accept queue is first in, first
    /// out, so every connection a client completed before the call is
    /// accepted, and counted, ahead of the probe. The probe itself is not
    /// counted.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the probe cannot connect or the listener
    /// fails, and an error of kind [`ErrorKind::TimedOut`] when the probe does
    /// not arrive within ten seconds.
    pub fn accepted(&self) -> std::io::Result<usize> {
        let mut accepted = self.shared.lock();
        count_through_probe(&self.shared.listener, &mut accepted)
    }
}

impl Drop for ConnectionCounter {
    fn drop(&mut self) {
        self.shared.shutdown.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            // A worker that panicked has nothing left to release.
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "test-only fixture setup")]

    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::io::Read;
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;

    const CLIENT: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 50_001));
    const SECOND_CLIENT: SocketAddr =
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 50_002));
    const PROBE: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 50_003));

    /// A scripted accept queue.
    ///
    /// `queued` holds the accept outcomes waiting when the count begins.
    /// `late` holds outcomes that reach the queue only once the probe opens,
    /// ahead of the probe, as a kernel that queues loopback connections
    /// asynchronously can deliver them. Opening the probe while `queued`
    /// still holds an entry fails: the script requires the count to drain
    /// what is queued before it probes.
    struct ScriptedQueue {
        queued: RefCell<VecDeque<std::io::Result<SocketAddr>>>,
        late: RefCell<Vec<std::io::Result<SocketAddr>>>,
    }

    impl ScriptedQueue {
        fn new(
            queued: Vec<std::io::Result<SocketAddr>>,
            late: Vec<std::io::Result<SocketAddr>>,
        ) -> Self {
            Self {
                queued: RefCell::new(queued.into()),
                late: RefCell::new(late),
            }
        }
    }

    impl AcceptSource for ScriptedQueue {
        type Probe = ();

        fn open_probe(&self) -> std::io::Result<((), SocketAddr)> {
            let mut queued = self.queued.borrow_mut();
            if !queued.is_empty() {
                return Err(std::io::Error::other(
                    "the probe was opened behind a queued connection",
                ));
            }
            queued.extend(self.late.borrow_mut().drain(..));
            queued.push_back(Ok(PROBE));
            Ok(((), PROBE))
        }

        fn accept_raw(&self) -> std::io::Result<SocketAddr> {
            self.queued
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Err(ErrorKind::WouldBlock.into()))
        }
    }

    /// A connection that reaches the queue only after the count began is
    /// still counted: the count waits for its probe, and the probe is queued
    /// behind the connection.
    #[test]
    fn the_count_includes_a_connection_queued_after_it_began() {
        let source = ScriptedQueue::new(vec![], vec![Ok(CLIENT)]);
        let mut accepted = 0;
        assert_eq!(
            count_through_probe(&source, &mut accepted).expect("connection count"),
            1
        );
        assert_eq!(accepted, 1);
        assert!(
            source.queued.borrow().is_empty(),
            "the probe is taken off the queue"
        );
    }

    /// The connections already queued are counted before the probe opens.
    #[test]
    fn the_count_drains_the_queue_before_it_probes() {
        let source = ScriptedQueue::new(vec![Ok(CLIENT), Ok(SECOND_CLIENT)], vec![]);
        let mut accepted = 0;
        assert_eq!(
            count_through_probe(&source, &mut accepted).expect("connection count"),
            2
        );
    }

    /// An accept that fails because the client aborted or reset its
    /// connection counts as contact, before and after the probe opens; an
    /// interrupted accept is retried and counts nothing.
    #[test]
    fn an_aborted_or_reset_connection_counts_as_contact() {
        let source = ScriptedQueue::new(
            vec![
                Err(ErrorKind::ConnectionReset.into()),
                Err(ErrorKind::Interrupted.into()),
                Err(ErrorKind::ConnectionAborted.into()),
            ],
            vec![Err(ErrorKind::ConnectionReset.into()), Ok(CLIENT)],
        );
        let mut accepted = 0;
        assert_eq!(
            count_through_probe(&source, &mut accepted).expect("connection count"),
            4
        );
    }

    #[test]
    fn counts_nothing_without_a_connection() {
        let counter = ConnectionCounter::start().expect("loopback listener");
        assert_eq!(counter.accepted().expect("connection count"), 0);
        assert_eq!(
            counter.accepted().expect("connection count"),
            0,
            "the probe connection of a count is never counted"
        );
    }

    /// A connection dropped right after `connect` returns is counted by the
    /// next call, however far the listening side has got with it.
    #[test]
    fn counts_each_tcp_connection() {
        let counter = ConnectionCounter::start().expect("loopback listener");
        for expected in 1..=3 {
            drop(TcpStream::connect(counter.address).expect("loopback connect"));
            assert_eq!(counter.accepted().expect("connection count"), expected);
        }
    }

    /// Without a worker, the call's own accept loop is the only acceptor, so
    /// a connection made right before each call reaches the count through it.
    #[test]
    fn counts_a_connection_its_own_call_accepts() {
        let counter = ConnectionCounter::bind().expect("loopback listener");
        let mut clients = Vec::new();
        for expected in 1..=64 {
            clients.push(TcpStream::connect(counter.address).expect("loopback connect"));
            assert_eq!(counter.accepted().expect("connection count"), expected);
        }
    }

    /// Every connection a client completed before the call is counted,
    /// however far the listening side has got with queueing each one.
    #[test]
    fn counts_every_connection_completed_before_the_call() {
        // 64 clients and the probe fit std's listen backlog of 128 on Linux, macOS, and Windows.
        const CLIENTS: usize = 64;
        let counter = ConnectionCounter::bind().expect("loopback listener");
        let clients: Vec<TcpStream> = (0..CLIENTS)
            .map(|_| TcpStream::connect(counter.address).expect("loopback connect"))
            .collect();
        assert_eq!(counter.accepted().expect("connection count"), CLIENTS);
        assert_eq!(clients.len(), CLIENTS);
    }

    #[test]
    fn https_uri_names_the_bound_loopback_port() {
        let counter = ConnectionCounter::start().expect("loopback listener");
        assert_eq!(
            counter.https_uri(),
            format!("https://127.0.0.1:{}", counter.address.port())
        );
    }

    /// The worker closes an accepted connection, so a client reading from it
    /// sees the close.
    #[test]
    fn closes_each_accepted_connection() {
        let counter = ConnectionCounter::start().expect("loopback listener");
        let mut stream = TcpStream::connect(counter.address).expect("loopback connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("read timeout");
        let mut buffer = [0_u8; 1];
        // End of stream or a reset both mean the counter closed it; a read
        // timeout means it left the connection open.
        let closed = match stream.read(&mut buffer) {
            Ok(read) => read == 0,
            Err(error) => !matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
        };
        assert!(closed, "the counter must close the connection");
        assert_eq!(counter.accepted().expect("connection count"), 1);
    }
}
