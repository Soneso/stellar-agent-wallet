//! Paired loopback listeners for a ceremony the browser reaches at
//! `http://localhost:<port>`.
//!
//! # Invariant
//!
//! When the wallet sends the browser to `http://localhost:<port>`, every
//! address that name resolves to on the loopback interface, `127.0.0.1` and
//! `::1`, is a wallet listener on that port for the whole ceremony. No other
//! local account can then serve the page, receive the bootstrap token, or
//! relay a challenge under the wallet's origin.
//!
//! # Why one family is never enough
//!
//! A browser resolves `localhost` to both loopback addresses and may connect
//! to `::1` first. A wallet that holds only `127.0.0.1:<port>` leaves
//! `[::1]:<port>` free for any other account on the host, and a page served
//! there runs at the same origin, `http://localhost:<port>`. The Host and
//! Origin allowlists compare names, not sockets, so they accept requests that
//! page relays. The name itself cannot change: WebAuthn needs `localhost` as
//! the relying party ID, and an IP literal is not a valid one.
//!
//! [`LoopbackPair::bind`] therefore acquires `127.0.0.1:<port>` and
//! `[::1]:<port>` together before the caller creates any token, and refuses
//! when either address cannot be held; it never falls back to one family.
//! [`LoopbackPair::serve`] runs one router on both sockets, so a session that
//! starts on one address is the same session on the other, and the returned
//! [`PairServer`] closes both together.
//!
//! On Unix tokio's `TcpListener::bind`, like the standard library's, sets
//! `SO_REUSEADDR`, which lets a listener reuse a port in `TIME_WAIT` but does
//! not let another socket bind an address a listening socket holds. On
//! Windows neither sets it, because there `SO_REUSEADDR` lets another socket
//! bind an address in active use. The pair sets no other socket option.

use std::{
    fmt, io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};

use axum::Router;
use tokio::{net::TcpListener, sync::watch, task::JoinHandle};

/// The number of ports [`LoopbackPair::bind`] tries for an ephemeral pair
/// before it refuses with [`PairBindError::Exhausted`].
///
/// A port another account holds on `::1` costs one attempt; sixteen
/// independent OS-assigned ports all held that way means the host is not in
/// a state where a ceremony should start.
pub const PAIR_BIND_ATTEMPTS: u32 = 16;

/// The address family of one listener of a [`LoopbackPair`].
///
/// `Display` is `IPv4` or `IPv6`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LoopbackFamily {
    /// The `127.0.0.1` listener.
    V4,
    /// The `::1` listener.
    V6,
}

impl LoopbackFamily {
    /// The family's name: `IPv4` or `IPv6`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        }
    }
}

impl fmt::Display for LoopbackFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a [`LoopbackPair`] could not be acquired.
///
/// Every variant carries only a [`LoopbackFamily`], a port, an
/// [`io::ErrorKind`] or an attempt count, so its `Display` form never
/// contains OS detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairBindError {
    /// The requested fixed port is held by another socket, or this account
    /// may not bind it, on `family`.
    PortUnavailable {
        /// The requested port.
        port: u16,
        /// The family whose bind failed.
        family: LoopbackFamily,
        /// The kind of the bind error.
        kind: io::ErrorKind,
    },
    /// The loopback address of `family` cannot be bound on this host at all,
    /// for example because the host has no IPv6 loopback.
    FamilyUnavailable {
        /// The family whose bind failed.
        family: LoopbackFamily,
        /// The kind of the bind error.
        kind: io::ErrorKind,
    },
    /// Every one of `attempts` OS-assigned ports was held on one of the two
    /// families.
    Exhausted {
        /// The number of ports tried.
        attempts: u32,
    },
}

impl PairBindError {
    /// The address family whose bind failed, when the refusal names one.
    #[must_use]
    pub fn family(&self) -> Option<LoopbackFamily> {
        match self {
            Self::PortUnavailable { family, .. } | Self::FamilyUnavailable { family, .. } => {
                Some(*family)
            }
            Self::Exhausted { .. } => None,
        }
    }

    /// The kind of the bind error, when the refusal carries one.
    #[must_use]
    pub fn kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::PortUnavailable { kind, .. } | Self::FamilyUnavailable { kind, .. } => {
                Some(*kind)
            }
            Self::Exhausted { .. } => None,
        }
    }
}

impl fmt::Display for PairBindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PortUnavailable { port, family, kind } => write!(
                f,
                "loopback port {port} cannot be held on {family}: {kind:?}"
            ),
            Self::FamilyUnavailable { family, kind } => write!(
                f,
                "the {family} loopback address cannot be bound on this host: {kind:?}"
            ),
            Self::Exhausted { attempts } => write!(
                f,
                "no loopback port could be held on both IPv4 and IPv6 after {attempts} attempts"
            ),
        }
    }
}

impl std::error::Error for PairBindError {}

/// Listeners on `127.0.0.1:<port>` and `[::1]:<port>`, one port, held
/// together.
///
/// Dropping the pair releases both addresses.
pub struct LoopbackPair {
    v4: TcpListener,
    v6: TcpListener,
    port: u16,
}

impl fmt::Debug for LoopbackPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoopbackPair")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl LoopbackPair {
    /// Binds `127.0.0.1:<port>` and `[::1]:<port>`, IPv4 first.
    ///
    /// Port `0` asks the OS for a port on IPv4 and binds IPv6 on the same
    /// port. A bind of either family that fails with
    /// [`io::ErrorKind::AddrInUse`] releases what was bound and tries the
    /// next port, at most [`PAIR_BIND_ATTEMPTS`] times; every other kind
    /// refuses at once and releases what was bound.
    ///
    /// A non-zero port is bound as given on both families.
    /// [`io::ErrorKind::AddrInUse`] and [`io::ErrorKind::PermissionDenied`]
    /// on either family refuse with [`PairBindError::PortUnavailable`], and
    /// every other kind refuses with [`PairBindError::FamilyUnavailable`].
    ///
    /// A refusal leaves nothing bound.
    ///
    /// # Errors
    ///
    /// - [`PairBindError::PortUnavailable`]: a non-zero `port` is held by
    ///   another socket, or may not be bound by this account, on either
    ///   family.
    /// - [`PairBindError::FamilyUnavailable`]: either loopback address cannot
    ///   be bound for any other reason, such as a host without IPv6
    ///   loopback.
    /// - [`PairBindError::Exhausted`]: no OS-assigned port could be held on
    ///   both families within [`PAIR_BIND_ATTEMPTS`] attempts.
    pub async fn bind(port: u16) -> Result<Self, PairBindError> {
        if port == 0 {
            bind_ephemeral_with(
                || TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
                |port| TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))),
                PAIR_BIND_ATTEMPTS,
            )
            .await
        } else {
            bind_fixed(port).await
        }
    }

    /// The port both listeners hold.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The IPv4 listener's address, `127.0.0.1:<port>`.
    ///
    /// The Host and Origin allowlists read only its port, so layers built
    /// from it admit the same requests on both sockets.
    #[must_use]
    pub fn v4_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.port))
    }

    /// Serves `router` on both listeners until [`PairServer::shutdown`] or
    /// until either listener's server ends.
    ///
    /// Both sockets run clones of the same router and therefore share its
    /// state.
    #[must_use = "dropping the PairServer stops both listeners"]
    pub fn serve(self, router: Router) -> PairServer {
        PairServer::spawn(self, move |listener, signal| {
            let router = router.clone();
            async move {
                axum::serve(listener, router)
                    .with_graceful_shutdown(signal.requested())
                    .await
            }
        })
    }
}

/// Acquires an ephemeral pair: `next_v4` yields an IPv4 listener on a port
/// the caller chose, and `bind_v6` binds IPv6 on that port.
///
/// A bind of either family that fails with [`io::ErrorKind::AddrInUse`]
/// releases what was bound and tries the next port, at most `attempts`
/// times; every other kind refuses at once and releases what was bound.
pub(crate) async fn bind_ephemeral_with<V4, V4Fut, V6, V6Fut>(
    mut next_v4: V4,
    mut bind_v6: V6,
    attempts: u32,
) -> Result<LoopbackPair, PairBindError>
where
    V4: FnMut() -> V4Fut,
    V4Fut: Future<Output = io::Result<TcpListener>>,
    V6: FnMut(u16) -> V6Fut,
    V6Fut: Future<Output = io::Result<TcpListener>>,
{
    for _ in 0..attempts {
        let v4 = match next_v4().await {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
            Err(error) => {
                return Err(PairBindError::FamilyUnavailable {
                    family: LoopbackFamily::V4,
                    kind: error.kind(),
                });
            }
        };
        let port = v4
            .local_addr()
            .map_err(|error| PairBindError::FamilyUnavailable {
                family: LoopbackFamily::V4,
                kind: error.kind(),
            })?
            .port();
        match bind_v6(port).await {
            Ok(v6) => return Ok(LoopbackPair { v4, v6, port }),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => drop(v4),
            Err(error) => {
                return Err(PairBindError::FamilyUnavailable {
                    family: LoopbackFamily::V6,
                    kind: error.kind(),
                });
            }
        }
    }
    Err(PairBindError::Exhausted { attempts })
}

/// Binds both families on the non-zero `port`, IPv4 first.
async fn bind_fixed(port: u16) -> Result<LoopbackPair, PairBindError> {
    let v4 = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .map_err(|error| fixed_port_refusal(port, LoopbackFamily::V4, &error))?;
    let v6 = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port)))
        .await
        .map_err(|error| fixed_port_refusal(port, LoopbackFamily::V6, &error))?;
    Ok(LoopbackPair { v4, v6, port })
}

/// The refusal of a fixed-port bind: [`io::ErrorKind::AddrInUse`] and
/// [`io::ErrorKind::PermissionDenied`] say the port is unavailable, and
/// every other kind says the family itself is.
fn fixed_port_refusal(port: u16, family: LoopbackFamily, error: &io::Error) -> PairBindError {
    match error.kind() {
        kind @ (io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied) => {
            PairBindError::PortUnavailable { port, family, kind }
        }
        kind => PairBindError::FamilyUnavailable { family, kind },
    }
}

/// Resolves once a [`PairServer`] asks its listeners to stop.
pub(crate) struct ShutdownSignal(watch::Receiver<bool>);

impl ShutdownSignal {
    /// Completes when shutdown is requested or every sender is gone.
    pub(crate) async fn requested(mut self) {
        let _stopped_or_closed = self.0.wait_for(|stop| *stop).await;
    }
}

/// Asks every listener of a pair to stop when it is dropped.
///
/// Each listener task owns one, so the task's end requests the end of its
/// sibling however the task ends: by returning, by panicking, or by being
/// aborted.
struct StopSibling(watch::Sender<bool>);

impl Drop for StopSibling {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

/// A server task that is aborted when its owner drops it.
struct ServerTask(JoinHandle<io::Result<()>>);

impl Drop for ServerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The two running servers of a [`LoopbackPair`].
///
/// [`PairServer::shutdown`] asks both to stop. When either server task ends
/// for any reason, a panic included, it asks the other to stop, so both
/// addresses close together.
///
/// Dropping a `PairServer` aborts both server tasks at once and does not
/// wait for open connections: both addresses stop accepting, and a request
/// already in flight finishes in its own connection task.
pub struct PairServer {
    shutdown: watch::Sender<bool>,
    tasks: [ServerTask; 2],
}

impl fmt::Debug for PairServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairServer").finish_non_exhaustive()
    }
}

impl PairServer {
    /// Spawns `serve` once per listener, each with its own shutdown signal,
    /// and makes the end of either task, a panic or an abort included,
    /// request the end of the other.
    pub(crate) fn spawn<F, Fut>(pair: LoopbackPair, serve: F) -> Self
    where
        F: Fn(TcpListener, ShutdownSignal) -> Fut,
        Fut: Future<Output = io::Result<()>> + Send + 'static,
    {
        let (shutdown, _) = watch::channel(false);
        let LoopbackPair { v4, v6, .. } = pair;
        let tasks = [v4, v6].map(|listener| {
            let served = serve(listener, ShutdownSignal(shutdown.subscribe()));
            let sibling = StopSibling(shutdown.clone());
            ServerTask(tokio::spawn(async move {
                let _sibling = sibling;
                let result = served.await;
                if let Err(error) = &result {
                    tracing::error!(
                        error.kind = ?error.kind(),
                        "loopback listener ended with an error"
                    );
                }
                result
            }))
        });
        Self { shutdown, tasks }
    }

    /// Asks both servers to stop accepting and to finish their open
    /// connections; [`PairServer::join`] then waits for the requests in
    /// flight.
    pub fn shutdown(&self) {
        self.shutdown.send_replace(true);
    }

    /// Waits until both servers have ended.
    ///
    /// Dropping the returned future before it completes aborts both
    /// servers.
    ///
    /// # Errors
    ///
    /// The first error in listener order, IPv4 then IPv6: a server that
    /// ended with an I/O error, or a task that panicked or was aborted.
    pub async fn join(self) -> io::Result<()> {
        let Self {
            shutdown: _shutdown,
            tasks: [mut v4, mut v6],
        } = self;
        let first = (&mut v4.0).await;
        let second = (&mut v6.0).await;
        first??;
        second??;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use axum::{extract::State, routing::get};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        sync::Notify,
    };

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    fn v6(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv6Addr::LOCALHOST, port))
    }

    /// A listener on `[::1]:P` for a port P that is free on `127.0.0.1`
    /// when this returns.
    fn competitor_on_ipv6() -> (std::net::TcpListener, u16) {
        for _ in 0..64 {
            let competitor = std::net::TcpListener::bind(v6(0)).unwrap();
            let port = competitor.local_addr().unwrap().port();
            if std::net::TcpListener::bind(v4(port)).is_ok() {
                return (competitor, port);
            }
        }
        panic!("no port free on 127.0.0.1 among 64 held on ::1");
    }

    /// Whether `addr` accepts a TCP connection within a second.
    async fn accepts(addr: SocketAddr) -> bool {
        matches!(
            tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(addr))
                .await,
            Ok(Ok(_))
        )
    }

    /// One `GET path` over `addr`, returning the response text.
    async fn get_text(addr: SocketAddr, path: &str) -> String {
        let mut stream = tokio::time::timeout(WAIT, tokio::net::TcpStream::connect(addr))
            .await
            .unwrap()
            .unwrap();
        let head = format!(
            "GET {path} HTTP/1.1\r\nhost: localhost:{}\r\nconnection: close\r\n\r\n",
            addr.port()
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        tokio::time::timeout(WAIT, stream.read_to_end(&mut raw))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8(raw).unwrap()
    }

    /// Waits until neither address on `port` accepts a connection.
    async fn both_close(port: u16, why: &str) {
        tokio::time::timeout(WAIT, async {
            while accepts(v4(port)).await || accepts(v6(port)).await {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{why}"));
    }

    #[tokio::test]
    async fn an_ephemeral_pair_skips_a_port_held_on_ipv6() {
        let (_competitor, held) = competitor_on_ipv6();
        let offered = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&offered);
        let mut calls = 0_u32;
        let pair = bind_ephemeral_with(
            move || {
                calls += 1;
                let port = if calls == 1 { held } else { 0 };
                let record = Arc::clone(&record);
                async move {
                    let listener = TcpListener::bind(v4(port)).await?;
                    record.lock().unwrap().push(listener.local_addr()?.port());
                    Ok(listener)
                }
            },
            |port| TcpListener::bind(v6(port)),
            PAIR_BIND_ATTEMPTS,
        )
        .await
        .unwrap();

        let offered = offered.lock().unwrap().clone();
        assert_eq!(offered.first(), Some(&held), "the first IPv4 port is P");
        assert!(offered.len() >= 2, "a held IPv6 port costs one attempt");
        assert_ne!(pair.port(), held, "the pair lands on another port");
        assert_eq!(pair.v4.local_addr().unwrap(), v4(pair.port()));
        assert_eq!(pair.v6.local_addr().unwrap(), v6(pair.port()));
        assert_eq!(pair.v4_addr(), v4(pair.port()));
        assert!(
            std::net::TcpListener::bind(v4(held)).is_ok(),
            "the IPv4 listener on the skipped port is released"
        );
        assert!(accepts(v4(pair.port())).await);
        assert!(accepts(v6(pair.port())).await);
    }

    #[tokio::test]
    async fn a_fixed_port_held_on_either_family_refuses() {
        let (competitor, port) = competitor_on_ipv6();
        assert_eq!(
            LoopbackPair::bind(port).await.unwrap_err(),
            PairBindError::PortUnavailable {
                port,
                family: LoopbackFamily::V6,
                kind: io::ErrorKind::AddrInUse,
            }
        );
        drop(competitor);
        let competitor = std::net::TcpListener::bind(v4(port)).unwrap();
        assert_eq!(
            LoopbackPair::bind(port).await.unwrap_err(),
            PairBindError::PortUnavailable {
                port,
                family: LoopbackFamily::V4,
                kind: io::ErrorKind::AddrInUse,
            }
        );
        drop(competitor);
        let pair = LoopbackPair::bind(port).await.unwrap();
        assert_eq!(pair.port(), port);
        assert_eq!(pair.v6.local_addr().unwrap(), v6(port));
    }

    #[tokio::test]
    async fn a_missing_ipv6_family_refuses_without_fallback() {
        let offered = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&offered);
        let error = bind_ephemeral_with(
            move || {
                let record = Arc::clone(&record);
                async move {
                    let listener = TcpListener::bind(v4(0)).await?;
                    record.lock().unwrap().push(listener.local_addr()?.port());
                    Ok(listener)
                }
            },
            |_| async { Err(io::Error::from(io::ErrorKind::AddrNotAvailable)) },
            PAIR_BIND_ATTEMPTS,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            PairBindError::FamilyUnavailable {
                family: LoopbackFamily::V6,
                kind: io::ErrorKind::AddrNotAvailable,
            }
        );
        assert_eq!(error.family(), Some(LoopbackFamily::V6));
        assert_eq!(error.kind(), Some(io::ErrorKind::AddrNotAvailable));
        let offered = offered.lock().unwrap().clone();
        assert_eq!(offered.len(), 1, "a missing family is not retried");
        assert!(
            std::net::TcpListener::bind(v4(offered[0])).is_ok(),
            "no IPv4 listener stays bound"
        );
    }

    #[tokio::test]
    async fn exhausted_attempts_refuse() {
        let (_competitor, held) = competitor_on_ipv6();
        let error = bind_ephemeral_with(
            || TcpListener::bind(v4(held)),
            |port| TcpListener::bind(v6(port)),
            3,
        )
        .await
        .unwrap_err();
        assert_eq!(error, PairBindError::Exhausted { attempts: 3 });
        assert_eq!(error.family(), None);
        assert!(std::net::TcpListener::bind(v4(held)).is_ok());

        // An IPv4 port another socket holds costs one attempt as well.
        let mut calls = 0_u32;
        let error = bind_ephemeral_with(
            || {
                calls += 1;
                async { Err(io::Error::from(io::ErrorKind::AddrInUse)) }
            },
            |port| TcpListener::bind(v6(port)),
            3,
        )
        .await
        .unwrap_err();
        assert_eq!(error, PairBindError::Exhausted { attempts: 3 });
        assert_eq!(calls, 3, "every attempt asks for a fresh IPv4 port");
    }

    #[test]
    fn a_fixed_port_refusal_names_the_port_only_for_a_held_or_forbidden_port() {
        for kind in [io::ErrorKind::AddrInUse, io::ErrorKind::PermissionDenied] {
            assert_eq!(
                fixed_port_refusal(7823, LoopbackFamily::V6, &io::Error::from(kind)),
                PairBindError::PortUnavailable {
                    port: 7823,
                    family: LoopbackFamily::V6,
                    kind,
                },
                "{kind:?}"
            );
        }
        assert_eq!(
            fixed_port_refusal(
                7823,
                LoopbackFamily::V4,
                &io::Error::from(io::ErrorKind::AddrNotAvailable)
            ),
            PairBindError::FamilyUnavailable {
                family: LoopbackFamily::V4,
                kind: io::ErrorKind::AddrNotAvailable,
            }
        );
    }

    #[test]
    fn refusals_display_no_os_detail() {
        assert_eq!(LoopbackFamily::V4.to_string(), "IPv4");
        assert_eq!(LoopbackFamily::V6.to_string(), "IPv6");
        let port = PairBindError::PortUnavailable {
            port: 7823,
            family: LoopbackFamily::V6,
            kind: io::ErrorKind::AddrInUse,
        };
        assert_eq!(
            port.to_string(),
            "loopback port 7823 cannot be held on IPv6: AddrInUse"
        );
        let family = PairBindError::FamilyUnavailable {
            family: LoopbackFamily::V6,
            kind: io::ErrorKind::AddrNotAvailable,
        };
        assert_eq!(
            family.to_string(),
            "the IPv6 loopback address cannot be bound on this host: AddrNotAvailable"
        );
        assert_eq!(
            PairBindError::Exhausted { attempts: 16 }.to_string(),
            "no loopback port could be held on both IPv4 and IPv6 after 16 attempts"
        );
    }

    #[tokio::test]
    async fn both_sockets_serve_one_router_and_close_together() {
        let hits = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .route(
                "/count",
                get(|State(hits): State<Arc<AtomicUsize>>| async move {
                    (hits.fetch_add(1, Ordering::SeqCst) + 1).to_string()
                }),
            )
            .with_state(Arc::clone(&hits));
        let pair = LoopbackPair::bind(0).await.unwrap();
        let port = pair.port();
        let server = pair.serve(router);

        assert!(get_text(v4(port), "/count").await.ends_with("\r\n\r\n1"));
        assert!(get_text(v6(port), "/count").await.ends_with("\r\n\r\n2"));
        assert!(get_text(v4(port), "/count").await.ends_with("\r\n\r\n3"));
        assert_eq!(hits.load(Ordering::SeqCst), 3);

        server.shutdown();
        tokio::time::timeout(WAIT, server.join())
            .await
            .unwrap()
            .unwrap();
        assert!(!accepts(v4(port)).await, "IPv4 closed after shutdown");
        assert!(!accepts(v6(port)).await, "IPv6 closed after shutdown");

        // A server that ends on its own stops its sibling.
        let pair = LoopbackPair::bind(0).await.unwrap();
        let port = pair.port();
        let server = PairServer::spawn(pair, |listener, signal| async move {
            if listener.local_addr()?.is_ipv4() {
                return Ok(());
            }
            axum::serve(listener, Router::new())
                .with_graceful_shutdown(signal.requested())
                .await
        });
        tokio::time::timeout(WAIT, server.join())
            .await
            .expect("the IPv6 server stops when the IPv4 server ends")
            .unwrap();
        assert!(!accepts(v4(port)).await);
        assert!(!accepts(v6(port)).await);
    }

    #[tokio::test]
    async fn the_first_error_is_reported_and_dropping_aborts_both() {
        let pair = LoopbackPair::bind(0).await.unwrap();
        let server = PairServer::spawn(pair, |listener, signal| async move {
            if listener.local_addr()?.is_ipv6() {
                return Err(io::Error::from(io::ErrorKind::ConnectionReset));
            }
            signal.requested().await;
            Ok(())
        });
        let error = tokio::time::timeout(WAIT, server.join())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);

        let pair = LoopbackPair::bind(0).await.unwrap();
        let port = pair.port();
        let server = pair.serve(Router::new());
        assert!(accepts(v6(port)).await);
        drop(server);
        both_close(port, "both listeners close when the server is dropped").await;

        // A pending join that is dropped aborts both servers.
        let pair = LoopbackPair::bind(0).await.unwrap();
        let port = pair.port();
        let server = pair.serve(Router::new());
        assert!(accepts(v4(port)).await);
        assert!(accepts(v6(port)).await);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), server.join())
                .await
                .is_err(),
            "nothing asked the servers to stop"
        );
        both_close(port, "both listeners close when a pending join is dropped").await;
    }

    #[tokio::test]
    async fn a_panicking_listener_task_stops_its_sibling() {
        for panicking in [LoopbackFamily::V4, LoopbackFamily::V6] {
            let pair = LoopbackPair::bind(0).await.unwrap();
            let port = pair.port();
            let server = PairServer::spawn(pair, move |listener, signal| async move {
                let family = if listener.local_addr()?.is_ipv4() {
                    LoopbackFamily::V4
                } else {
                    LoopbackFamily::V6
                };
                if family == panicking {
                    panic!("the {family} listener task panics");
                }
                axum::serve(listener, Router::new())
                    .with_graceful_shutdown(signal.requested())
                    .await
            });
            let error = tokio::time::timeout(WAIT, server.join())
                .await
                .unwrap_or_else(|_| panic!("join completes after the {panicking} task panics"))
                .unwrap_err();
            assert_eq!(error.to_string(), "task panicked", "{panicking}");
            assert!(
                !accepts(v4(port)).await,
                "IPv4 closed after the {panicking} task panics"
            );
            assert!(
                !accepts(v6(port)).await,
                "IPv6 closed after the {panicking} task panics"
            );
        }
    }

    /// A router whose `/slow` handler signals `entered` and answers `done`
    /// once `release` is notified.
    fn slow_router(entered: Arc<Notify>, release: Arc<Notify>) -> Router {
        Router::new()
            .route(
                "/slow",
                get(
                    |State((entered, release)): State<(Arc<Notify>, Arc<Notify>)>| async move {
                        entered.notify_one();
                        release.notified().await;
                        "done"
                    },
                ),
            )
            .with_state((entered, release))
    }

    /// Shutdown closes both addresses and `join` waits for the response in
    /// flight; dropping the server closes both addresses without waiting,
    /// and the response in flight finishes in its connection task.
    #[tokio::test]
    async fn shutdown_waits_for_a_request_in_flight_and_drop_does_not() {
        for graceful in [true, false] {
            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let pair = LoopbackPair::bind(0).await.unwrap();
            let port = pair.port();
            let server = pair.serve(slow_router(Arc::clone(&entered), Arc::clone(&release)));
            let request = tokio::spawn(get_text(v6(port), "/slow"));
            tokio::time::timeout(WAIT, entered.notified())
                .await
                .expect("the request reaches its handler");

            let join = if graceful {
                server.shutdown();
                let mut join = Box::pin(server.join());
                assert!(
                    tokio::time::timeout(Duration::from_millis(300), &mut join)
                        .await
                        .is_err(),
                    "join waits for the request in flight"
                );
                Some(join)
            } else {
                drop(server);
                None
            };
            both_close(port, "both addresses close while a request is in flight").await;
            assert!(!request.is_finished(), "the handler has not answered yet");

            release.notify_one();
            let response = tokio::time::timeout(WAIT, request).await.unwrap().unwrap();
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(response.ends_with("\r\n\r\ndone"), "{response}");
            if let Some(join) = join {
                tokio::time::timeout(WAIT, join)
                    .await
                    .expect("join completes once the response is sent")
                    .unwrap();
            }
        }
    }
}
