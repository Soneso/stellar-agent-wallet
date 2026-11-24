//! A TCP forwarder that reaches a loopback mock server under the host name
//! `localhost`.
//!
//! A `wiremock` server listens on `127.0.0.1` alone, and `localhost` may
//! resolve to `::1` first. A client that connects to `localhost` at the
//! mock's own port reaches whatever another process holds on `[::1]` at that
//! port. The forwarder listens on one port of both loopback families when
//! IPv6 is available. It copies each connection to the mock, whichever
//! address the client tries first.

#![allow(
    clippy::panic,
    clippy::expect_used,
    reason = "a fixture that cannot be set up fails the calling test"
)]

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener as StdTcpListener};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

/// How many forwarder ports are tried before the setup gives up.
const BIND_ATTEMPTS: usize = 64;

/// How long the accept loop pauses after a failed accept, so an exhausted
/// descriptor table does not spin it.
const ACCEPT_RETRY_PAUSE: Duration = Duration::from_millis(10);

/// The OS error code of an address family the host does not support.
#[cfg(unix)]
const ADDRESS_FAMILY_UNSUPPORTED: i32 = libc::EAFNOSUPPORT;

/// The OS error code of an address family the host does not support
/// (`WSAEAFNOSUPPORT`).
#[cfg(windows)]
const ADDRESS_FAMILY_UNSUPPORTED: i32 = 10047;

/// The port of the forwarder to the mock server on `127.0.0.1:mock_port`.
///
/// One forwarder serves each mock port for the rest of the process. It
/// connects to whichever server holds `127.0.0.1:mock_port` when a client
/// arrives, which is the caller's mock for as long as the caller holds it.
///
/// # Panics
///
/// Panics when no port is free on both loopback families within
/// [`BIND_ATTEMPTS`] attempts, or when a loopback listener cannot be bound or
/// served.
pub(crate) fn forwarder_port(mock_port: u16) -> u16 {
    static FORWARDERS: OnceLock<Mutex<HashMap<u16, u16>>> = OnceLock::new();
    let mut forwarders = FORWARDERS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if let Some(&port) = forwarders.get(&mock_port) {
        return port;
    }
    let (port, listeners) = bind_both_families();
    for listener in listeners {
        serve(listener, mock_port);
    }
    forwarders.insert(mock_port, port);
    port
}

/// Binds one port on `127.0.0.1` and on `[::1]`, and returns the port with
/// its listeners.
///
/// The IPv4 listener takes a free port first. When `[::1]` at that port is
/// taken, both are released and another port is tried. When the host has no
/// IPv6 loopback, the IPv4 listener serves alone: a client that tries `::1`
/// first then falls through to `127.0.0.1`.
fn bind_both_families() -> (u16, Vec<StdTcpListener>) {
    for _ in 0..BIND_ATTEMPTS {
        let ipv4 = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap_or_else(|error| panic!("the forwarder cannot bind 127.0.0.1: {error}"));
        let port = ipv4
            .local_addr()
            .expect("a bound listener has a local address")
            .port();
        match StdTcpListener::bind((Ipv6Addr::LOCALHOST, port)) {
            Ok(ipv6) => return (port, vec![ipv4, ipv6]),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) if ipv6_loopback_unavailable(&error) => return (port, vec![ipv4]),
            Err(error) => panic!("the forwarder cannot bind [::1]:{port}: {error}"),
        }
    }
    panic!(
        "no port was free on both 127.0.0.1 and [::1] in {BIND_ATTEMPTS} attempts: another \
         process holds the IPv6 loopback at every port tried"
    )
}

/// Whether a bind on `[::1]` failed because the host has no IPv6 loopback.
fn ipv6_loopback_unavailable(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::AddrNotAvailable
        || error.raw_os_error() == Some(ADDRESS_FAMILY_UNSUPPORTED)
}

/// Accepts connections on `listener` and copies each one to
/// `127.0.0.1:mock_port`.
fn serve(listener: StdTcpListener, mock_port: u16) {
    listener
        .set_nonblocking(true)
        .expect("a loopback listener switches to non-blocking mode");
    runtime().spawn(async move {
        let listener = TcpListener::from_std(listener)
            .expect("the forwarder runtime registers a loopback listener");
        loop {
            match listener.accept().await {
                Ok((inbound, _)) => {
                    tokio::spawn(forward(inbound, mock_port));
                }
                Err(_) => tokio::time::sleep(ACCEPT_RETRY_PAUSE).await,
            }
        }
    });
}

/// Copies `inbound` to and from `127.0.0.1:mock_port` until either side
/// closes.
///
/// When the mock cannot be reached, `inbound` is closed, which the client
/// observes as a failed request.
async fn forward(mut inbound: TcpStream, mock_port: u16) {
    let Ok(mut upstream) = TcpStream::connect((Ipv4Addr::LOCALHOST, mock_port)).await else {
        return;
    };
    // An error ends the copy and both connections close on return, which is
    // how the client learns of it.
    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await;
}

/// The runtime every forwarder runs on.
///
/// It is the forwarder's own, apart from the caller's: a test that blocks its
/// runtime's thread while a subprocess uses the forwarder is still served.
fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("loopback-forwarder")
            .enable_io()
            .enable_time()
            .build()
            .expect("the forwarder runtime starts")
    })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::second_loopback_host;

    /// Holds `[::1]:port` with a listener that accepts every connection and
    /// closes it at once, as a foreign process on that port answers a client
    /// that expected the mock. A host that cannot bind `[::1]` runs the test
    /// without the occupation.
    async fn occupy_ipv6_loopback(port: u16) {
        if let Ok(listener) = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await
        {
            tokio::spawn(async move {
                while let Ok((connection, _)) = listener.accept().await {
                    drop(connection);
                }
            });
        }
    }

    #[tokio::test]
    async fn a_listener_on_the_ipv6_loopback_at_the_mock_port_does_not_take_the_request() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/probe"))
            .respond_with(ResponseTemplate::new(200).set_body_string("the mock"))
            .expect(1)
            .mount(&mock)
            .await;
        occupy_ipv6_loopback(mock.address().port()).await;

        let url = second_loopback_host(&mock.uri());
        // Try [::1] before 127.0.0.1 on every host. The URL's port replaces port 0.
        let client = reqwest::Client::builder()
            .resolve_to_addrs(
                "localhost",
                &[
                    SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
                    SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                ],
            )
            .no_proxy()
            .build()
            .expect("a plain HTTP client");
        let response = client
            .get(format!("{url}/probe"))
            .send()
            .await
            .expect("the request reaches the mock");
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.expect("the mock's body"), "the mock");
        mock.verify().await;
    }

    #[tokio::test]
    async fn the_url_names_localhost_at_the_forwarder_port_with_the_mock_scheme_and_path() {
        let mock = MockServer::start().await;
        let mock_port = mock.address().port();
        occupy_ipv6_loopback(mock_port).await;

        let url = second_loopback_host(&format!("{}/rpc/v1", mock.uri()));
        let rest = url
            .strip_prefix("http://localhost:")
            .unwrap_or_else(|| panic!("an http URL on localhost: {url}"));
        let (port, path) = rest
            .split_once('/')
            .unwrap_or_else(|| panic!("a port and a path: {url}"));
        let port: u16 = port.parse().expect("a port number");
        assert_ne!(port, mock_port, "the port of the forwarder, not the mock's");
        assert_eq!(path, "rpc/v1");
        assert_eq!(
            second_loopback_host(&mock.uri()),
            format!("http://localhost:{port}"),
            "one forwarder serves the mock"
        );
    }
}
