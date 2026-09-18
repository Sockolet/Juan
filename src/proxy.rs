use std::{
    convert::Infallible,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version,
    header, uri::Authority,
};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{body::Incoming, service::service_fn};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{Sleep, timeout},
};
use tokio_rustls::TlsAcceptor;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    capture::{CaptureStore, SessionKind, Side},
    certificate::CertificateAuthority,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;
type HttpClient = Client<HttpsConnector<HttpConnector>, ProxyBody>;
type Reply = Result<Response<ProxyBody>, Infallible>;
type ReplyFuture = Pin<Box<dyn Future<Output = Reply> + Send>>;

const MAX_CONNECTIONS: usize = 128;
const MAX_REQUESTS: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub certificate: Option<Arc<CertificateAuthority>>,
    pub upstream_tls: Option<rustls::ClientConfig>,
    pub response_header_timeout: Duration,
    pub body_idle_timeout: Duration,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8866),
            certificate: None,
            upstream_tls: None,
            response_header_timeout: Duration::from_secs(120),
            body_idle_timeout: Duration::from_secs(300),
        }
    }
}

struct ProxyContext {
    client: HttpClient,
    store: Arc<CaptureStore>,
    certificate: Option<Arc<CertificateAuthority>>,
    address: SocketAddr,
    stop: CancellationToken,
    tasks: TaskTracker,
    connections: Arc<Semaphore>,
    requests: Arc<Semaphore>,
    response_header_timeout: Duration,
    body_idle_timeout: Duration,
}

pub struct ProxyHandle {
    context: Arc<ProxyContext>,
    accept_task: Option<JoinHandle<Result<()>>>,
}

impl ProxyHandle {
    pub fn address(&self) -> SocketAddr {
        self.context.address
    }

    pub fn running(&self) -> bool {
        !self.context.stop.is_cancelled()
            && self
                .accept_task
                .as_ref()
                .is_some_and(|task| !task.is_finished())
    }

    pub fn connections(&self) -> usize {
        MAX_CONNECTIONS - self.context.connections.available_permits()
    }

    pub async fn shutdown(mut self) -> Result<()> {
        self.context.stop.cancel();
        let listener_result = if let Some(task) = self.accept_task.take() {
            task.await.context("Join proxy listener")?
        } else {
            Ok(())
        };
        self.context.tasks.close();
        timeout(Duration::from_secs(5), self.context.tasks.wait())
            .await
            .context("Timed out waiting for proxy connections to close")?;
        self.context
            .store
            .notice("Proxy stopped. Existing proxy connections were closed.");
        listener_result
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.context.stop.cancel();
    }
}

pub async fn start(config: ProxyConfig, store: Arc<CaptureStore>) -> Result<ProxyHandle> {
    ensure!(
        config.listen.ip().is_loopback(),
        "Juan only listens on loopback; remote proxy access is not supported"
    );
    ensure!(
        !config.response_header_timeout.is_zero(),
        "Response-header timeout must be positive"
    );
    ensure!(
        !config.body_idle_timeout.is_zero(),
        "Body-idle timeout must be positive"
    );
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_connect_timeout(Some(CONNECT_TIMEOUT));
    http.set_nodelay(true);
    let builder = HttpsConnectorBuilder::new();
    let builder = match config.upstream_tls {
        Some(tls) => {
            ensure!(
                tls.alpn_protocols.is_empty(),
                "Custom upstream TLS ALPN must be empty; Juan negotiates HTTP/1.1 and HTTP/2"
            );
            builder.with_tls_config(tls)
        }
        None => builder
            .with_provider_and_platform_verifier(Arc::new(rustls::crypto::ring::default_provider()))
            .context("Initialize Windows/platform certificate verification")?,
    };
    let connector = builder
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    let client = Client::builder(TokioExecutor::new())
        .set_host(true)
        .pool_timer(TokioTimer::new())
        .pool_idle_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(2)
        .http1_preserve_header_case(true)
        .http1_max_buf_size(64 * 1024)
        .build(connector);
    let listener = TcpListener::bind(config.listen).await.with_context(|| {
        format!(
            "Listen on {} (another app may be using this port)",
            config.listen
        )
    })?;
    let address = listener.local_addr()?;
    let context = Arc::new(ProxyContext {
        client,
        store,
        certificate: config.certificate,
        address,
        stop: CancellationToken::new(),
        tasks: TaskTracker::new(),
        connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        requests: Arc::new(Semaphore::new(MAX_REQUESTS)),
        response_header_timeout: config.response_header_timeout,
        body_idle_timeout: config.body_idle_timeout,
    });
    context.store.notice(format!(
        "Listening on {address}. HTTPS {}. Upstream certificate verification is enabled.",
        if context.certificate.is_some() {
            "decryption enabled"
        } else {
            "tunneling only"
        }
    ));
    let task_context = context.clone();
    let accept_task = tokio::spawn(async move {
        let result = accept_loop(listener, task_context.clone()).await;
        if let Err(error) = &result {
            task_context
                .store
                .error(None, format!("Listener failed: {error:#}"));
        }
        task_context.stop.cancel();
        result
    });
    Ok(ProxyHandle {
        context,
        accept_task: Some(accept_task),
    })
}

async fn accept_loop(listener: TcpListener, context: Arc<ProxyContext>) -> Result<()> {
    loop {
        let (stream, peer) = tokio::select! {
            biased;
            _ = context.stop.cancelled() => break,
            accepted = listener.accept() => accepted.context("Accept proxy connection")?,
        };
        let permit = match context.connections.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                context
                    .store
                    .notice("Connection limit reached; a new client received HTTP 503.");
                if let Err(error) = stream.try_write(
                    b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                ) {
                    context.store.notice(format!("Could not send connection-limit response: {error}"));
                }
                continue;
            }
        };
        let job_context = context.clone();
        spawn_job(&context, None, async move {
            let _permit = permit;
            serve_io(stream, job_context, peer, None).await
        });
    }
    Ok(())
}

fn spawn_job(
    context: &Arc<ProxyContext>,
    id: Option<u64>,
    future: impl Future<Output = Result<()>> + Send + 'static,
) {
    let stop = context.stop.clone();
    let store = context.store.clone();
    context.tasks.spawn(async move {
        tokio::select! {
            biased;
            _ = stop.cancelled() => {
                if id.is_some() {
                    store.error(id, "Connection closed when the proxy stopped; totals may be partial.");
                }
            }
            result = future => {
                if let Err(error) = result {
                    store.error(id, format!("{error:#}"));
                }
            }
        }
    });
}

async fn serve_io<T>(
    io: T,
    context: Arc<ProxyContext>,
    peer: SocketAddr,
    origin: Option<Authority>,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service =
        service_fn(move |request| dispatch(request, context.clone(), peer, origin.clone()));
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(20))
        .max_buf_size(64 * 1024)
        .max_headers(128)
        .preserve_header_case(true);
    builder
        .http2()
        .max_concurrent_streams(64)
        .max_header_list_size(64 * 1024);
    builder
        .serve_connection_with_upgrades(TokioIo::new(io), service)
        .await
        .map_err(|error| anyhow::anyhow!("Client HTTP connection: {error}"))
}

// Boxing is the recursion boundary: CONNECT can create another HTTP service over TLS.
fn dispatch(
    request: Request<Incoming>,
    context: Arc<ProxyContext>,
    peer: SocketAddr,
    origin: Option<Authority>,
) -> ReplyFuture {
    Box::pin(async move {
        if request.method() == Method::CONNECT && origin.is_none() {
            return Ok(connect(request, context, peer).await);
        }
        Ok(forward(request, context, peer, origin).await)
    })
}

async fn forward(
    mut request: Request<Incoming>,
    context: Arc<ProxyContext>,
    peer: SocketAddr,
    origin: Option<Authority>,
) -> Response<ProxyBody> {
    let uri = match target_uri(&request, origin.as_ref()) {
        Ok(uri) => uri,
        Err(error) => {
            let id = context.store.begin(
                request.method(),
                request.uri(),
                request.version(),
                request.headers(),
                peer,
            );
            return error_reply(&context, id, StatusCode::BAD_REQUEST, format!("{error:#}"));
        }
    };
    let id = context.store.begin(
        request.method(),
        &uri,
        request.version(),
        request.headers(),
        peer,
    );
    if connection_bound_auth(request.headers()) {
        return error_reply(
            &context,
            id,
            StatusCode::NOT_IMPLEMENTED,
            "NTLM/Negotiate connection-bound authentication is not supported during HTTP inspection. Disable HTTPS decryption to preserve it inside an opaque CONNECT tunnel.",
        );
    }
    if let Err(error) = reject_self(&uri, context.address).await {
        return error_reply(&context, id, StatusCode::BAD_REQUEST, format!("{error:#}"));
    }
    let permit = match context.requests.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return error_reply(
                &context,
                id,
                StatusCode::SERVICE_UNAVAILABLE,
                "Concurrent request limit reached",
            );
        }
    };
    let client_version = request.version();
    let upgrade_requested = client_version != Version::HTTP_2 && is_upgrade(request.headers());
    let client_upgrade = upgrade_requested.then(|| hyper::upgrade::on(&mut request));
    let (mut parts, incoming) = request.into_parts();
    strip_hop_headers(&mut parts.headers, upgrade_requested);
    // The client derives Host for HTTP/1.x and :authority for HTTP/2 from this URI.
    // Carrying Host into HTTP/2 causes resets on origins such as Google's.
    parts.headers.remove(header::HOST);
    parts.uri = uri;
    parts.version = Version::HTTP_11;
    let body = observed(incoming, &context, id, Side::Request, None);
    let request = Request::from_parts(parts, body);
    let response = timeout(
        context.response_header_timeout,
        context.client.request(request),
    )
    .await;
    let mut response = match response {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            return error_reply(
                &context,
                id,
                StatusCode::BAD_GATEWAY,
                format!("Upstream request failed: {:#}", anyhow::Error::new(error)),
            );
        }
        Err(_) => {
            return error_reply(
                &context,
                id,
                StatusCode::GATEWAY_TIMEOUT,
                "Timed out waiting for upstream response headers",
            );
        }
    };
    context.store.response(
        id,
        response.status().as_u16(),
        response.version(),
        response.headers(),
    );
    let upgraded = response.status() == StatusCode::SWITCHING_PROTOCOLS;
    if upgraded && !upgrade_requested {
        return error_reply(
            &context,
            id,
            StatusCode::BAD_GATEWAY,
            "Upstream sent an unsolicited protocol upgrade",
        );
    }
    if upgraded {
        let server_upgrade = hyper::upgrade::on(&mut response);
        let client_upgrade = client_upgrade.expect("upgrade request checked");
        context.store.set_kind(id, SessionKind::WebSocket);
        let job_context = context.clone();
        spawn_job(&context, id, async move {
            let _permit = permit;
            let (client, server) = timeout(CONNECT_TIMEOUT, async {
                tokio::try_join!(client_upgrade, server_upgrade)
            })
            .await
            .context("WebSocket upgrade timed out")?
            .context("WebSocket upgrade failed")?;
            relay(TokioIo::new(client), TokioIo::new(server), job_context, id).await
        });
        let (mut parts, _) = response.into_parts();
        strip_hop_headers(&mut parts.headers, true);
        parts.version = client_version;
        return Response::from_parts(parts, full(Bytes::new()));
    }
    let (mut parts, incoming) = response.into_parts();
    strip_hop_headers(&mut parts.headers, false);
    parts.version = client_version;
    Response::from_parts(
        parts,
        observed(incoming, &context, id, Side::Response, Some(permit)),
    )
}

async fn connect(
    mut request: Request<Incoming>,
    context: Arc<ProxyContext>,
    peer: SocketAddr,
) -> Response<ProxyBody> {
    let id = context.store.begin(
        request.method(),
        request.uri(),
        request.version(),
        request.headers(),
        peer,
    );
    let authority = match connect_authority(request.uri()) {
        Ok(authority) => authority,
        Err(error) => {
            return error_reply(&context, id, StatusCode::BAD_REQUEST, format!("{error:#}"));
        }
    };
    let uri: Uri = format!("https://{authority}/")
        .parse()
        .expect("validated CONNECT authority");
    if let Err(error) = reject_self(&uri, context.address).await {
        return error_reply(&context, id, StatusCode::BAD_REQUEST, format!("{error:#}"));
    }
    let permit = match context.connections.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return error_reply(
                &context,
                id,
                StatusCode::SERVICE_UNAVAILABLE,
                "Tunnel connection limit reached",
            );
        }
    };
    let version = request.version();
    if version == Version::HTTP_2 {
        return error_reply(
            &context,
            id,
            StatusCode::NOT_IMPLEMENTED,
            "HTTP/2 CONNECT is not supported; use an HTTP/1.1 proxy connection",
        );
    }
    let host = authority.host().trim_matches(['[', ']']);
    let port = authority.port_u16().expect("validated CONNECT port");
    if let Some(certificate) = &context.certificate {
        let tls = match certificate.server_config(host) {
            Ok(config) => config,
            Err(error) => {
                return error_reply(
                    &context,
                    id,
                    StatusCode::BAD_GATEWAY,
                    format!("Issue local TLS certificate: {error:#}"),
                );
            }
        };
        let upgrade = hyper::upgrade::on(&mut request);
        let job_context = context.clone();
        spawn_job(&context, id, async move {
            let _permit = permit;
            let upgraded = timeout(CONNECT_TIMEOUT, upgrade)
                .await
                .context("CONNECT upgrade timed out")??;
            let stream = timeout(CONNECT_TIMEOUT, TlsAcceptor::from(tls).accept(TokioIo::new(upgraded))).await
                .context("TLS client handshake timed out")?
                .context("TLS client handshake failed; trust Juan's CA in this client. Certificate pinning and mTLS are unsupported")?;
            serve_io(stream, job_context.clone(), peer, Some(authority)).await?;
            job_context.store.complete_tunnel(id, 0, 0);
            Ok(())
        });
    } else {
        let server = match timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                return error_reply(
                    &context,
                    id,
                    StatusCode::BAD_GATEWAY,
                    format!("CONNECT to upstream failed: {error}"),
                );
            }
            Err(_) => {
                return error_reply(
                    &context,
                    id,
                    StatusCode::GATEWAY_TIMEOUT,
                    "CONNECT to upstream timed out",
                );
            }
        };
        if server
            .peer_addr()
            .is_ok_and(|peer| same_listener(peer, context.address))
        {
            return error_reply(
                &context,
                id,
                StatusCode::BAD_REQUEST,
                "Refusing a proxy loop",
            );
        }
        let upgrade = hyper::upgrade::on(&mut request);
        let job_context = context.clone();
        spawn_job(&context, id, async move {
            let _permit = permit;
            let client = timeout(CONNECT_TIMEOUT, upgrade)
                .await
                .context("CONNECT upgrade timed out")??;
            relay(TokioIo::new(client), server, job_context, id).await
        });
    }
    context.store.complete_body(id, Side::Request);
    context.store.response(id, 200, version, &HeaderMap::new());
    Response::builder()
        .status(StatusCode::OK)
        .body(full(Bytes::new()))
        .expect("valid CONNECT response")
}

async fn relay<C, S>(
    client: C,
    server: S,
    context: Arc<ProxyContext>,
    id: Option<u64>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut client = Metered {
        inner: client,
        store: context.store.clone(),
        id,
        side: Side::Request,
    };
    let mut server = Metered {
        inner: server,
        store: context.store.clone(),
        id,
        side: Side::Response,
    };
    let (sent, received) = tokio::io::copy_bidirectional(&mut client, &mut server)
        .await
        .context("Tunnel relay failed")?;
    context.store.complete_tunnel(id, sent, received);
    Ok(())
}

struct Metered<T> {
    inner: T,
    store: Arc<CaptureStore>,
    id: Option<u64>,
    side: Side,
}

impl<T: AsyncRead + Unpin> AsyncRead for Metered<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) {
            let count = buf.filled().len() - before;
            if count > 0 {
                self.store.count_tunnel_bytes(self.id, self.side, count);
            }
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Metered<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn connect_authority(uri: &Uri) -> Result<Authority> {
    ensure!(
        uri.scheme().is_none() && uri.path_and_query().is_none(),
        "CONNECT must use host:port authority form"
    );
    let authority = uri
        .authority()
        .context("CONNECT requires a host:port")?
        .clone();
    ensure!(
        !authority.as_str().contains('@'),
        "Credentials are not allowed in a CONNECT authority"
    );
    ensure!(!authority.host().is_empty(), "CONNECT hostname is empty");
    ensure!(
        authority.port_u16().is_some_and(|port| port > 0),
        "CONNECT requires a valid, nonzero port"
    );
    Ok(authority)
}

fn equivalent_authority(a: &Authority, b: &Authority, default_port: u16) -> bool {
    a.host().eq_ignore_ascii_case(b.host())
        && a.port_u16().unwrap_or(default_port) == b.port_u16().unwrap_or(default_port)
}

fn target_uri<B>(request: &Request<B>, origin: Option<&Authority>) -> Result<Uri> {
    ensure!(
        request.method() != Method::CONNECT,
        "Nested CONNECT and extended CONNECT are not supported"
    );
    let uri = request.uri();
    let target = if let Some(origin) = origin {
        if let Some(scheme) = uri.scheme_str() {
            ensure!(scheme == "https", "TLS-intercepted requests must use HTTPS");
        }
        if let Some(authority) = uri.authority() {
            ensure!(
                equivalent_authority(authority, origin, 443),
                "Request authority differs from the CONNECT destination"
            );
        }
        if let Some(host) = request.headers().get(header::HOST) {
            let host: Authority = host.to_str()?.parse().context("Invalid Host header")?;
            ensure!(
                equivalent_authority(&host, origin, 443),
                "Host differs from the CONNECT destination"
            );
        }
        Uri::builder()
            .scheme("https")
            .authority(origin.clone())
            .path_and_query(uri.path_and_query().map_or("/", |p| p.as_str()))
            .build()?
    } else if uri.scheme().is_some() {
        uri.clone()
    } else {
        let host: Authority = request
            .headers()
            .get(header::HOST)
            .context("Origin-form request requires Host")?
            .to_str()?
            .parse()
            .context("Invalid Host header")?;
        Uri::builder()
            .scheme("http")
            .authority(host)
            .path_and_query(uri.path_and_query().map_or("/", |p| p.as_str()))
            .build()?
    };
    ensure!(
        matches!(target.scheme_str(), Some("http" | "https")),
        "Only HTTP and HTTPS destinations are supported"
    );
    let authority = target
        .authority()
        .context("Request has no destination authority")?;
    ensure!(
        !authority.as_str().contains('@'),
        "Credentials in destination URLs are not supported; use Authorization headers"
    );
    ensure!(
        authority.port_u16() != Some(0),
        "Destination port must not be zero"
    );
    Ok(target)
}

fn same_listener(destination: SocketAddr, listener: SocketAddr) -> bool {
    destination.port() == listener.port()
        && (destination.ip() == listener.ip() || destination.ip().is_loopback())
}

async fn reject_self(uri: &Uri, listener: SocketAddr) -> Result<()> {
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    if port != listener.port() {
        return Ok(());
    }
    let host = uri
        .host()
        .context("Request has no hostname")?
        .trim_matches(['[', ']']);
    let addresses = timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .context("Destination lookup timed out")?
        .context("Resolve destination")?;
    ensure!(
        !addresses
            .into_iter()
            .any(|address| same_listener(address, listener)),
        "Refusing to forward to Juan's own listener (proxy loop)"
    );
    Ok(())
}

fn is_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(header::UPGRADE)
        && headers.get_all(header::CONNECTION).iter().any(|value| {
            value.to_str().is_ok_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
        })
}

fn connection_bound_auth(headers: &HeaderMap) -> bool {
    headers.get_all(header::AUTHORIZATION).iter().any(|value| {
        value
            .to_str()
            .ok()
            .and_then(|value| value.split_whitespace().next())
            .is_some_and(|scheme| {
                scheme.eq_ignore_ascii_case("ntlm") || scheme.eq_ignore_ascii_case("negotiate")
            })
    })
}

pub fn strip_hop_headers(headers: &mut HeaderMap, preserve_upgrade: bool) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named {
        if preserve_upgrade && name == header::UPGRADE {
            continue;
        }
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "transfer-encoding",
    ] {
        headers.remove(name);
    }
    if preserve_upgrade {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    } else {
        headers.remove(header::UPGRADE);
    }
    // TE: trailers and Trailer declarations are legal on both supported HTTP versions.
    if headers.contains_key(header::TE) {
        let trailers = headers.get_all(header::TE).iter().any(|value| {
            value.to_str().is_ok_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("trailers"))
            })
        });
        headers.remove(header::TE);
        if trailers {
            headers.insert(header::TE, HeaderValue::from_static("trailers"));
        }
    }
}

fn error_reply(
    context: &ProxyContext,
    id: Option<u64>,
    status: StatusCode,
    message: impl AsRef<str>,
) -> Response<ProxyBody> {
    let message = message.as_ref();
    context.store.error(id, message);
    let payload = Bytes::from(format!("Juan: {message}\n"));
    let response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(payload.clone()))
        .expect("valid error response");
    context
        .store
        .response(id, status.as_u16(), Version::HTTP_11, response.headers());
    context.store.append(id, Side::Response, &payload);
    context.store.complete_body(id, Side::Response);
    response
}

fn full(bytes: Bytes) -> ProxyBody {
    Full::new(bytes)
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

fn observed(
    incoming: Incoming,
    context: &ProxyContext,
    id: Option<u64>,
    side: Side,
    permit: Option<OwnedSemaphorePermit>,
) -> ProxyBody {
    let finished = incoming.is_end_stream();
    if finished {
        context.store.complete_body(id, side);
    }
    ObservedBody {
        inner: incoming,
        store: context.store.clone(),
        id,
        side,
        finished,
        idle: Box::pin(tokio::time::sleep(context.body_idle_timeout)),
        idle_duration: context.body_idle_timeout,
        _permit: permit,
    }
    .boxed_unsync()
}

struct ObservedBody {
    inner: Incoming,
    store: Arc<CaptureStore>,
    id: Option<u64>,
    side: Side,
    finished: bool,
    idle: Pin<Box<Sleep>>,
    idle_duration: Duration,
    _permit: Option<OwnedSemaphorePermit>,
}

impl Body for ObservedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.finished {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.store.append(self.id, self.side, data);
                }
                if let Some(trailers) = frame.trailers_ref() {
                    self.store.trailers(self.id, self.side, trailers);
                }
                let next = tokio::time::Instant::now() + self.idle_duration;
                self.idle.as_mut().reset(next);
                if self.inner.is_end_stream() {
                    self.finished = true;
                    self.store.complete_body(self.id, self.side);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.finished = true;
                self.store
                    .error(self.id, format!("{:?} body failed: {error}", self.side));
                Poll::Ready(Some(Err(Box::new(error))))
            }
            Poll::Ready(None) => {
                self.finished = true;
                self.store.complete_body(self.id, self.side);
                Poll::Ready(None)
            }
            Poll::Pending => {
                if self.idle.as_mut().poll(cx).is_ready() {
                    self.finished = true;
                    self.store.error(
                        self.id,
                        format!("{:?} body idle timeout; capture is incomplete", self.side),
                    );
                    Poll::Ready(Some(Err(Box::new(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Body idle timeout",
                    )))))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished || self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for ObservedBody {
    fn drop(&mut self) {
        if !self.finished {
            if self.inner.is_end_stream() {
                self.store.complete_body(self.id, self.side);
            } else {
                self.store.error(self.id, format!("{:?} body closed before completion (client disconnect, upstream early response, or proxy stop)", self.side));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_hop_headers_without_leaking_proxy_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", "keep-alive, x-private".parse().unwrap());
        headers.insert("x-private", "hop only".parse().unwrap());
        headers.insert("proxy-authorization", "Basic secret".parse().unwrap());
        headers.insert("authorization", "Bearer origin".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        headers.insert("te", "gzip, trailers".parse().unwrap());
        strip_hop_headers(&mut headers, false);
        for name in [
            "connection",
            "x-private",
            "proxy-authorization",
            "transfer-encoding",
        ] {
            assert!(!headers.contains_key(name), "{name}");
        }
        assert_eq!(headers["authorization"], "Bearer origin");
        assert_eq!(headers["te"], "trailers");
    }

    #[test]
    fn preserves_websocket_upgrade() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", "Upgrade".parse().unwrap());
        headers.insert("upgrade", "websocket".parse().unwrap());
        assert!(is_upgrade(&headers));
        strip_hop_headers(&mut headers, true);
        assert_eq!(headers["connection"], "upgrade");
        assert_eq!(headers["upgrade"], "websocket");
    }

    #[test]
    fn tls_requests_cannot_escape_connect_authority() {
        let origin: Authority = "example.test:443".parse().unwrap();
        let good = Request::builder()
            .uri("/path?q=1")
            .header("host", "example.test")
            .body(())
            .unwrap();
        assert_eq!(
            target_uri(&good, Some(&origin)).unwrap(),
            "https://example.test:443/path?q=1"
        );
        let bad = Request::builder()
            .uri("https://other.test/")
            .body(())
            .unwrap();
        assert!(target_uri(&bad, Some(&origin)).is_err());
        let bad_host = Request::builder()
            .uri("/")
            .header("host", "other.test")
            .body(())
            .unwrap();
        assert!(target_uri(&bad_host, Some(&origin)).is_err());
    }

    #[test]
    fn validates_connect_including_ipv6() {
        assert!(connect_authority(&"example.test:443".parse().unwrap()).is_ok());
        assert!(connect_authority(&"[::1]:443".parse().unwrap()).is_ok());
        for invalid in ["http://example.test/", "example.test:0", "/path"] {
            assert!(
                connect_authority(&invalid.parse().unwrap()).is_err(),
                "{invalid}"
            );
        }
    }

    #[tokio::test]
    async fn refuses_non_loopback_listeners_and_proxy_loops() {
        let config = ProxyConfig {
            listen: "0.0.0.0:0".parse().unwrap(),
            ..ProxyConfig::default()
        };
        assert!(
            start(config, Arc::new(CaptureStore::default()))
                .await
                .is_err()
        );
        assert!(
            reject_self(
                &"http://127.0.0.1:8866/".parse().unwrap(),
                "127.0.0.1:8866".parse().unwrap()
            )
            .await
            .is_err()
        );
    }
}
