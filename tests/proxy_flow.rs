use std::{
    collections::VecDeque,
    convert::Infallible,
    io::Write as _,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode, Version};
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use juan::{
    capture::{CaptureLimits, CaptureStore, SessionKind},
    certificate::CertificateAuthority,
    inspect,
    proxy::{self, ProxyConfig, ProxyHandle},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
    time::{Sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type TestBody = UnsyncBoxBody<Bytes, BoxError>;

fn body(value: impl Into<Bytes>) -> TestBody {
    Full::new(value.into())
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

struct Origin {
    address: SocketAddr,
    ca: Option<Arc<CertificateAuthority>>,
    stop: CancellationToken,
    task: JoinHandle<()>,
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}

impl Origin {
    async fn start(tls: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let ca = tls.then(|| Arc::new(CertificateAuthority::generate().unwrap()));
        let tls = ca.as_ref().map(|ca| ca.server_config("localhost").unwrap());
        let stop = CancellationToken::new();
        let token = stop.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    Some(result) = connections.join_next(), if !connections.is_empty() => {
                        result.unwrap();
                    }
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        let tls = tls.clone();
                        let stop = token.clone();
                        connections.spawn(async move {
                            if let Some(tls) = tls {
                                match TlsAcceptor::from(tls).accept(stream).await {
                                    Ok(stream) => serve_origin(stream, stop).await,
                                    Err(error) => eprintln!("Test origin TLS handshake ended: {error}"),
                                }
                            } else {
                                serve_origin(stream, stop).await;
                            }
                        });
                    }
                }
            }
            connections.abort_all();
        });
        Self {
            address,
            ca,
            stop,
            task,
        }
    }

    fn url(&self, path: &str) -> String {
        if self.ca.is_some() {
            format!("https://localhost:{}{path}", self.address.port())
        } else {
            format!("http://{}{path}", self.address)
        }
    }
}

async fn serve_origin<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: T,
    stop: CancellationToken,
) {
    let token = stop.clone();
    let service = service_fn(move |request| origin_reply(request, token.clone()));
    let builder = auto::Builder::new(TokioExecutor::new());
    tokio::select! {
        _ = stop.cancelled() => {}
        result = builder.serve_connection_with_upgrades(TokioIo::new(stream), service) => {
            if let Err(error) = result { eprintln!("Test origin connection ended: {error}"); }
        }
    }
}

async fn origin_reply(
    mut request: Request<Incoming>,
    stop: CancellationToken,
) -> Result<Response<TestBody>, Infallible> {
    let response = match request.uri().path() {
        "/authority" => Response::builder()
            .header("content-type", "application/json")
            .body(body(
                serde_json::to_vec(&serde_json::json!({
                    "authority": request.uri().authority().map(|authority| authority.as_str()),
                    "host": request.headers().get("host").map(|host| host.to_str().unwrap()),
                    "version": format!("{:?}", request.version()),
                }))
                .unwrap(),
            ))
            .unwrap(),
        "/echo" => Response::builder()
            .header("content-type", "application/octet-stream")
            .body(
                request
                    .into_body()
                    .map_err(|error| -> BoxError { Box::new(error) })
                    .boxed_unsync(),
            )
            .unwrap(),
        "/headers" => {
            let headers: Vec<_> = request
                .headers()
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str(),
                        String::from_utf8_lossy(value.as_bytes()).into_owned(),
                    )
                })
                .collect();
            let mut response = Response::new(body(serde_json::to_vec(&headers).unwrap()));
            response
                .headers_mut()
                .append("set-cookie", "first=1".parse().unwrap());
            response
                .headers_mut()
                .append("set-cookie", "second=2".parse().unwrap());
            response
        }
        "/large" => Response::builder()
            .header("content-type", "application/octet-stream")
            .body(body(vec![0xA5; 2 * 1024 * 1024]))
            .unwrap(),
        "/redirect" => Response::builder()
            .status(302)
            .header("location", "/not-followed")
            .body(body("redirect"))
            .unwrap(),
        "/gzip" => {
            let mut gzip =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gzip.write_all(br#"{"compressed":true}"#).unwrap();
            Response::builder()
                .header("content-encoding", "gzip")
                .header("content-type", "application/json")
                .body(body(gzip.finish().unwrap()))
                .unwrap()
        }
        "/stream" => Response::new(
            Frames {
                frames: VecDeque::from([
                    Frame::data(Bytes::from_static(b"first")),
                    Frame::data(Bytes::from_static(b"second")),
                ]),
                delay: Some(Box::pin(tokio::time::sleep(Duration::from_millis(800)))),
                sent: 0,
            }
            .boxed_unsync(),
        ),
        "/trailers" => {
            let mut trailers = HeaderMap::new();
            trailers.insert("x-checksum", "finished".parse().unwrap());
            Response::builder()
                .header("trailer", "x-checksum")
                .body(
                    Frames {
                        frames: VecDeque::from([
                            Frame::data(Bytes::from_static(b"hello")),
                            Frame::trailers(trailers),
                        ]),
                        delay: None,
                        sent: 0,
                    }
                    .boxed_unsync(),
                )
                .unwrap()
        }
        "/ws" => {
            let upgrade = hyper::upgrade::on(&mut request);
            tokio::spawn(async move {
                tokio::select! {
                    _ = stop.cancelled() => {}
                    result = async {
                        let upgraded = upgrade.await?;
                        let (mut read, mut write) = tokio::io::split(TokioIo::new(upgraded));
                        tokio::io::copy(&mut read, &mut write).await?;
                        Ok::<_, BoxError>(())
                    } => {
                        if let Err(error) = result { eprintln!("Test WebSocket relay ended: {error}"); }
                    }
                }
            });
            Response::builder()
                .status(101)
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .body(body(""))
                .unwrap()
        }
        _ => Response::builder()
            .status(404)
            .body(body("not found"))
            .unwrap(),
    };
    Ok(response)
}

struct Frames {
    frames: VecDeque<Frame<Bytes>>,
    delay: Option<Pin<Box<Sleep>>>,
    sent: usize,
}

impl Body for Frames {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.sent == 1
            && let Some(delay) = self.delay.as_mut()
            && delay.as_mut().poll(cx).is_pending()
        {
            return Poll::Pending;
        }
        self.sent += 1;
        Poll::Ready(self.frames.pop_front().map(Ok))
    }
    fn is_end_stream(&self) -> bool {
        self.frames.is_empty()
    }
}

async fn start_proxy(store: Arc<CaptureStore>) -> ProxyHandle {
    proxy::start(
        ProxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            ..ProxyConfig::default()
        },
        store,
    )
    .await
    .unwrap()
}

async fn get_response(
    address: SocketAddr,
    request: Request<Full<Bytes>>,
) -> (StatusCode, HeaderMap, Bytes, Option<HeaderMap>) {
    let stream = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    let response = timeout(Duration::from_secs(10), sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    let (parts, incoming) = response.into_parts();
    let collected = timeout(Duration::from_secs(10), incoming.collect())
        .await
        .unwrap()
        .unwrap();
    let trailers = collected.trailers().cloned();
    let bytes = collected.to_bytes();
    drop(sender);
    connection.abort();
    (parts.status, parts.headers, bytes, trailers)
}

fn request(method: &str, url: &str, value: impl Into<Bytes>) -> Request<Full<Bytes>> {
    Request::builder()
        .method(method)
        .uri(url)
        .body(Full::new(value.into()))
        .unwrap()
}

fn trusted_client(ca: Option<&CertificateAuthority>) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    if let Some(ca) = ca {
        roots.add(ca.der().to_vec().into()).unwrap();
    }
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

async fn tls_through(
    proxy: SocketAddr,
    origin_port: u16,
    ca: &CertificateAuthority,
    h2: bool,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(
            format!(
                "CONNECT localhost:{origin_port} HTTP/1.1\r\nHost: localhost:{origin_port}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let headers = read_headers(&mut stream).await;
    assert!(headers.starts_with("HTTP/1.1 200"), "{headers}");
    let mut config = trusted_client(Some(ca));
    config.alpn_protocols = vec![if h2 {
        b"h2".to_vec()
    } else {
        b"http/1.1".to_vec()
    }];
    timeout(
        Duration::from_secs(5),
        TlsConnector::from(Arc::new(config)).connect("localhost".try_into().unwrap(), stream),
    )
    .await
    .unwrap()
    .unwrap()
}

async fn read_headers(stream: &mut TcpStream) -> String {
    let mut output = Vec::new();
    timeout(Duration::from_secs(5), async {
        loop {
            output.push(stream.read_u8().await.unwrap());
            assert!(output.len() < 16 * 1024);
            if output.ends_with(b"\r\n\r\n") {
                break;
            }
        }
    })
    .await
    .unwrap();
    String::from_utf8(output).unwrap()
}

#[tokio::test]
async fn http_echo_preserves_bytes_but_bounds_both_capture_bodies() {
    let origin = Origin::start(false).await;
    let store = Arc::new(
        CaptureStore::with_limits(CaptureLimits {
            sessions: 10,
            body_bytes: 8192,
            total_body_bytes: 16384,
        })
        .unwrap(),
    );
    let proxy = start_proxy(store.clone()).await;
    let original = Bytes::from(vec![0xCC; 128 * 1024]);
    let (status, _, received, _) = get_response(
        proxy.address(),
        request("POST", &origin.url("/echo"), original.clone()),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(received, original);
    let session = store.all_sessions().pop().unwrap();
    assert_eq!(session.request.total_bytes, 128 * 1024);
    assert_eq!(session.response.total_bytes, 128 * 1024);
    assert_eq!(session.request.data.len(), 8192);
    assert_eq!(session.response.data.len(), 8192);
    assert!(session.response.complete && session.request.complete);
    assert_eq!(store.snapshot().retained_bytes, 16384);
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn large_downloads_are_not_truncated_by_capture_limits() {
    let origin = Origin::start(false).await;
    let store = Arc::new(CaptureStore::default());
    let proxy = start_proxy(store.clone()).await;
    let (status, _, received, _) =
        get_response(proxy.address(), request("GET", &origin.url("/large"), "")).await;
    assert_eq!(status, 200);
    assert_eq!(received.len(), 2 * 1024 * 1024);
    assert!(received.iter().all(|byte| *byte == 0xA5));
    let session = store.all_sessions().pop().unwrap();
    assert_eq!(session.response.data.len(), 1024 * 1024);
    assert_eq!(session.response.total_bytes, 2 * 1024 * 1024);
    assert!(session.response.truncated());
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn hop_headers_are_removed_duplicates_preserved_and_redirects_not_followed() {
    let origin = Origin::start(false).await;
    let store = Arc::new(CaptureStore::default());
    let proxy = start_proxy(store.clone()).await;
    let request = Request::builder()
        .uri(origin.url("/headers"))
        .header("connection", "x-hop")
        .header("x-hop", "private-hop-value")
        .header("proxy-authorization", "private-proxy-value")
        .header("authorization", "origin-value")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, headers, bytes, _) = get_response(proxy.address(), request).await;
    assert_eq!(status, 200);
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(!text.contains("private-hop-value"));
    assert!(!text.contains("private-proxy-value"));
    assert!(text.contains("origin-value"));
    assert_eq!(headers.get_all("set-cookie").iter().count(), 2);
    let (status, headers, _, _) = get_response(
        proxy.address(),
        self::request("GET", &origin.url("/redirect"), ""),
    )
    .await;
    assert_eq!(status, 302);
    assert_eq!(headers["location"], "/not-followed");
    assert_eq!(store.all_sessions().len(), 2);
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn compression_is_preserved_on_wire_and_decodable_in_inspectors() {
    let origin = Origin::start(false).await;
    let store = Arc::new(CaptureStore::default());
    let proxy = start_proxy(store.clone()).await;
    let (_, headers, bytes, _) =
        get_response(proxy.address(), request("GET", &origin.url("/gzip"), "")).await;
    assert_eq!(headers["content-encoding"], "gzip");
    assert_eq!(&bytes[..2], &[0x1f, 0x8b]);
    let session = store.all_sessions().pop().unwrap();
    assert_eq!(session.response.data.as_slice(), bytes.as_ref());
    assert_eq!(
        inspect::decode_body(&session, juan::capture::Side::Response, 1024).unwrap(),
        br#"{"compressed":true}"#
    );
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn response_chunks_arrive_before_the_upstream_finishes() {
    let origin = Origin::start(false).await;
    let store = Arc::new(CaptureStore::default());
    let proxy = start_proxy(store.clone()).await;
    let stream = TcpStream::connect(proxy.address()).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    let mut response = sender
        .send_request(request("GET", &origin.url("/stream"), ""))
        .await
        .unwrap();
    let frame = timeout(Duration::from_millis(400), response.body_mut().frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(frame.data_ref().unwrap(), "first");
    assert!(!store.all_sessions()[0].response.complete);
    let rest = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(rest, "second");
    connection.abort();
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn chunked_response_trailers_are_relayed_and_captured() {
    let origin = Origin::start(false).await;
    let store = Arc::new(CaptureStore::default());
    let proxy = start_proxy(store.clone()).await;
    let request = Request::builder()
        .uri(origin.url("/trailers"))
        .header("te", "trailers")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (_, _, bytes, trailers) = get_response(proxy.address(), request).await;
    assert_eq!(bytes, "hello");
    assert_eq!(trailers.unwrap()["x-checksum"], "finished");
    assert!(
        store.all_sessions()[0]
            .response
            .trailers
            .iter()
            .any(|h| h.name == "x-checksum")
    );
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn decrypts_https_and_negotiates_http2_on_both_legs_without_system_trust() {
    let origin = Origin::start(true).await;
    let ca = Arc::new(CertificateAuthority::generate().unwrap());
    let store = Arc::new(CaptureStore::default());
    let proxy = proxy::start(
        ProxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            certificate: Some(ca.clone()),
            upstream_tls: Some(trusted_client(origin.ca.as_deref())),
            ..ProxyConfig::default()
        },
        store.clone(),
    )
    .await
    .unwrap();
    let stream = tls_through(proxy.address(), origin.address.port(), &ca, true).await;
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    let connection = tokio::spawn(connection);
    let original = Bytes::from_static(b"{\"through\":\"TLS\",\"protocol\":\"h2\"}");
    let response = sender
        .send_request(request("POST", &origin.url("/echo"), original.clone()))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.version(), Version::HTTP_2);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        original
    );
    let sessions = store.all_sessions();
    let session = sessions.iter().find(|s| s.method == "POST").unwrap();
    assert!(session.url.starts_with("https://"));
    assert_eq!(session.protocol, "HTTP/2");
    assert_eq!(session.response_protocol, "HTTP/2");
    assert_eq!(session.request.data, original);
    assert_eq!(session.response.data, original);
    connection.abort();
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn encrypted_connect_tunnels_work_without_interception() {
    let origin = Origin::start(true).await;
    let store = Arc::new(CaptureStore::default());
    let proxy = start_proxy(store.clone()).await;
    let stream = tls_through(
        proxy.address(),
        origin.address.port(),
        origin.ca.as_deref().unwrap(),
        false,
    )
    .await;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    let response = sender
        .send_request(request("POST", &origin.url("/echo"), "still encrypted"))
        .await
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "still encrypted"
    );
    let sessions = store.all_sessions();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].method, "CONNECT");
    assert_eq!(sessions[0].kind, SessionKind::Tunnel);
    assert!(sessions[0].response.data.is_empty());
    assert!(sessions[0].response.total_bytes > 0);
    connection.abort();
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn untrusted_upstream_tls_is_rejected_instead_of_silently_bypassed() {
    let origin = Origin::start(true).await;
    let store = Arc::new(CaptureStore::default());
    let proxy = proxy::start(
        ProxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstream_tls: Some(trusted_client(None)),
            ..ProxyConfig::default()
        },
        store.clone(),
    )
    .await
    .unwrap();
    let (status, _, bytes, _) =
        get_response(proxy.address(), request("GET", &origin.url("/large"), "")).await;
    assert_eq!(status, 502);
    assert!(String::from_utf8_lossy(&bytes).contains("certificate"));
    assert!(store.all_sessions()[0].error.is_some());
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn websocket_upgrade_and_bidirectional_bytes_are_relayed() {
    let origin = Origin::start(false).await;
    let store = Arc::new(CaptureStore::default());
    let proxy = start_proxy(store.clone()).await;
    let mut stream = TcpStream::connect(proxy.address()).await.unwrap();
    stream.write_all(format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        origin.url("/ws"), origin.address,
    ).as_bytes()).await.unwrap();
    let headers = read_headers(&mut stream).await;
    assert!(headers.starts_with("HTTP/1.1 101"), "{headers}");
    let bytes = [
        0x81,
        0x84,
        1,
        2,
        3,
        4,
        b't' ^ 1,
        b'e' ^ 2,
        b's' ^ 3,
        b't' ^ 4,
    ];
    stream.write_all(&bytes).await.unwrap();
    let mut echoed = [0u8; 10];
    timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echoed, bytes);
    assert_eq!(store.all_sessions()[0].kind, SessionKind::WebSocket);
    assert_eq!(store.all_sessions()[0].status, Some(101));
    drop(stream);
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn pause_continues_forwarding_and_shutdown_releases_the_listener() {
    let origin = Origin::start(false).await;
    let store = Arc::new(CaptureStore::default());
    store.set_recording(false);
    let proxy = start_proxy(store.clone()).await;
    let address = proxy.address();
    let (status, _, bytes, _) = get_response(
        address,
        request("POST", &origin.url("/echo"), "not recorded"),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(bytes, "not recorded");
    assert!(store.all_sessions().is_empty());
    proxy.shutdown().await.unwrap();
    assert!(TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn connection_bound_auth_never_enters_a_shared_upstream_pool() {
    let origin = Origin::start(false).await;
    let store = Arc::new(CaptureStore::default());
    let proxy = start_proxy(store.clone()).await;
    for scheme in ["NTLM", "Negotiate"] {
        let request = Request::builder()
            .uri(origin.url("/headers"))
            .header("authorization", format!("{scheme} demo-not-a-real-token"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (status, _, bytes, _) = get_response(proxy.address(), request).await;
        assert_eq!(
            status, 501,
            "Connection-bound identity must not leak between pooled clients"
        );
        assert!(String::from_utf8_lossy(&bytes).contains("connection-bound"));
        let captured = store.all_sessions().pop().unwrap();
        assert_eq!(captured.response.data, bytes);
        assert!(captured.response.complete);
    }
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn http2_origin_receives_uri_authority_without_an_extra_host_header() {
    let origin = Origin::start(true).await;
    let store = Arc::new(CaptureStore::default());
    let proxy = proxy::start(
        ProxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstream_tls: Some(trusted_client(origin.ca.as_deref())),
            ..ProxyConfig::default()
        },
        store.clone(),
    )
    .await
    .unwrap();
    let request = Request::builder()
        .uri(origin.url("/authority"))
        .header("host", "client-supplied.invalid")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, _, bytes, _) = get_response(proxy.address(), request).await;
    assert_eq!(status, 200);
    let upstream: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(upstream["version"], "HTTP/2.0");
    assert_eq!(
        upstream["authority"],
        format!("localhost:{}", origin.address.port())
    );
    assert!(
        upstream["host"].is_null(),
        "HTTP/2 must use the URI-derived :authority, not a redundant forwarded Host"
    );
    let session = store.all_sessions().pop().unwrap();
    assert_eq!(session.response_protocol, "HTTP/2");
    assert_eq!(
        juan::capture::header(&session.request_headers, "host"),
        Some("client-supplied.invalid")
    );
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn http1_origin_still_receives_a_host_derived_from_the_target_uri() {
    let origin = Origin::start(false).await;
    let proxy = start_proxy(Arc::new(CaptureStore::default())).await;
    let request = Request::builder()
        .uri(origin.url("/authority"))
        .header("host", "client-supplied.invalid")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, _, bytes, _) = get_response(proxy.address(), request).await;
    assert_eq!(status, 200);
    let upstream: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(upstream["version"], "HTTP/1.1");
    assert_eq!(upstream["host"], origin.address.to_string());
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
#[ignore = "Requires public Internet access; local authority regressions run in the normal suite"]
async fn google_http2_get_through_proxy_keeps_certificate_verification_enabled() {
    let store = Arc::new(CaptureStore::default());
    let proxy = start_proxy(store.clone()).await;
    let request = Request::builder()
        .uri("https://www.google.com/")
        .header("host", "www.google.com")
        .header("user-agent", "Juan-Protocol-Interop")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, _, _, _) = get_response(proxy.address(), request).await;
    assert_eq!(status, 200);
    assert_eq!(store.all_sessions()[0].response_protocol, "HTTP/2");
    proxy.shutdown().await.unwrap();
}
