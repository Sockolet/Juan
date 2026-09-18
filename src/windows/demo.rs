use http::{HeaderMap, Method, Version};

use crate::capture::{CaptureStore, Side};

pub fn populate(store: &CaptureStore) {
    let samples = [
        (
            "GET",
            "https://api.contoso.test/v1/workspaces",
            200,
            "application/json",
            86,
            r#"{"workspaces":[{"id":"ws_1042","name":"Support Engineering","region":"westus2","status":"healthy"}],"total":1}"#,
        ),
        (
            "GET",
            "https://portal.contoso.test/",
            200,
            "text/html",
            124,
            "<!doctype html>\n<html><title>Support portal</title><body>Connected.</body></html>",
        ),
        (
            "GET",
            "https://portal.contoso.test/assets/app.css",
            200,
            "text/css",
            24,
            "body { font-family: system-ui; background: #f5f8fa; }",
        ),
        (
            "GET",
            "https://portal.contoso.test/assets/app.js",
            304,
            "application/javascript",
            18,
            "",
        ),
        (
            "OPTIONS",
            "https://api.contoso.test/v1/diagnostics",
            204,
            "",
            32,
            "",
        ),
        (
            "POST",
            "https://api.contoso.test/v1/diagnostics",
            200,
            "application/json",
            247,
            "{\n  \"requestId\": \"req_demo_7f92\",\n  \"status\": \"complete\",\n  \"checks\": {\n    \"dns\": \"resolved\",\n    \"tls\": \"valid\",\n    \"authentication\": \"passed\"\n  },\n  \"region\": \"westus2\",\n  \"durationMs\": 241\n}",
        ),
        (
            "GET",
            "https://api.contoso.test/v1/profile",
            401,
            "application/problem+json",
            63,
            "{\n  \"type\": \"https://errors.contoso.test/auth/token-expired\",\n  \"title\": \"Access token expired\",\n  \"status\": 401,\n  \"detail\": \"Acquire a new token and retry the request.\",\n  \"traceId\": \"demo-00-7d904e\"\n}",
        ),
        (
            "GET",
            "http://legacy.contoso.test/health",
            301,
            "text/html",
            17,
            "Moved permanently.",
        ),
        (
            "GET",
            "https://cdn.contoso.test/images/avatar.png",
            200,
            "image/png",
            41,
            "DEMO: binary image omitted",
        ),
        (
            "POST",
            "https://telemetry.contoso.test/v1/events",
            202,
            "application/json",
            54,
            "{\"accepted\":4}",
        ),
        (
            "GET",
            "https://api.contoso.test/v1/incidents?state=open",
            200,
            "application/json",
            138,
            "{\"incidents\":[{\"id\":\"INC-DEMO-001\",\"severity\":\"warning\",\"state\":\"open\"}],\"next\":null}",
        ),
        (
            "GET",
            "https://api.contoso.test/v1/backend/status",
            503,
            "application/problem+json",
            2015,
            "{\"title\":\"Upstream service unavailable\",\"status\":503,\"retryAfterSeconds\":30}",
        ),
    ];
    for (method, url, status, mime, elapsed, body) in samples {
        let method: Method = method.parse().expect("valid demo method");
        let uri: http::Uri = url.parse().expect("valid demo URL");
        let mut request = HeaderMap::new();
        request.insert("host", uri.authority().unwrap().as_str().parse().unwrap());
        request.insert(
            "user-agent",
            concat!(
                "Juan-Demo/",
                env!("CARGO_PKG_VERSION"),
                " (synthetic traffic)"
            )
            .parse()
            .unwrap(),
        );
        request.insert("accept", "application/json, */*".parse().unwrap());
        request.insert("x-request-id", "req_demo_7f92".parse().unwrap());
        if status == 401 {
            request.insert(
                "authorization",
                "Bearer DEMO-NOT-A-REAL-TOKEN".parse().unwrap(),
            );
        }
        let id = store.begin(
            &method,
            &uri,
            Version::HTTP_2,
            &request,
            "127.0.0.1:53042".parse().unwrap(),
        );
        if method == Method::POST {
            store.append(
                id,
                Side::Request,
                b"{\"scenario\":\"connectivity\",\"includeTimings\":true}",
            );
        }
        store.complete_body(id, Side::Request);
        let mut response = HeaderMap::new();
        if !mime.is_empty() {
            response.insert("content-type", mime.parse().unwrap());
        }
        response.insert("server", "contoso-edge".parse().unwrap());
        response.insert("date", "Thu, 17 Sep 2026 08:21:00 GMT".parse().unwrap());
        response.insert("x-request-id", "req_demo_7f92".parse().unwrap());
        response.insert("cache-control", "no-store".parse().unwrap());
        if status == 301 {
            response.insert(
                "location",
                "https://legacy.contoso.test/health".parse().unwrap(),
            );
        }
        if status == 503 {
            response.insert("retry-after", "30".parse().unwrap());
        }
        store.response(id, status, Version::HTTP_2, &response);
        store.append(id, Side::Response, body.as_bytes());
        store.complete_body(id, Side::Response);
        store.set_demo_timing(id, elapsed);
    }
    store.notice("DEMO MODE: These sessions are synthetic .test-domain examples. No listener, Windows proxy, or certificate trust was enabled.");
}
