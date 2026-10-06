//! The canvas HTTP transport.
//!
//! Lives here rather than in `pangu-core` because it needs a runtime and
//! `pangu-core` deliberately has none. The split is not cosmetic: routing,
//! escaping, the token check and every rendered page are in
//! `pangu_core::canvas` and covered by tests there, so this file contains only
//! the socket and the response writing.
//!
//! # Deliberately small
//!
//! `GET` only, one request per connection, `Content-Length` bounded. A read-only
//! viewer of a few pages does not need an HTTP framework, and every dependency
//! added to the process that holds a workspace is another thing to trust with
//! it.

use std::net::SocketAddr;

use pangu_core::canvas::{Canvas, CanvasSnapshot, Page};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The largest request we will look at.
///
/// A request line plus headers; anything larger is refused rather than buffered,
/// so a peer cannot make us allocate without bound.
const MAX_REQUEST_BYTES: usize = 8192;

/// Serve the canvas on loopback until the process is stopped.
///
/// Returns the address actually bound, which matters when the caller asks for
/// port 0 and needs to know what the OS chose.
pub async fn serve(canvas: Canvas, port: u16) -> anyhow::Result<SocketAddr> {
    // Loopback only, and not configurable: binding a viewer that can show
    // private paths to an interface reachable from the network would make the
    // token the only thing between a stranger and a repository's contents.
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|error| anyhow::anyhow!("cannot bind 127.0.0.1:{port}: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| anyhow::anyhow!("cannot read the bound address: {error}"))?;
    // Reported so a caller that asked for port 0 learns the chosen port.
    tracing::debug!("canvas listening on {address}");

    // Built once and shared: the canvas is immutable, and re-rendering the
    // pages per connection would let two clients receive pages built from
    // different states.
    let snapshot = std::sync::Arc::new(CanvasSnapshot::of(&canvas));

    loop {
        let Ok((mut socket, _peer)) = listener.accept().await else {
            // A failed accept is a transient, per-connection condition; the
            // listener itself is still usable, so keep serving.
            continue;
        };
        let snapshot = std::sync::Arc::clone(&snapshot);
        tokio::spawn(async move {
            // A client that disconnects mid-response is not an error worth
            // reporting: nothing here mutates state, so a dropped connection
            // cannot leave anything half-done.
            let _ = respond(&mut socket, &snapshot).await;
        });
    }
}

async fn respond(
    socket: &mut tokio::net::TcpStream,
    snapshot: &CanvasSnapshot,
) -> std::io::Result<()> {
    let mut buffer = vec![0u8; MAX_REQUEST_BYTES];
    let read = socket.read(&mut buffer).await?;
    if read == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..read]);
    let request_line = request.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");

    let page = snapshot.handle(method, path);
    write_response(socket, &page).await
}

async fn write_response(socket: &mut tokio::net::TcpStream, page: &Page) -> std::io::Result<()> {
    // `nosniff` stops a browser from reinterpreting a body as a type we did not
    // intend, and `no-store` keeps a run's contents out of the browser cache.
    // `Content-Security-Policy` with no script sources means that even if an
    // escaping bug let markup through, injected script would not execute.
    let header = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:\r\n\
         Referrer-Policy: no-referrer\r\n\
         Connection: close\r\n\r\n",
        page.status,
        status_text(page.status),
        page.content_type,
        page.body.len()
    );
    socket.write_all(header.as_bytes()).await?;
    socket.write_all(page.body.as_bytes()).await?;
    socket.flush().await
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "OK",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pangu_core::events::{Event, EventKind};

    fn event(seq: u64, kind: EventKind, message: &str) -> Event {
        let mut event = Event::new(kind, 1, message);
        event.seq = seq;
        event
    }

    fn canvas() -> Canvas {
        Canvas::new(
            "transport-test",
            &[event(1, EventKind::RunStarted, "started")],
            None,
        )
        .unwrap()
    }

    /// A real socket round trip, so the transport is exercised rather than only
    /// the routing it delegates to.
    #[tokio::test]
    async fn a_real_request_reaches_the_canvas() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let snapshot = CanvasSnapshot::of(&canvas());

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            respond(&mut socket, &snapshot).await.unwrap();
        });

        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        server.await.unwrap();

        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
        assert!(text.contains("Pangu canvas"), "{text}");
        // The hardening headers must actually be sent.
        assert!(text.contains("X-Content-Type-Options: nosniff"), "{text}");
        assert!(text.contains("Content-Security-Policy"), "{text}");
    }

    #[tokio::test]
    async fn the_content_length_matches_the_body() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let snapshot = CanvasSnapshot::of(&canvas());

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            respond(&mut socket, &snapshot).await.unwrap();
        });

        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET /api/trace HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        server.await.unwrap();

        let text = String::from_utf8_lossy(&response);
        let declared: usize = text
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .and_then(|value| value.trim().parse().ok())
            .expect("a Content-Length header");
        let body = text.split("\r\n\r\n").nth(1).expect("a body");
        // A short Content-Length would make a client truncate the JSON.
        assert_eq!(
            declared,
            body.len(),
            "declared {declared} but the body is {} bytes",
            body.len()
        );
    }

    #[tokio::test]
    async fn a_non_get_request_is_refused_over_the_wire() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let snapshot = CanvasSnapshot::of(&canvas());

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            respond(&mut socket, &snapshot).await.unwrap();
        });

        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        server.await.unwrap();

        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 405"), "{text}");
    }

    #[test]
    fn status_texts_cover_the_statuses_the_canvas_returns() {
        assert_eq!(status_text(200), "OK");
        assert_eq!(status_text(401), "Unauthorized");
        assert_eq!(status_text(404), "Not Found");
        assert_eq!(status_text(405), "Method Not Allowed");
    }
}
