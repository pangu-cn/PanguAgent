//! A deliberately narrow WebSocket client, sized for CDP.
//!
//! # Why not a general WebSocket crate
//!
//! CDP needs a very small part of RFC 6455: connect over TCP, send masked text
//! frames, read unmasked text frames, and honour close and ping. The full
//! protocol adds extensions, compression, subprotocol negotiation and client
//! role variants that this use never reaches. Implementing the subset keeps the
//! dependency surface small and — more importantly — makes the failure modes
//! visible: a handshake that does not validate is rejected rather than
//! half-accepted.
//!
//! # What is deliberately not supported, and why that is safe
//!
//! - **No compression extension (`permessage-deflate`).** The handshake never
//!   offers it, so a conforming server will not use it. If a server sent a
//!   compressed frame anyway, the reserved bits would be rejected rather than
//!   misinterpreted.
//! - **No fragmented messages.** CDP messages are single frames. A continuation
//!   frame is rejected with an explicit error instead of being silently dropped,
//!   because dropping it would look like a timeout.
//! - **No client-side masking of anything but text.** Payload sizes are known,
//!   so the 16-bit and 64-bit length forms are handled; the 7-bit form is used
//!   whenever it fits.
//!
//! # The security-relevant detail: masking
//!
//! RFC 6455 requires **every client-to-server frame to be masked** and every
//! server-to-client frame to be unmasked. This is not a stylistic choice — it
//! exists to stop a client from being tricked into emitting attacker-chosen
//! bytes to a server that confuses WebSocket frames with other protocols. So:
//! outgoing frames are always masked, and an incoming **masked** frame is
//! rejected as a protocol violation.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use pangu_core::{Error, Result};

/// Maximum accepted frame payload.
///
/// Bounded because a page can be made to return a very large screenshot or DOM,
/// and an unbounded read would let that exhaust memory. A CDP reply larger than
/// this is refused with a message naming the limit, rather than truncated — a
/// truncated screenshot would silently look like a small page.
pub const MAX_FRAME_BYTES: usize = 32 * 1024 * 1024;

/// A decoded WebSocket frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsFrame {
    pub opcode: Opcode,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl Opcode {
    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xA => Self::Pong,
            _ => return None,
        })
    }
}

/// The client half of a WebSocket connection.
pub struct WebSocket {
    stream: TcpStream,
    /// Bytes read from the socket but not yet consumed as a frame.
    ///
    /// A single `read` can return a partial frame, so bytes must be buffered
    /// across calls; reading frame-by-frame from the socket directly would fail
    /// intermittently under load, which is the worst kind of bug to debug.
    buffer: Vec<u8>,
}

impl WebSocket {
    /// Perform the opening handshake against an already-connected stream.
    ///
    /// `host` is the value sent in the `Host` header; `path` is the request
    /// target, including any query. The returned frame is checked for the exact
    /// accept token, so a server that simply echoes the request is rejected.
    pub fn handshake(mut stream: TcpStream, host: &str, path: &str, key: &str) -> Result<Self> {
        let request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n"
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|error| Error::Other(format!("websocket handshake write failed: {error}")))?;
        stream
            .flush()
            .map_err(|error| Error::Other(format!("websocket handshake flush failed: {error}")))?;

        let response = read_http_response(&mut stream)?;
        let expected = accept_key(key);
        if !response.contains("\r\n\r\n") {
            return Err(Error::Other(
                "websocket handshake response has no header terminator".into(),
            ));
        }
        let status_ok = response
            .lines()
            .next()
            .map(|line| line.contains("101"))
            .unwrap_or(false);
        if !status_ok {
            let first = response.lines().next().unwrap_or("<empty>");
            return Err(Error::Other(format!(
                "websocket handshake was refused: {first}"
            )));
        }
        if !response.contains(&expected) {
            return Err(Error::Other(
                "websocket handshake did not return the expected accept token; refusing to \
                 treat this connection as a WebSocket"
                    .into(),
            ));
        }

        Ok(Self {
            stream,
            buffer: Vec::new(),
        })
    }

    /// Wrap a raw TCP stream, skipping the handshake.
    ///
    /// For tests and for callers that already performed the handshake.
    pub fn from_stream(stream: TcpStream) -> Self {
        Self {
            stream,
            buffer: Vec::new(),
        }
    }

    /// Send a text frame, masked as the protocol requires.
    pub fn send_text(&mut self, payload: &str) -> Result<()> {
        self.send_frame(Opcode::Text, payload.as_bytes())
    }

    /// Read the next frame, honouring the given deadline.
    ///
    /// Ping frames are answered automatically and transparently: the caller sees
    /// only the frames it asked for, and a keepalive does not surface as a
    /// spurious message. A close frame is returned to the caller so it can
    /// distinguish "the browser closed" from "nothing arrived".
    pub fn read_frame(&mut self, deadline: Instant) -> Result<WsFrame> {
        loop {
            let frame = self.read_raw_frame(deadline)?;
            match frame.opcode {
                Opcode::Ping => {
                    // Reply with the same payload, per RFC 6455.
                    self.send_frame(Opcode::Pong, &frame.payload)?;
                    continue;
                }
                Opcode::Pong => continue,
                _ => return Ok(frame),
            }
        }
    }

    fn send_frame(&mut self, opcode: Opcode, payload: &[u8]) -> Result<()> {
        let mut frame = Vec::with_capacity(payload.len() + 14);
        // FIN set, no reserved bits: this client never fragments and never
        // negotiates an extension, so a set reserved bit would be a bug here.
        frame.push(0x80 | opcode_byte(opcode));
        let length = payload.len();
        // Mask bit is always set: client frames must be masked.
        if length < 126 {
            frame.push(0x80 | length as u8);
        } else if length <= u16::MAX as usize {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(length as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(length as u64).to_be_bytes());
        }
        let mask = masking_key();
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4]),
        );
        self.stream
            .write_all(&frame)
            .map_err(|error| Error::Other(format!("websocket write failed: {error}")))?;
        self.stream
            .flush()
            .map_err(|error| Error::Other(format!("websocket flush failed: {error}")))?;
        Ok(())
    }

    fn read_raw_frame(&mut self, deadline: Instant) -> Result<WsFrame> {
        let header = self.take(2, deadline)?;
        let first = header[0];
        let second = header[1];

        // Reserved bits must be zero: this client negotiated no extensions, so
        // their presence means the server is speaking a dialect we did not agree
        // to. Interpreting it anyway is how misparses become vulnerabilities.
        if first & 0x70 != 0 {
            return Err(Error::Other(
                "websocket frame set a reserved bit; this client negotiated no extensions".into(),
            ));
        }
        let fin = first & 0x80 != 0;
        let opcode = Opcode::from_byte(first & 0x0F).ok_or_else(|| {
            Error::Other(format!(
                "websocket frame used an unsupported opcode: 0x{:X}",
                first & 0x0F
            ))
        })?;
        if !fin {
            return Err(Error::Other(
                "websocket fragmentation is not supported; a CDP message arrives in one frame"
                    .into(),
            ));
        }
        if second & 0x80 != 0 {
            // Servers must not mask. Accepting a masked frame would be a
            // protocol violation, and tolerating it invites confusion attacks.
            return Err(Error::Other(
                "websocket server frame was masked, which the protocol forbids".into(),
            ));
        }

        let length = match second & 0x7F {
            value @ 0..=125 => value as usize,
            126 => {
                let bytes = self.take(2, deadline)?;
                let value = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
                // RFC 6455 forbids a 16-bit length below 126. Accepting it lets
                // two parsers disagree about where the payload starts.
                if value < 126 {
                    return Err(Error::Other(
                        "websocket frame used a non-minimal 16-bit length".into(),
                    ));
                }
                value
            }
            127 => {
                let bytes = self.take(8, deadline)?;
                let mut array = [0u8; 8];
                array.copy_from_slice(&bytes);
                let value = u64::from_be_bytes(array);
                if value < 65536 {
                    return Err(Error::Other(
                        "websocket frame used a non-minimal 64-bit length".into(),
                    ));
                }
                usize::try_from(value).map_err(|_| {
                    Error::Other("websocket frame length does not fit in memory".into())
                })?
            }
            _ => unreachable!("0x7F & mask cannot exceed 127"),
        };
        if matches!(opcode, Opcode::Ping | Opcode::Pong | Opcode::Close) && length > 125 {
            return Err(Error::Other(format!(
                "websocket control frame of {length} bytes exceeds the 125-byte limit"
            )));
        }
        if opcode == Opcode::Close && length == 1 {
            return Err(Error::Other(
                "websocket close frame has a one-byte payload; a status code needs two bytes"
                    .into(),
            ));
        }
        if length > MAX_FRAME_BYTES {
            return Err(Error::Other(format!(
                "websocket frame of {length} bytes exceeds the {MAX_FRAME_BYTES}-byte limit"
            )));
        }

        let payload = self.take(length, deadline)?;
        Ok(WsFrame { opcode, payload })
    }

    /// Read exactly `count` bytes, waiting until the deadline.
    fn take(&mut self, count: usize, deadline: Instant) -> Result<Vec<u8>> {
        while self.buffer.len() < count {
            if Instant::now() >= deadline {
                return Err(Error::Other(format!(
                    "websocket read timed out with {} of {count} bytes available",
                    self.buffer.len()
                )));
            }
            let mut chunk = [0u8; 8192];
            let read = self
                .stream
                .read(&mut chunk)
                .map_err(|error| Error::Other(format!("websocket read failed: {error}")))?;
            if read == 0 {
                return Err(Error::Other(
                    "websocket connection closed while a frame was being read".into(),
                ));
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
        Ok(self.buffer.drain(..count).collect())
    }
}

fn opcode_byte(opcode: Opcode) -> u8 {
    match opcode {
        Opcode::Text => 0x1,
        Opcode::Binary => 0x2,
        Opcode::Close => 0x8,
        Opcode::Ping => 0x9,
        Opcode::Pong => 0xA,
    }
}

/// A fresh masking key for every frame.
///
/// Predictable masks are legal but pointless; the RFC's own rationale for
/// masking is that the key must not be guessable in advance by an intermediary.
fn masking_key() -> [u8; 4] {
    // `RandomState` seeds from the OS and is not a counter, so consecutive keys
    // differ. `pangu-core` has no RNG dependency, and adding one for four bytes
    // of mask would be a poor trade.
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    );
    (hasher.finish() as u32).to_be_bytes()
}

/// `Sec-WebSocket-Accept` per RFC 6455: base64(SHA-1(key + GUID)).
fn accept_key(key: &str) -> String {
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let digest = sha1(format!("{key}{GUID}").as_bytes());
    base64(&digest)
}

/// A minimal SHA-1, used only for the WebSocket handshake.
///
/// SHA-1 is chosen here because the protocol mandates it for
/// `Sec-WebSocket-Accept`; it is not used as a security primitive. The value
/// proves the server understood the handshake, not the identity of the server —
/// which is why this client still validates the HTTP status and does not treat
/// the token as authentication.
fn sha1(input: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut message = input.to_vec();
    let bit_length = (input.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());

    for block in message.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (index, word) in block.chunks_exact(4).enumerate() {
            w[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..80 {
            w[index] = (w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (index, word) in w.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (index, value) in h.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    out
}

/// Standard base64, exposed so the CDP session encodes handshake keys the same
/// way it decodes screenshot data — one implementation, not two that can drift.
pub fn encode_base64(input: &[u8]) -> String {
    base64(input)
}

fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(triple >> 18) as usize & 0x3F] as char);
        out.push(TABLE[(triple >> 12) as usize & 0x3F] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(triple >> 6) as usize & 0x3F] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[triple as usize & 0x3F] as char
        } else {
            '='
        });
    }
    out
}

/// Read an HTTP response head, stopping at the blank line.
///
/// Bounded in both directions: a response with no terminator must not be read
/// forever, and a header block larger than the limit is refused rather than
/// buffered.
fn read_http_response(stream: &mut TcpStream) -> Result<String> {
    const MAX_HEADER_BYTES: usize = 64 * 1024;
    let mut collected = Vec::new();
    let mut chunk = [0u8; 1024];
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if collected.len() > MAX_HEADER_BYTES {
            return Err(Error::Other(format!(
                "websocket handshake response exceeded {MAX_HEADER_BYTES} bytes"
            )));
        }
        if Instant::now() >= deadline {
            return Err(Error::Other(
                "websocket handshake response did not complete in time".into(),
            ));
        }
        let read = stream
            .read(&mut chunk)
            .map_err(|error| Error::Other(format!("handshake read failed: {error}")))?;
        if read == 0 {
            return Err(Error::Other(
                "connection closed during the websocket handshake".into(),
            ));
        }
        collected.extend_from_slice(&chunk[..read]);
        if collected.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(String::from_utf8_lossy(&collected).into_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_accept_token_matches_the_rfc_example() {
        // RFC 6455 §1.3's worked example. If this drifts, every handshake fails
        // against a conforming server, so it is pinned rather than approximated.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn sha1_matches_known_vectors() {
        assert_eq!(
            sha1(b"abc"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
        assert_eq!(
            sha1(b""),
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
            ]
        );
    }

    #[test]
    fn base64_handles_padding() {
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
    }

    #[test]
    fn masking_keys_differ_between_calls() {
        // A repeated mask would be a protocol weakness; consecutive keys must
        // not be identical.
        let keys = (0..16).map(|_| masking_key()).collect::<Vec<_>>();
        let unique = keys.iter().collect::<std::collections::HashSet<_>>();
        assert!(unique.len() > 1, "masking keys repeated: {keys:?}");
    }

    #[test]
    fn opcodes_round_trip_and_reject_the_reserved_range() {
        for opcode in [
            Opcode::Text,
            Opcode::Binary,
            Opcode::Close,
            Opcode::Ping,
            Opcode::Pong,
        ] {
            assert_eq!(Opcode::from_byte(opcode_byte(opcode)), Some(opcode));
        }
        // 0x3-0x7 and 0xB-0xF are reserved: misreading them would mean
        // interpreting a frame whose meaning we do not know.
        for byte in [0x0u8, 0x3, 0x7, 0xB, 0xF] {
            assert_eq!(Opcode::from_byte(byte), None, "opcode {byte:#X}");
        }
    }

    #[test]
    fn text_frames_are_masked_with_the_mask_bit_set() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        let mut client =
            WebSocket::from_stream(TcpStream::connect(address).expect("connect to listener"));
        client.send_text("hi").expect("send");

        let (mut accepted, _) = listener.accept().expect("accept");
        let mut header = [0u8; 2];
        accepted.read_exact(&mut header).expect("header");
        assert_eq!(header[0], 0x81, "FIN + text opcode");
        // The mask bit must be set: unmasked client frames are a protocol
        // violation and some servers close the connection over it.
        assert_eq!(header[1] & 0x80, 0x80, "mask bit must be set");
        assert_eq!(header[1] & 0x7F, 2, "payload length");
    }

    #[test]
    fn a_masked_server_frame_is_rejected() {
        // Servers must not mask. Accepting this would be a protocol violation.
        let mut raw = Vec::new();
        raw.push(0x81); // FIN + text
        raw.push(0x80 | 2); // mask bit set by the server: illegal
        raw.extend_from_slice(&[0, 0, 0, 0]);
        raw.extend_from_slice(b"hi");
        let error = decode_one(&raw).expect_err("must reject");
        assert!(
            error.to_string().contains("masked"),
            "unexpected message: {error}"
        );
    }

    #[test]
    fn a_reserved_bit_is_rejected() {
        let raw = vec![0x81 | 0x40, 0x02, b'h', b'i'];
        let error = decode_one(&raw).expect_err("must reject");
        assert!(error.to_string().contains("reserved bit"), "{error}");
    }

    #[test]
    fn a_fragmented_frame_is_rejected_with_a_clear_message() {
        // Silently dropping a continuation frame would look like a timeout,
        // which is much harder to diagnose than an explicit refusal.
        let raw = vec![0x01, 0x02, b'h', b'i'];
        let error = decode_one(&raw).expect_err("must reject");
        assert!(error.to_string().contains("fragmentation"), "{error}");
    }

    #[test]
    fn an_oversized_frame_is_refused_rather_than_truncated() {
        // A truncated screenshot would silently look like a small page, which is
        // worse than a failure.
        let mut raw = vec![0x81, 0x7F];
        raw.extend_from_slice(&((MAX_FRAME_BYTES as u64) + 1).to_be_bytes());
        let error = decode_one(&raw).expect_err("must reject");
        assert!(error.to_string().contains("exceeds"), "{error}");
    }

    #[test]
    fn an_oversized_or_truncated_control_frame_is_rejected() {
        let mut ping = vec![0x89, 126, 0, 126];
        ping.extend(std::iter::repeat_n(b'x', 126));
        let error = decode_one(&ping).expect_err("control payload above 125");
        assert!(error.to_string().contains("125"), "{error}");

        let close = vec![0x88, 1, 0];
        let error = decode_one(&close).expect_err("one-byte close status");
        assert!(error.to_string().contains("two bytes"), "{error}");
    }

    #[test]
    fn a_non_minimal_extended_length_is_rejected() {
        let short = vec![0x81, 126, 0, 2, b'h', b'i'];
        let error = decode_one(&short).expect_err("16-bit form below 126");
        assert!(error.to_string().contains("non-minimal"), "{error}");

        let mut long = vec![0x81, 127];
        long.extend_from_slice(&300u64.to_be_bytes());
        long.extend(std::iter::repeat_n(b'x', 300));
        let error = decode_one(&long).expect_err("64-bit form below 65536");
        assert!(error.to_string().contains("non-minimal"), "{error}");
    }

    #[test]
    fn a_16_bit_length_is_decoded() {
        let payload = vec![b'x'; 300];
        let mut raw = vec![0x81, 126];
        raw.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        raw.extend_from_slice(&payload);
        let frame = decode_one(&raw).expect("decode");
        assert_eq!(frame.opcode, Opcode::Text);
        assert_eq!(frame.payload.len(), 300);
    }

    /// Decode exactly one frame from `raw` through a loopback socket.
    fn decode_one(raw: &[u8]) -> Result<WsFrame> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        let mut client =
            WebSocket::from_stream(TcpStream::connect(address).expect("connect to listener"));
        let payload = raw.to_vec();
        let writer = std::thread::spawn(move || {
            let (mut accepted, _) = listener.accept().expect("accept");
            accepted.write_all(&payload).expect("write");
            accepted
        });
        let frame = client.read_frame(Instant::now() + Duration::from_secs(5));
        let _ = writer.join();
        frame
    }
}
