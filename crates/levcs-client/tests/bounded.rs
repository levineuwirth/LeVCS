//! A client reads what an instance sends only up to a limit. Bodies were
//! read whole, and a pack's decoding budget applied only once its body had
//! been buffered, however large.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use levcs_client::{Client, ClientError};

/// Serve one HTTP response to each of `n` connections: `head` (status line
/// and headers, without the blank line), then `body` bytes of `b'x'`, or
/// without end for `usize::MAX`, until the client stops reading. Returns the
/// base URL, and the bytes of body sent so far.
fn serve(n: usize, head: &'static str, body: usize) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let sent = Arc::new(AtomicUsize::new(0));
    let counter = sent.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming().take(n) {
            let mut conn = conn.unwrap();
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 2 {
                line.clear();
            }
            let _ = write!(conn, "{head}\r\n\r\n");
            let chunk = vec![b'x'; 1 << 16];
            let mut left = body;
            while left > 0 {
                let n = left.min(chunk.len());
                if conn.write_all(&chunk[..n]).is_err() {
                    break;
                }
                counter.fetch_add(n, Ordering::Relaxed);
                left -= n;
            }
        }
    });
    (format!("http://{addr}/levcs/v1"), sent)
}

/// What a client that stops at its limit lets a sender get out: the limit
/// and the sockets' buffers, never the gigabytes of a read of the whole.
const STOPPED: usize = 64 << 20;

fn too_large<T: std::fmt::Debug>(r: Result<T, ClientError>) {
    match r {
        Err(ClientError::Decode(m)) => assert!(m.contains("response larger than"), "{m}"),
        other => panic!("{other:?}"),
    }
}

/// A body that says it is too large is refused before any of it is read.
#[test]
fn a_declared_length_past_the_limit_is_refused_unread() {
    let (base, _) = serve(
        1,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1099511627776",
        0,
    );
    too_large(Client::new(base).instance_info());
}

/// A body that does not say its length is read only up to the limit: here
/// one without end, which a read of the whole would not finish.
#[test]
fn an_undeclared_length_is_read_only_up_to_the_limit() {
    let (base, sent) = serve(
        1,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close",
        usize::MAX,
    );
    too_large(Client::new(base).instance_info());
    assert!(
        sent.load(Ordering::Relaxed) < STOPPED,
        "{}",
        sent.load(Ordering::Relaxed)
    );
}

/// An error answer's body is read only up to its limit too, whatever its
/// declared length, and what was read is kept as the message, cut off. It
/// was read whole.
#[test]
fn an_error_answer_is_read_only_up_to_its_limit() {
    for head in [
        "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: 1099511627776",
        "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nConnection: close",
    ] {
        let (base, sent) = serve(1, head, usize::MAX);
        match Client::new(base).instance_info() {
            Err(ClientError::Server { status, body }) => {
                assert_eq!(status, 500);
                assert!(body.len() <= (64 << 10) + 32, "{}", body.len());
                assert!(body.ends_with("(cut off)"), "{head}");
            }
            other => panic!("{head}: {other:?}"),
        }
        let sent = sent.load(Ordering::Relaxed);
        assert!(sent < STOPPED, "{head}: the client took {sent} bytes");
    }
}
