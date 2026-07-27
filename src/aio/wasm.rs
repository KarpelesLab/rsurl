//! Browser (wasm32) backend for [`crate::aio`]: HTTP over the Fetch API and
//! WebSockets over the browser's native `WebSocket`.
//!
//! This module only compiles on `wasm32-unknown-unknown`, where rsurl cannot
//! open sockets or run its own TLS/HTTP stack — the browser owns all of that.
//! [`request`] backs the module's HTTP entry points; [`WebSocket`] is the async
//! WebSocket client. See the [`crate::aio`] module docs for the browser-imposed
//! limits (forbidden headers, CORS, no custom WebSocket handshake headers, …)
//! and for which parts of the surface are portable across targets.

use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;

use futures_channel::mpsc::{self, UnboundedReceiver};
use futures_channel::oneshot;
use futures_util::StreamExt;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use super::{Request, Response, WsMessage};
use crate::error::{Error, Result};

/// Turn a JS exception / rejection value into an [`Error`].
fn js_err(v: JsValue) -> Error {
    let msg = v
        .as_string()
        .or_else(|| {
            v.dyn_ref::<js_sys::Error>()
                .map(|e| String::from(e.message()))
        })
        .unwrap_or_else(|| format!("{v:?}"));
    Error::BadResponse(format!("wasm: {msg}"))
}

// ─── Fetch (HTTP) ────────────────────────────────────────────────────────────

/// Perform a `GET` of `url` via the browser Fetch API. The wasm counterpart of
/// the native `get` — no `Runtime` argument, since the browser event loop is
/// implicit.
pub async fn get(url: &str) -> Result<Response> {
    request(&Request::get(url)).await
}

/// Perform a `POST` of `body` to `url` via the browser Fetch API. The wasm
/// counterpart of the native `post`.
pub async fn post(url: &str, body: impl Into<Vec<u8>>) -> Result<Response> {
    request(&Request::post(url, body)).await
}

/// Send `req` via the browser Fetch API, returning the buffered [`Response`].
/// The wasm counterpart of the native `request` — no `Runtime` argument.
///
/// The browser performs DNS, TLS, redirect following, and response
/// decompression itself, so [`Request::decompress`] is ignored and
/// [`Request::follow_redirects`] maps to fetch's redirect mode: `true` →
/// `follow` (the default), `false` → `manual` (a redirect yields an opaque
/// response you cannot read). [`Request::timeout`] becomes an
/// `AbortSignal.timeout()`. Forbidden headers set on `req` are dropped by the
/// browser, and cross-origin requests are subject to CORS.
pub async fn request(req: &Request) -> Result<Response> {
    let init = web_sys::RequestInit::new();
    init.set_method(&req.method);
    init.set_redirect(if req.follow_redirects {
        web_sys::RequestRedirect::Follow
    } else {
        web_sys::RequestRedirect::Manual
    });

    // Whole-request deadline. `AbortSignal.timeout` takes whole milliseconds and
    // is saturated rather than wrapped, so an absurd Duration just means "no
    // practical limit" instead of a surprise near-instant abort.
    if let Some(dur) = req.timeout {
        let ms = u32::try_from(dur.as_millis()).unwrap_or(u32::MAX);
        init.set_signal(Some(&web_sys::AbortSignal::timeout_with_u32(ms)));
    }

    // Body — an empty body sends no payload (a GET/HEAD must not carry one).
    if !req.body.is_empty() {
        let buf = js_sys::Uint8Array::from(req.body.as_slice());
        init.set_body(&buf.into());
    }

    // Headers — the browser drops the forbidden ones (Host, Connection, …).
    let headers = web_sys::Headers::new().map_err(js_err)?;
    for (k, v) in &req.headers {
        headers.append(k, v).map_err(js_err)?;
    }
    init.set_headers(&headers);

    let web_req = web_sys::Request::new_with_str_and_init(&req.url, &init).map_err(js_err)?;

    let resp_val = JsFuture::from(fetch_promise(&web_req)?)
        .await
        .map_err(js_err)?;
    let web_resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| Error::BadResponse("fetch did not resolve to a Response".into()))?;

    let status = web_resp.status();
    let reason = web_resp.status_text();
    let headers = read_headers(&web_resp.headers());

    // The browser has already applied any `Content-Encoding`, so the body is
    // plaintext and `Request::decompress` does not apply here.
    let buf = JsFuture::from(web_resp.array_buffer().map_err(js_err)?)
        .await
        .map_err(js_err)?;
    let body = js_sys::Uint8Array::new(&buf).to_vec();

    Ok(Response {
        status,
        reason,
        headers,
        body,
    })
}

/// Call `fetch()` off whichever global exists — a `Window` (main thread) or a
/// `WorkerGlobalScope` (Web Worker).
fn fetch_promise(req: &web_sys::Request) -> Result<js_sys::Promise> {
    if let Some(win) = web_sys::window() {
        return Ok(win.fetch_with_request(req));
    }
    let scope: web_sys::WorkerGlobalScope = js_sys::global()
        .dyn_into()
        .map_err(|_| Error::BadResponse("no fetch: neither Window nor WorkerGlobalScope".into()))?;
    Ok(scope.fetch_with_request(req))
}

/// Collect a `Headers` object into `(name, value)` pairs, in iteration order.
fn read_headers(headers: &web_sys::Headers) -> Vec<(String, String)> {
    let mut out = Vec::new();
    // `Headers` is a JS iterable of `[name, value]` pairs.
    if let Ok(Some(iter)) = js_sys::try_iter(headers.as_ref()) {
        for entry in iter.flatten() {
            let pair = js_sys::Array::from(&entry);
            let name = pair.get(0).as_string().unwrap_or_default();
            let value = pair.get(1).as_string().unwrap_or_default();
            out.push((name, value));
        }
    }
    out
}

// ─── WebSocket ───────────────────────────────────────────────────────────────

/// The JS event-handler closures for a `WebSocket`, kept alive for as long as
/// they are registered on it.
struct Handlers {
    _onopen: Closure<dyn FnMut(web_sys::Event)>,
    _onmessage: Closure<dyn FnMut(web_sys::MessageEvent)>,
    _onerror: Closure<dyn FnMut(web_sys::Event)>,
    _onclose: Closure<dyn FnMut(web_sys::CloseEvent)>,
}

/// The browser socket plus the closures registered on it, owned jointly by
/// every handle to the connection ([`WebSocket`], or the [`WsSink`] /
/// [`WsStream`] it splits into) via an [`Rc`].
///
/// Its [`Drop`] is the safety-critical part: the closures are about to be freed,
/// and a browser event delivered to a freed `Closure` traps with "closure
/// invoked recursively or after being dropped". Detaching every handler *before*
/// the `Handlers` field drops makes that impossible; closing the socket in the
/// same breath is what stops a dropped connection from leaking (the browser
/// keeps a `WebSocket` open until it is closed, reachable from Rust or not).
struct Inner {
    ws: web_sys::WebSocket,
    _handlers: Handlers,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Field drops (the `Closure`s) run after this body, so no handler can
        // still be registered when they are freed.
        self.ws.set_onopen(None);
        self.ws.set_onmessage(None);
        self.ws.set_onerror(None);
        self.ws.set_onclose(None);
        let _ = self.ws.close();
    }
}

/// An async WebSocket client over the browser's native `WebSocket`.
///
/// The browser owns framing, masking, permessage-deflate, ping/pong keepalive,
/// and the close handshake, so this is a thin async surface over it. It mirrors
/// the native [`aio::WebSocket`](crate::aio::WebSocket) method for method — same
/// names, receivers, `async`-ness, and return types — so only the
/// [`connect`](WebSocket::connect) call differs between targets.
///
/// Notable browser limits (not rsurl bugs): the handshake takes **no custom
/// headers** (no `Authorization`; only subprotocols, via
/// [`connect_with_subprotocols`](WebSocket::connect_with_subprotocols)), and
/// ping/pong control frames are inaccessible.
///
/// Dropping the last handle to the connection detaches the browser event
/// handlers and closes the socket.
pub struct WebSocket {
    inner: Rc<Inner>,
    rx: UnboundedReceiver<Result<WsMessage>>,
    subprotocol: Option<String>,
}

/// The send half of a [`WebSocket`] after [`split`](WebSocket::split). Cheap to
/// clone — every clone shares one browser socket — and safe to hold alongside
/// the [`WsStream`] on the same event loop.
#[derive(Clone)]
pub struct WsSink {
    inner: Rc<Inner>,
}

/// The receive half of a [`WebSocket`] after [`split`](WebSocket::split): an
/// async stream of incoming [`WsMessage`]s.
pub struct WsStream {
    inner: Rc<Inner>,
    rx: UnboundedReceiver<Result<WsMessage>>,
}

impl fmt::Debug for WebSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocket")
            .field("url", &self.inner.ws.url())
            .field("ready_state", &self.inner.ws.ready_state())
            .field("subprotocol", &self.subprotocol)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for WsSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WsSink")
            .field("url", &self.inner.ws.url())
            .field("ready_state", &self.inner.ws.ready_state())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for WsStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WsStream")
            .field("url", &self.inner.ws.url())
            .field("ready_state", &self.inner.ws.ready_state())
            .finish_non_exhaustive()
    }
}

/// Whether `ws` is CLOSING or CLOSED.
fn is_closed(ws: &web_sys::WebSocket) -> bool {
    ws.ready_state() >= web_sys::WebSocket::CLOSING
}

/// Send one message over `ws`, mapping a JS exception (e.g. sending on a closed
/// socket) to an [`Error`].
fn send_msg(ws: &web_sys::WebSocket, msg: &WsMessage) -> Result<()> {
    match msg {
        WsMessage::Text(t) => ws.send_with_str(t),
        WsMessage::Binary(b) => ws.send_with_u8_array(b),
    }
    .map_err(js_err)
}

impl WebSocket {
    /// Open a WebSocket to `url` (`ws://` or `wss://`), resolving once the
    /// browser's `open` event fires (or erroring if the handshake fails).
    pub async fn connect(url: &str) -> Result<WebSocket> {
        Self::connect_with_subprotocols(url, &[]).await
    }

    /// Open a WebSocket to `url` requesting the given `subprotocols` (sent in
    /// the `Sec-WebSocket-Protocol` header — the only handshake input the
    /// browser exposes). See [`connect`](WebSocket::connect).
    pub async fn connect_with_subprotocols(url: &str, subprotocols: &[&str]) -> Result<WebSocket> {
        let ws = if subprotocols.is_empty() {
            web_sys::WebSocket::new(url)
        } else {
            let arr = js_sys::Array::new();
            for p in subprotocols {
                arr.push(&JsValue::from_str(p));
            }
            web_sys::WebSocket::new_with_str_sequence(url, &arr)
        }
        .map_err(js_err)?;
        // Deliver binary frames as ArrayBuffer (not Blob) so we can read them
        // synchronously in the message handler.
        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

        let (msg_tx, msg_rx) = mpsc::unbounded::<Result<WsMessage>>();
        let (open_tx, open_rx) = oneshot::channel::<Result<()>>();
        let open_slot = Rc::new(RefCell::new(Some(open_tx)));

        let onopen = {
            let slot = open_slot.clone();
            Closure::<dyn FnMut(web_sys::Event)>::new(move |_e: web_sys::Event| {
                if let Some(tx) = slot.borrow_mut().take() {
                    let _ = tx.send(Ok(()));
                }
            })
        };
        ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));

        let onmessage = {
            let tx = msg_tx.clone();
            Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
                let data = e.data();
                let msg = match data.as_string() {
                    Some(text) => WsMessage::Text(text),
                    // Not a string ⇒ an ArrayBuffer (binary_type is Arraybuffer).
                    None => WsMessage::Binary(js_sys::Uint8Array::new(&data).to_vec()),
                };
                let _ = tx.unbounded_send(Ok(msg));
            })
        };
        ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

        let onerror = {
            let slot = open_slot.clone();
            let tx = msg_tx.clone();
            Closure::<dyn FnMut(web_sys::Event)>::new(move |_e: web_sys::Event| {
                // A pre-open error fails the connect; a later one is surfaced on
                // the message stream before the browser's `close` ends it.
                if let Some(otx) = slot.borrow_mut().take() {
                    let _ = otx.send(Err(Error::BadResponse(
                        "websocket connection failed".into(),
                    )));
                } else {
                    let _ = tx.unbounded_send(Err(Error::BadResponse("websocket error".into())));
                }
            })
        };
        ws.set_onerror(Some(onerror.as_ref().unchecked_ref()));

        let onclose = {
            let tx = msg_tx.clone();
            Closure::<dyn FnMut(web_sys::CloseEvent)>::new(move |_e: web_sys::CloseEvent| {
                // End the stream so `recv()` returns `None`.
                tx.close_channel();
            })
        };
        ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));

        // From here on the socket and its closures are owned together: a failed
        // dial returns early and `Inner::drop` detaches the handlers before they
        // are freed, so the browser cannot invoke a dropped closure.
        let inner = Rc::new(Inner {
            ws,
            _handlers: Handlers {
                _onopen: onopen,
                _onmessage: onmessage,
                _onerror: onerror,
                _onclose: onclose,
            },
        });

        match open_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(Error::BadResponse(
                    "websocket closed before it opened".into(),
                ))
            }
        }

        // The browser exposes the negotiated subprotocol only once open; it is
        // the empty string when none was selected.
        let subprotocol = Some(inner.ws.protocol()).filter(|p| !p.is_empty());
        Ok(WebSocket {
            inner,
            rx: msg_rx,
            subprotocol,
        })
    }

    /// The subprotocol the server selected, or `None`.
    pub fn subprotocol(&self) -> Option<&str> {
        self.subprotocol.as_deref()
    }

    /// Whether the connection is closing or closed.
    pub fn is_closed(&self) -> bool {
        is_closed(&self.inner.ws)
    }

    /// Receive the next message, or `None` once the connection has closed.
    pub async fn recv(&mut self) -> Option<Result<WsMessage>> {
        self.rx.next().await
    }

    /// Send a text message. `async` for parity with the native socket; the
    /// browser buffers the frame itself, so this never actually yields.
    pub async fn send_text(&mut self, text: &str) -> Result<()> {
        self.inner.ws.send_with_str(text).map_err(js_err)
    }

    /// Send a binary message. See [`send_text`](Self::send_text) on the `async`.
    pub async fn send_binary(&mut self, data: &[u8]) -> Result<()> {
        self.inner.ws.send_with_u8_array(data).map_err(js_err)
    }

    /// Send a [`WsMessage`].
    pub async fn send(&mut self, msg: &WsMessage) -> Result<()> {
        send_msg(&self.inner.ws, msg)
    }

    /// Initiate a normal close (code 1000). Idempotent.
    pub async fn close(&mut self) -> Result<()> {
        self.inner.ws.close().map_err(js_err)
    }

    /// Initiate a close with a specific code and reason. Idempotent.
    pub async fn close_with(&mut self, code: u16, reason: &str) -> Result<()> {
        self.inner
            .ws
            .close_with_code_and_reason(code, reason)
            .map_err(js_err)
    }

    /// Split into an independent [`WsSink`] (send) and [`WsStream`] (receive),
    /// both living on the same browser event loop and sharing one socket, which
    /// closes when the last of them drops. The single-threaded analogue of the
    /// blocking [`crate::WebSocket::split`]; the native async socket has no
    /// counterpart.
    pub fn split(self) -> (WsSink, WsStream) {
        (
            WsSink {
                inner: Rc::clone(&self.inner),
            },
            WsStream {
                inner: self.inner,
                rx: self.rx,
            },
        )
    }
}

impl WsSink {
    /// Whether the connection is closing or closed.
    pub fn is_closed(&self) -> bool {
        is_closed(&self.inner.ws)
    }

    /// Send a text message.
    pub async fn send_text(&self, text: &str) -> Result<()> {
        self.inner.ws.send_with_str(text).map_err(js_err)
    }

    /// Send a binary message.
    pub async fn send_binary(&self, data: &[u8]) -> Result<()> {
        self.inner.ws.send_with_u8_array(data).map_err(js_err)
    }

    /// Send a [`WsMessage`].
    pub async fn send(&self, msg: &WsMessage) -> Result<()> {
        send_msg(&self.inner.ws, msg)
    }

    /// Initiate a normal close (code 1000). Idempotent.
    pub async fn close(&self) -> Result<()> {
        self.inner.ws.close().map_err(js_err)
    }

    /// Initiate a close with a specific code and reason. Idempotent.
    pub async fn close_with(&self, code: u16, reason: &str) -> Result<()> {
        self.inner
            .ws
            .close_with_code_and_reason(code, reason)
            .map_err(js_err)
    }
}

impl WsStream {
    /// Whether the connection is closing or closed.
    pub fn is_closed(&self) -> bool {
        is_closed(&self.inner.ws)
    }

    /// Receive the next message, or `None` once the connection has closed.
    pub async fn recv(&mut self) -> Option<Result<WsMessage>> {
        self.rx.next().await
    }
}
