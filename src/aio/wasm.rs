//! Browser (wasm32) backend for [`crate::aio`]: HTTP over the Fetch API and
//! WebSockets over the browser's native `WebSocket`.
//!
//! This module only compiles on `wasm32-unknown-unknown`, where rsurl cannot
//! open sockets or run its own TLS/HTTP stack — the browser owns all of that.
//! [`fetch`] backs [`crate::aio::request`]; [`WebSocket`] is the async WebSocket
//! client. See the [`crate::aio`] module docs for the browser-imposed limits
//! (forbidden headers, CORS, no custom WebSocket handshake headers, …).

use std::cell::RefCell;
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

/// Perform `req` via the browser Fetch API and buffer the whole response.
pub async fn fetch(req: &Request) -> Result<Response> {
    let init = web_sys::RequestInit::new();
    init.set_method(&req.method);
    init.set_redirect(if req.follow_redirects {
        web_sys::RequestRedirect::Follow
    } else {
        web_sys::RequestRedirect::Manual
    });

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

/// Owns the JS event-handler closures for a `WebSocket` so they outlive the
/// connection; dropping this detaches them and lets the socket be reclaimed.
struct Handlers {
    _onopen: Closure<dyn FnMut(web_sys::Event)>,
    _onmessage: Closure<dyn FnMut(web_sys::MessageEvent)>,
    _onerror: Closure<dyn FnMut(web_sys::Event)>,
    _onclose: Closure<dyn FnMut(web_sys::CloseEvent)>,
}

/// An async WebSocket client over the browser's native `WebSocket`.
///
/// The browser owns framing, masking, permessage-deflate, ping/pong keepalive,
/// and the close handshake, so this is a thin async surface over it. Notable
/// browser limits (not rsurl bugs): the handshake takes **no custom headers**
/// (no `Authorization`; only subprotocols via
/// [`connect_with_subprotocols`](WebSocket::connect_with_subprotocols)), and
/// ping/pong control frames are inaccessible.
pub struct WebSocket {
    ws: web_sys::WebSocket,
    rx: UnboundedReceiver<Result<WsMessage>>,
    _handlers: Handlers,
}

/// The send half of a [`WebSocket`] after [`split`](WebSocket::split); cheap to
/// clone, safe to hold alongside the [`WsStream`] on the same event loop.
pub struct WsSink {
    ws: web_sys::WebSocket,
}

/// The receive half of a [`WebSocket`] after [`split`](WebSocket::split): an
/// async stream of incoming [`WsMessage`]s. Owns the event-handler closures, so
/// dropping it stops delivery.
pub struct WsStream {
    rx: UnboundedReceiver<Result<WsMessage>>,
    _handlers: Handlers,
}

/// Detach every handler from `ws` and close it, so the browser cannot invoke the
/// (about-to-be-dropped) handler closures after `connect` returns on a failed
/// dial — which would trap with "closure invoked recursively or after being
/// dropped". Setting each handler to `None` unregisters it from the JS socket
/// while the Rust `Closure`s are still alive, so none is called after they drop.
fn detach_and_close(ws: &web_sys::WebSocket) {
    ws.set_onopen(None);
    ws.set_onmessage(None);
    ws.set_onerror(None);
    ws.set_onclose(None);
    let _ = ws.close();
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

        match open_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                // The `onopen`/`onmessage`/`onerror`/`onclose` closures are about
                // to drop as this fn returns; detach them from the socket first so
                // a subsequent browser close/error event cannot invoke a dropped
                // closure (which traps).
                detach_and_close(&ws);
                return Err(e);
            }
            Err(_) => {
                detach_and_close(&ws);
                return Err(Error::BadResponse(
                    "websocket closed before it opened".into(),
                ));
            }
        }

        Ok(WebSocket {
            ws,
            rx: msg_rx,
            _handlers: Handlers {
                _onopen: onopen,
                _onmessage: onmessage,
                _onerror: onerror,
                _onclose: onclose,
            },
        })
    }

    /// Receive the next message, or `None` once the connection has closed.
    pub async fn recv(&mut self) -> Option<Result<WsMessage>> {
        self.rx.next().await
    }

    /// Send a text message.
    pub fn send_text(&self, text: &str) -> Result<()> {
        self.ws.send_with_str(text).map_err(js_err)
    }

    /// Send a binary message.
    pub fn send_binary(&self, data: &[u8]) -> Result<()> {
        self.ws.send_with_u8_array(data).map_err(js_err)
    }

    /// Send a [`WsMessage`].
    pub fn send(&self, msg: &WsMessage) -> Result<()> {
        match msg {
            WsMessage::Text(t) => self.send_text(t),
            WsMessage::Binary(b) => self.send_binary(b),
        }
    }

    /// Initiate a normal close (code 1000).
    pub fn close(&self) -> Result<()> {
        self.ws.close().map_err(js_err)
    }

    /// Initiate a close with a specific code and reason.
    pub fn close_with(&self, code: u16, reason: &str) -> Result<()> {
        self.ws
            .close_with_code_and_reason(code, reason)
            .map_err(js_err)
    }

    /// Split into an independent [`WsSink`] (send) and [`WsStream`] (receive),
    /// both living on the same browser event loop. The single-threaded analogue
    /// of the native [`crate::WebSocket::split`].
    pub fn split(self) -> (WsSink, WsStream) {
        (
            WsSink {
                ws: self.ws.clone(),
            },
            WsStream {
                rx: self.rx,
                _handlers: self._handlers,
            },
        )
    }
}

impl WsSink {
    /// Send a text message.
    pub fn send_text(&self, text: &str) -> Result<()> {
        self.ws.send_with_str(text).map_err(js_err)
    }

    /// Send a binary message.
    pub fn send_binary(&self, data: &[u8]) -> Result<()> {
        self.ws.send_with_u8_array(data).map_err(js_err)
    }

    /// Send a [`WsMessage`].
    pub fn send(&self, msg: &WsMessage) -> Result<()> {
        match msg {
            WsMessage::Text(t) => self.send_text(t),
            WsMessage::Binary(b) => self.send_binary(b),
        }
    }

    /// Initiate a normal close (code 1000).
    pub fn close(&self) -> Result<()> {
        self.ws.close().map_err(js_err)
    }
}

impl WsStream {
    /// Receive the next message, or `None` once the connection has closed.
    pub async fn recv(&mut self) -> Option<Result<WsMessage>> {
        self.rx.next().await
    }
}
