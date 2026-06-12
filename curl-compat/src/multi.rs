//! The libcurl "multi" interface on top of `rsurl::Multi`.
//!
//! Each added easy handle's request is built on the caller's thread and run on
//! an `rsurl::Multi` worker thread; completions are drained — and the easy
//! handle's write/header callbacks fired — on the thread that calls
//! `curl_multi_perform`, matching libcurl's callback-threading contract.

use std::collections::{HashMap, VecDeque};
use std::os::raw::{c_int, c_long};
use std::ptr;
use std::time::Duration;

use rsurl::multi::EasyId;
use rsurl::Multi;

use crate::consts::*;
use crate::easy::{build_request_ptr, deliver_ptr, map_error};
use crate::{ffi_guard, CURL, CURLM};

/// `CURLMSG` values.
pub const CURLMSG_NONE: c_int = 0;
pub const CURLMSG_DONE: c_int = 1;

/// `union { void *whatever; CURLcode result; }` — the second union arm is what
/// callers read after a `CURLMSG_DONE`.
#[repr(C)]
pub union CURLMsgData {
    pub whatever: *mut std::ffi::c_void,
    pub result: CURLcode,
}

/// Public `CURLMsg` layout.
#[repr(C)]
pub struct CURLMsg {
    pub msg: c_int,
    pub easy_handle: *mut CURL,
    pub data: CURLMsgData,
}

struct MultiState {
    inner: Multi,
    /// Added handles not yet started (started lazily on the first perform).
    pending: Vec<*mut CURL>,
    /// rsurl transfer id → the easy handle that produced it.
    id_to_easy: HashMap<EasyId, *mut CURL>,
    /// Completed transfers awaiting `curl_multi_info_read`.
    done: VecDeque<(*mut CURL, CURLcode)>,
    /// Storage for the `CURLMsg` returned by the last `info_read` (libcurl
    /// returns a pointer into multi-owned memory, valid until the next call).
    msg_slot: CURLMsg,
}

impl MultiState {
    fn new() -> Self {
        MultiState {
            inner: Multi::new(),
            pending: Vec::new(),
            id_to_easy: HashMap::new(),
            done: VecDeque::new(),
            msg_slot: CURLMsg {
                msg: CURLMSG_NONE,
                easy_handle: ptr::null_mut(),
                data: CURLMsgData {
                    whatever: ptr::null_mut(),
                },
            },
        }
    }

    /// Start any pending handles: build each request on this thread, queue it
    /// on the inner Multi (a build failure becomes an immediate completion).
    fn start_pending(&mut self) {
        for easy in self.pending.drain(..) {
            match build_request_ptr(easy) {
                Ok(req) => {
                    let id = self.inner.add(req);
                    self.id_to_easy.insert(id, easy);
                }
                Err(code) => self.done.push_back((easy, code)),
            }
        }
        self.inner.perform();
    }

    /// Drain finished transfers, firing each easy handle's callbacks here.
    fn drain(&mut self) {
        while let Some((id, result)) = self.inner.next_completed() {
            if let Some(&easy) = self.id_to_easy.get(&id) {
                let code = match result {
                    Ok(resp) => deliver_ptr(easy, resp),
                    Err(e) => map_error(&e),
                };
                self.done.push_back((easy, code));
                self.id_to_easy.remove(&id);
            }
        }
    }
}

fn as_state<'a>(m: *mut CURLM) -> Option<&'a mut MultiState> {
    if m.is_null() {
        None
    } else {
        // SAFETY: produced by Box::into_raw in curl_multi_init.
        Some(unsafe { &mut *(m as *mut MultiState) })
    }
}

#[no_mangle]
pub extern "C" fn curl_multi_init() -> *mut CURLM {
    ffi_guard(ptr::null_mut(), || {
        Box::into_raw(Box::new(MultiState::new())) as *mut CURLM
    })
}

#[no_mangle]
pub unsafe extern "C" fn curl_multi_cleanup(multi: *mut CURLM) -> CURLMcode {
    ffi_guard(CURLM_OK, || {
        if multi.is_null() {
            return CURLM_BAD_HANDLE;
        }
        // Dropping MultiState drops the inner Multi, which joins its workers.
        // Easy handles are owned by the caller (curl_easy_cleanup); not freed.
        drop(Box::from_raw(multi as *mut MultiState));
        CURLM_OK
    })
}

#[no_mangle]
pub extern "C" fn curl_multi_add_handle(multi: *mut CURLM, easy: *mut CURL) -> CURLMcode {
    ffi_guard(CURLM_BAD_HANDLE, || {
        let Some(st) = as_state(multi) else {
            return CURLM_BAD_HANDLE;
        };
        if easy.is_null() {
            return CURLM_BAD_EASY_HANDLE;
        }
        st.pending.push(easy);
        CURLM_OK
    })
}

#[no_mangle]
pub extern "C" fn curl_multi_remove_handle(multi: *mut CURLM, easy: *mut CURL) -> CURLMcode {
    ffi_guard(CURLM_BAD_HANDLE, || {
        let Some(st) = as_state(multi) else {
            return CURLM_BAD_HANDLE;
        };
        // Drop it if still pending; if already running we can't cancel the
        // worker, so just stop tracking it (its completion is ignored).
        st.pending.retain(|&e| e != easy);
        st.id_to_easy.retain(|_, &mut e| e != easy);
        CURLM_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn curl_multi_perform(
    multi: *mut CURLM,
    running_handles: *mut c_int,
) -> CURLMcode {
    ffi_guard(CURLM_BAD_HANDLE, || {
        let Some(st) = as_state(multi) else {
            return CURLM_BAD_HANDLE;
        };
        st.start_pending();
        st.drain();
        if !running_handles.is_null() {
            *running_handles = st.inner.running() as c_int;
        }
        CURLM_OK
    })
}

/// `curl_multi_poll` — block until a transfer makes progress or `timeout_ms`
/// elapses. We have no real sockets to expose, so `numfds` reports 1 when a
/// completion became ready, else 0.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_poll(
    multi: *mut CURLM,
    _extra_fds: *mut std::ffi::c_void,
    _extra_nfds: c_int,
    timeout_ms: c_int,
    numfds: *mut c_int,
) -> CURLMcode {
    ffi_guard(CURLM_BAD_HANDLE, || {
        let Some(st) = as_state(multi) else {
            return CURLM_BAD_HANDLE;
        };
        let timeout = if timeout_ms < 0 {
            None
        } else {
            Some(Duration::from_millis(timeout_ms as u64))
        };
        let ready = st.inner.poll(timeout);
        if !numfds.is_null() {
            *numfds = if ready { 1 } else { 0 };
        }
        CURLM_OK
    })
}

/// `curl_multi_wait` — the older sibling of `curl_multi_poll`; same behavior
/// here.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_wait(
    multi: *mut CURLM,
    extra_fds: *mut std::ffi::c_void,
    extra_nfds: c_int,
    timeout_ms: c_int,
    numfds: *mut c_int,
) -> CURLMcode {
    curl_multi_poll(multi, extra_fds, extra_nfds, timeout_ms, numfds)
}

/// `curl_multi_info_read` — pop one completion message. The returned pointer is
/// valid until the next call to this function or `curl_multi_perform`.
#[no_mangle]
pub unsafe extern "C" fn curl_multi_info_read(
    multi: *mut CURLM,
    msgs_in_queue: *mut c_int,
) -> *mut CURLMsg {
    ffi_guard(ptr::null_mut(), || {
        let Some(st) = as_state(multi) else {
            return ptr::null_mut();
        };
        match st.done.pop_front() {
            Some((easy, code)) => {
                st.msg_slot = CURLMsg {
                    msg: CURLMSG_DONE,
                    easy_handle: easy,
                    data: CURLMsgData { result: code },
                };
                if !msgs_in_queue.is_null() {
                    *msgs_in_queue = st.done.len() as c_int;
                }
                &mut st.msg_slot as *mut CURLMsg
            }
            None => {
                if !msgs_in_queue.is_null() {
                    *msgs_in_queue = 0;
                }
                ptr::null_mut()
            }
        }
    })
}

/// `curl_multi_setopt` — multi-handle tuning options. None of them change
/// correctness in this model, so they are accepted and ignored.
#[no_mangle]
pub extern "C" fn curl_multi_setopt(
    multi: *mut CURLM,
    _option: c_int,
    _value: c_long,
) -> CURLMcode {
    if multi.is_null() {
        return CURLM_BAD_HANDLE;
    }
    CURLM_OK
}
