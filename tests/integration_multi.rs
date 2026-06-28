//! Integration tests for the concurrent [`rsurl::Multi`] driver, against the
//! in-process HTTP test server.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use common::{Request as SReq, Response as SResp, TestServer};

use rsurl::{multi::Multi, Request};

/// Two independent requests run concurrently and both complete with the body
/// the server derived from their path.
#[test]
fn runs_two_transfers_concurrently() {
    let server = TestServer::start(|req: SReq| SResp::ok(format!("echo:{}", req.path)));

    let mut m = Multi::new();
    let a = m.add(Request::get(&server.url("/alpha")).unwrap());
    let b = m.add(Request::get(&server.url("/beta")).unwrap());

    let results: HashMap<_, _> = m
        .wait_all()
        .into_iter()
        .map(|(id, r)| (id, r.expect("transfer ok")))
        .collect();

    assert_eq!(results.len(), 2);
    assert_eq!(results[&a].status, 200);
    assert_eq!(results[&a].body, b"echo:/alpha");
    assert_eq!(results[&b].status, 200);
    assert_eq!(results[&b].body, b"echo:/beta");
}

/// `perform` + incremental `poll`/`next_completed` drive transfers and report
/// completions one at a time; `running()` drops to zero.
#[test]
fn incremental_poll_and_running_count() {
    let server = TestServer::start(|_req: SReq| SResp::ok("ok"));

    let mut m = Multi::new();
    m.add(Request::get(&server.url("/1")).unwrap());
    m.add(Request::get(&server.url("/2")).unwrap());
    m.add(Request::get(&server.url("/3")).unwrap());

    // Nothing starts until perform().
    assert_eq!(m.running(), 0, "no transfer runs before perform()");

    // perform() starts all three, then collects whatever already finished, so
    // its return value is racy (0..=3 depending on how fast the loopback
    // transfers complete) — assert only the bound, not an exact count. The
    // deterministic guarantees are below: every transfer is reported exactly
    // once and running() drains to zero.
    let running = m.perform();
    assert!(
        running <= 3,
        "perform() reported more transfers than started"
    );

    let mut collected = 0;
    // Drive to completion: drain everything currently ready, then block for the
    // next completion while any transfer is still running. Terminates once the
    // handle is idle (no pending, none running, ready queue empty).
    while !m.is_empty() {
        while let Some((_, r)) = m.next_completed() {
            assert_eq!(r.expect("ok").status, 200);
            collected += 1;
        }
        if m.running() > 0 {
            assert!(
                m.poll(Some(Duration::from_secs(5))),
                "poll timed out waiting for a completion"
            );
        }
    }

    assert_eq!(collected, 3);
    assert_eq!(m.running(), 0);
}

/// A failing transfer (connection refused) surfaces as an `Err` for that id
/// without affecting the successful one.
#[test]
fn mixes_success_and_error() {
    let server = TestServer::start(|_req: SReq| SResp::ok("good"));

    let mut m = Multi::new();
    let ok = m.add(Request::get(&server.url("/ok")).unwrap());
    // Port 1 is (almost certainly) closed → connection error.
    let bad = m.add(Request::get("http://127.0.0.1:1/nope").unwrap());

    let results: HashMap<_, _> = m.wait_all().into_iter().collect();
    assert!(results[&ok].is_ok());
    assert_eq!(results[&ok].as_ref().unwrap().status, 200);
    assert!(results[&bad].is_err());
}
