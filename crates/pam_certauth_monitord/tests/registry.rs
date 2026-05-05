#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]

use pam_certauth_monitord::registry::{ActiveSession, SessionRegistry};
use pam_certauth_proto::SessionTarget;
use std::time::SystemTime;
use uuid::Uuid;

fn make(id: u128, serial: Option<&str>) -> ActiveSession {
    ActiveSession {
        session_id: Uuid::from_u128(id),
        pam_user: "u".into(),
        pam_service: "s".into(),
        target: SessionTarget::logind("c1"),
        usb_serial: serial.map(str::to_string),
        host_id_hash: "h".into(),
        opened_at: SystemTime::UNIX_EPOCH,
        cert_cn: "cn".into(),
        cert_serial: "01".into(),
    }
}

#[test]
fn add_then_find_by_id() {
    let r = SessionRegistry::new();
    let s = make(1, Some("AB"));
    r.add(s.clone());
    assert!(r.find_by_session_id(s.session_id).is_some());
}

#[test]
fn find_by_serial_returns_all_matching() {
    let r = SessionRegistry::new();
    r.add(make(1, Some("AB")));
    r.add(make(2, Some("AB")));
    r.add(make(3, Some("CD")));
    let found = r.find_by_serial("AB");
    assert_eq!(found.len(), 2);
}

#[test]
fn remove_returns_session() {
    let r = SessionRegistry::new();
    let s = make(1, Some("AB"));
    r.add(s.clone());
    let removed = r.remove(s.session_id).expect("present");
    assert_eq!(removed.session_id, s.session_id);
    assert!(r.find_by_session_id(s.session_id).is_none());
}

#[test]
fn concurrent_add_remove_is_safe() {
    use std::sync::Arc;
    let r = Arc::new(SessionRegistry::new());
    let r1 = r.clone();
    let h = std::thread::spawn(move || {
        for i in 0..1000u128 {
            r1.add(make(i, Some("X")));
        }
    });
    let r2 = r.clone();
    let h2 = std::thread::spawn(move || {
        for i in 0..1000u128 {
            let _ = r2.remove(Uuid::from_u128(i));
        }
    });
    h.join().expect("h");
    h2.join().expect("h2");
    let _ = r.all();
}
