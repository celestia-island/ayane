//! End-to-end smoke: engine → control plane → submission → IMAP.
//!
//! Ignored by default — it needs the full rig:
//!
//! ```text
//! just engine-up          # compose: postfix/dovecot/rspamd/valkey
//! just serve &            # the control plane (sets AYANE_ADMIN_TOKEN)
//! cargo test -p ayane --test smoke -- --ignored --nocapture
//! ```
//!
//! Environment: `AYANE_API_URL` (default http://127.0.0.1:3023),
//! `AYANE_ADMIN_TOKEN` (required), `AYANE_SUBMISSION`
//! (default 127.0.0.1:30587), `AYANE_IMAP` (default 127.0.0.1:3043).

use std::net::SocketAddr;
use std::time::Duration;

use ayane_mail::client::{Imap, Submission};
use ayane_proto::Address;

const DOMAIN: &str = "example.test";
const ALICE: &str = "alice@example.test";
const BOSS: &str = "boss@example.test";
const INBOX: &str = "inbox@example.test";
const PASSWORDS: [(&str, &str); 3] = [
    (ALICE, "ayane-dev-pass-1"),
    (BOSS, "ayane-dev-pass-2"),
    (INBOX, "ayane-dev-pass-3"),
];

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

async fn api() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("http client")
}

/// Push the smoke fixture. `variants` is the policy's address-variant switch
/// table (all off when empty), so a step can turn a fold on and prove it there.
async fn put_state(client: &reqwest::Client, variants: serde_json::Value) {
    let base =
        std::env::var("AYANE_API_URL").unwrap_or_else(|_| "http://127.0.0.1:3023".to_owned());
    let token = std::env::var("AYANE_ADMIN_TOKEN").expect("AYANE_ADMIN_TOKEN must be set");
    let body = serde_json::json!({
        "domains": [
            {"name": DOMAIN, "catch_all": INBOX, "enabled": true}
        ],
        "accounts": PASSWORDS.iter().map(|(address, password)| {
            serde_json::json!({
                "address": address,
                "display_name": address.split('@').next().unwrap_or("account"),
                "quota_bytes": 0,
                "password": password
            })
        }).collect::<Vec<_>>(),
        "aliases": [
            {"source": format!("sales@{DOMAIN}"), "targets": [BOSS]}
        ],
        "shared": [],
        "policy": {
            "default_action": "reject",
            "allowlist": [],
            "denylist": [{"domain": "spam.example"}],
            "variants": variants,
        }
    });

    let response = client
        .put(format!("{base}/api/v1/state"))
        .header("x-admin-token", &token)
        .json(&body)
        .send()
        .await
        .expect("PUT state");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "PUT state: {}",
        response.text().await.unwrap_or_default()
    );

    let response = client
        .post(format!("{base}/api/v1/apply"))
        .header("x-admin-token", &token)
        .send()
        .await
        .expect("POST apply");
    let report = response.text().await.unwrap_or_default();
    assert!(
        report.contains("\"changed\":true"),
        "apply must report written files: {report}"
    );
}

fn submission() -> Submission {
    Submission::new(
        env_or("AYANE_SUBMISSION", "127.0.0.1:30587")
            .parse::<SocketAddr>()
            .expect("submission addr"),
    )
}

fn imap() -> Imap {
    Imap::new(
        env_or("AYANE_IMAP", "127.0.0.1:3043")
            .parse::<SocketAddr>()
            .expect("imap addr"),
    )
}

async fn send(alice_password: &str, to: &str, marker: &str) {
    let from = Address::parse(ALICE).expect("from");
    let to = Address::parse(to).expect("to");
    let message = ayane_mail::compose::build_plain_message(
        &from,
        "ayane smoke",
        &to,
        &format!("[ayane-smoke] {marker}"),
        &format!("Smoke message {marker}: delivered by the local engine.\n"),
    )
    .expect("message");
    submission()
        .send(ALICE, alice_password, message)
        .await
        .expect("submission accepted");
}

async fn wait_for(username: &str, password: &str, marker: &str, what: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    loop {
        match imap().inbox_overview(username, password).await {
            Ok(overview) => {
                if overview.has_subject_containing(marker) {
                    println!(
                        "PASS {what}: {username} INBOX has `{marker}` ({} messages)",
                        overview.exists
                    );
                    return;
                }
                println!("… {what}: not yet in {username} ({:?})", overview.subjects);
            }
            Err(e) => println!("… {what}: IMAP not ready for {username}: {e}"),
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "FAIL {what}: `{marker}` never arrived for {username}"
        );
        tokio::time::sleep(Duration::from_millis(750)).await;
    }
}

async fn wait_for_login() {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(overview) = imap().inbox_overview(BOSS, "ayane-dev-pass-2").await {
            println!("IMAP ready (boss INBOX exists = {})", overview.exists);
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "FAIL: Dovecot never accepted the rendered credentials"
        );
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
}

/// Send from a deny-listed sender without authentication (port 25, as a
/// foreign MTA would) and assert Postfix rejects the transaction.
async fn expect_rejected() {
    let from = Address::parse("bot@spam.example").expect("from");
    let to = Address::parse(BOSS).expect("to");
    let message = ayane_mail::compose::build_plain_message(
        &from,
        "spammer",
        &to,
        "[ayane-smoke] t5-deny",
        "must be rejected",
    )
    .expect("message");
    let mta = Submission::new(
        env_or("AYANE_MTA", "127.0.0.1:3025")
            .parse::<SocketAddr>()
            .expect("mta addr"),
    );
    let detail = match mta.send_unauthenticated(message).await {
        Err(e) => e.to_string(),
        Ok(()) => String::new(),
    };
    assert!(
        !detail.is_empty(),
        "deny-listed sender must be rejected, but delivery succeeded"
    );
    assert!(
        detail.contains("denied by policy"),
        "rejection must come from the policy map, got: {detail}"
    );
    println!("PASS deny list: unauthenticated spam.example sender rejected: {detail}");
}

#[tokio::test]
#[ignore = "needs the engine rig: just engine-up && just serve"]
async fn send_route_deliver_read_roundtrip() {
    let client = api().await;

    let base = env_or("AYANE_API_URL", "http://127.0.0.1:3023");
    let health = client
        .get(format!("{base}/api/health"))
        .send()
        .await
        .expect("health")
        .text()
        .await
        .expect("health body");
    assert!(health.contains("\"status\":\"ok\""), "health: {health}");

    put_state(&client, serde_json::json!({})).await;
    wait_for_login().await;

    // 1. direct delivery: alice → boss
    send("ayane-dev-pass-1", BOSS, "t1-direct").await;
    wait_for(BOSS, "ayane-dev-pass-2", "t1-direct", "direct delivery").await;

    // 2. alias: alice → sales@ routes to boss
    send("ayane-dev-pass-1", &format!("sales@{DOMAIN}"), "t2-alias").await;
    wait_for(BOSS, "ayane-dev-pass-2", "t2-alias", "alias forwarding").await;

    // 3. catch-all: alice → nobody@ lands in the catch-all inbox
    send(
        "ayane-dev-pass-1",
        &format!("nobody@{DOMAIN}"),
        "t3-catchall",
    )
    .await;
    wait_for(
        INBOX,
        "ayane-dev-pass-3",
        "t3-catchall",
        "catch-all delivery",
    )
    .await;

    // 4. subaddress: with `inbound_plus` on, alice → alice+tag lands in
    //    alice's own INBOX. The switch is the only authority over `+`, so the
    //    step flips it on first instead of assuming the pre-switch default.
    put_state(&client, serde_json::json!({"inbound_plus": true})).await;
    send(
        "ayane-dev-pass-1",
        &format!("alice+tag@{DOMAIN}"),
        "t4-subaddress",
    )
    .await;
    wait_for(
        ALICE,
        "ayane-dev-pass-1",
        "t4-subaddress",
        "subaddress folding",
    )
    .await;
    // …and with the switches off the tagged form is none of alice's business:
    // it is an unknown recipient and the catch-all takes it.
    put_state(&client, serde_json::json!({})).await;
    send(
        "ayane-dev-pass-1",
        &format!("alice+offsw@{DOMAIN}"),
        "t4b-subaddress-off",
    )
    .await;
    wait_for(
        INBOX,
        "ayane-dev-pass-3",
        "t4b-subaddress-off",
        "no tag fold with the switch off",
    )
    .await;

    // 5. deny list: a foreign MTA from a deny-listed domain is refused.
    expect_rejected().await;

    println!("SMOKE PASS: 6/6 policy paths verified");
}
