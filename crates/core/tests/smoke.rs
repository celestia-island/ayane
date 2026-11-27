//! Live smoke: the control plane's mail methods against a running instance.
//!
//! Ignored by default — it drives a *running* deployment rather than a
//! fixture:
//!
//! ```text
//! AYANE_MAIL_ENABLED=1 AYANE_MAIL_ROOT=… just serve &
//! cargo test -p ayane --test smoke -- --ignored --nocapture
//! ```
//!
//! Environment: `AYANE_API_URL` (default http://127.0.0.1:3023) and
//! `AYANE_ADMIN_TOKEN` (required). Every assertion goes through the same
//! JSON-RPC surface the webmail uses, so what this proves is what the
//! browser gets: the read path over the deployment's own maildir, not a
//! second copy of it.
//!
//! The account ids this test writes with are its own (`smoke-…@example.test`)
//! and are created through the state API; the passwords are invented here and
//! are not a credential of any deployment.

use std::time::Duration;

const DOMAIN: &str = "example.test";

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

async fn api() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("http client")
}

/// Push a state whose fixture is the three addresses this test reads.
async fn put_state(client: &reqwest::Client, variants: serde_json::Value) {
    let base =
        std::env::var("AYANE_API_URL").unwrap_or_else(|_| "http://127.0.0.1:3023".to_owned());
    let token = std::env::var("AYANE_ADMIN_TOKEN").expect("AYANE_ADMIN_TOKEN must be set");
    let body = serde_json::json!({
        "domains": [
            {"name": DOMAIN, "catch_all": "inbox@example.test", "enabled": true}
        ],
        "accounts": [
            {"address": "smoke@example.test", "display_name": "smoke", "quota_bytes": 0,
             "password": "smoke-placeholder-pass"},
        ],
        "aliases": [
            {"source": format!("sales@{DOMAIN}"), "targets": ["smoke@example.test"]}
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

/// One JSON-RPC call against the live instance's `/api/mcp` transport,
/// answered verbatim (a caller that expects an error asserts on it).
async fn rpc_raw(
    client: &reqwest::Client,
    token: &str,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let base =
        std::env::var("AYANE_API_URL").unwrap_or_else(|_| "http://127.0.0.1:3023".to_owned());
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let response = client
        .post(format!("{base}/api/mcp"))
        .bearer_auth(token)
        .json(&request)
        .send()
        .await
        .expect("rpc");
    response.json().await.expect("rpc json")
}

/// [`rpc_raw`] for the calls that must succeed.
async fn rpc(
    client: &reqwest::Client,
    token: &str,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let reply = rpc_raw(client, token, method, params).await;
    assert!(reply.get("error").is_none(), "{method} failed: {reply}");
    reply
}

/// The mailbox's listing, waiting for a message whose subject contains
/// `marker` to arrive (the delivery loop is asynchronous by design).
async fn wait_for(
    client: &reqwest::Client,
    token: &str,
    mailbox: &str,
    marker: &str,
) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    loop {
        let reply = rpc(
            client,
            token,
            "mail.list",
            serde_json::json!({ "mailbox": mailbox, "limit": 50 }),
        )
        .await;
        let rows = reply["result"]["messages"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if let Some(row) = rows.iter().find(|row| {
            row["subject"]
                .as_str()
                .is_some_and(|subject| subject.contains(marker))
        }) {
            println!(
                "PASS {marker}: {mailbox} holds it as {} ({} messages)",
                row["id"], reply["result"]["total"]
            );
            return row.clone();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "FAIL {marker}: never arrived in {mailbox}: {reply}"
        );
        tokio::time::sleep(Duration::from_millis(750)).await;
    }
}

#[tokio::test]
#[ignore = "needs a running deployment: just serve, then run with AYANE_ADMIN_TOKEN set"]
async fn the_webmail_read_path_works_on_a_live_maildir() {
    let client = api().await;
    let token = std::env::var("AYANE_ADMIN_TOKEN").expect("AYANE_ADMIN_TOKEN must be set");

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

    // 1. An empty folder lists as empty rather than failing: the reader is
    //    what the sidebar asks before anything has arrived.
    let listing = rpc(
        &client,
        &token,
        "mail.list",
        serde_json::json!({ "mailbox": "INBOX", "limit": 50 }),
    )
    .await;
    assert_eq!(
        listing["result"]["total"], 0,
        "a fresh mailbox lists empty: {listing}"
    );
    println!("PASS empty mailbox: mail.list answers 0 on a maildir nothing wrote yet");

    // 2. A draft is appended, listed by filename, and read back.
    let saved = rpc(
        &client,
        &token,
        "mail.saveDraft",
        serde_json::json!({
            "to": format!("someone@{DOMAIN}"),
            "subject": "[ayane-smoke] t1-draft",
            "body": "A draft the smoke test wrote.",
        }),
    )
    .await;
    let draft_id = saved["result"]["uid"]
        .as_str()
        .expect("the saved draft's id")
        .to_owned();
    let row = wait_for(&client, &token, "Drafts", "t1-draft").await;
    assert_eq!(row["id"], draft_id, "the id mail.saveDraft answered with");

    let opened = rpc(
        &client,
        &token,
        "mail.read",
        serde_json::json!({ "uid": draft_id, "mailbox": "Drafts", "markSeen": false }),
    )
    .await;
    assert_eq!(
        opened["result"]["message"]["subject"], "[ayane-smoke] t1-draft",
        "the draft reads back: {opened}"
    );
    println!("PASS draft round trip: append → list → read, id is the file name");

    // 3. Star it, and the starred roster finds it.
    let starred = rpc(
        &client,
        &token,
        "mail.star",
        serde_json::json!({ "uid": draft_id, "mailbox": "Drafts", "starred": true }),
    )
    .await;
    let starred_id = starred["result"]["uid"]
        .as_str()
        .expect("the id after the flag rename")
        .to_owned();
    assert_ne!(starred_id, draft_id, "a flag change renames the file");
    let roster = rpc(
        &client,
        &token,
        "mail.listStarred",
        serde_json::json!({ "limit": 50 }),
    )
    .await;
    assert!(
        roster["result"]["messages"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row["id"] == starred_id)),
        "the starred roster holds the flagged message: {roster}"
    );
    println!("PASS star: the file name carries `F` and 已加星标 lists it");

    // 4. Trash it, then purge it: the two steps the row menu offers.
    let trashed = rpc(
        &client,
        &token,
        "mail.trash",
        serde_json::json!({ "uid": starred_id, "mailbox": "Drafts" }),
    )
    .await;
    assert_eq!(trashed["result"]["mailbox"], "Trash", "{trashed}");
    let in_trash = wait_for(&client, &token, "Trash", "t1-draft").await;
    rpc(
        &client,
        &token,
        "mail.purge",
        serde_json::json!({ "uid": in_trash["id"], "mailbox": "Trash" }),
    )
    .await;
    // A second purge of the same id is answered as "not there", not as a
    // panic and not as a silent success.
    let after = rpc_raw(
        &client,
        &token,
        "mail.purge",
        serde_json::json!({ "uid": in_trash["id"], "mailbox": "Trash" }),
    )
    .await;
    assert!(
        after["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("Mail.NotFound")),
        "purging a purged message answers Mail.NotFound: {after}"
    );
    println!("PASS trash and purge: move → Trash/cur → gone");

    // 5. Templates live in the store, next to the state.
    let saved_template = rpc(
        &client,
        &token,
        "mail.templates.save",
        serde_json::json!({
            "name": "smoke template",
            "subject": "[ayane-smoke] t5-template",
            "body": "stored in the state, not in a maildir",
        }),
    )
    .await;
    let template_id = saved_template["result"]["id"]
        .as_str()
        .expect("the template id")
        .to_owned();
    let templates = rpc(
        &client,
        &token,
        "mail.templates.list",
        serde_json::json!({}),
    )
    .await;
    assert!(
        templates["result"]["templates"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row["id"] == template_id)),
        "the template lists: {templates}"
    );
    rpc(
        &client,
        &token,
        "mail.templates.delete",
        serde_json::json!({ "id": template_id }),
    )
    .await;
    println!("PASS templates: save → list → delete through the store");

    println!("SMOKE PASS: 5/5 read-path steps verified");
}
