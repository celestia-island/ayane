//! JSON-RPC surface contract tests: envelope shape, error paths, session
//! gates. These drive `handle_one` directly — the socket plumbing is thin
//! frame in/out and needs no test doubles — except for the handshake gate,
//! which is the HTTP layer's own: that one opens a real socket.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use serde_json::{json, Value};

use ayane::state::AppState;
use ayane::transport::RpcSurface;
use ayane_store::{password, RedbStateStore, StateStore, StoredState};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ayane-rpc-{tag}-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

const PASSWORD: &str = "correct-horse-battery";
/// The fixture account's id, fixed so the shared mailbox can name it.
const ACCOUNT_ID: uuid::Uuid = uuid::Uuid::nil();
const ADMIN: &str = "admin-secret-token";

async fn surface(tag: &str) -> (RpcSurface, PathBuf) {
    let root = temp_dir(tag);
    let store = RedbStateStore::open(root.join("store.redb")).expect("store");
    let mut hashes = std::collections::HashMap::new();
    hashes.insert(
        "test@example.test".to_owned(),
        password::hash_password(PASSWORD).expect("hash"),
    );
    let stored = StoredState {
        desired: ayane_proto::DesiredState {
            domains: vec![ayane_proto::MailDomain {
                name: "example.test".to_owned(),
                catch_all: None,
                enabled: true,
                dkim: None,
            }],
            accounts: vec![ayane_proto::Account {
                id: ACCOUNT_ID,
                address: ayane_proto::Address::parse("test@example.test").expect("addr"),
                display_name: "Test".to_owned(),
                quota_bytes: 0,
                admin: false,
            }],
            // A shared mailbox the account is a member of, so the send leg
            // that judges the *header* sender has something to judge: the
            // From picker's 公共信箱 entry.
            shared: vec![ayane_proto::SharedMailbox {
                id: uuid::Uuid::new_v4(),
                address: ayane_proto::Address::parse("team@example.test").expect("addr"),
                members: vec![ACCOUNT_ID],
            }],
            ..Default::default()
        },
        password_hashes: hashes,
        external_identities: Vec::new(),
    };
    store.save(&stored).expect("seed");
    let config = ayane::config::Config {
        listen: "127.0.0.1:3023".parse().expect("listen"),
        log_filter: String::new(),
        state_dir: root.join("state"),
        admin_token: Some(ADMIN.to_owned()),
        compose_file: root.join("docker-compose.yml"),
        cert_file: None,
        // The mail section is off in every control-plane test: what an
        // installation that has not enabled it gets, so no port is bound.
        // The roots are spelled absolutely even so: a test that reaches the
        // mail methods (a granted `mail.send` stages into the spool) must
        // write under this test's temporary root, never the process's cwd —
        // `MailConfig::default()`'s relative roots are resolved against the
        // state directory by `from_env`, and nothing here went through it.
        mail: ayane::config::MailConfig {
            spool_root: root.join("state/spool"),
            mail_root: root.join("state/mail"),
            state_path: root.join("state/desired-state.json"),
            ..ayane::config::MailConfig::default()
        },
    };
    let app = AppState {
        store: Arc::new(store),
        driver: Arc::new(ayane::driver::RecordingDriver::new(
            root.join("docker-compose.yml"),
        )),
        config: Arc::new(config),
        auth: Arc::new(ayane::auth::AuthState::local()),
        mail_health: None,
    };
    let surface = RpcSurface {
        app,
        sessions: Arc::new(ayane::session::SessionStore::new()),
    };
    (surface, root)
}

async fn call(surface: &RpcSurface, request: Value) -> Value {
    let mut ctx = ayane::rpc::WsContext::new();
    let text = ayane::transport::handle_one_for_tests(surface, &mut ctx, &request.to_string())
        .await
        .expect("reply for request");
    serde_json::from_str(&text).expect("json reply")
}

#[tokio::test]
async fn ping_answers_result() {
    let (surface, _root) = surface("ping").await;
    let reply = call(&surface, rpc_request("session.ping", json!({}), json!(1))).await;
    assert_eq!(reply["result"]["ok"], json!(true));
}

#[tokio::test]
async fn unknown_method_is_32601() {
    let (surface, _) = surface("unknown").await;
    let reply = call(&surface, rpc_request("nope.nope", json!({}), json!(2))).await;
    assert_eq!(reply["error"]["code"], json!(-32601));
}

#[tokio::test]
async fn malformed_json_is_32700() {
    let (surface, _) = surface("malformed").await;
    let mut ctx = ayane::rpc::WsContext::new();
    let text = ayane::transport::handle_one_for_tests(&surface, &mut ctx, "{ not json")
        .await
        .expect("reply");
    let reply: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(reply["error"]["code"], json!(-32700));
}

#[tokio::test]
async fn notifications_are_never_answered() {
    let (surface, _) = surface("notify").await;
    let mut ctx = ayane::rpc::WsContext::new();
    // A notification carries NO id member at all (`id: null` is a valid,
    // discouraged id and must be answered).
    let notification = json!({ "jsonrpc": "2.0", "method": "session.ping", "params": {} });
    assert!(
        ayane::transport::handle_one_for_tests(&surface, &mut ctx, &notification.to_string())
            .await
            .is_none(),
        "notifications must produce no reply"
    );
}

#[tokio::test]
async fn wrong_password_is_a_path_error() {
    let (surface, _) = surface("badpw").await;
    let reply = call(
        &surface,
        rpc_request(
            "session.login",
            json!({ "address": "test@example.test", "password": "wrong" }),
            json!(3),
        ),
    )
    .await;
    assert_eq!(reply["error"]["code"], json!(-32000));
    assert_eq!(
        reply["error"]["message"].as_str().expect("message"),
        "Session.InvalidCredentials: address or password is wrong"
    );
}

#[tokio::test]
async fn a_mailbox_session_reads_an_empty_maildir_as_empty() {
    let (surface, _) = surface("mailgate").await;
    let login = call(
        &surface,
        rpc_request(
            "session.login",
            json!({ "address": "test@example.test", "password": PASSWORD }),
            json!(1),
        ),
    )
    .await;
    let token = login["result"]["token"].as_str().expect("token").to_owned();
    assert_eq!(login["result"]["address"], "test@example.test");

    // The read path walks this process's mail root, which the default
    // `MailConfig` places under the state directory — a directory nothing
    // has written to in this fixture. A folder that does not exist lists as
    // empty, which is the honest answer for a fresh account.
    let reply = call(
        &surface,
        rpc_request("mail.list", json!({ "token": token }), json!(2)),
    )
    .await;
    assert!(reply.get("error").is_none(), "{reply}");
    assert_eq!(reply["result"]["total"], 0, "{reply}");
    assert_eq!(reply["result"]["mailbox"], "INBOX", "{reply}");
}

/// An admin-token session is not a mailbox session, and the mail methods say
/// so. It is minted with the synthetic address `admin@localhost` and no
/// password, so `mailbox_locked()` is false for it — the "mailbox session
/// required" gate is what keeps it out of a mailbox it never proved.
#[tokio::test]
async fn an_admin_session_cannot_read_a_mailbox() {
    let (surface, _) = surface("admingate-mail").await;
    let admin = call(
        &surface,
        rpc_request("session.adminLogin", json!({ "token": ADMIN }), json!(1)),
    )
    .await;
    let token = admin["result"]["token"]
        .as_str()
        .expect("admin token")
        .to_owned();

    for (method, params) in [
        ("mail.list", json!({})),
        ("mail.read", json!({ "uid": "1700000000.M1P2Q3.host:2," })),
        ("mail.listStarred", json!({})),
        (
            "mail.send",
            json!({ "to": "boss@example.test", "subject": "x", "body": "y" }),
        ),
    ] {
        let mut params = params;
        params["token"] = json!(token);
        let reply = call(&surface, rpc_request(method, params, json!(2))).await;
        assert_eq!(
            reply["error"]["message"], "Session.Required: mailbox session required",
            "{method} must refuse an admin session: {reply}"
        );
    }
}

#[tokio::test]
async fn admin_methods_require_an_admin_session() {
    let (surface, _) = surface("admingate").await;
    // Anonymous.
    let reply = call(
        &surface,
        rpc_request("admin.state.get", json!({}), json!(1)),
    )
    .await;
    assert_eq!(
        reply["error"]["message"].as_str().expect("m"),
        "Session.Required: login first"
    );

    // A mailbox session is NOT an admin session.
    let login = call(
        &surface,
        rpc_request(
            "session.login",
            json!({ "address": "test@example.test", "password": PASSWORD }),
            json!(2),
        ),
    )
    .await;
    let token = login["result"]["token"].as_str().expect("token");
    let reply = call(
        &surface,
        rpc_request("admin.state.get", json!({ "token": token }), json!(3)),
    )
    .await;
    assert_eq!(
        reply["error"]["message"].as_str().expect("m"),
        "Admin.Forbidden: admin account required"
    );

    // Admin login opens the gate and the state flows back.
    let admin = call(
        &surface,
        rpc_request("session.adminLogin", json!({ "token": ADMIN }), json!(4)),
    )
    .await;
    assert_eq!(admin["result"]["ok"], json!(true));
    let admin_token = admin["result"]["token"].as_str().expect("admin token");
    let state = call(
        &surface,
        rpc_request("admin.state.get", json!({ "token": admin_token }), json!(5)),
    )
    .await;
    assert_eq!(state["result"]["domains"][0]["name"], "example.test");
}

/// The send-identity path of `mail.send`, observed without a mail server: a
/// From the policy GRANTS runs through the composer and is staged in this
/// process's own queue (`queued: true`), while a From it REFUSES is answered
/// by `resolve_send_identity` first and never reaches the spool. That
/// difference is the assertion: the switch changes which refusal the caller
/// sees, not merely whether the send works.
#[tokio::test]
async fn mail_send_accepts_a_tagged_from_only_when_the_switch_is_on() {
    let (surface, _) = surface("fromvariants").await;
    let login = call(
        &surface,
        rpc_request(
            "session.login",
            json!({ "address": "test@example.test", "password": PASSWORD }),
            json!(1),
        ),
    )
    .await;
    let token = login["result"]["token"].as_str().expect("token").to_owned();

    let admin = call(
        &surface,
        rpc_request("session.adminLogin", json!({ "token": ADMIN }), json!(2)),
    )
    .await;
    let admin_token = admin["result"]["token"]
        .as_str()
        .expect("admin token")
        .to_owned();

    let send = |from: &str| {
        rpc_request(
            "mail.send",
            json!({
                "token": token,
                "to": "boss@example.test",
                "subject": "variant",
                "body": "body",
                "from": from,
            }),
            json!(9),
        )
    };
    // The reply's path-style message, or a marker when the call succeeded
    // (a granted send stages itself in this process's own queue and does not
    // need anything listening beside it).
    fn message(reply: &Value) -> String {
        reply["error"]["message"]
            .as_str()
            .map_or_else(|| format!("unexpected success: {reply}"), str::to_owned)
    }

    // Switch off (the seeded default): the tagged From is refused before the
    // relay is ever touched.
    let refused = call(&surface, send("test+news@example.test")).await;
    assert_eq!(
        message(&refused),
        "Mail.BadRecipient: that shared mailbox does not belong to this account"
    );

    // Turn the outbound plus switch on through the admin policy surface.
    let saved = call(
        &surface,
        rpc_request(
            "admin.policy.put",
            json!({
                "token": admin_token,
                "allowlist": [],
                "denylist": [],
                "variants": { "outbound_plus": true },
            }),
            json!(3),
        ),
    )
    .await;
    assert_eq!(saved["result"]["saved"], json!(true), "{saved}");

    // The same tagged From is now granted: the message is staged in this
    // process's queue. (The envelope sender stays the account — `compose`
    // pins it — so the variant only ever changes the From header.)
    let granted = call(&surface, send("test+news@example.test")).await;
    assert!(
        granted.get("error").is_none() && granted["result"]["queued"] == json!(true),
        "a granted variant must be queued, got {granted}"
    );
    // The dot switch is still off, so a dotted From stays refused.
    let dotted = call(&surface, send("te.st@example.test")).await;
    assert_eq!(
        message(&dotted),
        "Mail.BadRecipient: that shared mailbox does not belong to this account"
    );

    // Both switches on: the dotted form is granted too.
    let saved = call(
        &surface,
        rpc_request(
            "admin.policy.put",
            json!({
                "token": admin_token,
                "allowlist": [],
                "denylist": [],
                "variants": { "outbound_plus": true, "outbound_dots": true },
            }),
            json!(4),
        ),
    )
    .await;
    assert_eq!(saved["result"]["saved"], json!(true), "{saved}");
    let dotted = call(&surface, send("te.st@example.test")).await;
    assert!(
        dotted.get("error").is_none() && dotted["result"]["queued"] == json!(true),
        "a granted dotted variant must be queued, got {dotted}"
    );
}

/// `mail.send` runs the operator's sender rules before it writes anything: a
/// deny-listed sender is refused at the door, the same answer the submission
/// listener gives an SMTP client with the same reverse-path.
#[tokio::test]
async fn mail_send_refuses_a_deny_listed_sender() {
    let (surface, _) = surface("senddeny").await;
    let login = call(
        &surface,
        rpc_request(
            "session.login",
            json!({ "address": "test@example.test", "password": PASSWORD }),
            json!(1),
        ),
    )
    .await;
    let token = login["result"]["token"].as_str().expect("token").to_owned();
    // The policy is edited under the admin token, the way an operator does.
    let admin = call(
        &surface,
        rpc_request("session.adminLogin", json!({ "token": ADMIN }), json!(2)),
    )
    .await;
    let admin_token = admin["result"]["token"]
        .as_str()
        .expect("admin token")
        .to_owned();

    let send = |token: &str| {
        rpc_request(
            "mail.send",
            json!({
                "token": token,
                "to": "boss@example.test",
                "subject": "denied",
                "body": "body",
            }),
            json!(7),
        )
    };

    // The fixture's policy has an empty deny list: the send is accepted into
    // the queue (whether the recipient is reachable is the delivery layer's
    // business, not this handler's).
    let allowed = call(&surface, send(&token)).await;
    assert!(allowed.get("error").is_none(), "{allowed}");

    // Deny the sender's own domain through the policy surface, then send
    // again: the rule that judges a sender is what refuses it.
    let saved = call(
        &surface,
        rpc_request(
            "admin.policy.put",
            json!({
                "token": admin_token,
                "allowlist": [],
                "denylist": ["@example.test"],
                "variants": {},
            }),
            json!(3),
        ),
    )
    .await;
    assert_eq!(saved["result"]["saved"], json!(true), "{saved}");

    let denied = call(&surface, send(&token)).await;
    assert_eq!(
        denied["error"]["message"], "Mail.Rejected: the policy refuses this sender",
        "a deny-listed sender must be refused before anything is written: {denied}"
    );
}

/// A deny list on the address the *recipient reads* stops the send, even
/// when the envelope sender is a different address that is not denied.
///
/// Sending from a shared mailbox is exactly that shape: the envelope is the
/// account (it is what authenticated), the `From:` is the shared address. A
/// rule written against that address has to bind the header too, or the
/// operator's rule is bypassed by the From picker.
#[tokio::test]
async fn mail_send_refuses_a_deny_listed_from_header() {
    let (surface, _) = surface("senddenyfrom").await;
    let login = call(
        &surface,
        rpc_request(
            "session.login",
            json!({ "address": "test@example.test", "password": PASSWORD }),
            json!(1),
        ),
    )
    .await;
    let token = login["result"]["token"].as_str().expect("token").to_owned();
    let admin = call(
        &surface,
        rpc_request("session.adminLogin", json!({ "token": ADMIN }), json!(2)),
    )
    .await;
    let admin_token = admin["result"]["token"]
        .as_str()
        .expect("admin token")
        .to_owned();

    // Deny the shared address only; the account's own address stays allowed.
    let saved = call(
        &surface,
        rpc_request(
            "admin.policy.put",
            json!({
                "token": admin_token,
                "allowlist": [],
                "denylist": ["team@example.test"],
                "variants": {},
            }),
            json!(3),
        ),
    )
    .await;
    assert_eq!(saved["result"]["saved"], json!(true), "{saved}");

    let send_as_team = rpc_request(
        "mail.send",
        json!({
            "token": token,
            "to": "boss@example.test",
            "subject": "from the shared mailbox",
            "body": "body",
            "from": "team@example.test",
        }),
        json!(4),
    );
    let denied = call(&surface, send_as_team).await;
    assert_eq!(
        denied["error"]["message"], "Mail.Rejected: the policy refuses this sender",
        "the From the recipient reads is judged too: {denied}"
    );

    // The same account sending as itself is still allowed: the rule names one
    // address, and the other is untouched.
    let own = call(
        &surface,
        rpc_request(
            "mail.send",
            json!({
                "token": token,
                "to": "boss@example.test",
                "subject": "from the account",
                "body": "body",
            }),
            json!(5),
        ),
    )
    .await;
    assert!(own.get("error").is_none(), "{own}");
}

fn rpc_request(method: &str, params: Value, id: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

/// An admin token for this fixture, minted through `session.adminLogin`.
async fn admin_token(surface: &RpcSurface) -> String {
    let reply = call(
        surface,
        rpc_request("session.adminLogin", json!({ "token": ADMIN }), json!(0)),
    )
    .await;
    reply["result"]["token"]
        .as_str()
        .expect("admin token")
        .to_owned()
}

// ── ③ the DKIM selector has a write channel ─────────────────────────────

/// The selector a domain signs with had **no** RPC: `signers_from_env` reads
/// `state.domains[i].dkim.selector`, and the only writer of that field was the
/// panel's raw JSON editor. This is the channel, and the assertion is the
/// whole chain it exists for — the selector lands in the state, the stored
/// state validates, and `signers_from_env` (the function the engine's DKIM
/// step calls) then produces a signer for that domain.
///
/// The key comes from an environment variable, as it does in a deployment: the
/// state never carries it. The fixture pair is the same throwaway RSA-2048 key
/// `crates/smtpd/tests/outbound.rs` signs with, registered in
/// `_ledger/tool-exemptions.md`.
#[tokio::test]
async fn setting_a_dkim_selector_over_rpc_is_what_makes_a_domain_sign() {
    const FIXTURE_KEY: &str = include_str!("../../smtpd/tests/fixtures/dkim-private.pem");
    const VARIABLE: &str = "AYANE_RPC_L946_DKIM_KEY_example_test";
    let (surface, _root) = surface("dkimrpc").await;
    let token = admin_token(&surface).await;

    // Before: the fixture's domain has no selector, so nothing signs.
    let stored = surface.app.store.load().expect("load");
    assert!(
        ayane_smtpd::outbound::signers_from_env(&stored.desired, VARIABLE)
            .expect("no selector is not an error")
            .is_empty(),
        "the precondition: no selector, no signer"
    );

    // The write.
    let reply = call(
        &surface,
        rpc_request(
            "admin.domain.dkim.put",
            json!({ "token": token, "domain": "example.test", "selector": "ayane" }),
            json!(1),
        ),
    )
    .await;
    assert!(reply.get("error").is_none(), "{reply}");
    assert_eq!(reply["result"]["saved"], json!(true), "{reply}");
    assert_eq!(
        reply["result"]["requires_restart"],
        json!(true),
        "the keys are loaded at start, and the answer says so: {reply}"
    );

    // The state carries it (read back through the panel's own read path)…
    let state = call(
        &surface,
        rpc_request("admin.state.get", json!({ "token": token }), json!(2)),
    )
    .await;
    assert_eq!(
        state["result"]["domains"][0]["dkim"]["selector"], "ayane",
        "{state}"
    );

    // … and the signer set the engine builds from it has the domain.
    std::env::set_var(VARIABLE, FIXTURE_KEY);
    let stored = surface.app.store.load().expect("load");
    let signed = ayane_smtpd::outbound::signers_from_env(&stored.desired, VARIABLE)
        .expect("a selector and a key produce a signer");
    assert_eq!(
        signed.keys().collect::<Vec<_>>(),
        vec![&"example.test".to_owned()],
        "the domain the selector was set on is the domain that signs"
    );
    // The key stayed in the environment: the state holds the selector only.
    assert!(
        stored.desired.domains[0]
            .dkim()
            .expect("dkim")
            .private_key
            .is_none(),
        "the snapshot never carries the signing key"
    );
    std::env::remove_var(VARIABLE);

    // An empty selector is the "sign nothing here" write, not an error.
    let reply = call(
        &surface,
        rpc_request(
            "admin.domain.dkim.put",
            json!({ "token": token, "domain": "example.test", "selector": "" }),
            json!(3),
        ),
    )
    .await;
    assert!(reply.get("error").is_none(), "{reply}");
    let stored = surface.app.store.load().expect("load");
    assert!(
        stored.desired.domains[0].dkim().is_none(),
        "cleared: {stored:?}"
    );
}

/// The refusals: a selector that could never be published as the left half of
/// `<selector>._domainkey.<domain>`, a selector sent for a domain this instance
/// does not host, and an anonymous caller.
#[tokio::test]
async fn the_dkim_selector_write_refuses_what_it_cannot_publish() {
    let (surface, _root) = surface("dkimrpc-refuse").await;
    let token = admin_token(&surface).await;

    for selector in ["", "has.a.dot", "-leading", "trailing-", &"a".repeat(64)] {
        let reply = call(
            &surface,
            rpc_request(
                "admin.domain.dkim.put",
                json!({ "token": token, "domain": "example.test", "selector": selector }),
                json!(1),
            ),
        )
        .await;
        // The empty one is the documented clear; the rest are refused by the
        // snapshot's own selector law, with the domain named.
        if selector.is_empty() {
            assert!(reply.get("error").is_none(), "empty clears: {reply}");
            continue;
        }
        assert_eq!(
            reply["error"]["message"]
                .as_str()
                .expect("message")
                .split(':')
                .next(),
            Some("Admin.MalformedSelector"),
            "{selector:?} must be refused by validation: {reply}"
        );
        let stored = surface.app.store.load().expect("load");
        assert!(
            stored.desired.domains[0].dkim().is_none(),
            "a refused write writes nothing: {stored:?}"
        );
    }

    let reply = call(
        &surface,
        rpc_request(
            "admin.domain.dkim.put",
            json!({ "token": token, "domain": "nothosted.test", "selector": "ayane" }),
            json!(2),
        ),
    )
    .await;
    assert_eq!(
        reply["error"]["message"], "Admin.UnknownDomain: nothosted.test is not a hosted domain",
        "{reply}"
    );

    let reply = call(
        &surface,
        rpc_request(
            "admin.domain.dkim.put",
            json!({ "domain": "example.test", "selector": "ayane" }),
            json!(3),
        ),
    )
    .await;
    assert_eq!(
        reply["error"]["message"], "Session.Required: login first",
        "an anonymous caller writes nothing: {reply}"
    );
}

// ── ④ `admin.state.put` inherits ids ────────────────────────────────────

/// A save from the panel must not renumber the accounts.
///
/// `PutAccount` carries no id (the webui builds one from the fields it shows),
/// so the pre-fix replacement minted a fresh id per address **on every write** —
/// measured 3 → 0 on a live instance, where the shared mailbox's member list
/// then pointed at ids nothing had. The rule is inheritance: an account that
/// exists keeps its id, a new one gets one, and the shared mailbox's own id and
/// its membership survive a save that lists the same addresses.
///
/// The mutation this pins: mint a fresh id per address (`Uuid::new_v4()` at
/// [`ayane::api::put_state_impl`]'s map) and every assertion below goes red.
#[tokio::test]
async fn a_state_save_keeps_the_ids_the_accounts_already_have() {
    let (surface, _root) = surface("stateput-ids").await;
    let token = admin_token(&surface).await;

    // The fixture seeded one account (`ACCOUNT_ID`) that is a member of one
    // shared mailbox. Note the fixture's account id is `Uuid::nil()` — the
    // *default* a caller that does not send one gets, which is exactly the
    // shape that used to be "replaced" on the round trip.
    let before = surface.app.store.load().expect("load");
    let account_before = before.desired.accounts[0].id;
    let shared_before = before.desired.shared[0].id;
    assert_eq!(account_before, ACCOUNT_ID, "fixture precondition");

    // The panel's save: the same addresses, no ids (the body has no field for
    // one), and — as a webui form does — the shared mailbox's member list
    // spelled as addresses.
    let body = json!({
        "token": token,
        "domains": [{
            "name": "example.test",
            "catch_all": null,
            "enabled": true,
        }],
        "accounts": [{
            "address": "test@example.test",
            "display_name": "Test (renamed)",
            "quota_bytes": 0,
            "admin": false,
            "password": PASSWORD,
        }],
        "aliases": [],
        "shared": [{
            "address": "team@example.test",
            "members": ["test@example.test"],
        }],
    });
    let reply = call(&surface, rpc_request("admin.state.put", body, json!(1))).await;
    assert!(reply.get("error").is_none(), "{reply}");

    let after = surface.app.store.load().expect("load");
    assert_eq!(
        after.desired.accounts[0].id, account_before,
        "the account keeps its id across a save"
    );
    assert_eq!(
        after.desired.shared[0].id, shared_before,
        "the shared mailbox keeps its id across a save"
    );
    assert_eq!(
        after.desired.shared[0].members,
        vec![account_before],
        "its membership still names the account that exists"
    );
    assert_eq!(
        after.desired.accounts[0].display_name, "Test (renamed)",
        "the rest of the write is applied"
    );

    // A second save is idempotent on the ids: this is the round trip the panel
    // does on every page save, and the pre-fix code minted a new id each time.
    let reply = call(
        &surface,
        rpc_request("admin.state.get", json!({ "token": token }), json!(2)),
    )
    .await;
    let read_back = reply["result"].clone();
    let mut again = read_back.clone();
    again["token"] = json!(token);
    // The read shape carries the password-holding fields, so send the same
    // body shape as above rather than the read document.
    let reply = call(
        &surface,
        rpc_request(
            "admin.state.put",
            json!({
                "token": token,
                "domains": [{
                    "name": "example.test",
                    "catch_all": null,
                    "enabled": true,
                }],
                "accounts": [{
                    "address": "test@example.test",
                    "display_name": "Test (renamed)",
                    "quota_bytes": 0,
                    "admin": false,
                    "password": PASSWORD,
                }],
                "aliases": read_back["aliases"].clone(),
                "shared": [{
                    "address": "team@example.test",
                    "members": ["test@example.test"],
                }],
            }),
            json!(3),
        ),
    )
    .await;
    assert!(reply.get("error").is_none(), "{reply}");
    let settled = surface.app.store.load().expect("load");
    assert_eq!(
        settled.desired.accounts[0].id, account_before,
        "the second save keeps the same id"
    );
    assert_eq!(settled.desired.shared[0].id, shared_before);

    // A genuinely new account still gets an id of its own.
    let reply = call(
        &surface,
        rpc_request(
            "admin.state.put",
            json!({
                "token": token,
                "domains": [{
                    "name": "example.test",
                    "catch_all": null,
                    "enabled": true,
                }],
                "accounts": [
                    {
                        "address": "test@example.test",
                        "display_name": "Test",
                        "quota_bytes": 0,
                        "admin": false,
                        "password": PASSWORD,
                    },
                    {
                        "address": "second@example.test",
                        "display_name": "Second",
                        "quota_bytes": 0,
                        "admin": false,
                        "password": PASSWORD,
                    },
                ],
                "aliases": [],
                "shared": [{
                    "address": "team@example.test",
                    "members": ["test@example.test", "second@example.test"],
                }],
            }),
            json!(4),
        ),
    )
    .await;
    assert!(reply.get("error").is_none(), "{reply}");
    let grown = surface.app.store.load().expect("load");
    assert_eq!(grown.desired.accounts[0].id, account_before);
    let second = grown.desired.accounts[1].id;
    assert_ne!(second, account_before, "a new account is a new identity");
    assert_eq!(
        grown.desired.shared[0].members,
        vec![account_before, second]
    );

    // A shared mailbox whose member list is re-submitted but whose accounts
    // are not: the two-part panel save that used to answer
    // `references non-account member`. The member is not deleted by the write
    // (its account survives in the store), so the membership must survive too —
    // resolved against the stored account rather than refused.
    let reply = call(
        &surface,
        rpc_request(
            "admin.state.put",
            json!({
                "token": token,
                "domains": [{
                    "name": "example.test",
                    "catch_all": null,
                    "enabled": true,
                }],
                "accounts": [],
                "aliases": [],
                "shared": [{
                    "address": "team@example.test",
                    "members": ["test@example.test"],
                }],
            }),
            json!(9),
        ),
    )
    .await;
    assert!(
        reply.get("error").is_none(),
        "a member the write does not re-list still exists: {reply}"
    );
    let held = surface.app.store.load().expect("load");
    assert_eq!(
        held.desired.shared[0].id, shared_before,
        "the shared mailbox keeps its id even when no account is written"
    );
    assert!(
        held.desired.shared[0].members.contains(&account_before),
        "the membership resolved to the account that is in the store: {:?}",
        held.desired.shared[0].members
    );
}

/// The full application on a loopback socket of its own: the address to
/// reach it at. (A WebSocket handshake only survives a real server: the
/// upgrade extractor takes an extension the HTTP connection itself
/// inserts, so `tower::oneshot` answers 426 to every handshake.)
async fn serve(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("address");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    addr
}

/// One WebSocket handshake at `addr`, as a browser would open it: a raw
/// HTTP/1.1 upgrade request with every header the upgrade needs, the
/// `Host` given and the `Origin` given (`None` = the header is not sent
/// at all). Answers the head of the reply — status line and headers.
async fn upgrade_head(addr: SocketAddr, host: &str, origin: Option<&str>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut request = format!(
        "GET /api/ws HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    );
    if let Some(origin) = origin {
        request.push_str(&format!("Origin: {origin}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.expect("send");
    // The head ends at the first empty line; the body (for an accepted
    // upgrade, the socket itself) is never read.
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await.expect("read");
        assert!(
            read > 0,
            "closed before the head ended: {:?}",
            String::from_utf8_lossy(&head)
        );
        head.extend_from_slice(&chunk[..read]);
        if let Ok(text) = std::str::from_utf8(&head) {
            if let Some(end) = text.find("\r\n\r\n") {
                return text[..end].to_owned();
            }
        }
    }
}

/// The status code of a reply's head.
fn status_of(head: &str) -> u16 {
    head.split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status")
}

/// Whether the head carries the handshake's own acceptance header.
fn accepted(head: &str) -> bool {
    head.to_ascii_lowercase().contains("sec-websocket-accept:")
}

#[tokio::test]
async fn the_websocket_refuses_a_foreign_origin() {
    let (surface, _root) = surface("ws-origin").await;
    let addr = serve(ayane::api::full_router(surface)).await;
    let own = "mail.example.test";

    // MUT:ws-same-origin — the socket is upgraded only for this origin:
    // the `Origin` the browser names is the `Host` its request came to
    // (name and port; the case of the name is nobody's, and a port the
    // scheme makes the default goes unnamed on either side). The SPA's
    // page.
    for (host, origin) in [
        (own, "https://mail.example.test"),
        (own, "https://Mail.Example.Test"),
        ("127.0.0.1:3023", "http://127.0.0.1:3023"),
        ("mail.example.test:443", "https://mail.example.test"),
        ("mail.example.test:8443", "https://mail.example.test:8443"),
        ("[::1]:3023", "http://[::1]:3023"),
    ] {
        let head = upgrade_head(addr, host, Some(origin)).await;
        assert_eq!(status_of(&head), 101, "{origin} on {host}: {head}");
        assert!(accepted(&head), "{origin} on {host}: {head}");
    }
    // No `Origin` at all is not a browser: the MCP/WS tooling.
    let head = upgrade_head(addr, own, None).await;
    assert_eq!(status_of(&head), 101, "{head}");
    assert!(accepted(&head), "{head}");

    // Any other origin is refused before the handshake: another host,
    // another port, the `null` origin, a host that merely starts or ends
    // with ours, ours on another port, a scheme no page has — and an
    // origin with no `Host` to vouch for it.
    for (host, origin) in [
        (own, "https://evil.example"),
        (own, "https://mail.example.test:8443"),
        (own, "null"),
        (own, "https://mail.example.test.evil.example"),
        (own, "https://evil-mail.example.test"),
        (own, "ws://mail.example.test"),
        ("127.0.0.1:3023", "https://mail.example.test"),
        ("", "https://mail.example.test"),
    ] {
        let head = upgrade_head(addr, host, Some(origin)).await;
        assert_eq!(status_of(&head), 403, "{origin} on {host:?}: {head}");
        assert!(!accepted(&head), "{origin} on {host:?}: {head}");
    }
}
