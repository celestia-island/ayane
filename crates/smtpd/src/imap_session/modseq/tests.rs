//! Unit tests for the mod-sequence sidecar: the file round-trip, the
//! monotone watermark, the lazy assignment, the upgrade synthesis and the
//! expunge-queue trim.

use super::*;

/// A tiny directory under the system temporary directory, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "ayane-modseq-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn uniques(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn load_store_round_trips_and_skips_bad_lines() {
    let dir = Dir::new("roundtrip");
    std::fs::write(
        ModSeqTable::path(&dir.0),
        "h 90\nm a.msg 12\nnot-a-line\nx gone.msg 40\nm b.msg\nxf 30\nm 0 broken\n",
    )
    .expect("write");
    let table = ModSeqTable::load(&dir.0).expect("load");
    assert_eq!(table.highest(), 90, "the watermark is the maximum");
    assert_eq!(table.of("a.msg"), Some(12));
    assert_eq!(table.of("b.msg"), None, "a line without a value is skipped");
    assert_eq!(table.expunged_since(0), vec![("gone.msg".to_owned(), 40)]);
    assert_eq!(table.expired_through, 30);
    table.store(&dir.0).expect("store");
    let back = ModSeqTable::load(&dir.0).expect("reload");
    assert_eq!(back, table, "the file round-trips");
}

#[test]
fn a_fresh_table_starts_at_one_and_bump_assigns_above_it() {
    let dir = Dir::new("bump");
    let table = ModSeqTable::load(&dir.0).expect("load");
    assert_eq!(table.highest(), 1);
    let first = bump(&dir.0, &uniques(&["a.msg"])).expect("bump");
    let second = bump(&dir.0, &uniques(&["b.msg", "a.msg"])).expect("bump");
    assert_eq!(
        first, 2,
        "the watermark starts at 1, so the first bump is 2"
    );
    assert_eq!(second, 3, "bumps are distinct and increasing");
    let table = ModSeqTable::load(&dir.0).expect("reload");
    assert_eq!(table.of("a.msg"), Some(3), "the later bump wins");
    assert_eq!(table.of("b.msg"), Some(3));
    assert_eq!(table.highest(), 3);
}

#[test]
fn scan_sync_assigns_lazily_and_is_monotone_across_bumps() {
    let dir = Dir::new("lazy");
    let first = scan_sync(&dir.0, &uniques(&["a.msg", "b.msg"]), &[]).expect("scan");
    assert_eq!(
        first,
        vec![("a.msg".to_owned(), 2), ("b.msg".to_owned(), 3)],
        "assignments are sequential in scan order"
    );
    let second = scan_sync(&dir.0, &uniques(&["a.msg", "b.msg"]), &[]).expect("scan");
    assert_eq!(
        second, first,
        "a second scan reads the same values back, assigning nothing"
    );
    // A flag change bumps past everything lazily assigned.
    let bumped = bump(&dir.0, &uniques(&["a.msg"])).expect("bump");
    assert_eq!(bumped, 4, "the bump is above every assigned value");
    let third = scan_sync(&dir.0, &uniques(&["a.msg", "b.msg", "c.msg"]), &[]).expect("scan");
    assert_eq!(third[0], ("a.msg".to_owned(), 4));
    assert_eq!(
        third[2],
        ("c.msg".to_owned(), 5),
        "the new message lands above all"
    );
}

#[test]
fn a_fresh_sidecar_synthesises_expunge_history_for_dead_lines() {
    let dir = Dir::new("synth");
    let assigned =
        scan_sync(&dir.0, &uniques(&["live.msg"]), &uniques(&["old.msg"])).expect("scan");
    assert_eq!(
        assigned,
        vec![("live.msg".to_owned(), 3)],
        "the dead line is recorded first, the live one second"
    );
    let table = ModSeqTable::load(&dir.0).expect("reload");
    assert_eq!(
        table.expunged_since(0),
        vec![("old.msg".to_owned(), 2)],
        "the already-dead line joined the expunge queue at its own value"
    );
    // A second scan does not re-record or re-assign.
    let again = scan_sync(&dir.0, &uniques(&["live.msg"]), &uniques(&["old.msg"])).expect("scan");
    assert_eq!(again, vec![("live.msg".to_owned(), 3)]);
    let table = ModSeqTable::load(&dir.0).expect("reload");
    assert_eq!(table.highest(), 3, "nothing moved on the second scan");
}

#[test]
fn a_lost_sidecar_rotates_the_persisted_validity() {
    let dir = Dir::new("lost");
    // A CONDSTORE-era uidlist: the `v` line survived, the sidecar did not.
    std::fs::write(UidMap::path(&dir.0), "v 555\n1 old.msg:2,S\n2 live.msg\n").expect("write");
    scan_sync(&dir.0, &uniques(&["live.msg"]), &uniques(&["old.msg"])).expect("scan");
    let map = UidMap::load(&dir.0).expect("reload");
    assert_eq!(
        map.validity, 556,
        "the validity rotated past the persisted value (RFC 7162 §5.3)"
    );
    assert!(map.validity_persisted);
    let table = ModSeqTable::load(&dir.0).expect("sidecar rebuilt");
    assert_eq!(
        table.expunged_since(0).len(),
        1,
        "the dead line is recorded"
    );
    // The rotation is once: the rebuilt sidecar ends the fresh state.
    scan_sync(&dir.0, &uniques(&["live.msg"]), &uniques(&["old.msg"])).expect("scan");
    let map = UidMap::load(&dir.0).expect("reload");
    assert_eq!(map.validity, 556, "a second scan rotates nothing");
}

#[test]
fn an_upgrade_synthesises_history_and_keeps_the_identity() {
    let dir = Dir::new("upgrade");
    // A pre-CONDSTORE uidlist: message lines, no persisted validity.
    std::fs::write(UidMap::path(&dir.0), "1 old.msg:2,S\n2 live.msg\n").expect("write");
    let minted = UidMap::load(&dir.0).expect("load").validity;
    scan_sync(&dir.0, &uniques(&["live.msg"]), &uniques(&["old.msg"])).expect("scan");
    let map = UidMap::load(&dir.0).expect("reload");
    assert_eq!(
        map.validity, minted,
        "an upgrade keeps the folder's identity"
    );
    assert!(
        map.validity_persisted,
        "and the minted value is frozen into the file at the upgrade"
    );
    let table = ModSeqTable::load(&dir.0).expect("sidecar");
    assert_eq!(
        table.expunged_since(0).len(),
        1,
        "the dead line still joins the queue as synthesized history"
    );
}

#[test]
fn record_expunge_trims_to_the_cap_and_merges_into_the_watermark() {
    let dir = Dir::new("trim");
    // Raise the watermark so the trimmed values are distinctive.
    for seq in 0..(EXPUNGE_QUEUE_CAP as u64 + 5) {
        record_expunge(&dir.0, &format!("m{seq}.msg")).expect("record");
    }
    let table = ModSeqTable::load(&dir.0).expect("reload");
    assert_eq!(
        table.expunged_since(0).len(),
        EXPUNGE_QUEUE_CAP,
        "the queue holds exactly the cap"
    );
    assert_eq!(
        table.expired_through, 6,
        "the five oldest records (values 2..=6) merged into the trim watermark"
    );
    // The queue's oldest record is 7; RFC 7162 §3.2.6's <minmodseq> is 6, so
    // a request below it cannot be answered exactly and the fallback fires.
    assert!(
        table.predates_memory(5),
        "a request below minmodseq is answered as 'report everything'"
    );
    assert!(
        !table.predates_memory(6),
        "a request at minmodseq is still answered exactly"
    );
    assert!(
        !table.predates_memory(u64::MAX),
        "a request above every remembered value is answered exactly"
    );
    // Nothing ever trimmed: no request predates the memory.
    let fresh_dir = Dir::new("notrim");
    let fresh = ModSeqTable::load(&fresh_dir.0).expect("load");
    assert!(
        !fresh.predates_memory(0),
        "no trim means no fallback, at any request age"
    );
}

#[test]
fn expunged_since_orders_by_modseq_and_filters() {
    let dir = Dir::new("order");
    for unique in ["a.msg", "b.msg", "c.msg"] {
        record_expunge(&dir.0, unique).expect("record");
    }
    let table = ModSeqTable::load(&dir.0).expect("reload");
    let all = table.expunged_since(0);
    assert_eq!(
        all.iter().map(|(u, _)| u.as_str()).collect::<Vec<_>>(),
        vec!["a.msg", "b.msg", "c.msg"],
        "records come out oldest first"
    );
    assert_eq!(
        table.expunged_since(2).len(),
        2,
        "the filter is strict `>`: values 3 and 4 are above 2"
    );
    assert_eq!(table.expunged_since(3).len(), 1);
    assert_eq!(table.expunged_since(4).len(), 0);
}
