use juan::{
    capture::CaptureLimits,
    filter::Filter,
    har_import,
    troubleshoot::{self, Review},
};

#[test]
fn export_counts_and_payload_use_one_snapshot_for_both_modes() {
    let store = juan::capture::CaptureStore::default();
    store
        .replace_from_archive(
            har_import::read(
                include_bytes!("fixtures/har/troubleshooting.har").as_slice(),
                CaptureLimits::default(),
            )
            .unwrap()
            .sessions,
        )
        .unwrap();
    let rows = || store.snapshot().sessions;
    let snapshot = troubleshoot::view_snapshot(
        rows(),
        &Filter::default(),
        0,
        troubleshoot::HIDE_ASSETS_DEFAULT,
    );
    assert_eq!(snapshot.rows.len(), 10);
    assert_eq!(snapshot.excluded.asset_hidden, 3);
    assert_eq!(snapshot.excluded.other_excluded, 0);
    let message = snapshot.excluded.counts_message(snapshot.rows.len());
    assert!(message.contains("Export 10 visible sessions"));
    assert!(message.contains("3 hidden by Hide assets"));
    let filtered =
        troubleshoot::view_snapshot(rows(), &Filter::parse("status:403").unwrap(), 0, true);
    assert_eq!(filtered.rows.len(), 1);
    assert_eq!(filtered.excluded.asset_hidden, 0);
    assert_eq!(filtered.excluded.other_excluded, 12);
    let restored = troubleshoot::view_snapshot(rows(), &Filter::default(), 0, false);
    assert_eq!(restored.rows.len(), 13);
    assert_eq!(restored.excluded.asset_hidden, 0);
    let scoped = troubleshoot::view_snapshot(rows(), &Filter::default(), 3, true);
    assert!(scoped.rows.iter().all(|r| r.is_error()));
    assert_eq!(scoped.excluded.asset_hidden, 0);
    assert_eq!(scoped.rows.len() + scoped.excluded.other_excluded, 13);

    // Cancelling after preparing the confirmation cannot write a destination or mutate the store.
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let destination = dir.path().join("existing.har");
    std::fs::write(&destination, b"existing synthetic destination").unwrap();
    drop(filtered);
    assert_eq!(
        std::fs::read(&destination).unwrap(),
        b"existing synthetic destination"
    );
    assert_eq!(store.all_sessions().len(), 13);
    let ids: Vec<_> = snapshot.rows.iter().map(|r| r.id).collect();
    let sessions = store.sessions(&ids);
    store.clear();
    for mode in [
        juan::har::ExportMode::Full,
        juan::har::ExportMode::Sanitized,
    ] {
        let mut output = Vec::new();
        juan::har::write_har(&mut output, &sessions, mode).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["log"]["entries"].as_array().unwrap().len(), 10);
        assert_eq!(
            sessions.iter().map(|s| s.id).collect::<Vec<_>>(),
            (4..=13).collect::<Vec<_>>()
        );
    }
}

#[test]
fn imported_fixture_has_safe_asset_filtering_and_visible_scope_review() {
    let imported = har_import::read(
        include_bytes!("fixtures/har/troubleshooting.har").as_slice(),
        CaptureLimits::default(),
    )
    .unwrap();
    let rows: Vec<_> = imported.sessions.iter().map(|s| s.summary()).collect();
    assert_eq!(
        rows.iter()
            .filter(|r| troubleshoot::static_asset(r))
            .map(|r| r.id)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(rows[12].content_type_ambiguous);
    let visible: Vec<_> = rows
        .iter()
        .filter(|r| !troubleshoot::static_asset(r))
        .cloned()
        .collect();
    assert_eq!(visible.len(), 10);
    assert_eq!(
        troubleshoot::review_order(&visible),
        vec![10, 8, 7, 6, 9, 5]
    );
    assert_eq!(Review::of(&rows[10]), None);
    let filtered: Vec<_> = visible
        .into_iter()
        .filter(|r| Filter::parse("status:403").unwrap().matches(r))
        .collect();
    assert_eq!(troubleshoot::review_order(&filtered), vec![6]);
    assert_eq!(
        rows.iter().map(|r| r.id).collect::<Vec<_>>(),
        (1..=13).collect::<Vec<_>>()
    );
}
