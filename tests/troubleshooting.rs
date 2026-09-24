use juan::{
    capture::CaptureLimits,
    filter::Filter,
    har_import,
    troubleshoot::{self, Review},
};

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
