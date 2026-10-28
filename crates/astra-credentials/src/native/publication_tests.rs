use super::*;
use std::time::Duration;

#[test]
fn directory_sync_failure_reports_visible_publication_and_previous_session() {
    let (_directory, store) = tests::store();
    let (old, _) = store.publish(tests::session("A")).unwrap();
    let control = PublicationControl::new(Duration::from_secs(10));
    let published = store
        .publish_with_sync(tests::session("B"), &control, |_| {
            // This callback runs after the real rename, under the auth lock.
            assert!(!control.cancel(), "cancellation cannot win after commit");
            Err(std::io::Error::other("injected directory fsync failure"))
        })
        .unwrap();
    assert!(!published.directory_synced);
    assert_eq!(published.previous.unwrap().generation, old.generation);
    assert_eq!(
        store.current().unwrap().generation,
        published.session.generation
    );
    assert_eq!(store.current().unwrap().subject, "B");
}

#[test]
fn publication_lock_timeout_preserves_bytes_and_cannot_commit_later() {
    let (_directory, store) = tests::store();
    store.publish(tests::session("A")).unwrap();
    let before = fs::read(store.root.join("auth.json")).unwrap();
    let lock = private_open(&store.root.join("auth.lock"), true).unwrap();
    FileExt::lock_exclusive(&lock).unwrap();
    let control = PublicationControl::new(Duration::from_millis(30));
    let error = store
        .publish_controlled(tests::session("B"), &control)
        .err()
        .unwrap();
    assert!(error.contains("Timed out"));
    drop(lock);
    assert_eq!(fs::read(store.root.join("auth.json")).unwrap(), before);
    assert_eq!(store.current().unwrap().subject, "A");
}

#[test]
fn cancellation_before_rename_removes_temporary_file_and_preserves_session() {
    let (_directory, store) = tests::store();
    store.publish(tests::session("A")).unwrap();
    let before = fs::read(store.root.join("auth.json")).unwrap();
    let control = PublicationControl::new(Duration::from_secs(10));
    // The transaction callback is before serialization/fsync/rename. Cancel
    // there to exercise the final commit guard rather than only lock polling.
    let result = store.transaction_with_sync(Some(&control), sync_auth_directory, |state| {
        state.active = None;
        assert!(control.cancel());
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(fs::read(store.root.join("auth.json")).unwrap(), before);
    assert!(!fs::read_dir(&store.root).unwrap().any(|entry| {
        entry
            .unwrap()
            .path()
            .extension()
            .is_some_and(|extension| extension == "tmp")
    }));
}

#[tokio::test]
async fn refresh_intent_must_be_durable_before_sending_any_request() {
    use std::sync::atomic::Ordering;
    let fixture = tests::rotation_fixture("A").await;
    let (_directory, store) = tests::store();
    let mut expiring = tests::session("A");
    expiring.environment = fixture.environment.clone();
    expiring.expires_at = unix_now().unwrap();
    store.publish(expiring).unwrap();
    store.fail_sync_after.store(1, Ordering::SeqCst);
    assert!(store.credential("moi", None).await.is_err());
    assert_eq!(fixture.rotations.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.revocations.load(Ordering::SeqCst), 0);
    assert!(store.current().unwrap().refresh_pending);
    assert_eq!(store.current().unwrap().refresh_token, "synthetic-refresh");
}

#[tokio::test]
async fn visible_rotated_token_is_not_revoked_when_directory_sync_fails() {
    use std::sync::atomic::Ordering;
    let fixture = tests::rotation_fixture("A").await;
    let (_directory, store) = tests::store();
    let mut expiring = tests::session("A");
    expiring.environment = fixture.environment.clone();
    expiring.expires_at = unix_now().unwrap();
    store.publish(expiring).unwrap();
    // Intent sync succeeds; the save of the newly issued token fails sync.
    store.fail_sync_after.store(2, Ordering::SeqCst);
    fixture.release.notify_one();
    assert_eq!(
        store.credential("moi", None).await.unwrap_err(),
        CredentialFailure::RotationUnconfirmed
    );
    assert_eq!(fixture.rotations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.revocations.load(Ordering::SeqCst), 0);
    let saved = store.current().unwrap();
    assert!(!saved.refresh_pending);
    assert_eq!(saved.refresh_token, "synthetic-rotated");
    // The visible session is still usable; observing it must not rotate again.
    assert!(store.credential("moi", None).await.is_ok());
    assert_eq!(fixture.rotations.load(Ordering::SeqCst), 1);
}

#[test]
fn workspace_selection_lock_timeout_keeps_the_published_login() {
    let (_directory, store) = tests::store();
    let (session, _) = store.publish(tests::session("A")).unwrap();
    let before = fs::read(store.root.join("auth.json")).unwrap();
    let lock = private_open(&store.root.join("auth.lock"), true).unwrap();
    FileExt::lock_exclusive(&lock).unwrap();
    let control = PublicationControl::new(Duration::from_millis(30));
    assert!(
        store
            .select_workspace_controlled(&session, Some("workspace"), &control)
            .unwrap_err()
            .contains("Timed out")
    );
    drop(lock);
    assert_eq!(fs::read(store.root.join("auth.json")).unwrap(), before);
    assert_eq!(store.current().unwrap().generation, session.generation);
}
