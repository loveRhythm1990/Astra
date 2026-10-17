use astra_runtime_env::{
    load_or_create_materialization_id_in_roots, materialization_id_path_in_state,
};
use sha2::{Digest, Sha256};
use std::fs;

#[cfg(unix)]
#[test]
fn persisted_identity_survives_a_filesystem_device_number_change() {
    use std::os::unix::fs::MetadataExt;

    let device = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let workspace = workspace.path().canonicalize().unwrap();
    let device_id = "device-fixture";
    let metadata = workspace.metadata().unwrap();
    // Synthetic legacy writer: only the old mount number differs. Do not
    // mutate a real mount or use the developer's persisted identity files.
    let mut bytes = device_id.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(workspace.to_string_lossy().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&(metadata.dev() ^ 1).to_le_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&metadata.ino().to_le_bytes());
    let legacy = format!("materialization-{:x}", Sha256::digest(bytes));
    let canonical_path = materialization_id_path_in_state(&workspace, device.path());
    fs::create_dir_all(canonical_path.parent().unwrap()).unwrap();
    fs::write(
        canonical_path.parent().unwrap().join("device.id"),
        device_id,
    )
    .unwrap();
    fs::write(&canonical_path, &legacy).unwrap();

    // CLI/default state and standalone Edge/isolated state use the same owner.
    assert_eq!(
        load_or_create_materialization_id_in_roots(&workspace, device.path(), device.path())
            .unwrap(),
        legacy
    );
    assert_eq!(
        load_or_create_materialization_id_in_roots(&workspace, cache.path(), device.path())
            .unwrap(),
        legacy
    );
    assert_eq!(fs::read_to_string(canonical_path).unwrap(), legacy);
    assert_eq!(
        fs::read_to_string(materialization_id_path_in_state(&workspace, cache.path())).unwrap(),
        legacy
    );
}

#[test]
fn an_isolated_cache_cannot_replace_the_canonical_identity() {
    let device = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let workspace = workspace.path().canonicalize().unwrap();
    let canonical =
        load_or_create_materialization_id_in_roots(&workspace, cache.path(), device.path())
            .unwrap();
    let mirror = materialization_id_path_in_state(&workspace, cache.path());
    fs::write(&mirror, "materialization-conflicting-cache").unwrap();

    let error = load_or_create_materialization_id_in_roots(&workspace, cache.path(), device.path())
        .unwrap_err();
    assert!(error.contains("does not match its canonical identity"));
    assert_eq!(
        fs::read_to_string(materialization_id_path_in_state(&workspace, device.path())).unwrap(),
        canonical
    );
    assert_eq!(
        fs::read_to_string(mirror).unwrap(),
        "materialization-conflicting-cache"
    );
}

#[test]
fn malformed_canonical_identity_is_not_replaced() {
    let device = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let workspace = workspace.path().canonicalize().unwrap();
    let canonical_path = materialization_id_path_in_state(&workspace, device.path());
    fs::create_dir_all(canonical_path.parent().unwrap()).unwrap();
    for invalid in ["invalid identity", &"a".repeat(129)] {
        fs::write(&canonical_path, invalid).unwrap();
        assert!(
            load_or_create_materialization_id_in_roots(&workspace, cache.path(), device.path())
                .is_err()
        );
        assert_eq!(fs::read_to_string(&canonical_path).unwrap(), invalid);
    }
}

#[cfg(unix)]
#[test]
fn aliases_share_the_canonical_owner_without_writing_the_checkout() {
    use std::os::unix::fs::symlink;

    let device = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let aliases = tempfile::tempdir().unwrap();
    let alias = aliases.path().join("checkout");
    symlink(workspace.path(), &alias).unwrap();
    let first =
        load_or_create_materialization_id_in_roots(&alias, cache.path(), device.path()).unwrap();
    assert_eq!(
        load_or_create_materialization_id_in_roots(workspace.path(), device.path(), device.path())
            .unwrap(),
        first
    );
    assert!(fs::read_dir(workspace.path()).unwrap().next().is_none());
}

#[cfg(unix)]
#[test]
fn an_existing_default_state_alias_is_preserved_during_registration() {
    use std::os::unix::fs::symlink;

    let device = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let aliases = tempfile::tempdir().unwrap();
    let alias = aliases.path().join("checkout");
    symlink(workspace.path(), &alias).unwrap();
    let previous_path = materialization_id_path_in_state(&alias, device.path());
    fs::create_dir_all(previous_path.parent().unwrap()).unwrap();
    fs::write(&previous_path, "materialization-persisted-alias").unwrap();
    assert_eq!(
        load_or_create_materialization_id_in_roots(&alias, cache.path(), device.path()).unwrap(),
        "materialization-persisted-alias"
    );
    assert_eq!(
        load_or_create_materialization_id_in_roots(workspace.path(), cache.path(), device.path())
            .unwrap(),
        "materialization-persisted-alias"
    );
    assert_eq!(
        fs::read_to_string(previous_path).unwrap(),
        "materialization-persisted-alias"
    );
}

#[test]
fn concurrent_isolated_caches_share_one_durable_identity_owner() {
    let device = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let caches: Vec<_> = (0..8).map(|_| tempfile::tempdir().unwrap()).collect();
    let start = std::sync::Barrier::new(caches.len());
    let identities = std::thread::scope(|scope| {
        let workers: Vec<_> = caches
            .iter()
            .map(|cache| {
                let start = &start;
                let workspace = workspace.path();
                let device = device.path();
                scope.spawn(move || {
                    start.wait();
                    load_or_create_materialization_id_in_roots(workspace, cache.path(), device)
                        .unwrap()
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    let canonical_path =
        materialization_id_path_in_state(&workspace.path().canonicalize().unwrap(), device.path());
    let canonical = fs::read_to_string(canonical_path).unwrap();
    for (cache, identity) in caches.iter().zip(identities) {
        assert_eq!(identity, canonical);
        assert_eq!(
            fs::read_to_string(materialization_id_path_in_state(
                workspace.path(),
                cache.path()
            ))
            .unwrap(),
            canonical
        );
    }
}

#[cfg(unix)]
#[test]
fn a_conflicting_default_state_alias_cannot_override_the_canonical_owner() {
    use std::os::unix::fs::symlink;

    let device = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let workspace = workspace.path().canonicalize().unwrap();
    let canonical =
        load_or_create_materialization_id_in_roots(&workspace, device.path(), device.path())
            .unwrap();
    let aliases = tempfile::tempdir().unwrap();
    let alias = aliases.path().join("checkout");
    symlink(&workspace, &alias).unwrap();
    let previous_path = materialization_id_path_in_state(&alias, device.path());
    fs::write(&previous_path, "materialization-conflicting-alias").unwrap();
    assert!(
        load_or_create_materialization_id_in_roots(&alias, cache.path(), device.path())
            .unwrap_err()
            .contains("does not match its canonical identity")
    );
    assert_eq!(
        fs::read_to_string(materialization_id_path_in_state(&workspace, device.path())).unwrap(),
        canonical
    );
    assert_eq!(
        fs::read_to_string(previous_path).unwrap(),
        "materialization-conflicting-alias"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_canonical_identity_is_rejected() {
    use std::os::unix::fs::symlink;

    let device = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let workspace = workspace.path().canonicalize().unwrap();
    let canonical_path = materialization_id_path_in_state(&workspace, device.path());
    fs::create_dir_all(canonical_path.parent().unwrap()).unwrap();
    let target = device.path().join("not-an-identity-file");
    fs::write(&target, "materialization-do-not-follow").unwrap();
    symlink(&target, &canonical_path).unwrap();
    assert!(
        load_or_create_materialization_id_in_roots(&workspace, cache.path(), device.path())
            .is_err()
    );
    assert_eq!(
        fs::read_to_string(target).unwrap(),
        "materialization-do-not-follow"
    );
}

#[cfg(unix)]
#[test]
fn a_dangling_default_state_alias_is_not_ignored() {
    use std::os::unix::fs::symlink;

    let device = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let aliases = tempfile::tempdir().unwrap();
    let alias = aliases.path().join("checkout");
    symlink(workspace.path(), &alias).unwrap();
    let previous_path = materialization_id_path_in_state(&alias, device.path());
    fs::create_dir_all(previous_path.parent().unwrap()).unwrap();
    let missing = device.path().join("missing-target");
    symlink(&missing, &previous_path).unwrap();
    assert!(
        load_or_create_materialization_id_in_roots(&alias, cache.path(), device.path())
            .unwrap_err()
            .contains("not a regular bounded file")
    );
    assert_eq!(fs::read_link(previous_path).unwrap(), missing);
    assert!(!missing.exists());
}
