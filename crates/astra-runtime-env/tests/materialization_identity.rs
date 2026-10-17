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
