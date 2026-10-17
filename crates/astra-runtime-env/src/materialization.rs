//! Stable identity for a physical local checkout.
//!
//! The CLI and standalone Edge must publish the same materialization identity:
//! it is tied to a persisted device identity and the canonical checkout, not a
//! process id or a cache root.

use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
mod volume;

fn canonical_workspace_dir(workspace_dir: &Path) -> Result<PathBuf, String> {
    workspace_dir.canonicalize().map_err(|error| {
        format!(
            "failed to canonicalize workspace directory '{}': {error}",
            workspace_dir.display()
        )
    })
}

const MATERIALIZATION_ID_DIRECTORY: &str = "edge-materializations";
const MATERIALIZATION_ID_FILE_SUFFIX: &str = ".id";
const MATERIALIZATION_ID_MAX_BYTES: u64 = 128;

pub fn materialization_id_path_in_state(workspace_dir: &Path, state_root: &Path) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(workspace_dir.to_string_lossy().as_bytes());
    let workspace_key = format!("{:x}", hasher.finalize());
    state_root
        .join(MATERIALIZATION_ID_DIRECTORY)
        .join(format!("{workspace_key}{MATERIALIZATION_ID_FILE_SUFFIX}"))
}

/// Return the state file used for the stable device identity. This path is
/// deliberately rooted in Astra's default local state directory; an
/// `ASTRA_STATE_ROOT` override may isolate caches, but it must not turn one
/// physical device into multiple materialization identities.
fn device_identity_path(state_root: &Path) -> PathBuf {
    state_root
        .join(MATERIALIZATION_ID_DIRECTORY)
        .join("device.id")
}

/// Publish one identity file without ever exposing a partial value. A synced
/// temporary file is hard-linked into place, which gives us no-replace
/// semantics on the same filesystem. The caller may provide an expected value
/// to bind a cached identity to an independently persisted physical identity.
fn load_or_create_identity_file(
    path: &Path,
    expected: Option<(&str, &str)>,
    create_value: impl Fn() -> String,
    description: &str,
) -> Result<String, String> {
    let directory = path
        .parent()
        .ok_or_else(|| format!("{description} has no parent directory"))?;
    fs::create_dir_all(directory).map_err(|error| {
        format!(
            "failed to create Astra identity directory '{}': {error}",
            directory.display()
        )
    })?;
    sync_identity_directory(directory, description)?;
    if let Some(parent) = directory.parent() {
        sync_identity_directory(parent, description)?;
    }
    for _ in 0..3 {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() || metadata.len() > MATERIALIZATION_ID_MAX_BYTES
                {
                    return Err(format!(
                        "{description} '{}' is not a regular bounded file",
                        path.display()
                    ));
                }
                let value = fs::read_to_string(path).map_err(|error| {
                    format!("failed to read {description} '{}': {error}", path.display())
                })?;
                let value = value.trim();
                if !crate::is_valid_provider_id(value) {
                    return Err(format!("{description} '{}' is invalid", path.display()));
                }
                if let Some((expected, hint)) = expected
                    && expected != value
                {
                    return Err(format!(
                        "{description} '{}' does not match its canonical identity. {hint}",
                        path.display()
                    ));
                }
                return Ok(value.to_owned());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Never create the final path before the bytes are complete.
                // If the process crashes, only an unreferenced temporary file
                // remains and a later process can safely publish a new one.
                let temporary = path.with_file_name(format!(
                    ".{}-tmp-{}",
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("identity"),
                    uuid::Uuid::new_v4()
                ));
                let value = expected.map_or_else(&create_value, |(value, _)| value.to_owned());
                let publish = (|| -> Result<bool, String> {
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&temporary)
                        .map_err(|error| {
                            format!(
                                "failed to create {description} temporary file '{}': {error}",
                                temporary.display()
                            )
                        })?;
                    file.write_all(value.as_bytes()).map_err(|error| {
                        format!(
                            "failed to write {description} temporary file '{}': {error}",
                            temporary.display()
                        )
                    })?;
                    file.sync_all().map_err(|error| {
                        format!(
                            "failed to persist {description} temporary file '{}': {error}",
                            temporary.display()
                        )
                    })?;
                    match fs::hard_link(&temporary, path) {
                        Ok(()) => {
                            sync_identity_directory(directory, description)?;
                            Ok(true)
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                            Ok(false)
                        }
                        Err(error) => Err(format!(
                            "failed to publish {description} '{}': {error}",
                            path.display()
                        )),
                    }
                })();
                let _ = fs::remove_file(&temporary);
                match publish {
                    Ok(true) => return Ok(value),
                    Ok(false) => continue,
                    Err(error) => return Err(error),
                }
            }
            Err(error) => {
                return Err(format!(
                    "failed to inspect {description} '{}': {error}",
                    path.display()
                ));
            }
        }
    }
    Err(format!(
        "{description} '{}' changed during initialization",
        path.display()
    ))
}

fn sync_identity_directory(directory: &Path, description: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        let handle = OpenOptions::new()
            .read(true)
            .open(directory)
            .map_err(|error| {
                format!(
                    "failed to open {description} directory '{}' for sync: {error}",
                    directory.display()
                )
            })?;
        handle.sync_all().map_err(|error| {
            format!(
                "failed to persist {description} directory '{}': {error}",
                directory.display()
            )
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = (directory, description);
    }
    Ok(())
}

fn load_or_create_device_identity(state_root: &Path) -> Result<String, String> {
    load_or_create_identity_file(
        &device_identity_path(state_root),
        None,
        || format!("device-{}", uuid::Uuid::new_v4()),
        "Edge device identity",
    )
}

#[cfg(unix)]
fn checkout_binding(identity: &[u8], filesystem_uuid: &[u8], inode: u64) -> String {
    let mut binding = Sha256::new();
    binding.update(identity);
    binding.update([0]);
    binding.update(filesystem_uuid);
    binding.update([0]);
    binding.update(inode.to_le_bytes());
    format!("checkout-{:x}", binding.finalize())
}

/// Seed a new checkout identity from the device and canonical directory. The
/// Unix device/inode values seed the ID only. The separate checkout binding
/// excludes the volatile mount number but retains the filesystem UUID and
/// inode, so a different volume with the same inode cannot inherit the ID.
fn materialization_identity_for_workspace(
    workspace_dir: &Path,
    device_id: &str,
) -> Result<(String, String), String> {
    let workspace = canonical_workspace_dir(workspace_dir)?;
    #[cfg(unix)]
    let directory = fs::File::open(&workspace).map_err(|error| {
        format!(
            "failed to inspect canonical workspace directory '{}': {error}",
            workspace.display()
        )
    })?;
    #[cfg(unix)]
    let metadata = directory
        .metadata()
        .map_err(|error| format!("failed to inspect open workspace directory: {error}"))?;
    #[cfg(not(unix))]
    let metadata = fs::metadata(&workspace)
        .map_err(|error| format!("failed to inspect workspace directory: {error}"))?;
    if !metadata.is_dir() {
        return Err(format!(
            "canonical workspace path '{}' is not a directory",
            workspace.display()
        ));
    }
    let mut identity = device_id.as_bytes().to_vec();
    identity.push(0);
    identity.extend_from_slice(workspace.to_string_lossy().as_bytes());
    #[cfg(unix)]
    let binding = {
        use std::os::unix::fs::MetadataExt;

        let volume = volume::filesystem_uuid(&directory).map_err(|error| {
            format!(
                "Cannot establish a stable filesystem identity for workspace '{}': {error}. \
                 Use a filesystem and OS that expose a filesystem UUID \
                 (macOS ATTR_VOL_UUID or Linux FS_IOC_GETFSUUID); \
                 no existing identity files were replaced.",
                workspace.display()
            )
        })?;
        let binding = checkout_binding(&identity, &volume, metadata.ino());
        identity.push(0);
        identity.extend_from_slice(&metadata.dev().to_le_bytes());
        identity.push(0);
        identity.extend_from_slice(&metadata.ino().to_le_bytes());
        identity.push(0);
        identity.extend_from_slice(&volume);
        binding
    };
    #[cfg(not(unix))]
    let binding = format!("checkout-{:x}", Sha256::digest(&identity));
    let digest = Sha256::digest(identity);
    Ok((format!("materialization-{digest:x}"), binding))
}

pub fn load_or_create_materialization_id(workspace_dir: &Path) -> Result<String, String> {
    let cache_root = crate::local_state_root_override()
        .unwrap_or_else(astra_core::local_state::local_state_root);
    let device_root = astra_core::local_state::default_local_state_root();
    load_or_create_materialization_id_in_roots(workspace_dir, &cache_root, &device_root)
}

pub fn load_or_create_materialization_id_in_roots(
    workspace_dir: &Path,
    cache_root: &Path,
    device_root: &Path,
) -> Result<String, String> {
    let device_id = load_or_create_device_identity(device_root)?;
    let workspace = canonical_workspace_dir(workspace_dir)?;
    let canonical_path = materialization_id_path_in_state(&workspace, device_root);
    let previous_path = materialization_id_path_in_state(workspace_dir, device_root);
    let (seed, checkout_binding) = materialization_identity_for_workspace(&workspace, &device_id)?;
    // Older clients keyed their default-state file by the caller's path, even
    // though the ID used its canonical root. Preserve that published value
    // when first resolving an alias into the canonical default-state owner.
    let previous_exists = previous_path != canonical_path
        && match fs::symlink_metadata(&previous_path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(format!(
                    "failed to inspect workspace materialization identity: {error}"
                ));
            }
        };
    let previous_id = if previous_exists {
        Some(load_or_create_identity_file(
            &previous_path,
            None,
            || seed.clone(),
            "workspace materialization identity",
        )?)
    } else {
        None
    };
    // Legacy .id files have no checkout witness: their first upgraded start binds
    // the current directory. Publish that witness before a new owner, using
    // the same bounded, atomic no-replace storage. Later inode changes fail
    // closed without modifying the existing ID or any cache mirror.
    load_or_create_identity_file(
        &canonical_path.with_extension("checkout"),
        Some((
            &checkout_binding,
            &format!(
                "The checkout, filesystem, or local device identity differs from its saved binding. \
                 If you intentionally replaced this checkout, stop its Astra/astra-edge processes, \
                 back up and remove only '{}' and '{}', plus this checkout's alias/cache .id mirrors, \
                 then register it again. Keep device.id and login credentials.",
                canonical_path.display(),
                canonical_path.with_extension("checkout").display()
            ),
        )),
        || checkout_binding.clone(),
        "workspace checkout binding",
    )?;
    let canonical_id = load_or_create_identity_file(
        &canonical_path,
        None,
        || previous_id.as_ref().unwrap_or(&seed).clone(),
        "workspace materialization identity",
    )?;
    if previous_id.is_some() {
        load_or_create_identity_file(
            &previous_path,
            Some((
                &canonical_id,
                "This path alias conflicts with the default-state owner. Stop its Astra/astra-edge \
                 processes and back up/remove only the conflicting alias .id file before retrying; \
                 keep the canonical .id/.checkout, device.id and login credentials.",
            )),
            || canonical_id.clone(),
            "workspace materialization identity",
        )?;
    }
    // Isolated state roots contain mirrors, not independent identity owners.
    // A conflicting mirror still fails closed and is never overwritten.
    load_or_create_identity_file(
        &materialization_id_path_in_state(workspace_dir, cache_root),
        Some((
            &canonical_id,
            "This cache is not the identity owner and will not be adopted. Stop its Astra/astra-edge \
             processes and back up/remove only this conflicting cache .id file before retrying; \
             keep the default-state .id/.checkout, device.id and login credentials.",
        )),
        || canonical_id.clone(),
        "workspace materialization identity",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn checkout_binding_distinguishes_volumes_with_the_same_inode() {
        let prefix = b"device-fixture\0/canonical/checkout";
        let first = checkout_binding(prefix, &[1; 16], 2);
        assert_eq!(first, checkout_binding(prefix, &[1; 16], 2));
        assert_ne!(first, checkout_binding(prefix, &[2; 16], 2));
        assert_ne!(first, checkout_binding(prefix, &[1; 16], 3));
    }

    #[test]
    fn identity_is_stable_across_cache_roots_and_distinct_per_checkout() {
        let state_a = tempfile::tempdir().expect("state A");
        let state_b = tempfile::tempdir().expect("state B");
        let device_state = tempfile::tempdir().expect("device state");
        let independent_device_state = tempfile::tempdir().expect("independent device state");
        let workspace = tempfile::tempdir().expect("workspace");
        let first = load_or_create_materialization_id_in_roots(
            workspace.path(),
            state_a.path(),
            device_state.path(),
        )
        .unwrap();
        let reconnect = load_or_create_materialization_id_in_roots(
            workspace.path(),
            state_a.path(),
            device_state.path(),
        )
        .unwrap();
        let other_state = load_or_create_materialization_id_in_roots(
            workspace.path(),
            state_b.path(),
            device_state.path(),
        )
        .unwrap();
        assert_eq!(first, reconnect);
        assert_eq!(first, other_state);
        let independent_device_state_root = tempfile::tempdir().expect("independent device cache");
        let same_path_independent_device = load_or_create_materialization_id_in_roots(
            workspace.path(),
            independent_device_state_root.path(),
            independent_device_state.path(),
        )
        .unwrap();
        assert_ne!(first, same_path_independent_device);
        let independent_checkout = tempfile::tempdir().expect("independent checkout");
        let independent_checkout_id = load_or_create_materialization_id_in_roots(
            independent_checkout.path(),
            state_b.path(),
            device_state.path(),
        )
        .unwrap();
        assert_ne!(first, independent_checkout_id);
        fs::write(workspace.path().join("content-change"), b"changed").unwrap();
        assert_eq!(
            first,
            load_or_create_materialization_id_in_roots(
                workspace.path(),
                state_a.path(),
                device_state.path()
            )
            .unwrap()
        );
        assert!(
            materialization_id_path_in_state(workspace.path(), state_a.path())
                .starts_with(state_a.path())
        );
    }

    #[test]
    fn identity_publication_converges_under_concurrent_startup() {
        let state = tempfile::tempdir().expect("state");
        let device_state = tempfile::tempdir().expect("device state");
        let workspace = tempfile::tempdir().expect("workspace");
        let state_root = std::sync::Arc::new(state.path().to_path_buf());
        let device_root = std::sync::Arc::new(device_state.path().to_path_buf());
        let workspace_root = std::sync::Arc::new(workspace.path().to_path_buf());
        let workers = (0..16)
            .map(|_| {
                let state_root = std::sync::Arc::clone(&state_root);
                let device_root = std::sync::Arc::clone(&device_root);
                let workspace_root = std::sync::Arc::clone(&workspace_root);
                std::thread::spawn(move || {
                    load_or_create_materialization_id_in_roots(
                        &workspace_root,
                        &state_root,
                        &device_root,
                    )
                    .unwrap()
                })
            })
            .collect::<Vec<_>>();
        let identities = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert!(identities.windows(2).all(|pair| pair[0] == pair[1]));
        let identity_path = materialization_id_path_in_state(workspace.path(), state.path());
        assert_eq!(fs::read_to_string(identity_path).unwrap(), identities[0]);
    }
}
