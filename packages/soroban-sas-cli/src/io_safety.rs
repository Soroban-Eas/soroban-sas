//! Bounded reads and atomic, private writes for CLI file I/O (issues #176, #177).

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

/// Maximum size, in bytes, of a JSON attestation/envelope file this CLI will
/// read. Chosen generously above any legitimate attestation payload while
/// still bounding worst-case memory use from a mistaken or malicious file.
pub const MAX_INPUT_FILE_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB

/// Reads `path` into a `String`, rejecting it before allocation if its
/// on-disk size exceeds `max_bytes`. Symlinks are followed (matching
/// `std::fs::read_to_string`'s own behavior) and non-UTF-8 content is
/// rejected with an error rather than lossily replaced.
pub fn read_bounded(path: &str, max_bytes: u64) -> Result<String, String> {
    let metadata = fs::metadata(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    if !metadata.is_file() {
        return Err(format!("cannot read {path}: not a regular file"));
    }
    if metadata.len() > max_bytes {
        return Err(format!(
            "cannot read {path}: file size {} bytes exceeds the {max_bytes}-byte limit",
            metadata.len()
        ));
    }

    let mut file = fs::File::open(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    // Cap the read itself too, in case the file grows between the metadata
    // check and this read (TOCTOU) — take() ensures we never allocate past
    // the limit regardless.
    let mut buf = Vec::with_capacity(metadata.len().min(max_bytes) as usize);
    file.take(max_bytes)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read {path}: {e}"))?;

    String::from_utf8(buf).map_err(|_| format!("cannot read {path}: file is not valid UTF-8"))
}

/// Writes `contents` to `path` atomically: to a same-directory temp file
/// with mode 0600 (private by default on Unix), flushed and fsync'd, then
/// renamed into place. Refuses to clobber an existing destination unless
/// `force` is true, so an interrupted write never replaces a valid file
/// with partial JSON and an existing attestation is never silently
/// overwritten.
pub fn write_atomic_private(path: &str, contents: &str, force: bool) -> Result<(), String> {
    let dest = Path::new(path);
    let parent = dest.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let file_name = dest
        .file_name()
        .ok_or_else(|| format!("cannot write {path}: invalid file name"))?
        .to_string_lossy();
    // A random suffix (rather than a fixed ".<name>.tmp") stops a second
    // concurrent invocation, or an attacker who can predict the fixed name,
    // from pre-planting a symlink at the temp path before we create it.
    let tmp_path = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));

    {
        // create_new (not create) refuses to open an existing path at all —
        // including a symlink planted there ahead of time — instead of
        // following it, closing the classic temp-file symlink race.
        #[cfg(unix)]
        let mut tmp_file = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)
                .map_err(|e| format!("cannot create temp file for {path}: {e}"))?
        };
        #[cfg(not(unix))]
        let mut tmp_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|e| format!("cannot create temp file for {path}: {e}"))?;

        let write_result = tmp_file
            .write_all(contents.as_bytes())
            .and_then(|_| tmp_file.sync_all());
        if let Err(e) = write_result {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("cannot write {path}: {e}"));
        }
    }

    if force {
        return fs::rename(&tmp_path, dest).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            format!("cannot write {path}: {e}")
        });
    }

    // Without --force: hard_link fails atomically with AlreadyExists if
    // `dest` is present at link time, rather than checking existence and
    // renaming as two separate steps — closing the TOCTOU window where a
    // file (or attacker-planted symlink) could appear at `dest` in between.
    match fs::hard_link(&tmp_path, dest) {
        Ok(()) => {
            let _ = fs::remove_file(&tmp_path);
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Err(format!(
                    "cannot write {path}: destination already exists (remove it first, or pass the force option, before retrying)"
                ))
            } else {
                Err(format!("cannot write {path}: {e}"))
            }
        }
    }
}
