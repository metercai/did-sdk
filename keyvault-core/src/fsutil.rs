//! 文件系统工具：原子写、私有文件创建、时间戳。
//!
//! 仅 crate 内部使用；对外不暴露。

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_path(path: &Path) -> io::Result<std::path::PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("did-sdk");
    Ok(parent.join(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    )))
}

fn open_private(path: &Path, create_new: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(create_new);
    if !create_new {
        options.truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// 原子写入：同目录临时文件 + `fsync` + `rename`。
///
/// Unix 下临时文件权限为 `0600`；父目录不存在时自动创建。
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let tmp = temp_path(path)?;
    let result = (|| {
        let mut file = open_private(&tmp, true)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        #[cfg(unix)]
        {
            // 尽力而为地同步目录项；某些文件系统不支持对目录 fsync。
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// 以 `create_new` 方式创建私有文件。
///
/// 返回 `Ok(true)` 表示本次创建成功；`Ok(false)` 表示文件已存在（不会覆盖）。
pub(crate) fn create_private_file(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    match open_private(path, true) {
        Ok(mut file) => {
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(true)
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(err),
    }
}

/// 读取文本文件并去掉行尾的 `\r` / `\n`。
pub(crate) fn read_trimmed(path: &Path) -> io::Result<String> {
    let raw = fs::read_to_string(path)?;
    let trimmed = raw.trim_end_matches(['\r', '\n']).to_string();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "password file is empty",
        ));
    }
    Ok(trimmed)
}

/// 当前 Unix 时间戳（秒）。时间早于 epoch 时返回 0。
pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
