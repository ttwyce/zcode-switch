
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// 领取链路日志（claim.log）：preview/活动投放/领取/验证码配置的关键节点
/// 落盘。此前诊断信息走 eprintln——Windows GUI 子系统下 stderr 不可见，
/// 等于没有（2026-11-20 排查 oauth 链路靠 oauth.log 五分钟定位，claim 链
/// 缺等价物）。轮转策略与 flowlog 一致：256KB 单代，满则更名 .log.old。
/// tag 用 device_mid 尾 4 位标识账号。

static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();
static WRITE_LOCK: Mutex<()> = Mutex::new(());

const MAX_BYTES: u64 = 256 * 1024;

pub fn init(base: &Path) {
    let dir = base.join("logs");
    if std::fs::create_dir_all(&dir).is_ok() {
        let _ = LOG_PATH.set(dir.join("claim.log"));
    }
}

pub fn log(tag: &str, event: &str, detail: &str) {
    let Some(path) = LOG_PATH.get() else { return };
    append(path, &format_line(tag, event, detail));
}

/// device_mid 尾 4 位作账号标识（uuid 形态，ASCII 安全）。
pub fn mid_tag(mid: Option<&str>) -> String {
    let m = mid.unwrap_or("").trim();
    if m.len() <= 4 {
        return m.to_string();
    }
    m[m.len() - 4..].to_string()
}

fn format_line(tag: &str, event: &str, detail: &str) -> String {
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let clean: String = detail.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean.is_empty() {
        format!("{ts} [{tag}] {event}\n")
    } else {
        format!("{ts} [{tag}] {event} {clean}\n")
    }
}

fn append(path: &Path, line: &str) {
    let _guard = match WRITE_LOCK.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if std::fs::metadata(path).map(|m| m.len() > MAX_BYTES).unwrap_or(false) {
        let old = path.with_extension("log.old");
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::rename(path, &old);
    }
    let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let _ = f.write_all(line.as_bytes());
}
