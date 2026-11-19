
use crate::quota;
use crate::zcrypto;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

pub const BILLING_PREVIEW_URL: &str = "https://zcode.z.ai/api/v1/zcode-plan/billing/preview";
pub const BILLING_CLAIM_URL: &str = "https://zcode.z.ai/api/v1/zcode-plan/billing/claim";
pub const CLIENT_CONFIGS_URL: &str = "https://zcode.z.ai/api/v1/client/configs";
// 营销触达 / 活动投放端点（官方客户端逆向实证）：活动套餐（如每晚 19 点放量的
// 大额 token 包，plan_id 形如 zcode-v3-start-plan-MMDD）由此下发，不进
// billing/preview。deliveries[].banner 内含 action.type="claim_zcode_plan"
// 与 args.zcode_plan 完整套餐载荷。
const MARKETING_TOUCH_URL: &str = "https://zcode.z.ai/api/v1/marketing/touch";

const CLAIM_TIMEOUT_SECS: u64 = 25;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ClaimGrant {
    pub name: String,
    pub units: f64,
    pub period: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ClaimPlan {
    pub plan_id: String,
    pub name: String,
    pub description: String,
    pub priority: i64,
    pub grants: Vec<String>,
    #[serde(default)]
    pub grant_items: Vec<ClaimGrant>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptchaConfig {
    pub enabled: bool,
    pub region: String,
    pub prefix: String,
    pub scene_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimOutcome {
    pub account_id: String,
    pub account_name: String,
    pub plan_name: String,
    pub starts_at: Option<i64>,
    pub ends_at: Option<i64>,
    pub server_time: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ClaimError {
    pub code: i64,
    pub message: String,
    pub next_at: Option<i64>,
}

impl From<String> for ClaimError {
    fn from(message: String) -> Self {
        ClaimError {
            code: -1,
            message,
            next_at: None,
        }
    }
}

fn claim_error(code: i64, body: &Value) -> ClaimError {
    let next_at = if code == 1005 {
        body.pointer("/data/plan/ends_at")
            .and_then(|x| x.as_i64())
            .map(|s| s * 1000)
    } else {
        None
    };
    ClaimError {
        code,
        message: failure_message(code, body),
        next_at,
    }
}

pub fn failure_payload(
    account_id: &str,
    account_name: &str,
    plan_name: &str,
    err: &ClaimError,
) -> Value {
    serde_json::json!({
        "ok": false,
        "accountId": account_id,
        "accountName": account_name,
        "planName": plan_name,
        "code": err.code,
        "nextAt": err.next_at,
        "message": err.message,
    })
}

fn claim_token(creds: &Value, config: Option<&Value>, secret: &str) -> Result<String, String> {
    let jwt = creds
        .get("zcodejwttoken")
        .and_then(|v| v.as_str())
        .and_then(|v| decrypt_credential(v, secret));
    if let Some(t) = jwt.filter(|t| t.trim().len() > 20) {
        return Ok(t);
    }
    if let Some(t) = quota::zai_billing_token(creds, config, secret) {
        return Ok(t);
    }
    Err(crate::i18n::tr("err.claim.no_jwt"))
}

fn decrypt_credential(v: &str, secret: &str) -> Option<String> {
    if zcrypto::is_encrypted(v) {
        zcrypto::decrypt_with_secret(v, secret).ok()
    } else {
        Some(v.to_string())
    }
}

fn agent() -> ureq::Agent {
    // 静态复用：ureq Agent 内部按 host 池化连接，preview/claim/marketing/config
    // 共享 TLS 会话——每晚 19:00 抢量场景省掉每请求的 TCP+TLS 握手（数百毫秒）。
    static AGENT: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();
    AGENT
        .get_or_init(|| {
            ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(10))
                .timeout(Duration::from_secs(CLAIM_TIMEOUT_SECS))
                .build()
        })
        .clone()
}

pub const EVENT_REPORT_URL: &str = "https://zcode.z.ai/api/v1/event/report";
pub const ACTIVATION_EVENTS: [&str; 2] = ["app_launch", "app_daily_active"];
const SCREEN_RESOLUTION: &str = "2560x1440";
const ACTIVATION_TIMEOUT_SECS: u64 = 10;

pub(crate) fn telemetry_user_id(home: &Path, creds: &Value) -> Option<String> {
    let secret = zcrypto::default_secret(home);
    let provider = creds
        .get("oauth:active_provider")
        .and_then(|v| v.as_str())
        .and_then(|v| decrypt_credential(v, &secret))
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "zai".to_string());
    let raw = creds
        .get(format!("oauth:{provider}:user_info"))?
        .as_str()?;
    let plain = decrypt_credential(raw, &secret)?;
    let info: Value = serde_json::from_str(&plain).ok()?;
    let pick = |k: &str| {
        info.get(k)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    pick("id").or_else(|| pick("user_id")).map(String::from)
}

fn activation_event_body(element: &str, event_id: &str, user_id: &str, mid: &str) -> Value {
    serde_json::json!({
        "event_id": event_id,
        "client_timezone": quota::client_timezone(),
        "client_language": quota::ZCODE_LANG,
        "element_name": element,
        "event_region": "app",
        "event_type": "view",
        "event_text": "",
        "event_extra_detail": {},
        "user_id": user_id,
        "screen_resolution": SCREEN_RESOLUTION,
        "app_version": quota::zcode_app_version(),
        "device_os_category": device_os_category(),
        "device_os_version": quota::os_version().unwrap_or_default(),
        "device_mid": mid,
        "mac_id": "",
        "marketing_params": "{}",
    })
}

fn device_os_category() -> &'static str {
    match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "macos",
        _ => "linux",
    }
}

/// 激活上报每日去重门：device_mid → 最近一次**成功**上报的北京日期序号。
/// 官方节奏 = app_daily_active 每号每天 1 次（上游按 device_mid+日期去重，
/// 自动轮次每 60s 重发纯属浪费请求且添指纹噪音）。上报失败不记账，下轮
/// 自然重试；手动刷新 force=true 不走此门（用户触发 = 必发，zcode2api 口径）。
static ACTIVATION_REPORTED: std::sync::OnceLock<Mutex<HashMap<String, String>>> =
    std::sync::OnceLock::new();

/// 北京时间（UTC+8，中国无夏令时）当日序号：只用于同日比较，无需 Y-M-D 格式。
fn beijing_day_index() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
        + 8 * 3600;
    secs.div_euclid(86_400)
}

pub fn report_activation_events(user_id: &str, device_mid: &str, force: bool) -> Result<(), String> {
    if !force {
        let today = beijing_day_index().to_string();
        let table = ACTIVATION_REPORTED.get_or_init(|| Mutex::new(HashMap::new()));
        let hit = table
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(device_mid)
            .map(String::as_str)
            == Some(today.as_str());
        if hit {
            return Ok(());
        }
    }
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(ACTIVATION_TIMEOUT_SECS))
        .build();
    for element in ACTIVATION_EVENTS {
        let body = activation_event_body(
            element,
            &uuid::Uuid::new_v4().to_string(),
            user_id,
            device_mid,
        );
        let resp = agent
            .post(EVENT_REPORT_URL)
            .set("Content-Type", "application/json")
            .send_json(body)
            .map_err(|e| {
                crate::i18n::trf("err.claim.activate_req", &[("e", http_err("", e).trim())])
            })?
            .into_string()
            .map_err(|e| crate::i18n::trf("err.claim.activate_req", &[("e", &e.to_string())]))?;
        let v: Value = serde_json::from_str(&resp).unwrap_or(Value::String(resp));
        let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
        if code != 0 {
            return Err(failure_message(code, &v));
        }
    }
    // 上报成功才记账（失败不记，下轮自然重试）
    if !force {
        let today = beijing_day_index().to_string();
        let table = ACTIVATION_REPORTED.get_or_init(|| Mutex::new(HashMap::new()));
        table
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(device_mid.to_string(), today);
    }
    Ok(())
}

pub fn preview_plans(
    home: &Path,
    creds: &Value,
    config: Option<&Value>,
    device_mid: Option<String>,
) -> Result<Vec<ClaimPlan>, String> {
    let secret = zcrypto::default_secret(home);
    let token = claim_token(creds, config, &secret)?;
    let url = format!(
        "{BILLING_PREVIEW_URL}?app_version={}&platform={}",
        quota::zcode_app_version(),
        quota::client_platform()
    );
    let tag = crate::claimlog::mid_tag(device_mid.as_deref());
    let mut out = preview_once(&url, &token, device_mid.clone())?;
    // 合并 marketing/touch 活动投放通道（官方客户端实证：活动套餐由此下发，
    // 不进 billing/preview）。失败只跳过合并，不让整个 preview 报错。
    let marketing = fetch_marketing_touch_plans(&token, device_mid);
    crate::claimlog::log(&tag, "preview", &format!("billing={} marketing={}", out.len(), marketing.len()));
    if !marketing.is_empty() {
        // 用 owned String 建去重集：借 out 的 &str 再 push 会撞借用检查
        let seen: std::collections::HashSet<String> =
            out.iter().map(|p| p.plan_id.clone()).collect();
        for mp in marketing {
            if !seen.contains(&mp.plan_id) {
                out.push(mp);
            }
        }
        out.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.plan_id.cmp(&b.plan_id)));
    }
    Ok(out)
}

fn fetch_marketing_touch_plans(token: &str, mid: Option<String>) -> Vec<ClaimPlan> {
    let tag = crate::claimlog::mid_tag(mid.as_deref());
    let mut req = agent().get(&format!("{MARKETING_TOUCH_URL}?seq=0"));
    for (k, v) in quota::zai_billing_headers_with_mid(token, mid) {
        req = req.set(&k, &v);
    }
    let resp = match req.call() {
        Ok(r) => r,
        Err(e) => {
            crate::claimlog::log(&tag, "marketing-skip", &http_err("", e).trim());
            return Vec::new();
        }
    };
    let body = match resp.into_string() {
        Ok(b) => b,
        Err(e) => {
            crate::claimlog::log(&tag, "marketing-read-fail", &e.to_string());
            return Vec::new();
        }
    };
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    if v.get("code").and_then(|c| c.as_i64()).unwrap_or(-1) != 0 {
        crate::claimlog::log(&tag, "marketing-skip", &format!("code={}", v.get("code").and_then(|c| c.as_i64()).unwrap_or(-1)));
        return Vec::new();
    }
    let deliveries = v
        .pointer("/data/deliveries")
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default();
    let plans = extract_plans_from_deliveries(&deliveries);
    if !plans.is_empty() {
        let ids: Vec<&str> = plans.iter().map(|p| p.plan_id.as_str()).collect();
        crate::claimlog::log(&tag, "marketing-plans", &ids.join(","));
    }
    plans
}

/// 从 marketing/touch 的 deliveries 载荷递归提取待领取套餐。
/// 官方客户端结构实证：delivery.banner.buttons[].action 为
/// `{"type":"claim_zcode_plan","args":{"plan_id":...}}`；
/// delivery.banner.args.zcode_plan 为完整套餐对象。
/// ① `zcode_plan`/`zcodePlan` 对象走 parse_plan（后到者更新先到的占位项）；
/// ② 仅命中按钮动作时按 plan_id 生成占位套餐（priority 100 抢先领取）。
fn extract_plans_from_deliveries(deliveries: &[Value]) -> Vec<ClaimPlan> {
    fn scan(v: &Value, out: &mut Vec<ClaimPlan>) {
        match v {
            Value::Array(items) => {
                for it in items {
                    scan(it, out);
                }
            }
            Value::Object(map) => {
                let zp = map.get("zcode_plan").or_else(|| map.get("zcodePlan"));
                if let Some(parsed) = zp.and_then(parse_plan) {
                    match out.iter_mut().find(|p| p.plan_id == parsed.plan_id) {
                        Some(existing) => *existing = parsed,
                        None => out.push(parsed),
                    }
                }
                let action = map.get("action").filter(|a| a.is_object());
                if let Some(a) = action {
                    let atype = a.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    if atype == "claim_zcode_plan" {
                        let pid = a
                            .pointer("/args/plan_id")
                            .or_else(|| a.pointer("/args/planId"))
                            .and_then(|p| p.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty());
                        if let Some(pid) = pid {
                            if !out.iter().any(|p| p.plan_id == pid) {
                                out.push(ClaimPlan {
                                    plan_id: pid.to_string(),
                                    name: pid.to_string(),
                                    description: String::new(),
                                    priority: 100,
                                    grants: Vec::new(),
                                    grant_items: Vec::new(),
                                });
                            }
                        }
                    }
                }
                for val in map.values() {
                    scan(val, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for d in deliveries {
        scan(d, &mut out);
    }
    out
}

fn http_err(prefix: &str, e: ureq::Error) -> String {
    if let ureq::Error::Status(code, resp) = e {
        let body = resp.into_string().unwrap_or_default();
        let msg = serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|v| ["msg", "message", "error"]
                .iter()
                .find_map(|k| v.get(k).and_then(|x| x.as_str()).map(String::from)))
            .unwrap_or_default();
        return format!("{prefix} HTTP {code}: {msg}");
    }
    format!("{prefix} {e}")
}

fn preview_once(url: &str, token: &str, mid: Option<String>) -> Result<Vec<ClaimPlan>, String> {
    let mut req = agent().get(url);
    for (k, v) in quota::zai_billing_headers_with_mid(token, mid) {
        req = req.set(&k, &v);
    }
    let resp = req
        .call()
        .map_err(|e| http_err(&crate::i18n::tr("err.claim.preview_req"), e))?
        .into_string()
        .map_err(|e| crate::i18n::trf("err.http.read", &[("e", &e.to_string())]))?;
    let v: Value = serde_json::from_str(&resp).unwrap_or(Value::String(resp));
    let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
    if code != 0 {
        return Err(failure_message(code, &v));
    }
    let plans = v
        .pointer("/data/plans")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out: Vec<ClaimPlan> = plans.iter().filter_map(parse_plan).collect();
    out.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.plan_id.cmp(&b.plan_id)));
    Ok(out)
}

pub fn submit_claim(
    home: &Path,
    creds: &Value,
    config: Option<&Value>,
    plan_id: &str,
    captcha_param: &str,
    captcha_region: Option<&str>,
    device_mid: Option<String>,
) -> Result<Value, ClaimError> {
    if captcha_param.trim().is_empty() {
        return Err(crate::i18n::tr("err.claim.no_captcha").into());
    }
    let tag = crate::claimlog::mid_tag(device_mid.as_deref());
    let secret = zcrypto::default_secret(home);
    let token = claim_token(creds, config, &secret)?;
    let mut req = agent().post(BILLING_CLAIM_URL);
    for (k, v) in quota::zai_billing_headers_with_mid(&token, device_mid) {
        req = req.set(&k, &v);
    }
    req = req.set("X-Aliyun-Captcha-Verify-Param", captcha_param.trim());
    if let Some(r) = captcha_region.filter(|r| !r.trim().is_empty()) {
        req = req.set("X-Aliyun-Captcha-Verify-Region", r.trim());
    }
    let resp = req
        .send_json(serde_json::json!({ "plan_id": plan_id }))
        .map_err(|e| ClaimError {
            code: -1,
            message: http_err(&crate::i18n::tr("err.claim.claim_req"), e),
            next_at: None,
        })?
        .into_string()
        .map_err(|e| ClaimError {
            code: -1,
            message: crate::i18n::trf("err.http.read", &[("e", &e.to_string())]),
            next_at: None,
        })?;
    let v: Value = serde_json::from_str(&resp).unwrap_or(Value::String(resp));
    let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
    if code != 0 {
        let err = claim_error(code, &v);
        crate::claimlog::log(
            &tag,
            "claim-fail",
            &format!("plan={plan_id} code={} {}", err.code, err.message),
        );
        return Err(err);
    }
    crate::claimlog::log(&tag, "claim-ok", &format!("plan={plan_id}"));
    Ok(v)
}

pub fn fetch_captcha_config() -> Result<CaptchaConfig, String> {
    let mut req = agent().get(CLIENT_CONFIGS_URL);
    for (k, v) in quota::zai_billing_headers("") {
        req = req.set(&k, &v);
    }
    let resp = req
        .call()
        .map_err(|e| crate::i18n::trf("err.claim.config_req", &[("e", &e.to_string())]))?
        .into_string()
        .map_err(|e| crate::i18n::trf("err.http.read", &[("e", &e.to_string())]))?;
    let v: Value = serde_json::from_str(&resp).unwrap_or(Value::String(resp));
    if v.get("code").and_then(|c| c.as_i64()).unwrap_or(-1) != 0 {
        return Err(crate::i18n::tr("err.claim.config_unavailable"));
    }
    let c = v.pointer("/data/configs/captcha").cloned().unwrap_or(Value::Null);
    let s = |k: &str| c.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string();
    let mut region = s("region");
    // sgp 归一为 cn（zcode2api 2.7.58/2.7.59 实证）：上游按出口 IP 下发 region
    // （美区出口实测 sgp），但 sgp 端点无痕验证稳定必败；且 region 头必须与
    // 签发端点一致，错位 = 上游验签必败 3007。
    if region.eq_ignore_ascii_case("sgp") {
        region = "cn".to_string();
        crate::claimlog::log("", "captcha-region", "sgp normalized to cn");
    }
    Ok(CaptchaConfig {
        enabled: c.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false),
        region,
        prefix: s("prefix"),
        scene_id: s("sceneId"),
    })
}

fn str_field<'a>(e: &'a Value, snake: &str, camel: &str) -> Option<&'a str> {
    e.get(snake)
        .and_then(|v| v.as_str())
        .or_else(|| e.get(camel).and_then(|v| v.as_str()))
}

fn num_field(e: &Value, snake: &str, camel: &str) -> Option<f64> {
    e.get(snake)
        .and_then(|v| v.as_f64())
        .or_else(|| e.get(camel).and_then(|v| v.as_f64()))
}

fn parse_plan(p: &Value) -> Option<ClaimPlan> {
    let plan_id = str_field(p, "plan_id", "planId")?.trim().to_string();
    if plan_id.is_empty() {
        return None;
    }
    let grant_items: Vec<ClaimGrant> = p
        .get("entitlements")
        .and_then(|e| e.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|e| {
                    str_field(e, "meter", "meter") == Some("model_usage")
                        && str_field(e, "unit_type", "unitType") == Some("token")
                        && str_field(e, "show_name", "showName")
                            .map(|s| !s.trim().is_empty())
                            .unwrap_or(false)
                })
                .map(|e| ClaimGrant {
                    name: str_field(e, "show_name", "showName").unwrap_or("").to_string(),
                    units: num_field(e, "grant_units", "grantUnits").unwrap_or(0.0),
                    period: str_field(e, "period", "period").unwrap_or("one_time").to_string(),
                })
                .collect()
        })
        .unwrap_or_default();
    let grants = grant_items
        .iter()
        .map(|g| {
            let period_cn = match g.period.as_str() {
                "daily" => "每日",
                "weekly" => "每周",
                "monthly" => "每月",
                _ => "一次性",
            };
            format!("{} · {} Token（{period_cn}）", g.name, fmt_units(g.units))
        })
        .collect();
    Some(ClaimPlan {
        name: p.get("name").and_then(|s| s.as_str()).unwrap_or("").trim().to_string(),
        description: p
            .get("description")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .trim()
            .to_string(),
        priority: p.get("priority").and_then(|x| x.as_i64()).unwrap_or(0),
        plan_id,
        grants,
        grant_items,
    })
}

fn fmt_units(n: f64) -> String {
    let trim = |x: f64| {
        let r = (x * 10.0).round() / 10.0;
        if (r - r.trunc()).abs() < f64::EPSILON {
            format!("{}", r.trunc() as i64)
        } else {
            format!("{r:.1}")
        }
    };
    if n >= 1e8 {
        format!("{}亿", trim(n / 1e8))
    } else if n >= 1e4 {
        format!("{}万", trim(n / 1e4))
    } else {
        format!("{}", n.round() as i64)
    }
}

pub fn failure_message(code: i64, body: &Value) -> String {
    let server_msg = ["msg", "message"]
        .iter()
        .find_map(|k| body.get(k).and_then(|x| x.as_str()).map(String::from))
        .unwrap_or_default();
    let base = crate::i18n::tr(match code {
        1001 => "claim.fail.1001",
        1002 => "claim.fail.1002",
        1003 => "claim.fail.1003",
        1004 => "claim.fail.1004",
        1005 => "claim.fail.1005",
        3001 => "claim.fail.3001",
        3002 => "claim.fail.3002",
        3007 => "claim.fail.3007",
        401 => "claim.fail.401",
        _ => "claim.fail.generic",
    });
    if server_msg.is_empty() {
        base
    } else {
        crate::i18n::trf("claim.fail.with_server", &[("base", &base), ("server_msg", &server_msg)])
    }
}
