
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
import { init, t, lang, stripErr } from "./i18n.js";

const SDK_URL = "https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js";
const TRACELESS_TIMEOUT = 8000;
// 无痕求解重试预算（领取链口径，zcode2api CAPTCHA_CLAIM_SOLVE_RETRIES 缺省 2）：
// 预算耗尽 → 人工兜底。降级产物/超时/被拒才重试；SDK onError 属环境级失败直接放弃。
const TRACELESS_RETRIES = 2;

const $text = document.getElementById("cap-text");
const $detail = document.getElementById("cap-detail");
const $dot = document.getElementById("cap-dot");
const $btn = document.getElementById("cap-btn");

function status(text, tone = "run") {
  $text.textContent = text;
  $dot.className = "cap-dot" + (tone === "ok" ? " ok" : tone === "err" ? " err" : "");
}

function detail(text) {
  $detail.textContent = text || "";
}

document.addEventListener("securitypolicyviolation", (e) => {
  detail(t("c.cspBlocked", { directive: e.violatedDirective, uri: String(e.blockedURI).slice(0, 70) }));
});

const notifyStuck = () => { emit("captcha://interactive").catch(() => {}); };

// verifyParam 严格校验（zcode2api slidex_runner / solver_pw 同口径）：真实
// param ~280 字符 base64-JSON，内含 securityToken（≥50 字符）。len-76 的降级
// 产物上游必然 3007——绝不当成功提交，交由重试/人工兜底。
function paramValid(param) {
  if (!param || param.length < 200) return false;
  try {
    const b64 = param.replace(/-/g, "+").replace(/_/g, "/");
    const obj = JSON.parse(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)));
    const sec = obj.securityToken || obj.SecurityToken;
    return Boolean(sec) && String(sec).length >= 50;
  } catch {
    return false;
  }
}

function loadSdk() {
  return new Promise((resolve, reject) => {
    if (typeof window.initAliyunCaptcha === "function") return resolve();
    const s = document.createElement("script");
    s.src = SDK_URL;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error(t("c.sdkFail")));
    document.head.appendChild(s);
  });
}

let submitted = false;
let region = null;
let tracelessTimer = 0;

async function run() {
  try {
    const st = await invoke("get_state");
    if (st?.language) init(st.language);
  } catch { }
  document.title = t("c.title");
  $btn.textContent = t("c.btn");
  document.querySelector(".cap-foot").textContent = t("c.foot");
  status(t("c.preparing"));

  let cfg;
  try {
    cfg = await invoke("claim_captcha_config");
  } catch (e) {
    notifyStuck();
    status(t("c.cfgFail"), "err");
    detail(stripErr(e));
    return;
  }
  if (!cfg.enabled || !cfg.scene_id) {
    notifyStuck();
    status(t("c.cfgUnavailable"), "err");
    detail(t("c.cfgUnavailableDetail"));
    return;
  }
  region = cfg.region || null;
  try {
    await loadSdk();
  } catch (e) {
    notifyStuck();
    status(e.message || t("c.sdkFail"), "err");
    return;
  }

  window.AliyunCaptchaConfig = { region: cfg.region, prefix: cfg.prefix };

  status(t("c.traceless"));

  const submit = (param) => {
    if (submitted || !param || !param.trim()) return;
    submitted = true;
    clearTimeout(tracelessTimer);
    status(t("c.passed"));
    invoke("claim_captcha_submit", { param, region }).catch((e) => {
      status(t("c.claimReqFail"), "err");
      detail(stripErr(e));
    });
  };

  const interactive = (why) => {
    notifyStuck();
    clearTimeout(tracelessTimer);
    status(t("c.interactive"));
    $btn.hidden = false;
    $btn.focus();
    if (why) detail(typeof why === "string" ? why.slice(0, 120) : JSON.stringify(why).slice(0, 120));
  };

  // 单次无痕求解：resolve({kind:"param",param}) 成功 | {kind:"fail"} 可重试
  // | {kind:"error"} 环境级失败（重试同环境无意义）。降级 param 归入 fail。
  const solveOnce = () => new Promise((resolve) => {
    let done = false;
    const finish = (kind, why) => {
      if (done) return;
      done = true;
      clearTimeout(tracelessTimer);
      resolve({ kind, why });
    };
    try {
      window.initAliyunCaptcha({
        SceneId: cfg.scene_id,
        mode: "popup",
        language: lang() === "en" ? "en" : "zh-CN",
        showErrorTip: false,
        element: "#cap-holder",
        button: "#cap-btn",
        getInstance: (instance) => {
          if (typeof instance.startTracelessVerification === "function") {
            instance.startTracelessVerification();
            tracelessTimer = setTimeout(() => finish("fail", "timeout"), TRACELESS_TIMEOUT);
          } else {
            finish("fail", "noinstance");
          }
        },
        success: (param) => {
          const v = typeof param === "string" ? param : param?.captchaVerifyParam;
          if (paramValid(v)) finish("param", v);
          else finish("fail", "degraded");
        },
        fail: (p) => finish("fail", p),
        onError: (p) => finish("error", p),
      });
    } catch (e) {
      finish("error", e);
    }
  });

  (async () => {
    let lastWhy = null;
    for (let attempt = 1; attempt <= TRACELESS_RETRIES; attempt++) {
      if (attempt > 1) status(t("c.tracelessRetry", { n: attempt, total: TRACELESS_RETRIES }));
      const r = await solveOnce();
      if (r.kind === "param") {
        submit(r.param);
        return;
      }
      lastWhy = r.why;
      if (r.kind === "error") break;
    }
    interactive(lastWhy); // 无痕预算耗尽 → 人工兜底（auto 模式由此触发 captcha://interactive）
  })();
}

$btn.addEventListener("click", () => {
  if (!$btn.hidden) status(t("c.inPopup"));
});

run();
