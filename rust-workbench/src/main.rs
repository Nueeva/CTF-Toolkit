use axum::{
    extract::Json,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use tracing::{error, info};

static PROTOTYPE_HTML: &str = include_str!("../../prototype/prototype.html");

#[derive(Debug, Deserialize)]
struct HubSolveRequest {
    text: String,
}

#[derive(Debug, Deserialize)]
struct CallRequest {
    function: String,
    #[serde(default)]
    kwargs: Value,
}

#[derive(Debug, Deserialize)]
struct FlagVerifyRequest {
    #[serde(default)]
    candidate: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/prototype", get(serve_index))
        .route("/api/health", get(health_check))
        .route("/api/flags", get(get_flags).post(post_flags))
        .route("/api/flag/verify", post(verify_flag))
        .route("/api/tools", get(get_tools))
        .route("/api/cheatsheets", get(get_cheatsheets))
        .route("/api/queue", get(get_queue))
        .route("/api/patterns", get(get_patterns))
        .route("/api/hub/solve", post(handle_hub_solve))
        .route("/api/hub/rsa", post(handle_hub_rsa))
        .route("/api/hub/classical", post(handle_hub_classical))
        .route("/api/hub/jwt", post(handle_hub_jwt))
        .route("/api/hub/eccdh", post(handle_hub_eccdh))
        .route("/api/call", post(handle_call))
        .route("/api/writeup/generate", post(handle_writeup));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8090));
    info!("Apexsions CTF Rust High-Performance Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind port 8090");
    axum::serve(listener, app).await.expect("Server error");
}

async fn serve_index() -> Html<&'static str> {
    Html(PROTOTYPE_HTML)
}

async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "online",
        "engine": "Rust axum/tokio v0.1.0",
        "runtime": "native-compiled x86_64",
        "status_code": 200
    }))
}

async fn get_flags() -> Json<Value> {
    run_python_helper("from ctf_toolkit.utils.flag_manager import get_flag_manager; import json; print(json.dumps(get_flag_manager().templates))").await
}

async fn post_flags(Json(payload): Json<Value>) -> Json<Value> {
    let script = format!(
        "import json; from ctf_toolkit.utils.flag_manager import get_flag_manager; mgr = get_flag_manager(); p = json.loads({:?}); act = p.get('action','add');\nif act == 'add':\n mgr.add_template(p.get('name',''), p.get('pattern',''), int(p.get('priority',50)))\n print(json.dumps({{'success': True, 'templates': mgr.templates}}))\nelif act == 'remove':\n mgr.remove_template(p.get('name',''))\n print(json.dumps({{'success': True, 'templates': mgr.templates}}))\nelse:\n mgr.reset_to_defaults()\n print(json.dumps({{'success': True, 'templates': mgr.templates}}))",
        payload.to_string()
    );
    run_python_helper(&script).await
}

async fn verify_flag(Json(payload): Json<FlagVerifyRequest>) -> Json<Value> {
    let script = format!(
        "import json; from ctf_toolkit.utils.flag_manager import get_flag_manager; mgr = get_flag_manager(); cand = {:?}; hits = mgr.extract_flags(cand); first = mgr.find_first_flag(cand); print(json.dumps({{'success': True, 'accepted': bool(first), 'match': first, 'all_matches': hits}}))",
        payload.candidate
    );
    run_python_helper(&script).await
}

async fn get_tools() -> Json<Value> {
    let script = r#"
import json, inspect
from ctf_toolkit.ui.palette import build_tool_catalog
catalog = build_tool_catalog()
summary = []
for t in catalog:
    try:
        sig = inspect.signature(t['func'])
        params = [
            {'n': p.name, 'd': '' if p.default is inspect.Parameter.empty else repr(p.default)[:40], 'req': p.default is inspect.Parameter.empty}
            for p in sig.parameters.values() if p.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
        ]
    except Exception:
        params = []
    summary.append({'name': t['name'], 'category': t['category'], 'module': t['module'], 'doc': (t.get('doc') or '').strip(), 'params': params})
print(json.dumps(summary))
"#;
    run_python_helper(script).await
}

async fn get_cheatsheets() -> Json<Value> {
    run_python_helper("import json; from ctf_toolkit.web.cheatsheets import get_web_cheatsheet; print(json.dumps(get_web_cheatsheet()))").await
}

async fn get_queue() -> Json<Value> {
    let script = r#"
import json
from ctf_toolkit.ui.palette import build_tool_catalog
by_cat = {}
for t in build_tool_catalog():
    top = t['category'].split('.')[0]
    by_cat.setdefault(top, []).append(t['name'])
payload = {'categories': [{'name': k, 'tools': sorted(v), 'count': len(v)} for k, v in sorted(by_cat.items())]}
print(json.dumps(payload))
"#;
    run_python_helper(script).await
}

async fn get_patterns() -> Json<Value> {
    Json(json!({
        "identify": [
            {"name": "identify_cipher_text", "doc": ""},
            {"name": "identify_hash_format", "doc": ""},
            {"name": "auto_decode_layers", "doc": ""},
            {"name": "caesar_bruteforce", "doc": ""},
            {"name": "xor_bruteforce_single", "doc": ""},
            {"name": "triage_data", "doc": ""},
            {"name": "solve_crypto_task", "doc": ""}
        ]
    }))
}

async fn handle_hub_solve(Json(payload): Json<HubSolveRequest>) -> Json<Value> {
    let script = format!(
        "import json; from ctf_toolkit.crypto.omni_solver import auto_solve_hub; text = {:?}; print(json.dumps(auto_solve_hub(text)))",
        payload.text
    );
    run_python_helper(&script).await
}

async fn handle_hub_rsa(Json(payload): Json<Value>) -> Json<Value> {
    let script = format!(
        r#"
import json
from ctf_toolkit.crypto.omni_solver import solve_rsa_intent
p = json.loads({:?})
def _to_int(k):
    v = p.get(k)
    return int(str(v).strip(), 0) if v is not None and str(v).strip() else None
primes_raw = p.get("primes")
primes_list = [int(x.strip(), 0) for x in str(primes_raw).split(",") if x.strip()] if primes_raw else None
res = solve_rsa_intent(
    raw_desc=p.get("raw_desc", ""),
    n=_to_int("n"), e=_to_int("e"), c=_to_int("c"),
    p=_to_int("p"), q=_to_int("q"), phi=_to_int("phi"), d=_to_int("d"),
    primes=primes_list
)
print(json.dumps(res))
"#,
        payload.to_string()
    );
    run_python_helper(&script).await
}

async fn handle_hub_classical(Json(payload): Json<Value>) -> Json<Value> {
    let script = format!(
        r#"
import json
from ctf_toolkit.crypto.omni_solver import solve_classical_intent
p = json.loads({:?})
res = solve_classical_intent(
    text=p.get("text", ""),
    operation=p.get("operation", "caesar"),
    key=p.get("key", ""),
    shift=int(p.get("shift", 3)),
    a=int(p.get("a", 1)),
    b=int(p.get("b", 0)),
    rails=int(p.get("rails", 3)),
    is_hex=bool(p.get("is_hex", False)),
)
print(json.dumps(res))
"#,
        payload.to_string()
    );
    run_python_helper(&script).await
}

async fn handle_hub_jwt(Json(payload): Json<Value>) -> Json<Value> {
    let script = format!(
        r#"
import json
from ctf_toolkit.crypto.omni_solver import solve_jwt_intent
p = json.loads({:?})
res = solve_jwt_intent(token=p.get("token", ""), extra_secret=p.get("extra_secret", ""))
print(json.dumps(res))
"#,
        payload.to_string()
    );
    run_python_helper(&script).await
}

async fn handle_hub_eccdh(Json(payload): Json<Value>) -> Json<Value> {
    let script = format!(
        r#"
import json
p = json.loads({:?})
mode = p.get("type", "dh")
def _to_int(k):
    v = p.get(k)
    return int(str(v).strip(), 0) if v is not None and str(v).strip() else None

if mode == "dh":
    from ctf_toolkit.crypto.dh_ecc_tool import diffie_hellman_compute
    p_v = _to_int("p")
    g_v = _to_int("g")
    if p_v is None or g_v is None:
        print(json.dumps({{"success": False, "error": "Parameters p and g required."}}))
    else:
        res = diffie_hellman_compute(p=p_v, g=g_v, A=_to_int("A"), B=_to_int("B"), a=_to_int("a"), b=_to_int("b"))
        print(json.dumps({{"success": True, "result": res}}))
elif mode == "ecc":
    from ctf_toolkit.crypto.dh_ecc_tool import ecc_point_operation
    res = ecc_point_operation(
        mode=p.get("mode", "mul"),
        a=_to_int("a") or 0, b=_to_int("b") or 0, p=_to_int("p") or 0,
        Px=_to_int("Px") or 0, Py=_to_int("Py") or 0, k=_to_int("k"),
        Qx=_to_int("Qx"), Qy=_to_int("Qy")
    )
    print(json.dumps({{"success": True, "result": res}}))
else:
    print(json.dumps({{"success": False, "error": f"Unknown mode {mode}"}}))
"#,
        payload.to_string()
    );
    run_python_helper(&script).await
}

async fn handle_call(Json(payload): Json<Value>) -> Json<Value> {
    let script = format!(
        r#"
import json, inspect
from ctf_toolkit.ui.palette import build_tool_catalog
from ctf_toolkit.ui.web_server import _coerce_param

p = json.loads({:?})
func_name = p.get("function", "").strip()
kwargs_dict = p.get("kwargs", {{}})
catalog = build_tool_catalog()
tool = next((t for t in catalog if t["name"] == func_name), None)
if not tool:
    print(json.dumps({{"success": False, "error": f"Function '{{func_name}}' not found."}}))
else:
    try:
        fn = tool["func"]
        sig = inspect.signature(fn)
        params = [p for p in sig.parameters.values() if p.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)]
        call_kwargs = {{}}
        for param in params:
            if param.name in kwargs_dict:
                call_kwargs[param.name] = _coerce_param(kwargs_dict[param.name], param)
            elif param.default != inspect.Parameter.empty:
                call_kwargs[param.name] = param.default
        res = fn(**call_kwargs)
        if isinstance(res, bytes):
            res_val = {{"hex": res.hex(), "utf8": res.decode("utf-8", errors="replace")}}
        else:
            res_val = res
        print(json.dumps({{"success": True, "function": func_name, "result": res_val}}))
    except Exception as e:
        print(json.dumps({{"success": False, "error": str(e)}}))
"#,
        payload.to_string()
    );
    run_python_helper(&script).await
}

async fn handle_writeup(Json(payload): Json<Value>) -> Json<Value> {
    let script = format!(
        r#"
import json
from pathlib import Path
from ctf_toolkit.utils.writeup_generator import DynamicWriteupGenerator

p = json.loads({:?})
out_folder = Path("/tmp/ctf_writeups")
out_folder.mkdir(parents=True, exist_ok=True)
wf, sf = DynamicWriteupGenerator.generate_writeup_and_solver(
    challenge_name=p.get("name", "Challenge"),
    category=p.get("category", "Crypto"),
    flag=p.get("flag", ""),
    steps=p.get("steps", []),
    output_dir=out_folder,
    points=int(p.get("points", 100))
)
print(json.dumps({{
    "success": True,
    "writeup_path": str(wf),
    "solver_path": str(sf),
    "writeup_md": wf.read_text(encoding="utf-8"),
    "solver_py": sf.read_text(encoding="utf-8"),
}}))
"#,
        payload.to_string()
    );
    run_python_helper(&script).await
}

async fn run_python_helper(py_code: &str) -> Json<Value> {
    let output = tokio::task::spawn_blocking({
        let code = py_code.to_string();
        move || {
            Command::new("/opt/ctf-toolkit/venv/bin/python")
                .arg("-c")
                .arg(code)
                .current_dir("/opt/ctf-toolkit")
                .output()
        }
    })
    .await;

    match output {
        Ok(Ok(out)) => {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if let Ok(val) = serde_json::from_str::<Value>(stdout.trim()) {
                    return Json(val);
                }
                Json(json!({ "success": true, "raw": stdout.trim() }))
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                error!("Python helper error: {}", stderr);
                Json(json!({ "success": false, "error": stderr.trim() }))
            }
        }
        Ok(Err(e)) => Json(json!({ "success": false, "error": e.to_string() })),
        Err(e) => Json(json!({ "success": false, "error": e.to_string() })),
    }
}
