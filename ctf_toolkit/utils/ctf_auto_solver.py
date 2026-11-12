from __future__ import annotations

from ctf_toolkit.crypto.auto_solver import extract_flag, solve_crypto_task


def solve_challenge_text(desc: str) -> str | None:
    """Unified automated challenge solver combining crypto heuristics and flag extraction."""
    # 1. Primary: Omni-solver auto hub (universal entrypoint)
    try:
        from ctf_toolkit.crypto.omni_solver import auto_solve_hub
        hub_res = auto_solve_hub(desc)
        if hub_res.get("flags_found"):
            return hub_res["flags_found"][0]["flag"]
        best = hub_res.get("best_result")
        if best and isinstance(best, str) and "{" in best and "}" in best:
            return best.strip()
    except Exception:
        pass

    # 2. Secondary: AST-tracer & cascade on inline python scripts
    if "def " in desc or "import " in desc or "pow(" in desc:
        try:
            from ctf_toolkit.crypto.ast_tracer import infer_params, plan_from, trace_source
            from ctf_toolkit.crypto.cascade import run_cascade
            tr = trace_source(desc)
            if tr.categories:
                res = infer_params(tr, desc)
                report = {
                    "script": "inline",
                    "trace": tr.as_dict(),
                    "params": res["params"],
                    "notes": res["notes"],
                    "verified": res["verified"],
                    "plan": plan_from(tr, res["params"]),
                    "_output_text": desc,
                }
                c_res = run_cascade(report, total_seconds=10.0)
                if c_res.flag:
                    return c_res.flag
        except Exception:
            pass

    return solve_crypto_task(desc)
