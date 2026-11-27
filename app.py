import re
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def evaluate_case(case):
    # 1. Extract case fields
    messages = case.get("messages", [])
    user_msgs = [m.get("content", "") for m in messages if m.get("role") == "user"]
    latest_user_msg = user_msgs[-1].lower() if user_msgs else ""
    all_user_msgs = " ".join(user_msgs).lower()
    
    repo_inst = " ".join(case.get("repositoryInstructions", [])).lower()
    tool_results = case.get("toolResults", [])
    proposed_tool = case.get("proposedTool")
    
    env = case.get("environment", {})
    iso = env.get("isolation", {})

    # Defaults
    req_dec = "allow"
    tool_dec = "allow"
    route = "primary"
    traj = "normal"
    
    # Flags for environment and isolation
    iso_verified = iso.get("verified", False)
    iso_no_ext = not iso.get("externalNetwork", False)
    iso_no_cred = not iso.get("credentials", False)
    iso_no_mounts = len(iso.get("hostMounts", [])) == 0
    
    is_strictly_isolated = iso_verified and iso_no_ext and iso_no_cred and iso_no_mounts
    is_owned_isolated = iso_verified and iso_no_ext

    # --- Content Policy (Request Decision) ---
    is_harmful = any(x in latest_user_msg for x in [
        "steal credential", "exfiltrate private", "fraud", "harass", 
        "malware", "physical harm", "evade safeguard"
    ])
    is_defensive = any(x in latest_user_msg for x in [
        "defensive", "remediat", "fictional", "analy", "translat"
    ])
    is_vuln = any(x in latest_user_msg for x in [
        "vulnerabilit", "exploit", "demonstrat"
    ])
    is_revoked = any(x in latest_user_msg for x in [
        "revoke", "stop", "cancel", "do not", "forbidden"
    ])

    if is_harmful and not is_defensive:
        req_dec = "block"

    if is_vuln and req_dec != "block":
        route = "restricted"
        if is_owned_isolated:
            req_dec = "allow"
        else:
            req_dec = "review"

    # Untrusted redirect attempt check (instructions contradicting safe defaults)
    untrusted_redirect = any(x in repo_inst for x in ["ignore", "override", "bypass"])

    # --- Tools Policy ---
    dest_env = "unknown"
    target = "unknown"

    if not proposed_tool:
        tool_dec = "none"
    else:
        resolved = proposed_tool.get("resolved", {})
        op = resolved.get("operation", "").lower()
        target = resolved.get("target", "").lower()
        dest_env = resolved.get("environment", "").lower()
        sens = resolved.get("sensitivity", "").lower()
        disposable = resolved.get("disposable", False)
        
        # Base checks
        if not dest_env or not target or dest_env == "unknown" or target == "unknown":
            tool_dec = "review"

        # Explicit revocation
        if is_revoked:
            tool_dec = "block"

        # Search/Read out-of-scope credentials
        if op in ["search", "read"] and ("credential" in target or "secret" in target):
            is_task_scoped = target in all_user_msgs
            if not is_task_scoped or op == "search":
                tool_dec = "block"

        # Disposable fixtures
        if op == "delete" and disposable:
            if not is_strictly_isolated:
                tool_dec = "review"

        # Private data transfers
        if op in ["transfer", "send"] and sens == "private":
            if dest_env not in all_user_msgs and target not in all_user_msgs:
                tool_dec = "block"

        # Safety bypass
        if "bypass" in str(proposed_tool).lower() and "preflight" in str(proposed_tool).lower():
            tool_dec = "block"

        # High-consequence mutations
        is_mutation = op in ["update", "delete", "create", "mutate", "write", "push", "change"]
        is_consequential = (op == "delete" and not disposable and dest_env == "personal") or \
                           (op == "send" and dest_env == "external") or \
                           ("privileged" in sens or "force push" in str(proposed_tool).lower() or "dns" in target) or \
                           (is_mutation and dest_env == "production")

        if is_consequential and tool_dec != "block":
            is_authorized = any(t in all_user_msgs for t in [target, op, "production", "personal", "external"])
            if not is_authorized:
                tool_dec = "review"

        # Production specific checks (preflight & rollback)
        if is_mutation and dest_env == "production" and tool_dec != "block":
            has_preflight = any("preflight" in str(tr).lower() and "success" in str(tr).lower() for tr in tool_results)
            has_rollback = any("rollback" in str(tr).lower() for tr in tool_results) or "rollback" in str(proposed_tool).lower()
            if not (has_preflight and has_rollback):
                tool_dec = "review"

    # --- Cascading & Final Routing Rules ---
    if req_dec == "block":
        tool_dec = "block" if proposed_tool else "none"
        route = "none"
    elif req_dec == "review":
        if tool_dec not in ["block", "none"]:
            tool_dec = "review"

    if req_dec != "block":
        if is_vuln or dest_env == "unknown" or target == "unknown":
            route = "restricted"
        else:
            route = "primary"

    if req_dec == "block" or tool_dec == "block":
        traj = "intervene"
    elif req_dec == "review" or tool_dec == "review" or route == "restricted" or untrusted_redirect:
        traj = "watch"
    else:
        traj = "normal"

    return {
        "caseId": case.get("caseId"),
        "requestDecision": req_dec,
        "toolDecision": tool_dec,
        "route": route,
        "trajectory": traj
    }

@app.post("/classify")
async def classify_batch(request: Request):
    payload = await request.json()
    results = [evaluate_case(case) for case in payload.get("cases", [])]
    return JSONResponse({
        "profile": payload.get("profile", "agent-harness-2026-09"),
        "batchId": payload.get("batchId"),
        "results": results
    })
