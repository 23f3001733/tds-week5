from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/")
@app.head("/")
def health_check():
    return {"status": "live"}

def evaluate_case(case):
    try:
        # Default Decisions
        req_dec = "allow"
        tool_dec = "allow"
        route = "primary"
        traj = "normal"
        unclear_scope = False

        # 1. Safely extract all required fields
        messages = case.get("messages") or []
        user_msgs = [str(m.get("content", "")) for m in messages if isinstance(m, dict) and m.get("role") == "user"]
        latest_msg = user_msgs[-1].lower() if user_msgs else ""
        all_user_text = " ".join(user_msgs).lower()

        repo_insts = case.get("repositoryInstructions") or []
        repo_text = " ".join([str(r) for r in repo_insts]).lower()

        tool_results = case.get("toolResults") or []
        proposed = case.get("proposedTool") or {}
        resolved = proposed.get("resolved") or {}
        args = proposed.get("arguments") or {}
        rollback_plan = case.get("rollbackPlan")

        env = case.get("environment") or {}
        iso = env.get("isolation") or {}

        # Isolation checks
        iso_ver = bool(iso.get("verified"))
        iso_ext = bool(iso.get("externalNetwork"))
        iso_cred = bool(iso.get("credentials"))
        iso_mounts = bool(iso.get("hostMounts"))
        
        owned_isolated = iso_ver and not iso_ext
        strict_isolated = iso_ver and not iso_ext and not iso_cred and not iso_mounts

        # --- 2. Content Policy (req_dec) ---
        harmful_kws = ["steal", "exfiltrat", "fraud", "harass", "malware", "physical harm", "evade safeguard", "ransomware", "virus"]
        defensive_kws = ["defensive", "remediat", "fictional", "analy", "translat", "quote", "inspect", "explain", "mitigat"]
        vuln_kws = ["vulnerabilit", "exploit", "demonstrat", "penetrat", "cve", "cyberattack"]
        revoke_kws = ["revoke", "stop", "cancel", "do not", "forbidden", "halt", "abort"]

        is_harmful = any(kw in all_user_text for kw in harmful_kws)
        is_defensive = any(kw in all_user_text for kw in defensive_kws)
        is_vuln = any(kw in all_user_text for kw in vuln_kws)
        is_revoked = any(kw in latest_msg for kw in revoke_kws)

        if is_harmful and not is_defensive:
            req_dec = "block"
        
        if is_revoked:
            req_dec = "block"
            
        if is_vuln and req_dec != "block":
            if owned_isolated:
                route = "restricted"
            else:
                req_dec = "review"
                route = "restricted"
                unclear_scope = True

        # --- 3. Tools Policy (tool_dec) ---
        if not proposed:
            tool_dec = "none"
        else:
            op = str(resolved.get("operation", "")).lower()
            target = str(resolved.get("target", "")).lower()
            dest = str(resolved.get("environment", "")).lower()
            sens = str(resolved.get("sensitivity", "")).lower()
            disposable = bool(resolved.get("disposable"))
            
            args_str = str(args).lower()
            
            # Missing context
            if not dest or dest == "unknown" or not target or target == "unknown":
                tool_dec = "review"
                unclear_scope = True
                
            # Safety bypass
            if "bypass" in args_str and "preflight" in args_str:
                tool_dec = "block"
                
            # Credentials logic
            is_cred = "credential" in target or "secret" in target or sens == "credential" or "key" in target
            if is_cred:
                if op == "search":
                    tool_dec = "block"
                elif op in ["read", "load", "inspect"]:
                    if "credential" not in all_user_text and "secret" not in all_user_text:
                        tool_dec = "block"
            
            # Private data transfers
            if sens == "private" and op in ["send", "transfer", "upload", "post"]:
                if dest not in all_user_text and "external" not in all_user_text:
                    tool_dec = "block"
                    
            # Disposable fixtures
            if op == "delete" and disposable:
                if not strict_isolated and target not in all_user_text:
                    tool_dec = "review"
            
            # Consequential Mutations
            mutations = ["update", "delete", "create", "mutate", "write", "push", "change"]
            is_mut = op in mutations
            
            is_conseq = False
            if op == "delete" and dest == "personal" and not disposable: is_conseq = True
            if op in ["send", "transfer"] and dest == "external": is_conseq = True
            if sens == "privileged" or "privileged" in sens: is_conseq = True
            if is_mut and dest == "production": is_conseq = True
            if "force push" in args_str or (op == "push" and "force" in args_str): is_conseq = True
            if "docker" in op and dest == "host": is_conseq = True
            if "dns" in target or "dns" in args_str: is_conseq = True
            
            if is_conseq and tool_dec not in ["block", "none"]:
                # Requires explicit user authorization
                is_auth = any(kw in all_user_text for kw in [op, dest, "production", "personal", "external", "docker", "dns", "force push"])
                if not is_auth:
                    tool_dec = "review"
                
                # Production mutation preflight & rollback rules
                if is_mut and dest == "production" and tool_dec != "block":
                    has_preflight = False
                    for tr in tool_results:
                        if isinstance(tr, dict) and tr.get("type") == "preflight" and str(tr.get("status")).lower() in ["success", "true", "passed"]:
                            has_preflight = True
                        elif isinstance(tr, str) and "preflight" in tr.lower() and "success" in tr.lower():
                            has_preflight = True
                            
                    has_rollback = bool(rollback_plan) or "rollback" in args_str or any("rollback" in str(tr).lower() for tr in tool_results)
                    
                    if not (has_preflight and has_rollback):
                        tool_dec = "review"
                        
            if is_revoked:
                tool_dec = "block"

        # --- 4. Cascading Engine ---
        if req_dec == "block":
            tool_dec = "block" if proposed else "none"
            route = "none"
        elif req_dec == "review":
            if tool_dec not in ["block", "none"]:
                tool_dec = "review"
                
        if req_dec != "block":
            if is_vuln or unclear_scope:
                route = "restricted"
            else:
                route = "primary"
                
        # Untrusted Redirect Detection
        untrusted_redirect = any(kw in repo_text for kw in ["ignore", "override", "bypass"])
        
        # --- 5. Trajectory Mapping ---
        if req_dec == "block" or tool_dec == "block":
            traj = "intervene"
        elif req_dec == "review" or tool_dec == "review" or route == "restricted" or untrusted_redirect:
            traj = "watch"
        else:
            traj = "normal"
            
        return {
            "caseId": case.get("caseId", "unknown"),
            "requestDecision": req_dec,
            "toolDecision": tool_dec,
            "route": route,
            "trajectory": traj
        }
        
    except Exception as e:
        # Prevents any 500 error from failing the batch
        return {
            "caseId": case.get("caseId", "unknown") if isinstance(case, dict) else "unknown",
            "requestDecision": "review",
            "toolDecision": "review",
            "route": "restricted",
            "trajectory": "watch"
        }

@app.post("/")
@app.post("/classify")
async def classify_batch(request: Request):
    try:
        payload = await request.json()
        cases = payload.get("cases") or []
        results = [evaluate_case(case) for case in cases]
        return JSONResponse({
            "profile": payload.get("profile", "agent-harness-2026-09"),
            "batchId": payload.get("batchId"),
            "results": results
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=200)
