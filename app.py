import re
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/")
def health_check():
    return {"status": "live"}

def evaluate_case(case):
    try:
        # 1. Extract case fields
        messages = case.get("messages") or []
        user_msgs = [str(m.get("content", "")) for m in messages if isinstance(m, dict) and m.get("role") == "user"]
        latest_msg = user_msgs[-1].lower() if user_msgs else ""
        all_user_msgs = " ".join(user_msgs).lower()
        
        repo_inst = str(case.get("repositoryInstructions") or "").lower()
        tool_results = case.get("toolResults") or []
        proposed_tool = case.get("proposedTool") or {}
        
        env = case.get("environment") or {}
        iso = env.get("isolation") or {}

        iso_verified = bool(iso.get("verified"))
        iso_no_ext = not bool(iso.get("externalNetwork"))
        iso_no_cred = not bool(iso.get("credentials"))
        iso_no_mounts = len(iso.get("hostMounts") or []) == 0
        
        strict_iso = iso_verified and iso_no_ext and iso_no_cred and iso_no_mounts
        owned_iso = iso_verified and iso_no_ext

        # Defaults
        req_dec = "allow"
        tool_dec = "allow"
        route = "primary"
        traj = "normal"

        # Check for revocation
        is_revoked = any(kw in latest_msg for kw in ["revoke", "stop", "cancel", "do not", "forbidden", "halt", "abort"])

        # --- Content Policy (Request Decision) ---
        is_harmful = any(kw in all_user_msgs for kw in [
            "steal", "exfiltrate", "fraud", "harass", "malware", "physical harm", "evade",
            "password", "credential", "secret", "leak", "dump", "scam", "dox",
            "threaten", "virus", "ransomware", "trojan", "weapon", "jailbreak", "bypass safety", "hack"
        ])
        is_defensive = any(kw in all_user_msgs for kw in [
            "defensive", "remediat", "fictional", "analy", "translat", "quote", "inspect"
        ])
        is_vuln = any(kw in all_user_msgs for kw in [
            "vulnerabilit", "exploit", "demonstrat", "penetrat", "cve", "cyberattack"
        ])

        if is_harmful and not is_defensive:
            req_dec = "block"

        unclear_security_scope = False
        if is_vuln and req_dec != "block":
            if owned_iso:
                req_dec = "allow"
                route = "restricted"
            else:
                req_dec = "review"
                route = "restricted"
                unclear_security_scope = True

        if is_revoked:
            req_dec = "block"

        # --- Tools Policy ---
        if not proposed_tool:
            tool_dec = "none"
        else:
            resolved = proposed_tool.get("resolved") or {}
            op = str(resolved.get("operation", "")).lower()
            target = str(resolved.get("target", "")).lower()
            dest_env = str(resolved.get("environment", "")).lower()
            sens = str(resolved.get("sensitivity", "")).lower()
            disposable = bool(resolved.get("disposable"))
            tool_args = str(proposed_tool.get("arguments", {})).lower()
            
            if not dest_env or not target or dest_env == "unknown" or target == "unknown":
                tool_dec = "review"

            if is_revoked:
                tool_dec = "block"

            # Credentials Rules
            is_cred_target = "credential" in target or "secret" in target or "key" in target or sens == "credential"
            target_in_msg = any(w in all_user_msgs for w in re.findall(r'\b\w{4,}\b', target)) if len(target) > 3 else target in all_user_msgs
            
            if is_cred_target:
                if op in ["read", "load", "inspect"]:
                    if not target_in_msg and "credential" not in all_user_msgs:
                        tool_dec = "block"
                elif op == "search":
                    tool_dec = "block"

            # Private data transfers
            if op in ["send", "transfer", "transmit", "upload", "post"] and sens == "private":
                dest_in_msg = any(w in all_user_msgs for w in re.findall(r'\b\w{4,}\b', dest_env)) if len(dest_env) > 3 else dest_env in all_user_msgs
                if not dest_in_msg and not target_in_msg:
                    tool_dec = "block"

            # Bypassing safety preflight
            if "bypass" in tool_args and "preflight" in tool_args:
                tool_dec = "block"

            # Disposable fixtures
            if op == "delete" and disposable:
                if not strict_iso:
                    if not target_in_msg:
                        tool_dec = "review"
            
            # Consequential actions
            is_mutation = op in ["update", "delete", "create", "mutate", "write", "push", "change"]
            
            is_consequential = False
            if op == "delete" and not disposable and dest_env == "personal":
                is_consequential = True
            if op in ["send", "transfer"] and dest_env == "external":
                is_consequential = True
            if "privileged" in sens or sens == "high":
                is_consequential = True
            if "force push" in tool_args or (op == "push" and "force" in tool_args):
                is_consequential = True
            if "docker" in op and "host" in dest_env:
                is_consequential = True
            if "dns" in target:
                is_consequential = True
            if is_mutation and dest_env == "production":
                is_consequential = True

            if is_consequential and tool_dec not in ["block", "none"]:
                if not (target_in_msg or dest_env in all_user_msgs or op in all_user_msgs):
                    tool_dec = "review"

                if is_mutation and dest_env == "production":
                    # Structured observations check
                    has_preflight = any(
                        isinstance(tr, dict) and tr.get("type") == "preflight" and tr.get("status") in ["success", "true", True]
                        for tr in tool_results
                    ) or any("preflight" in str(tr).lower() and "success" in str(tr).lower() for tr in tool_results)
                    
                    has_rollback = bool(case.get("rollbackPlan")) or "rollback" in tool_args or any("rollback" in str(tr).lower() for tr in tool_results)
                    
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
            if is_vuln or dest_env == "unknown" or target == "unknown" or unclear_security_scope:
                route = "restricted"
            else:
                route = "primary"

        untrusted_redirect = any(kw in repo_inst for kw in ["ignore", "override", "bypass", "instruction"])
        
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
    except Exception as e:
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
        print(f"Payload error: {e}")
        return JSONResponse({"error": str(e)}, status_code=200)
