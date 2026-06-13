#!/usr/bin/env python3
# ============================================================
#  NexusGuard AI — HTTP Bridge  (FastAPI)
#  AI Integration/ai_service.py
#
#  Exposes the Python AI pipeline (Layer 3 + 4) as an HTTP
#  microservice so the Node.js orchestrator can call it.
#
#  Run:
#    uvicorn ai_service:app --host 0.0.0.0 --port 8000 --reload
#
#  Endpoints:
#    GET  /health                    — Liveness probe
#    POST /api/ai/generate-patch     — Main: generate patch from scan report
#    POST /api/ai/generate-poc       — PoC exploit for a single vulnerability
# ============================================================

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Load .env from this directory
load_dotenv(Path(__file__).resolve().parent / ".env")

# ── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[NexusGuard AI-Service] %(asctime)s %(levelname)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("nexusguard.ai_service")

# ── Import AI pipeline modules ────────────────────────────────
from scripts.ai_patch_generator import generate_full_output, create_github_pr, notify_layer5_webhook
from scripts.ai_exploit_reproduction import generate_poc, generate_vulnerability_explanation

# ── FastAPI App ───────────────────────────────────────────────
app = FastAPI(
    title="NexusGuard AI Service",
    description="AI Patch Generator & Exploit Reproduction HTTP Bridge",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────
#  REQUEST / RESPONSE MODELS
# ─────────────────────────────────────────────────────────────

class SemgrepFinding(BaseModel):
    vulnerabilityName: str
    filePath: str
    lineNumber: int
    severity: str
    message: str


class SecretFinding(BaseModel):
    detectorName: str
    filePath: str
    raw: str
    verified: bool
    severity: str


class VulnerabilityReport(BaseModel):
    repoName: Optional[str] = None
    commitSha: Optional[str] = None
    scannedAt: Optional[str] = None
    vulnerabilities: List[Dict[str, Any]] = []
    secrets: List[Dict[str, Any]] = []
    summary: Optional[Dict[str, Any]] = None
    hasFindings: bool = False


class GeneratePatchRequest(BaseModel):
    vulnerabilityReport: VulnerabilityReport
    # Optional: if provided, the service will create a real GitHub PR
    repoFullName: Optional[str] = None
    # Optional: contributor wallet for blockchain submitPatch call
    contributorWalletAddress: Optional[str] = None


class SingleVulnRequest(BaseModel):
    tool_name: str
    file_path: str
    line_number: int
    vulnerability_type: str
    description: str
    vulnerable_code_snippet: str
    provider: Optional[str] = None


# ─────────────────────────────────────────────────────────────
#  HELPER: Convert orchestrator report → ai_patch_generator format
# ─────────────────────────────────────────────────────────────

def _pick_top_vulnerability(report: VulnerabilityReport) -> Optional[Dict[str, Any]]:
    """
    Selects the highest-severity finding from the scan report and
    converts it into the vuln_json format expected by ai_patch_generator.

    Priority: CRITICAL secrets > ERROR vulns > WARNING vulns > any vuln/secret
    """
    # Check secrets first (always CRITICAL)
    for secret in (report.secrets or []):
        return {
            "tool_name": secret.get("detectorName", "TruffleHog"),
            "file_path": secret.get("filePath", "unknown"),
            "line_number": 0,
            "vulnerability_type": "Secret / Credential Leak",
            "description": (
                f"A {secret.get('detectorName', 'secret')} credential was detected "
                f"in the repository. Verified: {secret.get('verified', False)}. "
                f"Redacted value: {secret.get('raw', '****')}"
            ),
            "vulnerable_code_snippet": f"# Leaked credential in {secret.get('filePath', 'unknown')}\n# Redacted: {secret.get('raw', '****')}",
        }

    # Then check static vulnerabilities by severity
    severity_order = {"ERROR": 0, "WARNING": 1, "INFO": 2, "UNKNOWN": 3}
    vulns = sorted(
        report.vulnerabilities or [],
        key=lambda v: severity_order.get((v.get("severity") or "UNKNOWN").upper(), 3),
    )

    for vuln in vulns:
        return {
            "tool_name": "Semgrep",
            "file_path": vuln.get("filePath", "unknown"),
            "line_number": vuln.get("lineNumber", 0),
            "vulnerability_type": vuln.get("vulnerabilityName", "Security Issue"),
            "description": vuln.get("message", "No description available."),
            "vulnerable_code_snippet": (
                f"# File: {vuln.get('filePath', 'unknown')} "
                f"(line {vuln.get('lineNumber', 0)})\n"
                f"# Rule: {vuln.get('vulnerabilityName', 'unknown')}\n"
                f"# Severity: {vuln.get('severity', 'UNKNOWN')}\n"
                f"{vuln.get('message', '')}"
            ),
        }

    return None


def _get_provider() -> str:
    """Return the configured LLM provider.

    Priority (in order):
      1. Groq     — free tier, generous limits, very fast (llama-3.3-70b)
      2. OpenAI   — gpt-4o-mini, needs billing credits
      3. Gemini   — free tier but strict daily limits
      4. Anthropic

    Override by setting DEFAULT_LLM_PROVIDER env var to any of the above.
    """
    override = os.getenv("DEFAULT_LLM_PROVIDER", "").lower()
    if override in ("groq", "openai", "gemini", "anthropic"):
        return override

    # Auto-detect: prefer Groq (free tier) → OpenAI → Gemini → Anthropic
    if os.getenv("GROQ_API_KEY"):
        return "groq"
    if os.getenv("OPENAI_API_KEY"):
        return "openai"
    if os.getenv("GOOGLE_API_KEY"):
        return "gemini"
    if os.getenv("ANTHROPIC_API_KEY"):
        return "anthropic"
    return "groq"  # will fail with clear error if no key is set


# ─────────────────────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Liveness probe — called by the orchestrator before sending patch requests."""
    provider = _get_provider()
    has_gemini = bool(os.getenv("GOOGLE_API_KEY"))
    has_openai = bool(os.getenv("OPENAI_API_KEY"))
    has_github = bool(os.getenv("GITHUB_TOKEN"))

    return {
        "status": "healthy",
        "service": "nexusguard-ai-service",
        "defaultProvider": provider,
        "capabilities": {
            "gemini": has_gemini,
            "openai": has_openai,
            "githubPrCreation": has_github,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/ai/generate-patch")
async def generate_patch_endpoint(body: GeneratePatchRequest):
    """
    Main integration endpoint — called by the Node.js orchestrator.

    Accepts the full vulnerability report from the scanner, picks the
    most severe finding, generates a patch + explanation via LLM, and
    optionally creates a GitHub PR and calls the blockchain layer.

    Returns:
        {
          "patchCode": "...",
          "explanation": "...",
          "prTitle": "...",
          "prBody": "...",
          "prUrl": null | "https://github.com/...",
          "prNumber": null | 42,
          "blockchain": null | { bountyStatus, txHash }
        }
    """
    report = body.vulnerabilityReport
    logger.info(
        "Patch request received — repo=%s, vulns=%d, secrets=%d",
        report.repoName,
        len(report.vulnerabilities),
        len(report.secrets),
    )

    if not report.hasFindings:
        raise HTTPException(
            status_code=400,
            detail="No findings in the vulnerability report. Nothing to patch.",
        )

    # ── Pick the top vulnerability ────────────────────────────
    top_vuln = _pick_top_vulnerability(report)
    if not top_vuln:
        raise HTTPException(
            status_code=422,
            detail="Could not extract a patchable vulnerability from the report.",
        )

    logger.info(
        "Top finding selected: %s in %s",
        top_vuln["vulnerability_type"],
        top_vuln["file_path"],
    )

    provider = _get_provider()

    # ── Generate patch via LLM ────────────────────────────────
    try:
        output = generate_full_output(top_vuln, provider=provider)
    except Exception as exc:
        logger.error("LLM patch generation failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"LLM patch generation failed: {exc}")

    patch_code = output.get("patched_code") or output.get("patchCode", "")
    explanation = output.get("explanation", "")
    pr_title = output.get("pr_title", f"Fix: Remediate {top_vuln['vulnerability_type']}")
    pr_body = output.get("pr_body", "")

    response: Dict[str, Any] = {
        "patchCode": patch_code,
        "explanation": explanation,
        "prTitle": pr_title,
        "prBody": pr_body,
        "prUrl": None,
        "prNumber": None,
        "blockchain": None,
        "vulnerability": top_vuln,
    }

    # ── Optionally create GitHub PR ───────────────────────────
    if body.repoFullName and os.getenv("GITHUB_TOKEN"):
        try:
            vuln_hash = hashlib.sha256(
                json.dumps(top_vuln, sort_keys=True).encode()
            ).hexdigest()[:8]
            branch = f"nexusguard/fix-{vuln_hash}"

            pr_result = create_github_pr(
                repo_full_name=body.repoFullName,
                branch_name=branch,
                file_path=top_vuln["file_path"],
                patched_code=patch_code,
                pr_title=pr_title,
                pr_body=pr_body,
            )
            response["prUrl"] = pr_result.get("pr_url")
            response["prNumber"] = pr_result.get("pr_number")
            logger.info("GitHub PR created: %s", pr_result.get("pr_url"))

            # ── Notify blockchain: submitPatch ────────────────
            backend_url = os.getenv("NEXUSGUARD_BACKEND_URL", "http://localhost:3000")
            webhook_secret = os.getenv("WEBHOOK_SECRET", "")
            contributor_wallet = (
                body.contributorWalletAddress
                or os.getenv("ORACLE_ADDRESS", "")
            )

            if webhook_secret and contributor_wallet:
                bug_id = f"NEXUS-{report.repoName or 'repo'}-{vuln_hash}"
                try:
                    blockchain_result = notify_layer5_webhook(
                        bug_id=bug_id,
                        contributor_wallet=contributor_wallet,
                        pr_number=pr_result.get("pr_number", 0),
                        repo_full_name=body.repoFullName,
                    )
                    response["blockchain"] = blockchain_result
                except Exception as bc_err:
                    logger.warning("Blockchain notify failed (non-fatal): %s", bc_err)

        except Exception as pr_err:
            logger.warning("GitHub PR creation failed (non-fatal): %s", pr_err)

    logger.info(
        "Patch generation complete. patchCode length=%d, prUrl=%s",
        len(patch_code),
        response.get("prUrl"),
    )
    return JSONResponse(content=response)


@app.post("/api/ai/generate-poc")
async def generate_poc_endpoint(body: SingleVulnRequest):
    """
    Generate a proof-of-concept exploit for a single vulnerability.
    Used by the Layer 3 pipeline independently.
    """
    vuln_json = body.dict()
    provider = body.provider or _get_provider()

    try:
        poc = generate_poc(vuln_json, provider=provider)
        explanation = generate_vulnerability_explanation(vuln_json, provider=provider)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"PoC generation failed: {exc}")

    return {
        "poc": poc,
        "explanation": explanation,
        "vulnerability": vuln_json,
    }


# ─────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.getenv("AI_SERVICE_PORT", "8000"))
    logger.info("Starting NexusGuard AI Service on port %d ...", port)
    uvicorn.run(
        "ai_service:app",
        host="0.0.0.0",
        port=port,
        reload=os.getenv("NODE_ENV") == "development",
        log_level="info",
    )
