import os
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

app = FastAPI(title="NexusGuard AI Service", version="1.0.0")

class Vulnerability(BaseModel):
    ruleId: Optional[str] = None
    message: Optional[str] = None
    severity: str
    path: Optional[str] = None
    line: Optional[int] = None

class Summary(BaseModel):
    totalVulnerabilities: int
    totalSecrets: int
    vulnBySeverity: Dict[str, int]

class VulnerabilityReport(BaseModel):
    repoUrl: str
    commitSha: str
    vulnerabilities: List[Vulnerability]
    summary: Summary

class PatchRequest(BaseModel):
    vulnerabilityReport: VulnerabilityReport
    repoFullName: Optional[str] = None
    contributorWalletAddress: Optional[str] = None

class PatchResponse(BaseModel):
    patchCode: str
    explanation: str
    prTitle: str
    prBody: str
    prUrl: Optional[str] = None
    prNumber: Optional[int] = None

@app.post("/api/ai/generate-patch", response_model=PatchResponse)
async def generate_patch(payload: PatchRequest):
    report = payload.vulnerabilityReport
    vulns = report.vulnerabilities
    
    if not vulns:
        raise HTTPException(status_code=400, detail="No vulnerability findings present in the report.")
    
    target_vuln = vulns[0]
    vuln_msg = target_vuln.message or "vulnerability detected"
    vuln_rule = target_vuln.ruleId or "security-rule"
    vuln_path = target_vuln.path or "unknown_file.js"
    vuln_line = target_vuln.line or 1

    # Simulate LangChain / custom LLM patch prompt synthesis:
    explanation = f"Root cause: Code snippet at {vuln_path}:{vuln_line} matches safety signature '{vuln_rule}'. Specifically: '{vuln_msg}'. Input validations were bypassed."
    
    # Generate mock diff based on rule check
    patch_code = (
      f"// AI Safe Patch suggestion for {vuln_path} line {vuln_line}\n"
      f"// Mitigates: {vuln_msg}\n"
      f"+ function sanitizeAndValidateInput(input) {{\n"
      f"+   if (!input || typeof input !== 'string') return '';\n"
      f"+   return input.replace(/[<>]/g, ''); // Simple XSS Sanitization\n"
      f"+ }}\n"
    )

    pr_title = f"security: automatic AI patch for {vuln_rule}"
    pr_body = (
        f"### NexusGuard AI Patches\n"
        f"This automated PR resolves a high severity vulnerability detected in commit `{report.commitSha[:8]}`.\n\n"
        f"**Finding details:**\n"
        f"- **Rule ID:** {vuln_rule}\n"
        f"- **File:** `{vuln_path}:{vuln_line}`\n"
        f"- **Severity:** {target_vuln.severity}\n\n"
        f"**Suggested fix:**\n"
        f"```javascript\n"
        f"{patch_code}\n"
        f"```"
    )

    # If repoFullName and credentials are set, simulate automatic push and PR release
    mock_pr_num = 101
    mock_pr_url = f"https://github.com/{payload.repoFullName or 'dummy-org/dummy-repo'}/pull/{mock_pr_num}"

    return PatchResponse(
        patchCode=patch_code,
        explanation=explanation,
        prTitle=pr_title,
        prBody=pr_body,
        prUrl=mock_pr_url,
        prNumber=mock_pr_num
    )

@app.get("/health")
async def health():
    return {"status": "ok", "service": "python-ai-service"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
