#!/usr/bin/env python3
# ============================================================
#  NexusGuard AI — Layer 4: AI Patch Generator
#  scripts/ai_patch_generator.py
#
#  Generates secure code patches from vulnerability findings,
#  explains fixes, and auto-creates GitHub Pull Requests.
# ============================================================

"""
Layer 4 — AI Patch Generator

Capabilities:
  1. Code fix suggestion via LLM
  2. Patch explanation ("why this fix works")
  3. Auto PR creation on GitHub with the patch
  4. Developer review trigger
  5. Webhook integration with Layer 5 (blockchain bounty)
"""

import hashlib
import hmac
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
import yaml
from dotenv import load_dotenv

# Load .env from project root
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# ── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[NexusGuard L4] %(asctime)s %(levelname)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("nexusguard.layer4")


# ─────────────────────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────────────────────
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "ai_config.yaml"


def load_config(config_path: str = str(CONFIG_PATH)) -> dict:
    """Load AI configuration from YAML."""
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ─────────────────────────────────────────────────────────────
#  LLM PROVIDER (shared abstraction)
# ─────────────────────────────────────────────────────────────
class LLMProvider:
    """Unified interface for LLM patch generation."""

    def __init__(self, provider: str = "openai"):
        self.provider = provider
        self.config = load_config()
        provider_cfg = self.config.get("llm", {}).get(provider, {})
        self.api_key = os.getenv(provider_cfg.get("api_key_env", ""))
        self.model = provider_cfg.get("model", "gpt-4")
        self.temperature = provider_cfg.get("temperature", 0.1)
        self.max_tokens = provider_cfg.get("max_tokens", 2048)

        if not self.api_key:
            raise RuntimeError(
                f"Missing API key. Set '{provider_cfg.get('api_key_env')}' env var."
            )

    def invoke(self, prompt: str) -> str:
        """Send a prompt to the configured LLM and return the text response."""
        if self.provider == "openai":
            from langchain_openai import ChatOpenAI
            llm = ChatOpenAI(
                model=self.model,
                openai_api_key=self.api_key,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
        elif self.provider == "groq":
            # Groq uses the OpenAI-compatible API — free tier, very fast
            from langchain_openai import ChatOpenAI
            llm = ChatOpenAI(
                model=self.model,
                openai_api_key=self.api_key,
                base_url="https://api.groq.com/openai/v1",
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
        elif self.provider == "anthropic":
            from langchain_anthropic import ChatAnthropic
            llm = ChatAnthropic(
                model=self.model,
                anthropic_api_key=self.api_key,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
        elif self.provider == "gemini":
            from langchain_google_genai import ChatGoogleGenerativeAI
            llm = ChatGoogleGenerativeAI(
                model=self.model,
                google_api_key=self.api_key,
                temperature=self.temperature,
                max_output_tokens=self.max_tokens,
            )
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

        response = llm.invoke(prompt)
        return response.content.strip()


# ─────────────────────────────────────────────────────────────
#  1. AI CODE FIX SUGGESTION
# ─────────────────────────────────────────────────────────────
PATCH_PROMPT = """You are a senior secure-code reviewer.

Given the vulnerability details below, provide a **secure, functional replacement** for the vulnerable code. The patch must:
- Fix the vulnerability completely
- Not break existing functionality
- Not introduce new vulnerabilities
- Follow the language's best practices and idioms

### Vulnerability Details
- **Type:** {vulnerability_type}
- **File:** {file_path}
- **Line:** {line_number}
- **Tool:** {tool_name}
- **Description:** {description}

### Vulnerable Code
```
{vulnerable_code_snippet}
```

Respond in EXACTLY this JSON format (no markdown fences):
{{
  "patched_code": "<the complete corrected code>",
  "explanation": "<technical explanation of why the original was vulnerable and how the patch fixes it>"
}}"""


def generate_patch(vuln_json: dict, provider: str = "openai") -> dict:
    """Use an LLM to generate a secure code patch.

    Args:
        vuln_json: Vulnerability payload dictionary.
        provider:  LLM backend ("openai" or "anthropic").
    Returns:
        Dict with keys 'patched_code' and 'explanation'.
    """
    logger.info(
        "Generating patch for %s in %s:%s",
        vuln_json.get("vulnerability_type"),
        vuln_json.get("file_path"),
        vuln_json.get("line_number"),
    )

    llm = LLMProvider(provider)
    prompt = PATCH_PROMPT.format(**vuln_json)
    raw = llm.invoke(prompt)

    # Strip markdown code fences if present
    if raw.startswith("```"):
        lines = raw.splitlines()
        lines = [l for l in lines if not l.strip().startswith("```")]
        raw = "\n".join(lines)

    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("LLM returned non-JSON; wrapping raw output.")
        result = {"patched_code": raw, "explanation": "Auto-generated patch."}

    logger.info("Patch generated (%d chars)", len(result.get("patched_code", "")))
    return result


# ─────────────────────────────────────────────────────────────
#  2. PATCH EXPLANATION
# ─────────────────────────────────────────────────────────────
EXPLAIN_PROMPT = """You are writing a Pull Request description for a security fix.

### Original Vulnerable Code
```
{vulnerable_code_snippet}
```

### Patched Code
```
{patched_code}
```

### Vulnerability Type
{vulnerability_type}

Write a clear, concise explanation (2–3 paragraphs) covering:
1. **Why the original code was vulnerable** — root cause and attack vector.
2. **How the patch resolves it** — the specific secure pattern applied.
3. **What developers should watch for** — similar patterns elsewhere in the codebase."""


def generate_explanation(vuln_json: dict, patched_code: str, provider: str = "openai") -> str:
    """Generate a detailed human-readable explanation of the fix."""
    logger.info("Generating patch explanation...")
    llm = LLMProvider(provider)
    prompt = EXPLAIN_PROMPT.format(
        vulnerable_code_snippet=vuln_json.get("vulnerable_code_snippet", ""),
        patched_code=patched_code,
        vulnerability_type=vuln_json.get("vulnerability_type", ""),
    )
    return llm.invoke(prompt)


# ─────────────────────────────────────────────────────────────
#  3. GITHUB PR CREATION
# ─────────────────────────────────────────────────────────────
def format_pr(vuln_json: dict, patch_result: dict, explanation: str) -> dict:
    """Format the PR title and body for GitHub.

    Returns:
        Dict with 'pr_title' and 'pr_body'.
    """
    vuln_type = vuln_json.get("vulnerability_type", "Security Issue")
    file_path = vuln_json.get("file_path", "unknown")
    tool_name = vuln_json.get("tool_name", "scanner")

    pr_title = f"Fix: Remediate {vuln_type} in `{file_path}`"

    pr_body = f"""## 🛡️ Security Patch — NexusGuard AI

**Vulnerability:** {vuln_type}
**File:** `{file_path}` (line {vuln_json.get('line_number', '?')})
**Detected by:** {tool_name}

---

### Description
{vuln_json.get('description', '')}

### Vulnerable Code
```
{vuln_json.get('vulnerable_code_snippet', '')}
```

### Patched Code
```
{patch_result.get('patched_code', '')}
```

---

### Why This Fix Works
{explanation}

---

### Patch Explanation
{patch_result.get('explanation', '')}

---

> ⚠️ **Reviewer:** Please verify the patch does not break existing tests
> before merging. Once merged, the NexusGuard bounty will be released
> automatically via the Layer 5 Oracle.

*This PR was generated automatically by NexusGuard AI — Layer 4.*
"""
    return {"pr_title": pr_title, "pr_body": pr_body}


def create_github_pr(
    repo_full_name: str,
    branch_name: str,
    file_path: str,
    patched_code: str,
    pr_title: str,
    pr_body: str,
    base_branch: str = "main",
    reviewers: Optional[list] = None,
) -> dict:
    """Create a Pull Request on GitHub using the GitHub REST API.

    Steps:
      1. Get the SHA of the base branch HEAD.
      2. Create a new branch from the base.
      3. Update (or create) the file with the patched code.
      4. Open a PR from the new branch to base.
      5. Request reviewers (optional).

    Args:
        repo_full_name: "owner/repo" format.
        branch_name: Name for the patch branch.
        file_path: Relative path of the file to patch.
        patched_code: The new file content.
        pr_title: Title of the PR.
        pr_body: Markdown body of the PR.
        base_branch: The branch to merge into (default: main).
        reviewers: Optional list of GitHub usernames to request reviews from.
    Returns:
        Dict with PR URL and number.
    """
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN environment variable is not set.")

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    api = f"https://api.github.com/repos/{repo_full_name}"

    logger.info("Creating PR on %s ...", repo_full_name)

    # ── Step 1: Get base branch SHA ─────────────────────────
    resp = requests.get(f"{api}/git/ref/heads/{base_branch}", headers=headers, timeout=15)
    resp.raise_for_status()
    base_sha = resp.json()["object"]["sha"]
    logger.info("Base branch '%s' SHA: %s", base_branch, base_sha[:10])

    # ── Step 2: Create patch branch ─────────────────────────
    resp = requests.post(
        f"{api}/git/refs",
        headers=headers,
        json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
        timeout=15,
    )
    if resp.status_code == 422:
        logger.warning("Branch '%s' already exists; continuing.", branch_name)
    else:
        resp.raise_for_status()
        logger.info("Created branch: %s", branch_name)

    # ── Step 3: Get current file (if exists) for its SHA ────
    file_sha = None
    resp = requests.get(
        f"{api}/contents/{file_path}",
        headers=headers,
        params={"ref": branch_name},
        timeout=15,
    )
    if resp.status_code == 200:
        file_sha = resp.json().get("sha")

    # ── Step 4: Create or update the file ───────────────────
    import base64

    payload = {
        "message": f"fix: {pr_title}",
        "content": base64.b64encode(patched_code.encode()).decode(),
        "branch": branch_name,
    }
    if file_sha:
        payload["sha"] = file_sha

    resp = requests.put(
        f"{api}/contents/{file_path}",
        headers=headers,
        json=payload,
        timeout=15,
    )
    resp.raise_for_status()
    logger.info("File '%s' updated on branch '%s'.", file_path, branch_name)

    # ── Step 5: Open Pull Request ───────────────────────────
    pr_payload = {
        "title": pr_title,
        "body": pr_body,
        "head": branch_name,
        "base": base_branch,
    }
    resp = requests.post(f"{api}/pulls", headers=headers, json=pr_payload, timeout=15)
    resp.raise_for_status()
    pr_data = resp.json()
    pr_url = pr_data["html_url"]
    pr_number = pr_data["number"]
    logger.info("✅ PR #%d created: %s", pr_number, pr_url)

    # ── Step 6: Request reviewers (optional) ────────────────
    if reviewers:
        requests.post(
            f"{api}/pulls/{pr_number}/requested_reviewers",
            headers=headers,
            json={"reviewers": reviewers},
            timeout=15,
        )
        logger.info("Requested reviews from: %s", ", ".join(reviewers))

    return {"pr_url": pr_url, "pr_number": pr_number, "branch": branch_name}


# ─────────────────────────────────────────────────────────────
#  4. LAYER 5 WEBHOOK INTEGRATION (submitPatch → blockchain)
# ─────────────────────────────────────────────────────────────
def notify_layer5_webhook(
    bug_id: str,
    contributor_wallet: str,
    pr_number: int,
    repo_full_name: str,
) -> dict:
    """Notify the Layer 5 Oracle backend that a patch PR was merged.

    Computes the HMAC-SHA256 signature as required by the webhook endpoint
    and sends the release-bounty request.
    """
    backend_url = os.getenv("NEXUSGUARD_BACKEND_URL", "http://localhost:3000")
    webhook_secret = os.getenv("WEBHOOK_SECRET", "")

    if not webhook_secret:
        raise RuntimeError("WEBHOOK_SECRET environment variable is not set.")

    payload = {
        "bugId": bug_id,
        "contributorWalletAddress": contributor_wallet,
        "prNumber": pr_number,
        "repositoryFullName": repo_full_name,
    }
    body = json.dumps(payload, separators=(",", ":"))
    signature = "sha256=" + hmac.new(
        webhook_secret.encode(), body.encode(), hashlib.sha256
    ).hexdigest()

    logger.info("Notifying Layer 5 Oracle — bugId=%s, PR=#%d", bug_id, pr_number)

    resp = requests.post(
        f"{backend_url}/api/web3/webhook/merge",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-NexusGuard-Signature": signature,
        },
        timeout=60,
    )
    data = resp.json()

    if data.get("success"):
        logger.info("✅ Bounty released! Tx: %s", data.get("explorerUrl"))
    else:
        logger.error("❌ Bounty release failed: %s", data.get("error"))

    return data


# ─────────────────────────────────────────────────────────────
#  5. FULL PIPELINE OUTPUT (JSON format for automation)
# ─────────────────────────────────────────────────────────────
def generate_full_output(vuln_json: dict, provider: str = "openai") -> dict:
    """Run the full Layer 4 pipeline and return the JSON output.

    This is the primary function to call from other modules or CI.

    Returns:
        A dict matching the NexusGuard AI output schema:
        {
          "patched_code": "...",
          "explanation": "...",
          "pr_title": "Fix: ...",
          "pr_body": "## Security Patch\\n..."
        }
    """
    # Step 1 — Generate patch
    patch_result = generate_patch(vuln_json, provider)

    # Step 2 — Generate detailed explanation
    explanation = generate_explanation(
        vuln_json, patch_result["patched_code"], provider
    )

    # Step 3 — Format PR
    pr_info = format_pr(vuln_json, patch_result, explanation)

    return {
        "patched_code": patch_result["patched_code"],
        "explanation": patch_result["explanation"],
        "pr_title": pr_info["pr_title"],
        "pr_body": pr_info["pr_body"],
    }


# ─────────────────────────────────────────────────────────────
#  CLI ENTRYPOINT
# ─────────────────────────────────────────────────────────────
def main(
    json_input_path: str = "vulnerability.json",
    provider: str = "openai",
    repo: Optional[str] = None,
    create_pr: bool = False,
):
    """Full Layer 4 pipeline: Patch → Explain → PR → Webhook."""
    logger.info("═══ NexusGuard AI — Layer 4 Pipeline ═══")

    with open(json_input_path, "r", encoding="utf-8") as f:
        vuln = json.load(f)

    output = generate_full_output(vuln, provider)

    # Print the structured JSON output
    print(json.dumps(output, indent=2))

    # Optionally create the actual GitHub PR
    if create_pr and repo:
        vuln_hash = hashlib.sha256(
            json.dumps(vuln, sort_keys=True).encode()
        ).hexdigest()[:8]
        branch = f"nexusguard/fix-{vuln_hash}"

        pr_result = create_github_pr(
            repo_full_name=repo,
            branch_name=branch,
            file_path=vuln["file_path"],
            patched_code=output["patched_code"],
            pr_title=output["pr_title"],
            pr_body=output["pr_body"],
        )
        logger.info("PR created: %s", pr_result["pr_url"])

    logger.info("═══ Layer 4 Pipeline Complete ═══")
    return output


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="NexusGuard AI — Layer 4 Patch Generator")
    parser.add_argument("--input", default="vulnerability.json", help="Path to vulnerability JSON")
    parser.add_argument("--provider", default="gemini", choices=["openai", "anthropic", "gemini"], help="LLM provider")
    parser.add_argument("--repo", default=None, help="GitHub repo (owner/name) for PR creation")
    parser.add_argument("--create-pr", action="store_true", help="Actually create the PR on GitHub")
    args = parser.parse_args()
    main(args.input, args.provider, args.repo, args.create_pr)
