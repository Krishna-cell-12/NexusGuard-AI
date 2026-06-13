/**
 * NexusGuard AI — Security Scanner
 *
 * Clones a git repository into a temp directory, then runs Semgrep
 * and TruffleHog in parallel. Combines both outputs into a single
 * structured report. The temp directory is always cleaned up,
 * regardless of success or failure.
 *
 * Prerequisites (must be available on PATH):
 *   - git
 *   - semgrep  (pip install semgrep)
 *   - trufflehog (brew/pip install trufflehog, or GitHub releases)
 */

import { exec } from "child_process";
import { promisify } from "util";
import { rm, mkdtemp } from "fs/promises";
import { join } from "path";
import { tmpdir } from "os";

const execAsync = promisify(exec);

// ─── Constants ────────────────────────────────────────────────────────────────

/** Maximum time (ms) to wait for any single shell command. */
const EXEC_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

/** Maximum bytes of stdout we will buffer (prevents OOM on huge repos). */
const EXEC_MAX_BUFFER = 50 * 1024 * 1024; // 50 MB

// ─── Internal Helpers ─────────────────────────────────────────────────────────

/**
 * Runs a shell command and returns its stdout string.
 * Throws a structured error on non-zero exit, including the stderr text.
 *
 * @param {string} command  - The shell command to execute.
 * @param {string} cwd      - Working directory for the command.
 * @returns {Promise<string>} stdout
 */
async function runCommand(command, cwd) {
  try {
    const { stdout } = await execAsync(command, {
      cwd,
      timeout: EXEC_TIMEOUT_MS,
      maxBuffer: EXEC_MAX_BUFFER,
    });
    return stdout;
  } catch (err) {
    // Attach the cwd and command for easier upstream debugging.
    const enhanced = new Error(
      `Command failed: ${command}\n` +
      `  Exit code : ${err.code ?? "unknown"}\n` +
      `  Stderr    : ${(err.stderr ?? "").trim()}`
    );
    enhanced.code = err.code;
    enhanced.stderr = err.stderr;
    enhanced.command = command;
    throw enhanced;
  }
}

/**
 * Safely parses a string of newline-delimited JSON objects (NDJSON).
 * Lines that are empty or fail to parse are skipped with a warning.
 *
 * @param {string} raw - Raw stdout from a tool that emits NDJSON.
 * @returns {object[]}
 */
function parseNdjson(raw) {
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .reduce((acc, line) => {
      try {
        acc.push(JSON.parse(line));
      } catch {
        // Silently drop non-JSON lines (e.g. progress banners).
      }
      return acc;
    }, []);
}

// ─── Step 1: Clone ────────────────────────────────────────────────────────────

/**
 * Clones `repoUrl` at the given `commitSha` into a unique temp directory.
 * Uses a shallow clone (--depth 1) for speed; then checks out the exact SHA.
 *
 * @param {string} repoUrl   - HTTPS clone URL, e.g. https://github.com/owner/repo.git
 * @param {string} commitSha - The exact commit to scan.
 * @returns {Promise<string>} Absolute path to the cloned directory.
 */
export async function cloneRepository(repoUrl, commitSha) {
  // mkdtemp creates a directory like /tmp/nexusguard-XXXXXX
  const tempDir = await mkdtemp(join(tmpdir(), "nexusguard-"));

  // --no-local prevents symlink tricks; --filter=blob:none skips large blobs.
  // We clone the default branch first (shallow), then fetch & checkout the SHA.
  await runCommand(
    `git clone --no-local --depth 1 --filter=blob:none "${repoUrl}" .`,
    tempDir
  );

  // If the SHA is already the HEAD of the shallow clone, this is a no-op.
  // If not (e.g. a PR head that differs from default branch tip), fetch it.
  try {
    await runCommand(`git checkout ${commitSha}`, tempDir);
  } catch {
    // SHA not present in shallow history — fetch it explicitly.
    await runCommand(
      `git fetch --depth 1 origin ${commitSha} && git checkout FETCH_HEAD`,
      tempDir
    );
  }

  return tempDir;
}

// ─── Step 2a: Semgrep ─────────────────────────────────────────────────────────

/**
 * @typedef {Object} SemgrepFinding
 * @property {string} vulnerabilityName - Rule ID / check ID.
 * @property {string} filePath          - Relative path of the affected file.
 * @property {number} lineNumber        - Line number where the issue starts.
 * @property {string} severity          - "ERROR" | "WARNING" | "INFO".
 * @property {string} message           - Human-readable description.
 */

/**
 * Runs `semgrep scan --config auto --json` in `dir` and returns normalised
 * findings. Exits cleanly even if semgrep returns exit code 1 (findings found).
 *
 * @param {string} dir - Absolute path to the repository to scan.
 * @returns {Promise<SemgrepFinding[]>}
 */
export async function runSemgrep(dir) {
  let raw;

  try {
    // On Windows, running semgrep scan may output the JSON to stdout or stderr depending on Python configuration.
    // We capture stdout from a direct exec execution.
    const { stdout, stderr } = await execAsync(
      "semgrep scan --config auto --json --quiet",
      { cwd: dir, timeout: EXEC_TIMEOUT_MS, maxBuffer: EXEC_MAX_BUFFER }
    );
    raw = stdout || stderr;
  } catch (err) {
    raw = err.stdout || err.stderr || "";
    if (!raw.trim().startsWith("{")) {
      throw err;
    }
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`Semgrep returned non-JSON output:\n${raw.slice(0, 500)}`);
  }

  const results = parsed?.results ?? [];

  return results.map((finding) => ({
    vulnerabilityName: finding.check_id ?? "unknown",
    filePath: finding.path ?? "unknown",
    lineNumber: finding.start?.line ?? 0,
    severity: finding.extra?.severity ?? "UNKNOWN",
    message: finding.extra?.message ?? "",
  }));
}

// ─── Step 2b: TruffleHog ─────────────────────────────────────────────────────

/**
 * @typedef {Object} SecretFinding
 * @property {string} detectorName - The type of secret detected (e.g. "AWS").
 * @property {string} filePath     - Path of the file containing the secret.
 * @property {string} raw          - Redacted snippet of the leaked value.
 * @property {boolean} verified    - Whether TruffleHog verified the credential is live.
 * @property {string} severity     - Always "CRITICAL" for secrets.
 */

/**
 * Runs `trufflehog filesystem . --json --no-update` in `dir` and returns
 * normalised secret findings.
 *
 * @param {string} dir - Absolute path to the repository to scan.
 * @returns {Promise<SecretFinding[]>}
 */
export async function runTruffleHog(dir) {
  let raw;

  try {
    // Check if we are running the older python-based trufflehog (which doesn't support the 'filesystem' command)
    // or the newer Go-based trufflehog v3. We run a legacy compatible command or handle fallback.
    raw = await runCommand("trufflehog --json .", dir);
  } catch (err) {
    if (err.code === 183 || err.stdout || err.code === 1) {
      raw = err.stdout ?? "";
    } else {
      // Try fallback to newer filesystem syntax in case it's actually v3 but exited strangely
      try {
        raw = await runCommand("trufflehog filesystem . --json --no-update", dir);
      } catch (innerErr) {
        if (innerErr.stdout) {
          raw = innerErr.stdout;
        } else {
          throw err;
        }
      }
    }
  }

  const lines = parseNdjson(raw);

  return lines.map((item) => {
    const raw_value = item.Raw ?? item.RawV2 ?? "";
    // Redact all but the first 4 chars to avoid storing the actual secret.
    const redacted =
      raw_value.length > 4
        ? `${raw_value.slice(0, 4)}${"*".repeat(raw_value.length - 4)}`
        : "****";

    return {
      detectorName: item.DetectorName ?? item.DetectorType ?? "unknown",
      filePath: item.SourceMetadata?.Data?.Filesystem?.file ?? "unknown",
      raw: redacted,
      verified: item.Verified ?? false,
      severity: "CRITICAL",
    };
  });
}

// ─── Step 3: Orchestrator ─────────────────────────────────────────────────────

/**
 * @typedef {Object} ScanReport
 * @property {string}           repoUrl       - The scanned repository URL.
 * @property {string}           commitSha     - The exact commit that was scanned.
 * @property {string}           scannedAt     - ISO 8601 timestamp.
 * @property {SemgrepFinding[]} vulnerabilities - Semgrep static analysis findings.
 * @property {SecretFinding[]}  secrets         - TruffleHog secret findings.
 * @property {object}           summary         - Counts by category and severity.
 * @property {string|null}      error           - Set if a partial/total failure occurred.
 */

/**
 * Full scan pipeline:
 *  1. Clones the repo at `commitSha` into a temp directory.
 *  2. Runs Semgrep and TruffleHog **in parallel**.
 *  3. Combines results into a single {@link ScanReport}.
 *  4. Deletes the temp directory in a `finally` block — always.
 *
 * @param {string} repoUrl   - HTTPS clone URL.
 * @param {string} commitSha - Git commit SHA to scan.
 * @returns {Promise<ScanReport>}
 */
export async function scanRepository(repoUrl, commitSha) {
  const scannedAt = new Date().toISOString();
  let tempDir = null;
  let partialError = null;

  try {
    // ── 1. Clone ──────────────────────────────────────────────────────────
    tempDir = await cloneRepository(repoUrl, commitSha);

    // ── 2. Parallel scans ─────────────────────────────────────────────────
    const [semgrepResult, truffleHogResult] = await Promise.allSettled([
      runSemgrep(tempDir),
      runTruffleHog(tempDir),
    ]);

    // Tolerate partial failures: one tool failing should not void the other.
    const vulnerabilities =
      semgrepResult.status === "fulfilled"
        ? semgrepResult.value
        : (() => {
            partialError = `Semgrep failed: ${semgrepResult.reason?.message}`;
            return [];
          })();

    const secrets =
      truffleHogResult.status === "fulfilled"
        ? truffleHogResult.value
        : (() => {
            const msg = `TruffleHog failed: ${truffleHogResult.reason?.message}`;
            partialError = partialError ? `${partialError}; ${msg}` : msg;
            return [];
          })();

    // ── 3. Combine ────────────────────────────────────────────────────────
    const report = buildReport({
      repoUrl,
      commitSha,
      scannedAt,
      vulnerabilities,
      secrets,
      error: partialError,
    });

    return report;
  } finally {
    // ── 4. Cleanup — always runs, even on thrown errors ───────────────────
    if (tempDir) {
      await rm(tempDir, { recursive: true, force: true }).catch((e) => {
        // Log but do not re-throw — cleanup failure is non-fatal.
        console.error(
          JSON.stringify({
            level: "warn",
            message: "Failed to delete temp directory",
            tempDir,
            error: e.message,
          })
        );
      });
    }
  }
}

// ─── Report Builder ───────────────────────────────────────────────────────────

/**
 * Assembles the final report and computes a severity summary.
 *
 * @param {object} params
 * @returns {ScanReport}
 */
function buildReport({ repoUrl, commitSha, scannedAt, vulnerabilities, secrets, error }) {
  // Count Semgrep findings by severity.
  const vulnBySeverity = vulnerabilities.reduce((acc, v) => {
    const key = (v.severity ?? "UNKNOWN").toUpperCase();
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {});

  const verifiedSecrets = secrets.filter((s) => s.verified).length;

  return {
    repoUrl,
    commitSha,
    scannedAt,
    vulnerabilities,
    secrets,
    summary: {
      totalVulnerabilities: vulnerabilities.length,
      totalSecrets: secrets.length,
      verifiedSecrets,
      vulnBySeverity,
    },
    error: error ?? null,
  };
}
