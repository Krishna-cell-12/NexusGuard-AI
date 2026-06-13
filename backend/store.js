/**
 * NexusGuard AI — Shared In-Memory Run Store
 *
 * Extracted into its own module to break the circular dependency between
 * server.js (which exports runStore) and orchestrator.js (which imports it).
 *
 * Both server.js and orchestrator.js import from here.
 */

/**
 * Maps runId → full pipeline state snapshot (updated at every transition).
 * Queried by GET /api/status/:runId and GET /api/runs in server.js.
 *
 * Shape of each entry:
 * {
 *   runId, repoName, commitSha, senderLogin,
 *   state, startedAt, updatedAt,
 *   scanReport, patchResult, blockchainResult, error
 * }
 *
 * @type {Map<string, object>}
 */
export const runStore = new Map();

/**
 * Maps repoName → cumulative security score (0-100).
 * Recomputed after each completed scan.
 * @type {Map<string, object>}
 */
export const scoreStore = new Map();

/**
 * Compute and cache a security score for a repo based on the latest scan report.
 * Score starts at 100 and deducts points per finding severity.
 *
 * @param {string} repoName
 * @param {object} scanReport
 * @returns {number} score 0-100
 */
export function computeScore(repoName, scanReport) {
  const vulns = scanReport?.vulnerabilities ?? [];
  const secrets = scanReport?.secrets ?? [];

  let deductions = 0;
  for (const v of vulns) {
    const sev = (v.severity ?? "").toUpperCase();
    if (sev === "ERROR")   deductions += 10;
    else if (sev === "WARNING") deductions += 5;
    else if (sev === "INFO")    deductions += 1;
    else deductions += 3;
  }
  // Secrets are critical
  deductions += secrets.length * 15;

  const score = Math.max(0, 100 - deductions);

  scoreStore.set(repoName, {
    repoName,
    score,
    grade: score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F",
    totalVulnerabilities: vulns.length,
    totalSecrets: secrets.length,
    vulnBySeverity: scanReport?.summary?.vulnBySeverity ?? {},
    lastScannedAt: scanReport?.scannedAt ?? new Date().toISOString(),
    commitSha: scanReport?.commitSha,
  });

  return score;
}
