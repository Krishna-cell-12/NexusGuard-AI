/**
 * NexusGuard AI — OSINT Threat Intelligence Crawler
 * backend/scripts/threat_intel.js
 *
 * Simulates OSINT background collection from Dark Web, Exploit DB, and CVE feeds,
 * maintaining a signature database of vulnerabilities.
 */

import { promises as fs } from "fs";
import { join } from "path";

const SIGNATURE_FILE = join(process.cwd(), "threat_intel_db.json");

const MOCK_OSINT_SOURCES = [
  { source: "Exploit DB", query: "Remote Code Execution (RCE)", severity: "CRITICAL" },
  { source: "Dark Web Forum", query: "0-day authentication bypass payload", severity: "CRITICAL" },
  { source: "NVD (NVD NIST)", query: "SQL Injection in npm database driver", severity: "HIGH" },
  { source: "GitHub Security Advisory", query: "Prototype Pollution in lodash", severity: "MEDIUM" },
];

export async function fetchThreatFeeds() {
  try {
    let currentData = [];
    try {
      const content = await fs.readFile(SIGNATURE_FILE, "utf-8");
      currentData = JSON.parse(content);
    } catch {
      // file doesn't exist yet
    }

    // Crawl new random threat indicator
    const randomSource = MOCK_OSINT_SOURCES[Math.floor(Math.random() * MOCK_OSINT_SOURCES.length)];
    const newThreat = {
      id: `INTEL-${Math.random().toString(36).substring(2, 9).toUpperCase()}`,
      source: randomSource.source,
      indicator: randomSource.query,
      severity: randomSource.severity,
      timestamp: new Date().toISOString(),
      status: "ACTIVE"
    };

    currentData.unshift(newThreat);
    // Limit to last 50 threats
    currentData = currentData.slice(0, 50);

    await fs.writeFile(SIGNATURE_FILE, JSON.stringify(currentData, null, 2), "utf-8");
    console.log(`[OSINT Threat Intel] Successfully indexed signature: ${newThreat.id} (${newThreat.source})`);
    return newThreat;
  } catch (err) {
    console.error("[OSINT Threat Intel] Crawler run failed:", err.message);
  }
}

// If run directly, kick off interval loop
if (process.argv[1] && process.argv[1].endsWith("threat_intel.js")) {
  console.log("[OSINT Threat Intel] Daemon started. Periodically scanning dark web & vulnerability databases...");
  fetchThreatFeeds();
  setInterval(fetchThreatFeeds, 15000); // scan every 15 seconds
}
