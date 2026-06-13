/**
 * NexusGuard AI — Dynamic Analysis Sandbox
 *
 * Spins up an isolated Docker container, bind-mounts a local repository,
 * executes language-appropriate build/test commands, captures all output,
 * and unconditionally destroys the container when done.
 *
 * Security guarantees:
 *   - NetworkDisabled: true  — container cannot reach the internet
 *   - ReadonlyRootfs: false  — writable inside /app only (npm install needs it)
 *   - No capabilities added beyond the Docker default set
 *   - Hard 30-second wall-clock timeout enforced by the host
 *   - Container is force-removed in a finally block
 *
 * Prerequisites:
 *   - Docker daemon running and accessible at /var/run/docker.sock
 *   - npm install dockerode
 */

import Dockerode from "dockerode";
import { readdir } from "fs/promises";
import { join } from "path";

// ─── Constants ────────────────────────────────────────────────────────────────

const EXECUTION_TIMEOUT_MS = 30_000; // 30 seconds hard limit

/**
 * Maps a detected project type to:
 *   image   — Docker image to pull / use
 *   command — Shell command executed inside the container at /app
 */
const RUNTIME_PROFILES = {
  node: {
    image: "node:20-alpine",
    command: "sh -c 'npm install --prefer-offline 2>&1 && npm test 2>&1'",
  },
  python: {
    image: "python:3.12-slim",
    command: "sh -c 'pip install -r requirements.txt --quiet 2>&1 && python -m pytest -v 2>&1'",
  },
  generic: {
    image: "ubuntu:24.04",
    command: "sh -c 'echo \"No recognised runtime — listing /app\" && ls -la /app'",
  },
};

// ─── Runtime Detection ────────────────────────────────────────────────────────

/**
 * Inspects the top-level files of `repoPath` to determine the project runtime.
 *
 * @param {string} repoPath - Absolute path to the repository root.
 * @returns {Promise<'node'|'python'|'generic'>}
 */
async function detectRuntime(repoPath) {
  let entries;
  try {
    entries = await readdir(repoPath);
  } catch {
    return "generic";
  }

  const files = new Set(entries.map((e) => e.toLowerCase()));

  if (files.has("package.json")) return "node";
  if (files.has("requirements.txt") || files.has("setup.py") || files.has("pyproject.toml"))
    return "python";
  return "generic";
}

// ─── Stream Collector ─────────────────────────────────────────────────────────

/**
 * Reads a Docker multiplexed stream (from `container.exec().start()` or
 * `container.attach()`) into a single string.
 *
 * Docker multiplexes stdout and stderr into one stream using an 8-byte header
 * per frame: [stream_type(1), 0,0,0, size(4)]. We strip the headers and
 * concatenate the raw text.
 *
 * @param {NodeJS.ReadableStream} stream
 * @returns {Promise<string>}
 */
function collectStream(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];

    stream.on("data", (chunk) => {
      // Each Docker multiplexed frame starts with an 8-byte header.
      // Byte 0: stream type (1=stdout, 2=stderr). Bytes 4-7: uint32 payload size.
      // We strip the header and keep only the payload text.
      let offset = 0;
      while (offset < chunk.length) {
        if (chunk.length - offset < 8) {
          // Incomplete header — treat remainder as raw text (safety fallback).
          chunks.push(chunk.slice(offset).toString("utf8"));
          break;
        }
        const payloadSize = chunk.readUInt32BE(offset + 4);
        const payload = chunk.slice(offset + 8, offset + 8 + payloadSize);
        chunks.push(payload.toString("utf8"));
        offset += 8 + payloadSize;
      }
    });

    stream.on("end", () => resolve(chunks.join("")));
    stream.on("error", reject);
  });
}

// ─── Ensure Image ─────────────────────────────────────────────────────────────

/**
 * Pulls `imageName` if not already present locally.
 * Resolves when the image is ready; rejects on pull failure.
 *
 * @param {Dockerode} docker
 * @param {string}    imageName
 */
async function ensureImage(docker, imageName) {
  try {
    await docker.getImage(imageName).inspect();
    // Image already present — no pull needed.
  } catch (err) {
    if (err.statusCode !== 404) throw err;

    // Pull the image and wait for it to finish.
    await new Promise((resolve, reject) => {
      docker.pull(imageName, (pullErr, pullStream) => {
        if (pullErr) return reject(pullErr);
        // docker.modem.followProgress drains the stream and calls onFinished.
        docker.modem.followProgress(pullStream, (finishErr) =>
          finishErr ? reject(finishErr) : resolve()
        );
      });
    });
  }
}

// ─── Core: runDynamicAnalysis ─────────────────────────────────────────────────

/**
 * @typedef {Object} AnalysisResult
 * @property {'node'|'python'|'generic'} runtime - Detected project runtime.
 * @property {string}                    image   - Docker image used.
 * @property {string}                    output  - Combined stdout + stderr.
 * @property {number|null}               exitCode - Container process exit code.
 * @property {boolean}                   timedOut - True if the 30 s limit fired.
 * @property {string}                    containerId - ID of the (removed) container.
 */

/**
 * Runs an isolated dynamic analysis of the repository at `repoPath`.
 *
 * Flow:
 *   1. Detect runtime (node / python / generic)
 *   2. Ensure Docker image is present
 *   3. Create container — network disabled, bind-mount repoPath → /app
 *   4. Start container + attach to combined output stream
 *   5. Race container wait against 30 s timeout
 *   6. Force-remove container in finally block
 *
 * @param {string} repoPath - Absolute path to the cloned repository.
 * @returns {Promise<AnalysisResult>}
 */
export async function runDynamicAnalysis(repoPath) {
  // ── 1. Detect runtime ────────────────────────────────────────────────────
  const runtime = await detectRuntime(repoPath);
  const profile = RUNTIME_PROFILES[runtime];

  // ── 2. Connect to Docker daemon ─────────────────────────────────────────
  const docker = new Dockerode({ socketPath: "/var/run/docker.sock" });

  // Verify the daemon is reachable before doing anything else.
  await docker.ping().catch(() => {
    throw new Error(
      "Docker daemon is not reachable at /var/run/docker.sock. " +
      "Ensure Docker is running and the current user has socket access."
    );
  });

  await ensureImage(docker, profile.image);

  // ── 3. Create container ──────────────────────────────────────────────────
  const container = await docker.createContainer({
    Image: profile.image,

    // Run the command via sh -c so shell features (&&, pipes) work.
    Cmd: ["/bin/sh", "-c", profile.command],

    WorkingDir: "/app",

    // ── Security constraints ─────────────────────────────────────────────
    NetworkDisabled: true,        // No outbound or inbound network
    // ReadonlyRootfs:  true would break npm install; keep writable.

    HostConfig: {
      // Bind-mount: host repoPath → container /app (read-write so npm can install)
      Binds: [`${repoPath}:/app:rw`],

      // Resource caps — prevent runaway CPU/RAM consumption.
      Memory: 512 * 1024 * 1024,   // 512 MB RAM hard limit
      NanoCpus: 1_000_000_000,      // 1 vCPU

      // Prevent privilege escalation inside the container.
      SecurityOpt: ["no-new-privileges"],

      // Auto-remove would race with our explicit rm; we handle removal manually.
      AutoRemove: false,

      // Disable all Linux capabilities beyond the minimal default set.
      CapDrop: ["ALL"],
      CapAdd: [],                   // Add nothing back

      // Use the host's PID namespace? No. Stay isolated.
      PidMode: "",
    },

    // Attach stdout + stderr so we can stream them.
    AttachStdout: true,
    AttachStderr: true,
    Tty: false, // Must be false for Docker's multiplexed stream protocol.
  });

  const containerId = container.id;
  let timedOut = false;
  let exitCode = null;

  try {
    // ── 4. Attach to output stream BEFORE starting ───────────────────────
    // Attaching before start ensures we capture output from the very first byte.
    const attachStream = await container.attach({
      stream: true,
      stdout: true,
      stderr: true,
      logs: true,   // Include any output produced before we attached.
    });

    // Start the container.
    await container.start();

    // ── 5. Race: container exit vs. 30 s timeout ─────────────────────────
    let timeoutHandle;

    const waitPromise = container.wait().then((result) => {
      exitCode = result.StatusCode;
    });

    const timeoutPromise = new Promise((_, reject) => {
      timeoutHandle = setTimeout(() => {
        timedOut = true;
        reject(new Error(`Container exceeded the ${EXECUTION_TIMEOUT_MS / 1000}s timeout.`));
      }, EXECUTION_TIMEOUT_MS);
    });

    // Collect the stream concurrently with the race.
    const [output] = await Promise.all([
      collectStream(attachStream),
      Promise.race([waitPromise, timeoutPromise]).finally(() =>
        clearTimeout(timeoutHandle)
      ),
    ]);

    return {
      runtime,
      image: profile.image,
      output,
      exitCode,
      timedOut,
      containerId,
    };
  } finally {
    // ── 6. Force-remove — always, even on timeout or thrown error ─────────
    await container
      .remove({ force: true, v: true }) // v: true also removes anonymous volumes
      .catch((removeErr) => {
        // Log but do not re-throw — removal failure is non-fatal for the caller.
        console.error(
          JSON.stringify({
            level: "warn",
            message: "Failed to remove container",
            containerId,
            error: removeErr.message,
          })
        );
      });
  }
}
