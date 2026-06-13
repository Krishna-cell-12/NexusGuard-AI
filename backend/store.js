/**
 * NexusGuard AI — Shared In-Memory Run Store
 *
 * Extracted into its own module to break the circular dependency between
 * server.js (which exports runStore) and orchestrator.js (which imports it).
 *
 * Both server.js and orchestrator.js import from here.
 */

/**
 * Maps runId → pipeline state snapshot.
 * Updated by orchestrator.js at every state transition.
 * Queried by GET /api/status/:runId in server.js.
 *
 * @type {Map<string, object>}
 */
export const runStore = new Map();
