"use client";
import { useState, useEffect } from "react";
import { fetchers, type Run, type ScoreEntry, type PatchEntry } from "@/lib/api";

const POLL_MS = 5000;

function usePoll<T>(fetcher: () => Promise<T>, interval = POLL_MS) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const result = await fetcher();
        if (!cancelled) { setData(result); setError(null); }
      } catch (e) {
        if (!cancelled) setError(e as Error);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    const id = setInterval(load, interval);
    return () => { cancelled = true; clearInterval(id); };
  }, [interval]);

  return { data, error, loading };
}

export function useRuns(limit = 20) {
  return usePoll(() => fetchers.runs(limit));
}

export function useScores() {
  return usePoll(() => fetchers.scores());
}

export function usePatches(limit = 20) {
  return usePoll(() => fetchers.patches(limit));
}

export function useHealth() {
  return usePoll(() => fetchers.health(), 10000);
}
