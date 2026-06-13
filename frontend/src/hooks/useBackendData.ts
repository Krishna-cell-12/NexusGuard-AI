"use client";
import { useState, useEffect } from "react";
import { fetchers } from "@/lib/api";

function usePoll<T>(fetcher: () => Promise<T>, ms = 5000) {
  const [data, setData]     = useState<T | null>(null);
  const [error, setError]   = useState<Error | null>(null);
  const [loading, setLoad]  = useState(true);

  useEffect(() => {
    let dead = false;
    const run = async () => {
      try   { const d = await fetcher(); if (!dead) { setData(d); setError(null); } }
      catch (e) { if (!dead) setError(e as Error); }
      finally   { if (!dead) setLoad(false); }
    };
    run();
    const id = setInterval(run, ms);
    return () => { dead = true; clearInterval(id); };
  }, [ms]);

  return { data, error, loading };
}

export const useRuns    = (n = 20)  => usePoll(() => fetchers.runs(n));
export const useScores  = ()        => usePoll(() => fetchers.scores());
export const usePatches = (n = 20)  => usePoll(() => fetchers.patches(n));
export const useHealth  = ()        => usePoll(() => fetchers.health(), 10000);
export const useThreats = ()        => usePoll(() => fetchers.threats(), 5000);
