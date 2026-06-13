"use client";
import { useEffect, useRef, useState, useCallback } from "react";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:3000";

export interface WsEvent {
  event: "PIPELINE_STATE" | "SCAN_COMPLETE" | "PIPELINE_FAILED";
  runId?: string;
  state?: string;
  repoName?: string;
  commitSha?: string;
  message?: string;
  payload?: unknown;
  timestamp?: string;
}

export function useWebSocket() {
  const [events, setEvents] = useState<WsEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [lastEvent, setLastEvent] = useState<WsEvent | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => {
      setConnected(false);
      retryRef.current = setTimeout(connect, 3000);
    };
    ws.onerror = () => ws.close();
    ws.onmessage = ({ data }) => {
      try {
        const parsed: WsEvent = JSON.parse(data);
        setLastEvent(parsed);
        setEvents((prev) => [{ ...parsed, timestamp: new Date().toISOString() }, ...prev].slice(0, 100));
      } catch {}
    };
  }, []);

  useEffect(() => {
    connect();
    return () => {
      if (retryRef.current) clearTimeout(retryRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { events, connected, lastEvent };
}
