"use client";
import { useEffect, useRef, useState, useCallback } from "react";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:3000";

export interface WsEvent {
  event: "PIPELINE_STATE" | "SCAN_COMPLETE" | "PIPELINE_FAILED";
  runId?: string; state?: string; repoName?: string;
  commitSha?: string; message?: string; payload?: unknown; timestamp?: string;
}

export function useWebSocket() {
  const [events, setEvents]     = useState<WsEvent[]>([]);
  const [connected, setConn]    = useState(false);
  const [lastEvent, setLast]    = useState<WsEvent | null>(null);
  const wsRef   = useRef<WebSocket | null>(null);
  const retryRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const connectRef = useRef<(() => void) | null>(null);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;
    ws.onopen  = () => setConn(true);
    ws.onclose = () => {
      setConn(false);
      retryRef.current = setTimeout(() => connectRef.current?.(), 3000);
    };
    ws.onerror = () => ws.close();
    ws.onmessage = ({ data }) => {
      try {
        const p: WsEvent = JSON.parse(data);
        const ev = { ...p, timestamp: new Date().toISOString() };
        setLast(ev);
        setEvents(prev => [ev, ...prev].slice(0, 200));
      } catch {}
    };
  }, []);

  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  useEffect(() => {
    connect();
    return () => {
      if (retryRef.current) clearTimeout(retryRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { events, connected, lastEvent };
}
