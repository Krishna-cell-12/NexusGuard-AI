import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "NexusGuard AI — Security Command Center",
  description: "Autonomous AI-powered security scanner with real-time vulnerability detection, AI patch generation, and blockchain bounty releases.",
  keywords: ["cybersecurity", "AI", "vulnerability scanner", "blockchain", "NexusGuard"],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
