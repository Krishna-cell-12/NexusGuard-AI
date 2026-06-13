"use client";
import Sidebar from "@/components/layout/Sidebar";
import TopBar from "@/components/layout/TopBar";
import HeroStats from "@/components/dashboard/HeroStats";
import LiveFeed from "@/components/dashboard/LiveFeed";
import PipelineTracker from "@/components/dashboard/PipelineTracker";
import SecurityScore from "@/components/dashboard/SecurityScore";
import PatchViewer from "@/components/dashboard/PatchViewer";
import BountyBoard from "@/components/dashboard/BountyBoard";

export default function DashboardPage() {
  return (
    <div className="shell">
      <Sidebar />
      <TopBar />
      <main className="main">

        {/* KPI Row */}
        <HeroStats />

        {/* Pipeline + Live Feed */}
        <div className="two-col">
          <PipelineTracker />
          <LiveFeed />
        </div>

        {/* Vulns + Scores */}
        <div className="two-col">
          <PatchViewer />
          <SecurityScore />
        </div>

        {/* Bounty Board */}
        <BountyBoard />

      </main>
    </div>
  );
}
