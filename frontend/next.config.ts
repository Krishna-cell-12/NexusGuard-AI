import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Run on port 3001 so backend can stay on 3000
  // Headers for CORS pass-through when calling backend
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
        ],
      },
    ];
  },
  // Suppress hydration noise in dev
  reactStrictMode: true,
};

export default nextConfig;
