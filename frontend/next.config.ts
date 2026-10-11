import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: [
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "X-Frame-Options", value: "DENY" },
      { key: "Referrer-Policy", value: "no-referrer" },
      { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
      // Deliberately avoid a script-src restriction without Next's nonce flow:
      // hydration and bundled PDF workers must continue to function.
      { key: "Content-Security-Policy", value: "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'" },
    ] }];
  },

  publicRuntimeConfig: {
    // Will be available on both server and client
    apiUrl: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
  },

  async rewrites() {
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

    return [
      {
        source: "/api/:path*",
        destination: `${apiUrl}/:path*`,
      },
    ];
  },
};

export default nextConfig;
