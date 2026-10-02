import type { NextConfig } from "next";

const config: NextConfig = {
  output: "standalone",
  serverExternalPackages: ["imapflow", "nodemailer", "mailparser"],
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          // Not "no-referrer": that makes browsers send `Origin: null` on the consent form POST.
          { key: "Referrer-Policy", value: "same-origin" },
          // Blocks clickjacking of the consent page.
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Strict-Transport-Security", value: "max-age=31536000" },
        ],
      },
    ];
  },
};

export default config;
