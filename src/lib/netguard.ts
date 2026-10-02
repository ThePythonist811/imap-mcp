import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

// Mail and CalDAV hosts are user-supplied. Without this check the server could be
// pointed at the LAN, the Docker network (postgres) or the tailnet and used as a
// port scanner. Set ALLOW_PRIVATE_HOSTS=true for self-hosted servers on the LAN.

function ipv4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

const V4_BLOCKED: [string, number][] = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10], // CGNAT, includes Tailscale
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12], // includes Docker bridge networks
  ["192.0.0.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
];

export function isPrivateAddress(ip: string): boolean {
  const v = isIP(ip);
  if (v === 4) {
    const n = ipv4ToInt(ip);
    return V4_BLOCKED.some(([base, bits]) => {
      const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
      return (n & mask) === (ipv4ToInt(base) & mask);
    });
  }
  if (v === 6) {
    const a = ip.toLowerCase();
    if (a === "::" || a === "::1") return true;
    const mapped = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateAddress(mapped[1]);
    return /^(fc|fd|fe[89ab]|ff)/.test(a); // ULA (incl. Tailscale fd7a:), link-local, multicast
  }
  return true; // not an IP at all: refuse
}

export async function assertPublicHost(host: string): Promise<void> {
  if (process.env.ALLOW_PRIVATE_HOSTS === "true") return;
  const h = host.trim().replace(/^\[|\]$/g, "");
  let addrs: string[];
  try {
    addrs = isIP(h) ? [h] : (await lookup(h, { all: true, verbatim: true })).map((a) => a.address);
  } catch {
    throw new Error(`Host ${host} could not be resolved`);
  }
  if (addrs.length === 0 || addrs.some(isPrivateAddress)) {
    throw new Error(`Host ${host} points to a private or local network address, which is not allowed`);
  }
}

export async function assertPublicUrl(url: string): Promise<void> {
  const u = new URL(url);
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("Only http(s) URLs are allowed");
  await assertPublicHost(u.hostname);
}
