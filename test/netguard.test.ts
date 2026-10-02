import { test } from "node:test";
import assert from "node:assert/strict";
import { assertPublicHost, assertPublicUrl, isPrivateAddress } from "../src/lib/netguard.ts";

test("private, loopback, tailnet and docker addresses are blocked", () => {
  for (const ip of [
    "127.0.0.1", "10.1.2.3", "172.17.0.2", "172.31.255.255", "192.168.1.24", "100.124.95.80",
    "169.254.169.254", "0.0.0.0", "::1", "::", "fd7a:115c:a1e0::1", "fe80::1", "::ffff:192.168.1.1",
  ]) {
    assert.equal(isPrivateAddress(ip), true, ip);
  }
});

test("public addresses pass", () => {
  for (const ip of ["1.1.1.1", "142.250.185.109", "172.32.0.1", "2a00:1450:4001:80b::2005"]) {
    assert.equal(isPrivateAddress(ip), false, ip);
  }
});

test("hostnames resolving to private addresses are refused", async () => {
  await assert.rejects(assertPublicHost("localhost"), /private or local/);
  await assert.rejects(assertPublicHost("192.168.1.24"), /private or local/);
  await assert.rejects(assertPublicHost("[::1]"), /private or local/);
  await assert.rejects(assertPublicUrl("http://127.0.0.1:8123/api"), /private or local/);
  await assert.rejects(assertPublicUrl("file:///etc/passwd"), /Only http/);
});

test("ALLOW_PRIVATE_HOSTS opts out (self-hosted mail on the LAN)", async () => {
  process.env.ALLOW_PRIVATE_HOSTS = "true";
  try {
    await assertPublicHost("192.168.1.24");
  } finally {
    delete process.env.ALLOW_PRIVATE_HOSTS;
  }
});
