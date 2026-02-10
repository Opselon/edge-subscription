import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { TestUtils } from "../worker.js";

const {
  stableDedupe,
  sanitizeLines,
  limitOutput,
  assertSafeUpstream,
  SubscriptionAssembler,
  resolveOperatorBaseUrl,
  buildOperatorScopedSubLink,
  buildPremiumSubscriptionMessage,
} = TestUtils;

describe("unit: sanitization and dedupe", () => {
  it("dedupes while preserving order", () => {
    const input = ["a", "b", "a", "c", "b"];
    assert.deepEqual(stableDedupe(input), ["a", "b", "c"]);
  });

  it("sanitizes invalid schemes and keywords", () => {
    const lines = ["vmess://ok", "http://bad", "vless://safe", "#comment", "ss://ads-server"];
    const result = sanitizeLines(lines, ["ads"]);
    assert.deepEqual(result, ["vmess://ok", "vless://safe"]);
  });

  it("limits output by lines and bytes", () => {
    const lines = ["one", "two", "three", "four"];
    const limited = limitOutput(lines, 2, 100);
    assert.deepEqual(limited, ["one", "two"]);
  });
});

describe("unit: SSRF guard", () => {
  it("blocks non-https and localhost", () => {
    assert.equal(assertSafeUpstream("http://example.com").ok, false);
    assert.equal(assertSafeUpstream("https://localhost").ok, false);
  });

  it("respects allowlist", () => {
    assert.equal(assertSafeUpstream("https://safe.example.com", ["example.com"], []).ok, true);
    assert.equal(assertSafeUpstream("https://evil.test", ["example.com"], []).ok, false);
  });
});

describe("unit: merge policies", () => {
  it("merges append by default", () => {
    const merged = SubscriptionAssembler.mergeContent("a", "b", { merge_policy: "append" });
    assert.equal(merged, "a\nb");
  });

  it("extras_only returns extras", () => {
    const merged = SubscriptionAssembler.mergeContent("a", "b", { merge_policy: "extras_only" });
    assert.equal(merged, "b");
  });
});

describe("unit: smart paste link mapping", () => {
  it("resolves base URL in required fallback order", () => {
    const request = { url: "https://worker.example.workers.dev/webhook" };
    assert.equal(
      resolveOperatorBaseUrl({
        activeDomain: "sub.example.com",
        brandingBaseUrl: "https://branding.example",
        envBaseUrl: "https://env.example",
        request,
      }),
      "https://sub.example.com"
    );
    assert.equal(
      resolveOperatorBaseUrl({
        activeDomain: "",
        brandingBaseUrl: "https://branding.example/",
        envBaseUrl: "https://env.example",
        request,
      }),
      "https://branding.example"
    );
    assert.equal(
      resolveOperatorBaseUrl({
        activeDomain: "",
        brandingBaseUrl: "",
        envBaseUrl: "https://env.example/",
        request,
      }),
      "https://env.example"
    );
    assert.equal(
      resolveOperatorBaseUrl({
        activeDomain: "",
        brandingBaseUrl: "",
        envBaseUrl: "",
        request,
      }),
      "https://worker.example.workers.dev"
    );
  });

  it("always builds operator-scoped subscription links", () => {
    assert.equal(
      buildOperatorScopedSubLink({
        baseUrl: "https://worker.example.workers.dev/",
        shareToken: "OPERATOR123",
        panelToken: "PANEL456",
      }),
      "https://worker.example.workers.dev/sub/OPERATOR123/PANEL456"
    );
  });

  it("renders legacy premium message format and exact button order", () => {
    const payload = buildPremiumSubscriptionMessage({
      operatorName: "Rexa Panel",
      username: "Premium User",
      mainLink: "https://worker.example.workers.dev/sub/OPERATOR123/PANEL456",
    });
    assert.match(payload.text, /^🧊 Rexa Panel/m);
    assert.match(payload.text, /👤 کاربر: Premium User/);
    assert.match(payload.text, /🧊 اتصال فوری با یک کلیک/);
    assert.match(payload.text, /🧭 راهنمای اتصال دستی/);
    const labels = payload.keyboard.inline_keyboard.flat().map((btn) => btn.text);
    assert.deepEqual(labels, ["v2rayNG", "NekoBox", "v2Box", "Streisand", "Share"]);
  });
});
