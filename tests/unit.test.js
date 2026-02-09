import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { TestUtils } from "../worker.js";

const { stableDedupe, sanitizeLines, limitOutput, assertSafeUpstream, SubscriptionAssembler } = TestUtils;

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
