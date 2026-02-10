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
  createTelegramSendMessageBody,
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

  it("uses https redirect buttons so Telegram accepts keyboard URLs", () => {
    const payload = buildPremiumSubscriptionMessage({
      operatorName: "Rexa Panel",
      username: "Premium User",
      mainLink: "https://worker.example.workers.dev/sub/OPERATOR123/PANEL456",
    });
    const appButtons = payload.keyboard.inline_keyboard.slice(0, 2).flat();
    assert.equal(appButtons.length, 4);
    for (const button of appButtons) {
      assert.match(button.url, /^https:\/\/worker\.example\.workers\.dev\/redirect\?target=/);
      const parsed = new URL(button.url);
      const target = decodeURIComponent(parsed.searchParams.get("target") || "");
      assert.match(target, /^(v2rayng|sn|v2box|streisand):\/\//);
    }
  });
});

describe("unit: telegram keyboard sanitization", () => {
  it("sanitizes bad button and keeps valid buttons for send", () => {
    const { body, sanitizeResult } = createTelegramSendMessageBody(123, "hello", {
      inline_keyboard: [
        [
          { text: "Broken" },
          { text: "Valid", callback_data: "do_something" },
        ],
      ],
    });
    assert.equal(sanitizeResult.removedCount, 1);
    assert.deepEqual(sanitizeResult.removedReasons, { missing_url_and_callback_data: 1 });
    assert.deepEqual(body.reply_markup, {
      inline_keyboard: [[{ text: "Valid", callback_data: "do_something" }]],
    });
    assert.equal(body.parse_mode, "HTML");
  });

  it("drops reply_markup when all buttons are invalid", () => {
    const { body, sanitizeResult } = createTelegramSendMessageBody(123, "hello", {
      inline_keyboard: [[{ text: "Broken" }, { text: 1, callback_data: "x" }]],
    });
    assert.equal(sanitizeResult.removedCount, 2);
    assert.equal(sanitizeResult.keyboard, null);
    assert.equal("reply_markup" in body, false);
  });
});
