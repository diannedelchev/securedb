const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

test("explorer links keep connection values inside a single query parameter", () => {
  const events = new Map();
  const changes = new Map();
  const select = {
    value: "",
    options: [],
    selectedIndex: -1,
    addEventListener: (name, callback) => changes.set(name, callback),
  };
  const link = {};
  const document = {
    addEventListener: (name, callback) => events.set(name, callback),
    getElementById: (id) => ({ "explorer-conn": select, "xp-open-editor": link })[id] || null,
    querySelector: () => null,
  };
  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../internal/web/static/js/app.js"), "utf8"),
    { window: {}, document },
  );
  events.get("DOMContentLoaded")();
  assert.equal(link.href, "/editor");
  for (const value of [
    "6b2cda7e-c855-4fda-bfbd-6fd3650c00c8",
    'id&admin=true#fragment"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "name with spaces/é",
  ]) {
    select.value = value;
    changes.get("change")();
    const url = new URL(link.href, "https://securedb.example");
    assert.equal(url.origin, "https://securedb.example");
    assert.equal(url.pathname, "/editor");
    assert.equal(url.hash, "");
    assert.deepEqual([...url.searchParams], [["connection", value]]);
    assert.ok(!link.href.includes("<"));
  }
});
