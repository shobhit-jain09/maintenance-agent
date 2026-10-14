// Drives the real <maintenance-agent-panel> in jsdom against a real server.
// env: BASE_URL, FLOW=real|hostile, REPO (what to type), CONFIRM (repo name to type), MODE
const { JSDOM } = require("jsdom");
const base = process.env.BASE_URL, flow = process.env.FLOW || "real";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, what, ms = 90000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { const v = fn(); if (v) return v; await sleep(100); }
  throw new Error("timeout waiting for: " + what);
}
function assert(cond, msg) { if (!cond) throw new Error("ASSERT FAILED: " + msg); }

(async () => {
  const dom = await JSDOM.fromURL(base + "/", {
    runScripts: "dangerously", resources: "usable", pretendToBeVisual: true,
    beforeParse(window) { window.fetch = (u, o) => fetch(new URL(u, base), o); },
  });
  const win = dom.window, doc = win.document;
  const panel = doc.querySelector("maintenance-agent-panel");
  const root = () => panel.shadowRoot;
  const q = (sel) => root().querySelector(sel);
  const btn = (text) => [...root().querySelectorAll("button")].find((b) => b.textContent.trim() === text);
  const type = (el, v) => { el.value = v; el.dispatchEvent(new win.Event("input", { bubbles: true })); };
  const out = { flow };
  await waitFor(() => panel.shadowRoot, "component upgrade (script loaded)");

  // 1. form is rendered, modes loaded from the server
  const mode = await waitFor(() => { const s = q("#mode"); return s && s.options.length === 3 ? s : null; }, "mode select");
  out.modes = [...mode.options].map((o) => o.value + (o.disabled ? ":disabled" : ""));
  assert(q("#url"), "url input present");

  // 2. a bad web URL gets a courtesy error and nothing is sent
  type(q("#url"), "https://example.com/not/github");
  btn("Review access notice").click();
  await waitFor(() => q('[role="alert"]'), "client-side URL error");
  assert(/GitHub URL/.test(q('[role="alert"]').textContent), "hint shown for non-GitHub URL");

  // 3. real URL/path + mode -> access notice
  type(q("#url"), process.env.REPO);
  mode.value = process.env.MODE || "analyze"; mode.dispatchEvent(new win.Event("change", { bubbles: true }));
  btn("Review access notice").click();
  const confirm = await waitFor(() => q("#confirm"), "access notice with confirm box");
  assert(q("pre").textContent.includes("ACCESS NOTICE"), "notice text is shown");
  const go = btn("Authorise and run");
  assert(go.disabled === true, "Authorise is disabled until the name is typed");

  // 4. consent = typing the exact repo name (clicking is not enough)
  for (const wrong of ["yes", "y", "", "demo", process.env.CONFIRM + "x"]) { type(confirm, wrong); assert(go.disabled, `still disabled for '${wrong}'`); }
  type(confirm, process.env.CONFIRM.toUpperCase());
  assert(go.disabled === false, "enabled once the name matches (case-insensitive)");
  go.click();

  // 5. progress, then result
  await waitFor(() => btn("\u2190 Check another repository"), "result view");
  assert(q(".ok"), "completed banner: " + (q(".err") ? q(".err").textContent : ""));
  const stats = [...root().querySelectorAll(".stat b")].map((b) => b.textContent);
  out.stats = stats;
  assert(stats.length === 5, "five stat cards");

  // 6. findings table
  const rows = [...root().querySelectorAll("table tbody tr")];
  assert(rows.length > 0, "findings rows rendered");
  const text = root().textContent;
  if (flow === "real") {
    assert(text.includes("_legacy_discount") && text.includes("_unused_helper"), "real dead-code findings listed");
    assert(text.includes("Authorised by web-ui@"), "authorisation line shown");
  }

  // 7. hostile strings must be visible as TEXT and never become elements
  if (flow === "hostile") {
    for (const needle of ["<img src=x onerror=window.__pwned=1>", "<script>window.__pwned=2</script>", "</pre><svg onload=window.__pwned=3>"]) {
      assert(text.includes(needle), "hostile string shown literally: " + needle);
    }
    assert(root().querySelectorAll("img,script,svg,iframe,object,embed,link").length === 0, "no injected elements in shadow DOM");
    assert(win.__pwned === undefined, "no injected script ran");
  }

  // 8. generated code tab: unified diff with coloured +/- lines, copy/download controls
  btn("Generated code").click();
  await waitFor(() => root().querySelectorAll(".diff div").length > 3, "diff rendered", 30000);
  const dels = [...root().querySelectorAll(".diff .del")].map((d) => d.textContent);
  assert(dels.length > 0, "removed lines styled");
  assert(btn("Copy patch") && btn("Download .diff"), "copy/download buttons");
  assert(root().querySelector("pre").textContent.includes("git apply"), "apply instructions shown");
  if (flow === "real") assert(dels.some((d) => d.includes("def _legacy_discount")), "diff removes _legacy_discount");
  if (flow === "hostile") { assert(root().querySelectorAll(".diff img, .diff script").length === 0, "diff has no injected elements"); }
  out.removedLines = dels.length;

  // 9. PR text and report tabs
  btn("PR text").click();
  await waitFor(() => { const p = root().querySelector("pre"); return p && p.textContent.length > 20; }, "PR text", 15000);
  btn("Full report").click();
  await waitFor(() => { const p = root().querySelector("pre"); return p && /report/i.test(p.textContent); }, "report text", 15000);

  // 10. start over resets to the form
  btn("\u2190 Check another repository").click();
  assert(q("#url") && !q(".tabs"), "back to the form");
  console.log("UI-SMOKE-OK " + JSON.stringify(out));
  process.exit(0);
})().catch((e) => { console.error("UI-SMOKE-FAIL " + e.message); process.exit(1); });
