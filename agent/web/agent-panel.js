/* <maintenance-agent-panel api="" token=""></maintenance-agent-panel>
 *
 * Self-contained Web Component (no framework, no build step). Flow:
 *   1. enter a GitHub URL + mode  ->  2. read the access notice and TYPE the repo name to consent
 *   3. watch the backend run the agent  ->  4. see findings and the generated code (patch), copy/download it.
 *
 * SECURITY: nothing derived from a repository (symbol names, paths, comment excerpts, notes) is ever inserted as
 * HTML. Everything goes through h(), which only creates elements and text nodes. Do not add innerHTML here.
 */
(() => {
  const STAGES = [
    ["consent", "Authorisation recorded"], ["intake", "Clone repository (read-only)"], ["scan", "Scan for secrets and hostile text"],
    ["analyze", "Analyse dead and duplicate code"], ["baseline", "Run baseline tests (sandbox)"],
    ["plan_and_change", "Generate and verify the code change"], ["publish", "Prepare PR text / branch"],
  ];
  const ICON = { pending: "\u25CB", running: "\u25D4", done: "\u2713", failed: "\u2717" };
  const GITHUB_URL = /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/?$/;

  const CSS = `
    :host { display:block; font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; color:var(--fg);
      --bg:#ffffff; --fg:#1b1f24; --muted:#5b6670; --line:#d8dee4; --card:#f6f8fa; --accent:#0b6bcb; --accent-fg:#fff;
      --ok:#1a7f37; --ok-bg:#dafbe1; --warn:#9a6700; --warn-bg:#fff8c5; --bad:#cf222e; --bad-bg:#ffebe9;
      --add-bg:#e6ffec; --del-bg:#ffebe9; --hunk-bg:#ddf4ff; }
    @media (prefers-color-scheme: dark) { :host { --bg:#0d1117; --fg:#e6edf3; --muted:#8b949e; --line:#30363d; --card:#161b22;
      --accent:#4493f8; --accent-fg:#0d1117; --ok:#3fb950; --ok-bg:#12261e; --warn:#d29922; --warn-bg:#2d2208;
      --bad:#f85149; --bad-bg:#2d1214; --add-bg:#12261e; --del-bg:#2d1214; --hunk-bg:#0c2d4a; } }
    * { box-sizing:border-box; }
    .wrap { background:var(--bg); border:1px solid var(--line); border-radius:12px; padding:20px; max-width:980px; margin:0 auto; }
    h2 { margin:0 0 4px; font-size:20px; } h3 { margin:18px 0 8px; font-size:15px; }
    .sub { color:var(--muted); margin:0 0 16px; }
    label { display:block; font-weight:600; margin:12px 0 4px; }
    input[type=text], input[type=password], select { width:100%; padding:9px 10px; border:1px solid var(--line); border-radius:8px;
      background:var(--bg); color:var(--fg); font:inherit; }
    input:focus-visible, select:focus-visible, button:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
    button { font:inherit; border:1px solid var(--line); background:var(--card); color:var(--fg); padding:8px 14px; border-radius:8px; cursor:pointer; }
    button.primary { background:var(--accent); color:var(--accent-fg); border-color:var(--accent); font-weight:600; }
    button:disabled { opacity:.5; cursor:not-allowed; }
    .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-top:14px; }
    .err { margin-top:12px; padding:10px 12px; border-radius:8px; background:var(--bad-bg); color:var(--bad); border:1px solid var(--bad); }
    .note { padding:10px 12px; border-radius:8px; background:var(--warn-bg); color:var(--warn); border:1px solid var(--warn); margin:10px 0; }
    .ok { background:var(--ok-bg); color:var(--ok); border:1px solid var(--ok); padding:10px 12px; border-radius:8px; }
    pre { margin:0; padding:12px; background:var(--card); border:1px solid var(--line); border-radius:8px; overflow:auto;
      font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; white-space:pre-wrap; word-break:break-word; }
    .chip { display:inline-block; padding:1px 8px; border-radius:999px; font-size:12px; font-weight:600; border:1px solid var(--line); }
    .chip.high,.chip.trusted,.chip.READY,.chip.ready { background:var(--ok-bg); color:var(--ok); border-color:var(--ok); }
    .chip.medium,.chip.unknown { background:var(--warn-bg); color:var(--warn); border-color:var(--warn); }
    .chip.low,.chip.untrusted { background:var(--card); color:var(--muted); }
    .chip.bad { background:var(--bad-bg); color:var(--bad); border-color:var(--bad); }
    ul.steps { list-style:none; margin:8px 0; padding:0; } ul.steps li { padding:4px 0; display:flex; gap:10px; }
    ul.steps .ic { width:18px; text-align:center; } li.running { color:var(--accent); font-weight:600; } li.done { color:var(--ok); }
    li.failed { color:var(--bad); font-weight:600; } li.pending { color:var(--muted); }
    .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:10px; margin:14px 0; }
    .stat { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:10px 12px; }
    .stat b { display:block; font-size:22px; } .stat span { color:var(--muted); font-size:12px; }
    .tabs { display:flex; gap:4px; border-bottom:1px solid var(--line); margin-top:16px; flex-wrap:wrap; }
    .tabs button { border:none; border-bottom:2px solid transparent; border-radius:0; background:none; padding:8px 12px; }
    .tabs button[aria-selected=true] { border-bottom-color:var(--accent); font-weight:600; }
    table { width:100%; border-collapse:collapse; font-size:13px; } th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
    th { color:var(--muted); font-weight:600; } td.mono, .mono { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12px; word-break:break-all; }
    .scroll { overflow-x:auto; }
    .diff { border:1px solid var(--line); border-radius:8px; overflow:auto; max-height:520px; font:12px/1.5 ui-monospace,Menlo,Consolas,monospace; }
    .diff div { padding:0 10px; white-space:pre; } .diff .add { background:var(--add-bg); } .diff .del { background:var(--del-bg); }
    .diff .hunk { background:var(--hunk-bg); } .diff .meta { color:var(--muted); font-weight:600; }
    .muted { color:var(--muted); } a { color:var(--accent); }
    .back { background:none; border:none; padding:0; color:var(--accent); cursor:pointer; margin-bottom:10px; }
  `;

  // The ONLY way DOM is built: elements + text nodes. Never HTML strings.
  function h(tag, props = {}, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k.startsWith("on") && typeof v === "function") e.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === "class") e.className = v;
      else if (k === "value" || k === "disabled") e[k] = v;
      else e.setAttribute(k, v === true ? "" : String(v));
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid === null || kid === undefined || kid === false) continue;
      e.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return e;
  }

  class MaintenanceAgentPanel extends HTMLElement {
    constructor() {
      super();
      this.root = this.attachShadow({ mode: "open" });
      this.s = { view: "form", url: "", mode: "analyze", caps: null, notice: null, job: null, tab: "findings", err: "",
                 token: "", needToken: false, busy: false, filter: "all", patch: null, pr: null, report: null };
      this.timer = null;
    }

    connectedCallback() {
      this.api = (this.getAttribute("api") || "").replace(/\/$/, "");
      this.s.token = this.getAttribute("token") || "";
      try { this.s.token = this.s.token || sessionStorage.getItem("agentToken") || ""; } catch (e) { /* storage blocked */ }
      this.draw();
      this.loadCaps();
    }

    disconnectedCallback() { clearInterval(this.timer); }

    async call(method, path, body, text = false) {
      const headers = {};
      if (body !== undefined) headers["Content-Type"] = "application/json";
      if (this.s.token) headers["X-Agent-Token"] = this.s.token;
      let res;
      try {
        res = await fetch(this.api + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
      } catch (e) {
        return { ok: false, status: 0, data: { error: "Cannot reach the agent server." } };
      }
      if (res.status === 401) { this.s.needToken = true; }
      let data;
      try { data = text && res.ok ? await res.text() : await res.json(); } catch (e) { data = { error: "Unexpected response." }; }
      return { ok: res.ok, status: res.status, data };
    }

    async loadCaps() {
      const r = await this.call("GET", "/api/capabilities");
      if (r.ok) { this.s.caps = r.data; this.s.needToken = false; } else if (r.status !== 401) { this.s.err = r.data.error || "Server error"; }
      this.draw();
    }

    // ---------------------------------------------------------------- actions
    async reviewNotice() {
      this.s.err = "";
      const v = this.s.url.trim();
      // Courtesy check only; the server is the authority. Obvious web URLs that are not GitHub repos get a clear hint.
      if (!v || (/^https?:\/\//i.test(v) && !GITHUB_URL.test(v.replace(/\.git$/, "")))) {
        this.s.err = "Enter a GitHub URL like https://github.com/owner/name"; this.draw(); return;
      }
      this.s.busy = true; this.draw();
      const r = await this.call("POST", "/api/notice", { repo_url: this.s.url.trim(), mode: this.s.mode });
      this.s.busy = false;
      if (r.ok) { this.s.notice = r.data; this.s.view = "notice"; } else { this.s.err = r.data.error || "Request failed"; }
      this.draw();
    }

    async authorise(typed) {
      this.s.err = ""; this.s.busy = true; this.draw();
      const r = await this.call("POST", "/api/jobs", { repo_url: this.s.url.trim(), mode: this.s.mode, confirm: typed });
      this.s.busy = false;
      if (!r.ok) { this.s.err = r.data.error || "Could not start the job"; this.draw(); return; }
      this.s.job = { id: r.data.id, state: "queued", stages: Object.fromEntries(STAGES.map(([k]) => [k, "pending"])), summary: null };
      this.s.view = "running"; this.s.patch = this.s.pr = this.s.report = null; this.s.tab = "findings";
      this.draw();
      clearInterval(this.timer);
      this.timer = setInterval(() => this.poll(), 1200);
      this.poll();
    }

    async poll() {
      const r = await this.call("GET", `/api/jobs/${encodeURIComponent(this.s.job.id)}`);
      if (!r.ok) { clearInterval(this.timer); this.s.err = r.data.error || "Lost contact with the server"; this.draw(); return; }
      this.s.job = r.data;
      if (["done", "failed", "refused"].includes(r.data.state)) { clearInterval(this.timer); this.s.view = "result"; }
      this.draw();
    }

    async loadText(kind) {
      this.loading = this.loading || new Set();
      if (this.s[kind] !== null || this.loading.has(kind)) return;
      this.loading.add(kind);
      const r = await this.call("GET", `/api/jobs/${encodeURIComponent(this.s.job.id)}/${kind}`, undefined, true);
      this.s[kind] = r.ok ? r.data : `(${r.data.error || "not available"})`;
      this.loading.delete(kind);
      this.draw();
    }

    reset() { clearInterval(this.timer); this.loading = new Set(); Object.assign(this.s, { view: "form", notice: null, job: null, err: "", patch: null, pr: null, report: null }); this.draw(); }

    // ---------------------------------------------------------------- views
    draw() {
      const s = this.s;
      const body = s.view === "form" ? this.formView() : s.view === "notice" ? this.noticeView()
        : s.view === "running" ? this.runningView() : this.resultView();
      this.root.replaceChildren(h("style", {}, CSS), h("div", { class: "wrap" },
        h("h2", {}, "Code Maintenance Agent"),
        h("p", { class: "sub" }, "Paste a GitHub repository URL. The agent finds dead and duplicate code, checks it against your tests and generates a safe code change for you to review."),
        s.needToken ? this.tokenBox() : null, body));
    }

    errBox() { return this.s.err ? h("div", { class: "err", role: "alert" }, this.s.err) : null; }

    tokenBox() {
      const inp = h("input", { type: "password", id: "tok", value: this.s.token, autocomplete: "off" });
      return h("div", { class: "note" }, h("label", { for: "tok" }, "This server requires an access token"), inp,
        h("div", { class: "row" }, h("button", { onClick: () => {
          this.s.token = inp.value.trim(); try { sessionStorage.setItem("agentToken", this.s.token); } catch (e) { /* ignore */ }
          this.s.err = ""; this.loadCaps();
        } }, "Use token")));
    }

    formView() {
      const s = this.s, caps = s.caps;
      const url = h("input", { type: "text", id: "url", value: s.url, placeholder: "https://github.com/owner/name", autocomplete: "off", spellcheck: "false" });
      url.addEventListener("input", () => { s.url = url.value; });
      url.addEventListener("keydown", (e) => { if (e.key === "Enter") this.reviewNotice(); });
      const sel = h("select", { id: "mode" });
      for (const [key, m] of Object.entries(caps ? caps.modes : { analyze: { available: true, label: "Analyze" } })) {
        const o = h("option", { value: key, disabled: !m.available }, m.label + (m.available ? "" : ` (unavailable: ${m.reason})`));
        sel.append(o);
      }
      sel.value = s.mode;
      sel.addEventListener("change", () => { s.mode = sel.value; });
      return h("div", {},
        h("label", { for: "url" }, "GitHub repository URL"), url,
        h("label", { for: "mode" }, "What should the agent do?"), sel,
        h("p", { class: "muted" }, "Nothing is accessed yet. Next you will see exactly what the agent will do and confirm it."),
        this.errBox(),
        h("div", { class: "row" }, h("button", { class: "primary", disabled: s.busy, onClick: () => this.reviewNotice() }, s.busy ? "Checking..." : "Review access notice")));
    }

    noticeView() {
      const s = this.s, n = s.notice;
      const typed = h("input", { type: "text", id: "confirm", autocomplete: "off", spellcheck: "false", placeholder: n.slug });
      const go = h("button", { class: "primary", disabled: true, onClick: () => this.authorise(typed.value) }, "Authorise and run");
      typed.addEventListener("input", () => { go.disabled = s.busy || typed.value.trim().toLowerCase() !== n.slug.toLowerCase(); });
      return h("div", {},
        h("button", { class: "back", onClick: () => { s.view = "form"; s.err = ""; this.draw(); } }, "\u2190 Back"),
        h("h3", {}, "Access notice for ", h("span", { class: "mono" }, n.slug), " ", h("span", { class: `chip ${n.trust}` }, n.trust)),
        h("p", { class: "muted" }, n.trust_reason),
        h("ul", {}, Object.entries(n.scope_text).map(([k, v]) => h("li", {}, h("b", {}, k), ": ", v))),
        h("pre", {}, n.notice),
        h("label", { for: "confirm" }, `To authorise this access, type the repository name: ${n.slug}`), typed,
        this.errBox(),
        h("div", { class: "row" }, go, h("button", { onClick: () => this.reset() }, "Cancel")));
    }

    progress(stages) {
      return h("ul", { class: "steps", "aria-live": "polite" }, STAGES.map(([k, label]) => {
        const st = stages[k] || "pending";
        return h("li", { class: st }, h("span", { class: "ic", "aria-hidden": "true" }, ICON[st] || ICON.pending), label);
      }));
    }

    runningView() {
      const j = this.s.job;
      return h("div", {}, h("h3", {}, "Running on the server\u2026"), h("p", { class: "muted" }, `Job ${j.id}. You can leave this page open; results appear here.`),
        this.progress(j.stages || {}), this.errBox());
    }

    resultView() {
      const s = this.s, j = s.job, sum = j.summary;
      const head = j.state === "done" ? h("div", { class: "ok" }, "Completed. Review the findings and the generated code below; nothing has been changed in your repository unless a PR was opened.")
        : h("div", { class: "err", role: "alert" }, `${j.state === "refused" ? "Refused" : "Failed"}: ${j.error || "see details"}`);
      const out = [h("button", { class: "back", onClick: () => this.reset() }, "\u2190 Check another repository"),
        h("h3", {}, h("span", { class: "mono" }, j.repo), " \u00B7 ", j.mode), head];
      if (!sum) return h("div", {}, out, this.progress(j.stages || {}));
      const c = sum.counts;
      const stat = (n, label) => h("div", { class: "stat" }, h("b", {}, String(n)), h("span", {}, label));
      out.push(h("div", { class: "stats" }, stat(c.dead_code_high, "dead code: safe to remove"), stat(c.dead_code, "dead code: all findings"),
        stat(c.duplicates, "duplicate blocks"), stat(c.secrets, "possible secrets"), stat(c.injections, "hostile-text hits")));
      if (sum.consent) {
        const k = sum.consent;
        out.push(h("p", { class: "muted" }, `Authorised by ${k.granted_by} (${k.method}) \u00B7 permissions: ${k.scopes.join(", ")} \u00B7 trust: ${k.trust}`));
      }
      for (const n of sum.notes || []) out.push(h("div", { class: "note" }, n));
      const tabs = [["findings", "Findings"], ["code", "Generated code"], ["pr", "PR text"], ["report", "Full report"]];
      out.push(h("div", { class: "tabs", role: "tablist" }, tabs.map(([k, label]) => h("button", { role: "tab", "aria-selected": String(s.tab === k),
        onClick: () => { s.tab = k; if (k === "code") this.loadText("patch"); if (k === "pr") this.loadText("pr"); if (k === "report") this.loadText("report"); this.draw(); } }, label))));
      out.push(s.tab === "findings" ? this.findingsTab(sum) : s.tab === "code" ? this.codeTab(sum) : s.tab === "pr" ? this.textTab("pr", sum.has_pr_text, "No PR text was generated (no verified change set).")
        : this.textTab("report", true, ""));
      if (s.tab === "code" && s.patch === null && sum.has_patch) this.loadText("patch");
      return h("div", {}, out);
    }

    findingsTab(sum) {
      const s = this.s;
      const filt = h("select", { id: "flt", "aria-label": "Filter by confidence" }, ["all", "high", "medium", "low"].map((v) => h("option", { value: v }, v === "all" ? "All confidence levels" : `${v} confidence`)));
      filt.value = s.filter;
      filt.addEventListener("change", () => { s.filter = filt.value; this.draw(); });
      const dead = sum.findings.dead_code.filter((f) => s.filter === "all" || f.confidence === s.filter);
      const sec = sum.security;
      return h("div", {},
        h("h3", {}, "Dead code"), filt,
        dead.length ? h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, ["Confidence", "Symbol", "Location", "Action", "Why"].map((t) => h("th", {}, t)))),
          h("tbody", {}, dead.map((f) => h("tr", {}, h("td", {}, h("span", { class: `chip ${f.confidence}` }, f.confidence)), h("td", { class: "mono" }, f.symbol),
            h("td", { class: "mono" }, `${f.file}:${f.line}`), h("td", {}, f.proposed_action === "remove" ? (f.status === "included_in_pr" ? "removed in patch" : "eligible") : "report only"),
            h("td", {}, f.evidence[f.evidence.length - 1] || ""))))))
          : h("p", { class: "muted" }, "No dead-code findings at this confidence level."),
        h("p", { class: "muted" }, "Only HIGH findings (private, unreferenced, no framework wiring) can ever be removed, and only if your tests still pass."),
        h("h3", {}, "Duplicate code (report only)"),
        sum.findings.duplicates.length ? h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, ["Location A", "Location B", "Detail"].map((t) => h("th", {}, t)))),
          h("tbody", {}, sum.findings.duplicates.map((d) => h("tr", {}, h("td", { class: "mono" }, `${d.file}:${d.line}-${d.end_line}`),
            h("td", { class: "mono" }, `${d.related[0].file}:${d.related[0].start}-${d.related[0].end}`), h("td", {}, d.evidence[0]))))))
          : h("p", { class: "muted" }, "No duplicate blocks found."),
        h("h3", {}, "Security observations"),
        sec.secrets.length ? h("ul", {}, sec.secrets.map((x) => h("li", {}, h("span", { class: "mono" }, `${x.file}:${x.line}`), ` possible ${x.kind} (${x.preview})`))) : h("p", { class: "muted" }, "No secrets detected."),
        sec.sensitive_files.length ? h("p", {}, "Sensitive files present (never opened): ", h("span", { class: "mono" }, sec.sensitive_files.join(", "))) : null,
        sec.injections.length ? h("div", {}, h("p", {}, "Instruction-like text aimed at AI agents was found. It was treated as data and not obeyed:"),
          h("ul", {}, sec.injections.map((x) => h("li", {}, h("span", { class: "mono" }, `${x.file}:${x.line}`), " ", h("span", { class: "mono" }, x.excerpt))))) : null);
    }

    codeTab(sum) {
      const s = this.s;
      if (!sum.change_sets.length) {
        const b = sum.baseline;
        return h("div", {}, h("h3", {}, "No code change was generated"),
          h("p", {}, sum.counts.dead_code_high === 0 ? "No finding was safe enough to change automatically."
            : "Safe candidates exist, but the agent needs to run your tests to prove a change is safe. Choose the Verify mode."),
          b && !b.green ? h("div", { class: "note" }, `Baseline not usable: ${b.reason}`) : null);
      }
      const parts = [];
      for (const cs of sum.change_sets) {
        parts.push(h("h3", {}, `Change set ${cs.id}: `, h("span", { class: `chip ${cs.decision === "ready" ? "ready" : "bad"}` }, cs.decision.toUpperCase())),
          h("p", {}, `${cs.findings.length} symbol(s) removed \u00B7 `, h("span", { class: "mono" }, (cs.files || []).join(", ")), ` \u00B7 +${cs.added || 0} / \u2212${cs.removed || 0} lines`),
          cs.gates && cs.gates.length ? h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, ["Gate", "Result", "Detail"].map((t) => h("th", {}, t)))),
            h("tbody", {}, cs.gates.map((g) => h("tr", {}, h("td", {}, g.name), h("td", {}, h("span", { class: `chip ${g.passed ? "ready" : "bad"}` }, g.passed ? "PASS" : "FAIL")), h("td", {}, g.detail)))))) : null);
      }
      const patch = s.patch;
      if (!sum.has_patch) parts.push(h("p", { class: "muted" }, "No patch file was produced for this run."));
      else if (patch === null) parts.push(h("p", { class: "muted" }, "Loading patch\u2026"));
      else {
        const name = `${s.job.repo.replace("/", "__")}-${s.job.id}.diff`;
        parts.push(h("h3", {}, "Generated code (unified diff)"),
          h("div", { class: "row" },
            h("button", { onClick: async (e) => { try { await navigator.clipboard.writeText(patch); e.target.textContent = "Copied"; } catch (err) { e.target.textContent = "Copy failed"; } } }, "Copy patch"),
            h("button", { onClick: () => this.download(name, patch) }, "Download .diff")),
          h("div", { class: "diff", tabindex: "0", "aria-label": "Generated patch" }, patch.split("\n").map((line) => {
            const cls = /^(\+\+\+|---|diff |index )/.test(line) ? "meta" : line.startsWith("@@") ? "hunk" : line.startsWith("+") ? "add" : line.startsWith("-") ? "del" : "";
            return h("div", { class: cls }, line || " ");
          })),
          h("h3", {}, "Apply it yourself"), h("pre", {}, `git checkout -b agent/dead-code-manual\ngit apply ${name}\n# run your tests, then review and commit`));
      }
      return h("div", {}, parts);
    }

    download(name, text) {
      try {
        const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
        const a = h("a", { href: url, download: name }); this.root.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
      } catch (e) { /* unavailable: user can still copy */ }
    }

    textTab(kind, available, emptyMsg) {
      if (!available) return h("p", { class: "muted" }, emptyMsg);
      const t = this.s[kind];
      if (t === null) { this.loadText(kind); return h("p", { class: "muted" }, "Loading\u2026"); }
      return h("pre", {}, t);
    }
  }

  if (!customElements.get("maintenance-agent-panel")) customElements.define("maintenance-agent-panel", MaintenanceAgentPanel);
})();
