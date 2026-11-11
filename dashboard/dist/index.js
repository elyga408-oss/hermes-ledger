(function () {
  "use strict";
  const SDK = window.__HERMES_PLUGIN_SDK__;
  const { React } = SDK;
  const { useState, useEffect, useCallback } = SDK.hooks;
  const { Card, CardHeader, CardTitle, CardContent, Badge, Button } = SDK.components;
  const h = React.createElement;

  function detail(r) {
    if (r.kind === "tool_call") return JSON.stringify(r.args_redacted);
    if (r.kind === "tool_result") {
      let t = (r.status || "done") + (r.duration_ms != null ? " " + r.duration_ms + "ms" : "");
      t += " sha256:" + String(r.result_sha256 || "").slice(0, 12);
      if (r.approval_seq != null) t += " approved by #" + r.approval_seq;
      return t;
    }
    if (r.kind === "approval") {
      const a = r.approval || {};
      return (a.choice || "?") + " via " + (a.surface || "?") +
        (a.binds_seq != null ? " -> call #" + a.binds_seq : "");
    }
    return r.note || "";
  }

  function LedgerPage() {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const load = useCallback(function () {
      SDK.fetchJSON("/api/plugins/hermes-ledger/status?last=100")
        .then(function (d) { setData(d); setError(null); })
        .catch(function (e) { setError(String(e)); });
    }, []);
    useEffect(function () {
      load();
      const t = setInterval(load, 5000);
      return function () { clearInterval(t); };
    }, [load]);

    const v = data && data.verify;
    const badge = v
      ? h(Badge, {
          className: v.ok ? "bg-green-600 text-white" : "bg-red-600 text-white",
        }, v.ok ? "chain intact" : "chain broken")
      : null;

    const rows = data ? data.records.slice().reverse().map(function (r) {
      const bad = v && !v.ok && v.broken_seq != null && r.seq >= v.broken_seq;
      return h("tr", { key: r.seq + ":" + r.hash, className: bad ? "text-red-500" : "" },
        h("td", { className: "pr-3 text-right tabular-nums", style: { paddingRight: "1rem", textAlign: "right", verticalAlign: "top" } }, r.seq),
        h("td", { className: "pr-3 whitespace-nowrap", style: { paddingRight: "1rem", whiteSpace: "nowrap", verticalAlign: "top" } }, String(r.ts || "").slice(11, 19)),
        h("td", { className: "pr-3", style: { paddingRight: "1rem", whiteSpace: "nowrap", verticalAlign: "top" } }, r.kind),
        h("td", { className: "pr-3", style: { paddingRight: "1rem", whiteSpace: "nowrap", verticalAlign: "top" } }, r.tool || "-"),
        h("td", { className: "font-mono text-xs break-all" }, detail(r)));
    }) : [];

    return h(Card, null,
      h(CardHeader, null,
        h(CardTitle, { className: "flex items-center gap-3" }, "Ledger", badge,
          h(Button, { onClick: load, size: "sm", variant: "outline" }, "Refresh"))),
      h(CardContent, null,
        error ? h("p", { className: "text-sm text-red-500" }, error) : null,
        v ? h("p", { className: "text-sm text-muted-foreground mb-3" }, v.summary) : null,
        h("table", { className: "w-full text-sm" },
          h("thead", null, h("tr", { className: "text-left text-muted-foreground" },
            h("th", { className: "pr-3 text-right", style: { paddingRight: "1rem", textAlign: "right" } }, "seq"), h("th", { style: { paddingRight: "1rem" } }, "time"),
            h("th", { style: { paddingRight: "1rem" } }, "kind"), h("th", { style: { paddingRight: "1rem" } }, "tool"), h("th", null, "detail"))),
          h("tbody", null, rows))));
  }

  window.__HERMES_PLUGINS__.register("hermes-ledger", LedgerPage);
})();
