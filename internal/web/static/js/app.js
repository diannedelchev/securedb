// SecureDB client helpers: toasts, modal handling, editor conveniences.
(function () {
  "use strict";

  // --- Toasts -------------------------------------------------------------
  window.toast = function (kind, message) {
    var host = document.getElementById("toasts");
    if (!host) return;
    var el = document.createElement("div");
    el.className = "toast toast-" + (kind || "info");
    el.textContent = message;
    host.appendChild(el);
    setTimeout(function () {
      el.style.opacity = "0";
      el.style.transition = "opacity 0.3s";
      setTimeout(function () { el.remove(); }, 320);
    }, 4200);
  };

  // Responses rendered into #toast-sink become floating toasts.
  document.addEventListener("htmx:afterSwap", function (evt) {
    var sink = evt.detail && evt.detail.target;
    if (!sink || sink.id !== "toast-sink") return;
    var t = sink.querySelector("[data-toast]");
    if (t) {
      window.toast(t.getAttribute("data-kind") || "info", t.textContent.trim());
      sink.innerHTML = "";
    }
  });

  document.addEventListener("htmx:responseError", function (evt) {
    var xhr = evt.detail.xhr;
    window.toast("error", xhr && xhr.status ? "Request failed (" + xhr.status + ")" : "Request failed");
  });

  // --- Modals -------------------------------------------------------------
  window.openModal = function (id) {
    var m = document.getElementById(id);
    if (m) m.style.display = "grid";
  };
  window.closeModal = function (id) {
    var m = document.getElementById(id);
    if (m) m.style.display = "none";
  };
  document.addEventListener("click", function (e) {
    if (e.target.classList && e.target.classList.contains("modal-backdrop")) {
      e.target.style.display = "none";
    }
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      document.querySelectorAll(".modal-backdrop").forEach(function (m) { m.style.display = "none"; });
    }
  });

  // --- SQL editor helpers ---------------------------------------------------
  // Client-generated run id lets the Stop button cancel an in-flight query.
  window.newRunId = function () {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
      var r = (Math.random() * 16) | 0;
      return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
    });
  };

  window.setEditorSQL = function (sql) {
    var ta = document.getElementById("sql-input");
    if (ta) {
      ta.value = sql;
      ta.focus();
    }
  };

  // Ctrl/Cmd+Enter executes the query.
  document.addEventListener("keydown", function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      var btn = document.getElementById("btn-execute");
      if (btn) { e.preventDefault(); btn.click(); }
    }
  });

  // --- SQL editor: line-number gutter, connection chips, copy rows ---------
  function refreshGutter() {
    var ta = document.getElementById("sql-input");
    var gutter = document.getElementById("sql-gutter");
    if (!ta || !gutter) return;
    var lines = ta.value.split("\n").length || 1;
    var out = [];
    for (var i = 1; i <= lines; i++) out.push(i);
    gutter.textContent = out.join("\n");
    gutter.scrollTop = ta.scrollTop;
  }

  function refreshConnMeta() {
    var sel = document.getElementById("connection-select");
    if (!sel) return;
    var opt = sel.options[sel.selectedIndex];
    var env = opt ? opt.getAttribute("data-env") : null;
    var ro = opt && opt.getAttribute("data-ro") === "1";

    var banner = document.getElementById("prod-banner");
    if (banner) banner.style.display = env === "production" ? "flex" : "none";

    var chip = document.getElementById("conn-env-chip");
    if (chip) {
      if (!env) {
        chip.style.display = "none";
      } else {
        chip.style.display = "inline-block";
        chip.textContent = { production: "PROD", staging: "STAGING", development: "DEV" }[env] || env.toUpperCase();
        chip.className = "chip " + ({ production: "chip-prod", staging: "chip-staging" }[env] || "chip-dev");
      }
    }
    var roChip = document.getElementById("ro-chip");
    if (roChip) roChip.style.display = ro ? "inline-block" : "none";

    var limit = document.getElementById("limit-chip");
    if (limit && env) {
      var v = limit.getAttribute("data-limit-" + env);
      if (v) limit.textContent = "LIMIT " + v;
    }
    var dot = document.getElementById("conn-dot");
    if (dot) dot.style.background = env ? "var(--green)" : "var(--text-faint)";
  }

  window.copyResultRows = function (btn) {
    var table = document.querySelector("#query-result .rg-table");
    if (!table) return;
    var lines = [];
    table.querySelectorAll("tr").forEach(function (tr) {
      var cells = [];
      tr.querySelectorAll("th,td").forEach(function (c, i) {
        if (i === 0) return; // skip row-number column
        cells.push(c.textContent.replace(/\s*masked\s*$/, "").trim());
      });
      lines.push(cells.join("\t"));
    });
    navigator.clipboard.writeText(lines.join("\n")).then(function () {
      window.toast("success", "Rows copied to clipboard");
    }, function () {
      window.toast("error", "Clipboard unavailable");
    });
  };

  // --- Database explorer helpers -------------------------------------------
  window.xpTab = function (tab, key) {
    document.querySelectorAll(".xp-tab").forEach(function (t) { t.classList.remove("on"); });
    tab.classList.add("on");
    document.querySelectorAll(".xp-pane").forEach(function (p) { p.style.display = "none"; });
    var pane = document.getElementById("xp-pane-" + key);
    if (pane) pane.style.display = "block";
  };

  window.filterTree = function (q) {
    q = q.toLowerCase();
    document.querySelectorAll("#xp-tree .tree-item").forEach(function (item) {
      var match = item.textContent.toLowerCase().indexOf(q) !== -1;
      item.parentElement.style.display = !q || match ? "" : "none";
    });
  };

  function refreshExplorerConn() {
    var sel = document.getElementById("explorer-conn");
    if (!sel) return;
    var opt = sel.options[sel.selectedIndex];
    var env = opt ? opt.getAttribute("data-env") : null;
    var chip = document.getElementById("xp-env-chip");
    if (chip) {
      if (!env) {
        chip.style.display = "none";
      } else {
        chip.style.display = "inline-block";
        chip.textContent = { production: "PROD", staging: "STAGING", development: "DEV" }[env] || env;
        chip.className = "chip " + ({ production: "chip-prod", staging: "chip-staging" }[env] || "chip-dev");
      }
    }
    var open = document.getElementById("xp-open-editor");
    if (open) open.href = sel.value ? "/editor?connection=" + sel.value : "/editor";
  }

  document.addEventListener("DOMContentLoaded", function () {
    var xsel = document.getElementById("explorer-conn");
    if (xsel) {
      xsel.addEventListener("change", refreshExplorerConn);
      refreshExplorerConn();
    }
    var ta = document.getElementById("sql-input");
    if (ta) {
      ta.addEventListener("input", function () {
        refreshGutter();
        var tab = document.getElementById("editor-tab");
        if (tab) tab.classList.add("is-dirty");
      });
      ta.addEventListener("scroll", refreshGutter);
      refreshGutter();
    }
    var sel = document.getElementById("connection-select");
    if (sel) {
      sel.addEventListener("change", refreshConnMeta);
      refreshConnMeta();
    }
  });
})();
