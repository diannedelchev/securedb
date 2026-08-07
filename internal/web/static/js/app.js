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
      refreshGutter();
      refreshHighlight();
    }
  };

  // Ctrl/Cmd+Enter executes the query.
  document.addEventListener("keydown", function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      var btn = document.getElementById("btn-execute");
      if (btn) { e.preventDefault(); btn.click(); }
    }
  });

  // --- SQL editor: syntax highlighting --------------------------------------
  // A <pre> render layer sits behind the transparent-text textarea; on every
  // edit the SQL is re-tokenized into colored spans and scroll is kept in sync.
  var SQL_KEYWORDS = new Set((
    "select from where and or not null insert into values update set delete " +
    "create table alter drop index view materialized sequence trigger function procedure " +
    "join left right inner outer full cross on as order by group having limit offset " +
    "distinct union all intersect except case when then else end if exists in is like " +
    "ilike similar between asc desc nulls first last primary key foreign references " +
    "default constraint unique check begin commit rollback transaction savepoint " +
    "explain analyze vacuum grant revoke truncate returning with recursive over " +
    "partition window using natural cast collate true false unknown add column rename " +
    "to database schema temp temporary replace show describe use lateral fetch only " +
    "row rows filter within escape any some current_date current_time current_timestamp " +
    "int integer bigint smallint serial bigserial text varchar char character boolean bool " +
    "date timestamp timestamptz time interval numeric decimal float real double precision " +
    "json jsonb uuid bytea array enum money bit varying"
  ).split(" "));

  function escapeHTML(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  var SQL_TOKEN_RE = new RegExp(
    "(\\/\\*[\\s\\S]*?(?:\\*\\/|$))" +          // 1 block comment
    "|(--[^\\n]*|#[^\\n]*)" +                    // 2 line comment
    "|('(?:[^']|'')*'?)" +                       // 3 string ('' escapes)
    "|(\"(?:[^\"]|\"\")*\"?|`[^`\\n]*`?)" +      // 4 quoted identifier
    "|(\\b0x[0-9a-fA-F]+\\b|\\b\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?\\b)" + // 5 number
    "|([A-Za-z_][A-Za-z0-9_$]*)" +               // 6 word
    "|(::|[+\\-*/%<>=!|&~^@#]+)",                // 7 operator
    "g"
  );

  function highlightSQL(src) {
    var out = "";
    var last = 0;
    var m;
    SQL_TOKEN_RE.lastIndex = 0;
    while ((m = SQL_TOKEN_RE.exec(src)) !== null) {
      out += escapeHTML(src.slice(last, m.index));
      last = SQL_TOKEN_RE.lastIndex;
      var text = escapeHTML(m[0]);
      if (m[1] || m[2]) {
        out += '<span class="sql-com">' + text + "</span>";
      } else if (m[3]) {
        out += '<span class="sql-str">' + text + "</span>";
      } else if (m[4]) {
        out += text; // quoted identifiers keep the base color
      } else if (m[5]) {
        out += '<span class="sql-num">' + text + "</span>";
      } else if (m[6]) {
        if (SQL_KEYWORDS.has(m[0].toLowerCase())) {
          out += '<span class="sql-kw">' + text + "</span>";
        } else if (src.slice(last).match(/^\s*\(/)) {
          out += '<span class="sql-fn">' + text + "</span>";
        } else {
          out += text;
        }
      } else {
        out += '<span class="sql-op">' + text + "</span>";
      }
    }
    return out + escapeHTML(src.slice(last));
  }

  function syncHighlightScroll() {
    var ta = document.getElementById("sql-input");
    var layer = document.getElementById("sql-highlight");
    if (!ta || !layer) return;
    layer.scrollTop = ta.scrollTop;
    layer.scrollLeft = ta.scrollLeft;
  }

  function refreshHighlight() {
    var ta = document.getElementById("sql-input");
    var layer = document.getElementById("sql-highlight");
    if (!ta || !layer) return;
    // Trailing newline keeps the layer's height in step with the textarea
    // when the caret sits on a fresh last line.
    layer.innerHTML = highlightSQL(ta.value) + "\n";
    syncHighlightScroll();
  }

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

  // --- SQL editor: resizable panes (persisted on the user profile) ---------
  // Bounds mirror the server-side clamps in users.SaveEditorLayout.
  var PANE = {
    tree: { min: 160, max: 480, def: 216 },
    editor: { min: 100, max: 900, def: 252 }
  };

  function clamp(v, b) { return Math.min(b.max, Math.max(b.min, v)); }

  function csrfToken() {
    try {
      return JSON.parse(document.body.getAttribute("hx-headers"))["X-CSRF-Token"] || "";
    } catch (e) { return ""; }
  }

  function initEditorResize() {
    var root = document.getElementById("sqled");
    var tree = document.querySelector(".sqled-tree");
    var editor = document.querySelector(".sqled-editor");
    if (!root || !tree || !editor) return;

    // Apply the layout saved on the user profile (empty attribute = defaults).
    var saved = {};
    try { saved = JSON.parse(root.getAttribute("data-layout") || "{}") || {}; } catch (e) {}
    if (saved.tree_width) tree.style.width = clamp(saved.tree_width, PANE.tree) + "px";
    if (saved.editor_height) editor.style.height = clamp(saved.editor_height, PANE.editor) + "px";

    var saveTimer = null;
    function persistLayout() {
      clearTimeout(saveTimer);
      saveTimer = setTimeout(function () {
        var body = new URLSearchParams();
        body.set("_csrf", csrfToken());
        body.set("tree_width", Math.round(tree.getBoundingClientRect().width));
        body.set("editor_height", Math.round(editor.getBoundingClientRect().height));
        fetch("/profile/editor-layout", { method: "POST", body: body }).catch(function () {});
      }, 400);
    }

    function bindResizer(handle, onMove, reset) {
      if (!handle) return;
      handle.addEventListener("pointerdown", function (e) {
        e.preventDefault();
        handle.setPointerCapture(e.pointerId);
        handle.classList.add("dragging");
        document.body.classList.add("sqled-resizing");
        function move(ev) { onMove(ev); }
        function up() {
          handle.classList.remove("dragging");
          document.body.classList.remove("sqled-resizing");
          handle.removeEventListener("pointermove", move);
          handle.removeEventListener("pointerup", up);
          handle.removeEventListener("pointercancel", up);
          persistLayout();
        }
        handle.addEventListener("pointermove", move);
        handle.addEventListener("pointerup", up);
        handle.addEventListener("pointercancel", up);
      });
      handle.addEventListener("dblclick", function () {
        reset();
        persistLayout();
      });
    }

    bindResizer(document.getElementById("tree-resizer"), function (ev) {
      tree.style.width = clamp(ev.clientX - tree.getBoundingClientRect().left, PANE.tree) + "px";
    }, function () {
      tree.style.width = PANE.tree.def + "px";
    });

    bindResizer(document.getElementById("editor-resizer"), function (ev) {
      editor.style.height = clamp(ev.clientY - editor.getBoundingClientRect().top, PANE.editor) + "px";
    }, function () {
      editor.style.height = PANE.editor.def + "px";
    });
  }

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
        refreshHighlight();
        var tab = document.getElementById("editor-tab");
        if (tab) tab.classList.add("is-dirty");
      });
      ta.addEventListener("scroll", function () {
        refreshGutter();
        syncHighlightScroll();
      });
      refreshGutter();
      refreshHighlight();
    }
    var sel = document.getElementById("connection-select");
    if (sel) {
      sel.addEventListener("change", refreshConnMeta);
      refreshConnMeta();
    }
    initEditorResize();
  });
})();
