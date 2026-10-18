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

  // One token stream feeds both the highlighter and the formatter, so the two
  // can never disagree about where a string or comment starts. Dollar-quoted
  // bodies ($$...$$) are matched whole — their contents are opaque and must
  // survive formatting untouched.
  var SQL_TOKEN_RE = new RegExp(
    "(\\/\\*[\\s\\S]*?(?:\\*\\/|$))" +          // 1 block comment
    "|(--[^\\n]*|#[^\\n]*)" +                    // 2 line comment
    "|(\\$([A-Za-z_]\\w*)?\\$[\\s\\S]*?\\$\\3\\$)" + // 3 dollar-quoted string (4 = tag)
    "|('(?:[^']|'')*'?)" +                       // 5 string ('' escapes)
    "|(\"(?:[^\"]|\"\")*\"?|`[^`\\n]*`?)" +      // 6 quoted identifier
    "|(\\b0x[0-9a-fA-F]+\\b|\\b\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?\\b)" + // 7 number
    "|([A-Za-z_][A-Za-z0-9_$]*)" +               // 8 word
    "|([(),;.])" +                               // 9 punctuation
    "|(::|[+\\-*/%<>=!|&~^@#]+)" +               // 10 operator
    "|(\\s+)",                                   // 11 whitespace
    "g"
  );

  // Returns [{t, v}] where t is one of: com str ident num word punct op ws other.
  // Concatenating every .v reproduces the input exactly.
  function tokenizeSQL(src) {
    var toks = [];
    var last = 0;
    var m;
    SQL_TOKEN_RE.lastIndex = 0;
    while ((m = SQL_TOKEN_RE.exec(src)) !== null) {
      if (m.index > last) toks.push({ t: "other", v: src.slice(last, m.index) });
      last = SQL_TOKEN_RE.lastIndex;
      var t = m[1] || m[2] ? "com"
        : m[3] ? "str"
        : m[5] ? "str"
        : m[6] ? "ident"
        : m[7] ? "num"
        : m[8] ? "word"
        : m[9] ? "punct"
        : m[10] ? "op"
        : "ws";
      // A line comment swallows everything to the newline; the formatter needs
      // to know so it never joins code onto that line.
      toks.push({ t: t, v: m[0], line: !!m[2] });
    }
    if (last < src.length) toks.push({ t: "other", v: src.slice(last) });
    return toks;
  }

  function highlightSQL(src) {
    var toks = tokenizeSQL(src);
    var out = "";
    for (var i = 0; i < toks.length; i++) {
      var tok = toks[i];
      var text = escapeHTML(tok.v);
      if (tok.t === "com") {
        out += '<span class="sql-com">' + text + "</span>";
      } else if (tok.t === "str") {
        out += '<span class="sql-str">' + text + "</span>";
      } else if (tok.t === "num") {
        out += '<span class="sql-num">' + text + "</span>";
      } else if (tok.t === "word") {
        if (SQL_KEYWORDS.has(tok.v.toLowerCase())) {
          out += '<span class="sql-kw">' + text + "</span>";
        } else if (nextCode(toks, i) === "(") {
          out += '<span class="sql-fn">' + text + "</span>";
        } else {
          out += text;
        }
      } else if (tok.t === "op") {
        out += '<span class="sql-op">' + text + "</span>";
      } else {
        out += text; // quoted identifiers, punctuation and whitespace stay plain
      }
    }
    return out;
  }

  // First non-whitespace, non-comment token value after index i ("" at end).
  function nextCode(toks, i) {
    for (var j = i + 1; j < toks.length; j++) {
      if (toks[j].t !== "ws" && toks[j].t !== "com") return toks[j].v;
    }
    return "";
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

  // --- SQL editor: formatter ------------------------------------------------
  // Clause keywords that begin a new line at the current nesting depth.
  var FMT_MAJOR = new Set((
    "select from where having limit offset values set returning union intersect " +
    "except join insert update delete with window group order fetch " +
    "left right inner full cross natural"
  ).split(" "));
  // Words that bind to a following major keyword, so it stays on the same line
  // ("LEFT JOIN", "DELETE FROM", "GROUP BY", "UNION ALL", "INSERT INTO").
  var FMT_BINDS_NEXT = new Set(
    "left right inner outer full cross natural lateral delete insert union except intersect with".split(" ")
  );
  // Indented continuation keywords inside a clause.
  var FMT_INDENT_KW = new Set("and or on".split(" "));

  function fmtIndent(n) {
    var s = "";
    for (var i = 0; i < n; i++) s += "  ";
    return s;
  }

  // Reflows SQL onto clause-per-line with two-space nesting. Strings, comments
  // and dollar-quoted bodies pass through byte-for-byte; only whitespace between
  // tokens and the case of recognised keywords change.
  function formatSQL(src) {
    var toks = tokenizeSQL(src).filter(function (t) { return t.t !== "ws"; });
    var out = "";
    var depth = 0;
    var atLineStart = true;
    var noSpace = false;   // suppress the space before the next token
    var curExtra = 0;      // indent offset of the line being built
    // For each open paren, whether it wraps a subquery (gets its own lines).
    var parenStack = [];
    var prevWord = "";
    var prevType = "";

    function newline(extra) {
      extra = extra || 0;
      out = out.replace(/[ \t]+$/, "");
      if (atLineStart) {
        // Already on a fresh line — just correct its indent, never blank-pad.
        out = out.replace(/[^\n]*$/, fmtIndent(depth + extra));
      } else {
        out += "\n" + fmtIndent(depth + extra);
      }
      atLineStart = true;
      noSpace = false;
      curExtra = extra;
    }
    function write(text) {
      if (!atLineStart && !noSpace && out !== "" && !/\s$/.test(out)) out += " ";
      out += text;
      atLineStart = false;
      noSpace = false;
    }
    // Append with no separating space (qualifiers, casts, call parens).
    function writeTight(text) {
      out = out.replace(/[ \t]+$/, "");
      out += text;
      atLineStart = false;
      noSpace = false;
    }

    for (var i = 0; i < toks.length; i++) {
      var tok = toks[i];
      var v = tok.v;
      var lower = v.toLowerCase();

      if (tok.t === "com") {
        if (!atLineStart) out += " ";
        out += v;
        atLineStart = false;
        // Anything after a line comment would be commented out; force a break
        // that keeps the indent of the clause we were building.
        if (tok.line) newline(curExtra);
        prevType = "com";
        continue;
      }

      if (tok.t === "punct") {
        if (v === ".") {
          writeTight(".");
          noSpace = true;      // t.col stays glued on both sides
        } else if (v === "(") {
          // `count(` is a call; `IN (` and `VALUES (` keep their space.
          var isCall = (prevType === "word" && !SQL_KEYWORDS.has(prevWord)) || prevType === "ident";
          var sub = nextCode(toks, i).toLowerCase() === "select";
          parenStack.push(sub);
          if (isCall) writeTight("("); else write("(");
          if (sub) {
            depth++;
            newline();
          } else {
            noSpace = true;    // no gap after the paren
          }
        } else if (v === ")") {
          var wasSub = parenStack.pop();
          if (wasSub) {
            depth = Math.max(0, depth - 1);
            newline();
          }
          writeTight(")");
        } else if (v === ",") {
          writeTight(",");
          // Break the select/insert list only at the statement's own level;
          // inside a function call the arguments stay inline.
          if (parenStack.length === 0) newline(1);
        } else { // ;
          writeTight(";");
          depth = 0;
          parenStack = [];
          newline();
          out += "\n" + fmtIndent(0); // blank line between statements
          atLineStart = true;
        }
        prevWord = "";
        prevType = "punct";
        continue;
      }

      if (tok.t === "word") {
        var isKw = SQL_KEYWORDS.has(lower);
        var text = isKw ? v.toUpperCase() : v;
        if (FMT_MAJOR.has(lower) && !FMT_BINDS_NEXT.has(prevWord) && out !== "") {
          newline();
        } else if (FMT_INDENT_KW.has(lower) && out !== "") {
          newline(1);
        }
        write(text);
        prevWord = lower;
        prevType = "word";
        continue;
      }

      if (tok.t === "op" && (v === "::" || v === ".")) {
        writeTight(v);
        noSpace = true;
        prevWord = "";
        prevType = "op";
        continue;
      }

      write(v);
      prevWord = "";
      prevType = tok.t;
    }

    return out.split("\n").map(function (l) {
      return l.replace(/\s+$/, "");
    }).join("\n").replace(/\n{3,}/g, "\n\n").trim();
  }

  // Formatting must never alter the statement. Compare the meaningful token
  // streams before and after; if they differ in any way the reflow is unsafe
  // and gets discarded rather than handed back to the user.
  function formatIsLossless(before, after) {
    function sig(s) {
      return tokenizeSQL(s)
        .filter(function (t) { return t.t !== "ws"; })
        .map(function (t) {
          // Keyword case is intentionally changed; nothing else may differ.
          return t.t === "word" ? t.t + ":" + t.v.toLowerCase() : t.t + ":" + t.v;
        })
        .join("\x00");
    }
    return sig(before) === sig(after);
  }

  window.formatEditorSQL = function () {
    var ta = document.getElementById("sql-input");
    if (!ta) return;
    var src = ta.value;
    if (!src.trim()) {
      window.toast("info", "Nothing to format");
      return;
    }
    var formatted;
    try {
      formatted = formatSQL(src);
    } catch (e) {
      window.toast("error", "Could not format this SQL");
      return;
    }
    if (!formatIsLossless(src, formatted)) {
      window.toast("error", "Formatting skipped — it would have altered this SQL");
      return;
    }
    if (formatted === src) {
      window.toast("info", "Already formatted");
      return;
    }
    var top = ta.scrollTop;
    ta.value = formatted;
    ta.scrollTop = top;
    refreshGutter();
    refreshHighlight();
    var tab = document.getElementById("editor-tab");
    if (tab) tab.classList.add("is-dirty");
    window.toast("success", "SQL formatted");
  };

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

  // --- Result export --------------------------------------------------------
  // Exports are built from the rendered grid rather than by re-running the
  // query: that keeps the file identical to what the user was shown, preserves
  // server-side column masking, and avoids a second hit on the target database.

  // Header text without the "masked" badge — take only direct text nodes.
  function headerName(th) {
    var s = "";
    for (var i = 0; i < th.childNodes.length; i++) {
      var n = th.childNodes[i];
      if (n.nodeType === 3) s += n.nodeValue;
    }
    return s.trim();
  }

  function readResultGrid() {
    var table = document.querySelector("#query-result .rg-table");
    if (!table) return null;
    var headCells = table.querySelectorAll("thead th");
    var columns = [];
    var masked = [];
    for (var i = 1; i < headCells.length; i++) { // 0 is the row-number column
      columns.push(headerName(headCells[i]));
      masked.push(!!headCells[i].querySelector(".badge-masked"));
    }
    if (!columns.length) return null;
    var rows = [];
    table.querySelectorAll("tbody tr").forEach(function (tr) {
      var cells = tr.querySelectorAll("td");
      var row = [];
      for (var j = 1; j < cells.length; j++) {
        row.push({
          v: cells[j].textContent,
          isNull: cells[j].classList.contains("null")
        });
      }
      rows.push(row);
    });
    return { columns: columns, rows: rows, masked: masked };
  }

  // RFC 4180: quote when the value contains a delimiter, quote or newline;
  // literal quotes are doubled. A NULL becomes an empty unquoted field, which
  // is what distinguishes it from the empty string ("").
  function csvField(cell) {
    if (cell.isNull) return "";
    var v = cell.v;
    if (/[",\r\n]/.test(v)) return '"' + v.replace(/"/g, '""') + '"';
    return v;
  }

  function gridToCSV(grid) {
    var lines = [grid.columns.map(function (c) {
      return csvField({ v: c, isNull: false });
    }).join(",")];
    grid.rows.forEach(function (row) {
      lines.push(row.map(csvField).join(","));
    });
    return lines.join("\r\n");
  }

  function gridToJSON(grid) {
    // Duplicate column labels would collide as object keys, so disambiguate.
    var keys = [];
    var seen = {};
    grid.columns.forEach(function (c) {
      var k = c || "column";
      if (Object.prototype.hasOwnProperty.call(seen, k)) {
        seen[k]++;
        k = k + "_" + seen[k];
      } else {
        seen[k] = 1;
      }
      keys.push(k);
    });
    var out = grid.rows.map(function (row) {
      var o = {};
      row.forEach(function (cell, i) {
        o[keys[i]] = cell.isNull ? null : cell.v;
      });
      return o;
    });
    return JSON.stringify(out, null, 2);
  }

  function exportStamp() {
    var d = new Date();
    function p(n) { return (n < 10 ? "0" : "") + n; }
    return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) +
      "-" + p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds());
  }

  function downloadFile(name, mime, text) {
    var blob = new Blob([text], { type: mime + ";charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // Revoke on the next tick so the download has taken the reference.
    setTimeout(function () { URL.revokeObjectURL(url); }, 0);
  }

  // Exporting data out of the gateway is an audited event; the server records
  // it against the session. Failure to log must not lose the user's file, so
  // this is fire-and-forget after the download has already started.
  function recordExport(format, grid) {
    var body = new URLSearchParams();
    body.set("_csrf", csrfToken());
    body.set("format", format);
    body.set("rows", String(grid.rows.length));
    body.set("columns", String(grid.columns.length));
    body.set("masked", String(grid.masked.filter(Boolean).length));
    var ta = document.getElementById("sql-input");
    if (ta) body.set("sql", ta.value);
    var conn = document.getElementById("connection-select");
    if (conn) body.set("connection_id", conn.value);
    fetch("/query/export", { method: "POST", body: body }).catch(function () {});
  }

  window.exportResults = function (format) {
    closeExportMenus();
    var grid = readResultGrid();
    if (!grid) {
      window.toast("info", "No result grid to export");
      return;
    }
    if (!grid.rows.length) {
      window.toast("info", "Nothing to export — the query returned no rows");
      return;
    }
    var stamp = exportStamp();
    if (format === "json") {
      downloadFile("securedb-export-" + stamp + ".json", "application/json", gridToJSON(grid));
    } else {
      format = "csv";
      downloadFile("securedb-export-" + stamp + ".csv", "text/csv", gridToCSV(grid));
    }
    recordExport(format, grid);
    var maskedCount = grid.masked.filter(Boolean).length;
    window.toast("success", grid.rows.length + " row" + (grid.rows.length === 1 ? "" : "s") +
      " exported as " + format.toUpperCase() +
      (maskedCount ? " · " + maskedCount + " column" + (maskedCount === 1 ? "" : "s") +
        " stayed masked" : ""));
  };

  function closeExportMenus() {
    document.querySelectorAll(".export-menu.open").forEach(function (m) {
      m.classList.remove("open");
    });
  }

  window.toggleExportMenu = function (btn) {
    var menu = btn.parentNode.querySelector(".export-menu");
    if (!menu) return;
    var wasOpen = menu.classList.contains("open");
    closeExportMenus();
    if (!wasOpen) menu.classList.add("open");
  };

  // Any click outside an export menu dismisses it.
  document.addEventListener("click", function (e) {
    if (!e.target.closest || !e.target.closest(".export-wrap")) closeExportMenus();
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") closeExportMenus();
  });

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
      // Shift+Alt+F — the conventional "format document" chord.
      ta.addEventListener("keydown", function (e) {
        if (e.shiftKey && e.altKey && (e.key === "F" || e.key === "f")) {
          e.preventDefault();
          window.formatEditorSQL();
        }
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

  // --- Global search (topbar) ---------------------------------------------
  (function () {
    var input = document.getElementById("global-search");
    if (!input) return;
    document.addEventListener("keydown", function (e) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        input.focus();
        input.select();
      } else if (e.key === "Escape" && document.activeElement === input) {
        input.value = "";
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.blur();
      }
    });
    input.addEventListener("keydown", function (e) {
      if (e.key === "Enter") {
        e.preventDefault();
        var q = input.value.trim();
        if (q) window.location.href = "/history?q=" + encodeURIComponent(q);
      }
    });
    document.addEventListener("click", function (e) {
      var box = document.getElementById("searchbox");
      var results = document.getElementById("search-results");
      if (box && results && !box.contains(e.target)) results.innerHTML = "";
    });
  })();
