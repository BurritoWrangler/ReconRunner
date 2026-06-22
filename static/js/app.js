(function () {
  "use strict";

  // ---- Config page: live command preview -----------------------------------
  function collectOptions(card) {
    var mid = card.getAttribute("data-mid");
    var prefix = "mod__" + mid + "__";
    var opts = {};
    card.querySelectorAll(".opt").forEach(function (el) {
      var key = el.name.slice(prefix.length);
      if (el.type === "checkbox") opts[key] = el.checked;
      else opts[key] = el.value;
    });
    return { module: mid, options: opts };
  }

  function refreshPreview(card) {
    if (!window.RECON || !window.RECON.previewUrl) return;
    var body = collectOptions(card);
    fetch(window.RECON.previewUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var pre = document.getElementById("preview-" + body.module);
        if (pre && data.lines) pre.textContent = data.lines.join("\n");
      })
      .catch(function () {});
  }

  function initConfig() {
    var cards = document.querySelectorAll(".module-card");
    if (!cards.length) return;
    cards.forEach(function (card) {
      card.querySelectorAll(".opt").forEach(function (el) {
        el.addEventListener("change", function () { refreshPreview(card); });
        el.addEventListener("input", function () { refreshPreview(card); });
      });
    });
  }

  // ---- Status page: poll JSON API ------------------------------------------
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c];
    });
  }

  var PHASE_LABELS = {
    queued: "Queued", import: "Importing nmap XML",
    discovery: "Discovery — dnsx + nmap", phase2: "Service modules",
    correlate: "Correlating findings", report: "Building report",
    done: "Complete", interrupted: "Interrupted"
  };

  function fmtDur(sec) {
    sec = Math.max(0, Math.round(sec || 0));
    if (sec < 60) return sec + "s";
    var m = Math.floor(sec / 60), s = sec % 60;
    if (m < 60) return m + "m " + (s < 10 ? "0" : "") + s + "s";
    var h = Math.floor(m / 60), mm = m % 60;
    return h + "h " + (mm < 10 ? "0" : "") + mm + "m";
  }

  function modStatusClass(s) {
    s = String(s || "");
    if (s.indexOf("error") >= 0 || s.indexOf("timeout") >= 0) return "mstat-warn";
    if (s.indexOf("missing") >= 0 || s.indexOf("not found") >= 0) return "mstat-missing";
    if (s.indexOf("skip") >= 0) return "mstat-skip";
    return "mstat-ok";
  }

  function runCounts(runs) {
    var c = {}, order = [];
    (runs || []).forEach(function (r) {
      var k = r.status || "?";
      if (c[k] === undefined) { c[k] = 0; order.push(k); }
      c[k]++;
    });
    return order.map(function (k) { return c[k] + " " + k; }).join(" · ");
  }

  function renderModules(data) {
    var modules = data.modules || {};
    var mids = Object.keys(modules).sort();
    var expanded = window.__reconExpanded || (window.__reconExpanded = {});
    var tbody = document.querySelector("#st-modules tbody");
    if (tbody) {
      var rows = "";
      mids.forEach(function (mid) {
        var m = modules[mid];
        var runs = m.runs || [];
        var dur = runs.reduce(function (a, r) { return a + (r.duration || 0); }, 0);
        var open = !!expanded[mid];
        var caret = runs.length ? (open ? "▾ " : "▸ ") : "&nbsp;&nbsp;";
        rows += "<tr class='mod-row' data-mid='" + esc(mid) + "'>" +
          "<td>" + caret + esc(mid) + "</td>" +
          "<td><span class='mstat " + modStatusClass(m.status) + "'>" + esc(m.status) + "</span></td>" +
          "<td class='small'>" + esc(runCounts(runs) || String(runs.length)) + "</td>" +
          "<td class='small'>" + (dur ? fmtDur(dur) : "—") + "</td></tr>";
        if (open && runs.length) {
          var inner = "";
          runs.forEach(function (r) {
            inner += "<tr><td class='small'>" + esc(r.label) + "</td>" +
              "<td class='small'><span class='mstat " + modStatusClass(r.status) + "'>" + esc(r.status) + "</span></td>" +
              "<td class='small'>" + (r.duration ? fmtDur(r.duration) : "—") + "</td>" +
              "<td class='runcmd'>" + esc(r.command || "") + "</td></tr>";
          });
          rows += "<tr class='mod-detail'><td colspan='4'><table class='runs'>" +
            "<thead><tr><th>Run</th><th>Status</th><th>Time</th><th>Command</th></tr></thead>" +
            "<tbody>" + inner + "</tbody></table></td></tr>";
        }
      });
      tbody.innerHTML = rows;
      tbody.querySelectorAll(".mod-row").forEach(function (tr) {
        tr.addEventListener("click", function () {
          var mid = tr.getAttribute("data-mid");
          expanded[mid] = !expanded[mid];
          renderModules(window.__reconLast || data);
        });
      });
    }
    var ms = document.getElementById("st-modsum");
    if (ms) {
      if (mids.length) {
        var sum = { ok: 0, skipped: 0, errors: 0, missing: 0 };
        mids.forEach(function (mid) {
          var st = String(modules[mid].status || "");
          if (st.indexOf("error") >= 0 || st.indexOf("timeout") >= 0) sum.errors++;
          else if (st.indexOf("missing") >= 0 || st.indexOf("not found") >= 0) sum.missing++;
          else if (st.indexOf("skip") >= 0) sum.skipped++;
          else sum.ok++;
        });
        ms.textContent = mids.length + " modules — " + sum.ok + " ok · " +
          sum.skipped + " skipped · " + sum.errors + " with errors · " + sum.missing + " tool-missing";
      } else {
        ms.textContent = "";
      }
    }
  }

  function renderStatus(data) {
    window.__reconLast = data;
    var stt = document.getElementById("st-status");
    if (stt) { stt.textContent = data.status; stt.className = "status status-" + data.status; }
    var ph = document.getElementById("st-phase");
    if (ph) ph.textContent = PHASE_LABELS[data.phase] || data.phase || "";
    var el = document.getElementById("st-elapsed");
    if (el && typeof data.elapsed_seconds === "number") {
      el.textContent = (data.status === "done" ? "took " : "elapsed ") + fmtDur(data.elapsed_seconds);
    }

    var prog = data.progress || { total: 0, completed: 0 };
    var pct = prog.total ? Math.round((prog.completed / prog.total) * 100) : (data.status === "done" ? 100 : 0);
    var bar = document.getElementById("st-bar");
    if (bar) bar.style.width = pct + "%";
    var pl = document.getElementById("st-progress");
    if (pl) pl.textContent = prog.total ? ("Phase 2: " + prog.completed + " / " + prog.total + " module tasks (" + pct + "%)") : "";

    renderModules(data);

    var log = document.getElementById("st-log");
    if (log && data.log) { log.textContent = data.log.join("\n"); log.scrollTop = log.scrollHeight; }

    var con = document.getElementById("st-console");
    if (con && typeof data.console === "string") {
      con.textContent = data.console;
      con.scrollTop = con.scrollHeight;
    }

    if (data.report) {
      var link = document.getElementById("report-link");
      if (link) link.style.display = "";
    }
    return data.status === "done" || data.status === "error";
  }

  function initStatus() {
    var panel = document.getElementById("scan-status");
    if (!panel || !window.RECON || !window.RECON.statusUrl) return;
    var timer = null;
    function tick() {
      fetch(window.RECON.statusUrl)
        .then(function (r) { return r.json(); })
        .then(function (data) {
          var done = renderStatus(data);
          if (done && timer) { clearInterval(timer); }
        })
        .catch(function () {});
    }
    tick();
    timer = setInterval(tick, 2000);
  }

  // ---- Theme toggle (light/dark) ------------------------------------------
  function applyThemeIcon(theme) {
    var b = document.getElementById("theme-toggle");
    if (!b) return;
    b.textContent = theme === "light" ? "☾" : "☀";
    b.title = "Switch to " + (theme === "light" ? "dark" : "light") + " theme";
  }
  function initTheme() {
    var root = document.documentElement;
    var theme = root.getAttribute("data-theme") || "dark";
    root.setAttribute("data-theme", theme);
    applyThemeIcon(theme);
    var b = document.getElementById("theme-toggle");
    if (!b) return;
    b.addEventListener("click", function () {
      var next = (root.getAttribute("data-theme") === "light") ? "dark" : "light";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("recon-theme", next); } catch (e) {}
      applyThemeIcon(next);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    initTheme();
    initConfig();
    initStatus();
  });
})();
