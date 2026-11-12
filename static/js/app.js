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
    var prefix = "mod__" + body.module + "__";
    var enabled = card.querySelector('[name="' + prefix + 'enabled"]');
    var automatic = card.querySelector('[name="' + prefix + 'automatic"]');
    var pre = document.getElementById("preview-" + body.module);
    var error = document.getElementById("preview-error-" + body.module);
    var sequence = (card.__previewSequence || 0) + 1;
    card.__previewSequence = sequence;
    if (error) { error.hidden = true; error.textContent = ""; }
    if (enabled && !enabled.checked && !(automatic && automatic.checked)) {
      if (pre) pre.textContent = "Disabled — no commands will run.";
      return;
    }
    var root = document.querySelector('[name="run_as_root"]');
    var rate = document.querySelector('[name="rate_limit"]');
    if (root) body.run_as_root = root.checked;
    if (rate) body.rate_limit = rate.value;
    var ok = true;
    fetch(window.RECON.previewUrl, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }).then(function (response) {
      ok = response.ok;
      return response.json();
    }).then(function (data) {
      if (sequence !== card.__previewSequence) return;
      if (!ok) throw new Error((data.errors || ["Preview request failed."]).join(" "));
      if (pre && data.lines) pre.textContent =
        (automatic && automatic.checked ? "Automatic — only after a matching fingerprint.\n" : "") + data.lines.join("\n");
      var badge = document.getElementById("availability-" + body.module);
      if (badge && data.availability) {
        var availability = data.availability;
        badge.className = "avail " + (availability.available ? "ok" : "no");
        badge.textContent = Object.keys(availability.binaries || {}).join(" + ") +
          (availability.available ? "" : " — not found");
      }
    }).catch(function (failure) {
      if (sequence !== card.__previewSequence) return;
      if (pre) pre.textContent = "Preview unavailable — correct settings or retry.";
      if (error) { error.hidden = false; error.textContent = failure.message; }
    });
  }

  function schedulePreview(card) {
    card.__previewSequence = (card.__previewSequence || 0) + 1;
    if (card.__previewTimer) clearTimeout(card.__previewTimer);
    card.__previewTimer = setTimeout(function () { refreshPreview(card); }, 250);
  }

  function initConfig() {
    var cards = document.querySelectorAll(".module-card");
    if (!cards.length) return;
    cards.forEach(function (card) {
      var mid = card.getAttribute("data-mid");
      var enabled = card.querySelector('[name="mod__' + mid + '__enabled"]');
      var automatic = card.querySelector('[name="mod__' + mid + '__automatic"]');
      function syncOptions() {
        var active = (enabled && enabled.checked) || (automatic && automatic.checked);
        card.querySelectorAll(".opt").forEach(function (el) { el.disabled = !active; });
      }
      syncOptions();
      card.querySelectorAll("input, select").forEach(function (el) {
        el.addEventListener("change", function () {
          if (el === enabled && el.checked && automatic) automatic.checked = false;
          if (el === automatic && el.checked && enabled) enabled.checked = false;
          syncOptions();
          schedulePreview(card);
        });
        if (el.classList.contains("opt")) el.addEventListener("input", function () { schedulePreview(card); });
      });
      if (enabled && !enabled.checked && !(automatic && automatic.checked)) {
        var pre = document.getElementById("preview-" + mid);
        if (pre) pre.textContent = "Disabled — no commands will run.";
      }
    });
    ['run_as_root', 'rate_limit'].forEach(function (name) {
      var global = document.querySelector('[name="' + name + '"]');
      if (global) global.addEventListener("change", function () {
        cards.forEach(schedulePreview);
      });
    });
  }

  // ---- Status page: poll JSON API ------------------------------------------
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>'"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[c];
    });
  }

  var PHASE_LABELS = {
    queued: "Queued", import: "Importing nmap XML",
    discovery: "Discovery — dnsx + nmap", phase2: "Service modules",
    correlate: "Correlating findings", report: "Building report",
    done: "Complete", interrupted: "Interrupted", error: "Failed",
    cancelled: "Cancelled", cancelling: "Stopping active tools",
    adaptive: "Fingerprint-triggered modules", "vulnerability-results": "Waiting for vulnerability scan"
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
    if (/error|timeout|failed|partial|cancel/.test(s)) return "mstat-warn";
    if (/missing|not found|unavailable/.test(s)) return "mstat-missing";
    if (/^ok$|^successful|^demo$/.test(s)) return "mstat-ok";
    return "mstat-skip";
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
    var modules = {};
    Object.keys(data.modules || {}).forEach(function (mid) { modules[mid] = data.modules[mid]; });
    Object.keys(data.execution_plan || {}).forEach(function (mid) {
      var planned = data.execution_plan[mid];
      modules[mid] = { status: planned.status, note: planned.note || "",
        runs: ((data.modules || {})[mid] || {}).runs || [] };
    });
    (data.coverage_rows || []).forEach(function (row) {
      if (!modules[row.id]) modules[row.id] = { runs: [] };
      modules[row.id].status = row.status;
      modules[row.id].note = row.note;
    });
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
          "<td><span class='mstat " + modStatusClass(m.status) + "'>" + esc(m.status) + "</span><div class='small'>" + esc(m.note || "") + "</div></td>" +
          "<td class='small'>" + esc(runCounts(runs) || String(runs.length)) + "</td>" +
          "<td class='small'>" + (dur ? fmtDur(dur) : "—") + "</td></tr>";
        if (open && runs.length) {
          var inner = "";
          runs.forEach(function (r) {
            inner += "<tr><td class='small'>" + esc(r.label) + "</td>" +
              "<td class='small'><span class='mstat " + modStatusClass(r.status) + "'>" + esc(r.status) + "</span></td>" +
              "<td class='small'>" + (typeof r.duration === "number" ? fmtDur(r.duration) : "—") + "</td>" +
              "<td class='runcmd'>" + esc(r.command || "") + "<div class='err'>" +
              esc([r.error || ""].concat(r.output_warnings || []).filter(Boolean).join(" · ")) + "</div></td></tr>";
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
          var kind = modStatusClass(modules[mid].status);
          if (kind === "mstat-warn") sum.errors++;
          else if (kind === "mstat-missing") sum.missing++;
          else if (kind === "mstat-ok") sum.ok++;
          else sum.skipped++;
        });
        ms.textContent = mids.length + " modules — " + sum.ok + " ok · " +
          sum.skipped + " pending/disabled/skipped · " + sum.errors + " with errors · " + sum.missing + " tool-missing";
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
    var actions = data.actions || {};
    ["cancel", "resume", "partial"].forEach(function (action) {
      var form = document.getElementById(action + "-action");
      if (form) {
        form.style.display = actions[action] ? "inline" : "none";
        var button = form.querySelector("button");
        if (button) button.disabled = false;
      }
    });
    var connection = document.getElementById("st-connection");
    if (connection) connection.hidden = true;
    var err = document.getElementById("st-error");
    if (err) { err.textContent = data.error || ""; err.hidden = !data.error; }
    var cov = document.getElementById("st-coverage");
    if (cov) cov.textContent = "Coverage: " + (data.coverage_status || "pending");
    var warning = document.getElementById("st-coverage-warning");
    if (warning) warning.hidden = data.coverage_status !== "incomplete";
    var el = document.getElementById("st-elapsed");
    if (el && typeof data.elapsed_seconds === "number") {
      el.textContent = (data.status === "done" ? "took " : "elapsed ") + fmtDur(data.elapsed_seconds);
    }

    var prog = data.progress || { total: 0, completed: 0 };
    var pct = prog.total ? Math.min(100, Math.max(0, Math.round(((prog.completed || 0) / prog.total) * 100))) : (data.status === "done" ? 100 : 0);
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

    var link = document.getElementById("report-link");
    if (link) link.style.display = data.report_ready ? "" : "none";
    if (typeof data.settled === "boolean") return data.settled;
    return data.terminal === true || ["done", "error", "cancelled", "interrupted"].indexOf(data.status) >= 0;
  }

  function initStatus() {
    var panel = document.getElementById("scan-status");
    if (!panel || !window.RECON || !window.RECON.statusUrl) return;
    function tick() {
      var controller = window.AbortController ? new window.AbortController() : null;
      var watchdog = controller ? setTimeout(function () { controller.abort(); }, 10000) : null;
      var permanent = false;
      fetch(window.RECON.statusUrl, { cache: "no-store", signal: controller ? controller.signal : undefined })
        .then(function (response) {
          if (!response.ok) {
            permanent = [401, 403, 404].indexOf(response.status) >= 0;
            throw new Error(response.status === 404 ? "Scan no longer exists." :
              "Status request failed (" + response.status + "). Reload or check access.");
          }
          return response.json();
        }).then(function (data) {
          if (watchdog) clearTimeout(watchdog);
          if (!renderStatus(data)) setTimeout(tick, 2000);
        }).catch(function (error) {
          if (watchdog) clearTimeout(watchdog);
          var el = document.getElementById("st-connection");
          if (el) { el.hidden = false; el.textContent = error.name === "AbortError" ?
            "Status request timed out; retrying." : error.message; }
          ["cancel", "resume", "partial"].forEach(function (action) {
            var form = document.getElementById(action + "-action");
            var button = form && form.querySelector("button");
            if (button) button.disabled = true;
          });
          if (!permanent) setTimeout(tick, 5000);
        });
    }
    tick();
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

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { renderStatus: renderStatus, initStatus: initStatus,
      refreshPreview: refreshPreview, initConfig: initConfig };
  }

  document.addEventListener("DOMContentLoaded", function () {
    initTheme();
    initConfig();
    initStatus();
  });
})();
