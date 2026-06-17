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

  function renderStatus(data) {
    var stt = document.getElementById("st-status");
    if (stt) { stt.textContent = data.status; stt.className = "status status-" + data.status; }
    var ph = document.getElementById("st-phase");
    if (ph) ph.textContent = data.phase || "";

    var prog = data.progress || { total: 0, completed: 0 };
    var pct = prog.total ? Math.round((prog.completed / prog.total) * 100) : (data.status === "done" ? 100 : 0);
    var bar = document.getElementById("st-bar");
    if (bar) bar.style.width = pct + "%";
    var pl = document.getElementById("st-progress");
    if (pl) pl.textContent = prog.total ? (prog.completed + " / " + prog.total + " module tasks") : "";

    var tbody = document.querySelector("#st-modules tbody");
    if (tbody && data.modules) {
      var rows = "";
      Object.keys(data.modules).forEach(function (mid) {
        var m = data.modules[mid];
        rows += "<tr><td>" + esc(mid) + "</td><td>" + esc(m.status) +
          "</td><td class='small'>" + ((m.runs || []).length) + "</td></tr>";
      });
      tbody.innerHTML = rows;
    }

    var log = document.getElementById("st-log");
    if (log && data.log) { log.textContent = data.log.join("\n"); log.scrollTop = log.scrollHeight; }

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

  document.addEventListener("DOMContentLoaded", function () {
    initConfig();
    initStatus();
  });
})();
