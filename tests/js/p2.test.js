function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function deferred() {
  var state = "pending", value, handlers = [];
  var promise = {
    then: function (success, failure) {
      var next = deferred();
      function deliver() {
        try {
          var fn = state === "resolved" ? success : failure;
          if (!fn) { (state === "resolved" ? next.resolve : next.reject)(value); return; }
          var result = fn(value);
          if (result && typeof result.then === "function") result.then(next.resolve, next.reject);
          else next.resolve(result);
        } catch (error) { next.reject(error); }
      }
      if (state === "pending") handlers.push(deliver);
      else deliver();
      return next;
    },
    catch: function (fn) { return promise.then(null, fn); },
    resolve: function (result) {
      state = "resolved"; value = result;
      handlers.splice(0).forEach(function (fn) { fn(); });
    },
    reject: function (error) {
      state = "rejected"; value = error;
      handlers.splice(0).forEach(function (fn) { fn(); });
    }
  };
  return promise;
}

function resolved(value) {
  var result = deferred(); result.resolve(value); return result;
}

function response(data, status) {
  status = status || 200;
  return { ok: status === 200, status: status, json: function () { return resolved(data); } };
}

function environment() {
  var elements = {}, cards = [], timers = [], globals = {};
  function element(id) {
    if (!elements[id]) elements[id] = {
      style: {}, textContent: "", hidden: false, innerHTML: "",
      button: { disabled: false },
      querySelector: function (selector) { return selector === "button" ? this.button : null; },
      querySelectorAll: function () { return []; }
    };
    return elements[id];
  }
  var doc = {
    getElementById: element,
    querySelector: function (selector) {
      if (selector === "#st-modules tbody") return element("body");
      return globals[selector] || null;
    },
    querySelectorAll: function (selector) { return selector === ".module-card" ? cards : []; },
    addEventListener: function () {}
  };
  var win = { RECON: { statusUrl: "status", previewUrl: "preview" } };
  var module = { exports: {} };
  var env = { element: element, timers: timers, window: win, globals: globals,
    fetch: function () { throw new Error("unexpected fetch"); } };
  function input(name, checked, option) {
    return { name: name, type: "checkbox", checked: checked, value: "",
      handlers: {}, classList: { contains: function () { return !!option; } },
      addEventListener: function (type, handler) { this.handlers[type] = handler; } };
  }
  env.card = function () {
    var enabled = input("mod__wpscan__enabled", true);
    var automatic = input("mod__wpscan__automatic", false);
    var opt = input("mod__wpscan__fullpage", false, true);
    var inputs = [enabled, automatic, opt];
    var card = {
      enabled: enabled, automatic: automatic, opt: opt,
      getAttribute: function () { return "wpscan"; },
      querySelectorAll: function (selector) { return selector === ".opt" ? [opt] : inputs; },
      querySelector: function (selector) {
        return inputs.filter(function (el) { return selector.indexOf('"' + el.name + '"') >= 0; })[0] || null;
      }
    };
    cards.push(card); return card;
  };
  new Function("window", "document", "fetch", "setTimeout", "clearTimeout", "module", source)(
    win, doc, function () { return env.fetch.apply(null, arguments); },
    function (fn, delay) { var timer = { fn: fn, delay: delay }; timers.push(timer); return timer; },
    function (timer) { timer.cancelled = true; }, module);
  env.ui = module.exports;
  return env;
}

var tests = [
  function terminalStatesStopPolling() {
    ["done", "error", "cancelled", "interrupted"].forEach(function (status) {
      var env = environment();
      env.fetch = function () { return resolved(response({ status: status, actions: {}, terminal: true })); };
      env.ui.initStatus();
      assert(env.timers.length === 0, status + " kept polling");
    });
  },
  function runningPollsAndStaleReportDisappears() {
    var env = environment();
    env.element("report-link").style.display = "";
    env.fetch = function () { return resolved(response({
      status: "running", actions: { cancel: true }, report_ready: false })); };
    env.ui.initStatus();
    assert(env.timers[0].delay === 2000, "running scan did not schedule next poll");
    assert(env.element("report-link").style.display === "none", "stale report stayed visible");
    assert(env.element("cancel-action").style.display === "inline", "cancel hidden");
  },
  function goneOrUnauthorizedStopsPolling() {
    [401, 403, 404].forEach(function (status) {
      var env = environment();
      env.fetch = function () { return resolved(response({}, status)); };
      env.ui.initStatus();
      assert(env.timers.length === 0, "permanent HTTP error kept polling");
      assert(env.element("cancel-action").button.disabled, "stale action remained enabled");
      assert(!env.element("st-connection").hidden, "connection failure hidden");
    });
  },
  function networkFailureRetriesWithoutErasingScanError() {
    var env = environment();
    env.element("st-error").textContent = "scanner failed";
    env.fetch = function () { var d = deferred(); d.reject(new Error("offline")); return d; };
    env.ui.initStatus();
    assert(env.timers[0].delay === 5000, "network failure did not back off");
    assert(env.element("st-error").textContent === "scanner failed", "scan error overwritten");
  },
  function coverageDoesNotTreatDisabledAsSuccess() {
    var env = environment();
    env.ui.renderStatus({ status: "done", actions: {}, coverage_status: "incomplete",
      coverage_rows: [{ id: "disabled-tool", status: "disabled" },
                      { id: "missing-tool", status: "unavailable" }] });
    assert(env.element("st-modsum").textContent.indexOf("0 ok") >= 0, "untested modules counted successful");
    assert(env.element("body").innerHTML.indexOf("disabled-tool") >= 0, "planned module omitted");
    assert(!env.element("st-coverage-warning").hidden, "incomplete coverage warning hidden");
  },
  function latestPreviewWins() {
    var env = environment(), card = env.card(), requests = [];
    env.fetch = function () { var d = deferred(); requests.push(d); return d; };
    env.ui.refreshPreview(card);
    env.ui.refreshPreview(card);
    requests[1].resolve(response({ lines: ["new command"] }));
    requests[0].resolve(response({ lines: ["old command"] }));
    assert(env.element("preview-wpscan").textContent === "new command", "stale preview overwrote current settings");
  },
  function disabledModeCannotDisplayPendingPreview() {
    var env = environment(), card = env.card(), pending = deferred();
    env.fetch = function () { return pending; };
    env.ui.refreshPreview(card);
    card.enabled.checked = false;
    env.ui.refreshPreview(card);
    pending.resolve(response({ lines: ["must not run"] }));
    assert(env.element("preview-wpscan").textContent.indexOf("Disabled") >= 0, "disabled preview replaced");
  },
  function automaticAndEnabledAreExclusive() {
    var env = environment(), card = env.card();
    env.ui.initConfig();
    card.automatic.checked = true;
    card.automatic.handlers.change();
    assert(!card.enabled.checked, "automatic left always-enabled mode active");
    card.enabled.checked = true;
    card.enabled.handlers.change();
    assert(!card.automatic.checked, "always-enabled left automatic mode active");
    assert(env.timers.filter(function (t) { return !t.cancelled; }).length === 1, "preview was not debounced");
  },
  function previewIncludesGlobalSettings() {
    var env = environment(), card = env.card(), sent;
    env.globals['[name="run_as_root"]'] = { checked: false };
    env.globals['[name="rate_limit"]'] = { value: "17" };
    env.fetch = function (url, options) { sent = JSON.parse(options.body); return resolved(response({ lines: ["preview"] })); };
    env.ui.refreshPreview(card);
    assert(sent.run_as_root === false && sent.rate_limit === "17", "globals missing from preview");
  },
  function previewErrorsAreVisible() {
    var env = environment(), card = env.card();
    env.fetch = function () { return resolved(response({ errors: ["invalid threads"] }, 400)); };
    env.ui.refreshPreview(card);
    assert(!env.element("preview-error-wpscan").hidden, "validation error hidden");
    assert(env.element("preview-error-wpscan").textContent === "invalid threads", "wrong validation message");
  },
  function requestTimeoutRetriesWithoutOverlappingRequests() {
    var env = environment(), pending = deferred(), calls = 0;
    env.window.AbortController = function () {
      this.signal = {};
      this.abort = function () {
        var error = new Error("aborted"); error.name = "AbortError"; pending.reject(error);
      };
    };
    env.fetch = function () { calls++; return pending; };
    env.ui.initStatus();
    assert(calls === 1 && env.timers[0].delay === 10000, "missing request watchdog");
    env.timers[0].fn();
    assert(calls === 1, "overlapping request launched");
    assert(env.timers[1].delay === 5000, "timeout did not back off");
    assert(env.element("st-connection").textContent.indexOf("timed out") >= 0, "timeout message hidden");
  },
  function expandedErrorsAreEscaped() {
    var env = environment();
    env.window.__reconExpanded = { nuclei: true };
    env.ui.renderStatus({ status: "error", actions: {}, modules: {
      nuclei: { status: "completed with errors", runs: [
        { label: "nuclei", status: "error", error: "<script>unsafe</script>", duration: 0 }] }
    } });
    var html = env.element("body").innerHTML;
    assert(html.indexOf("&lt;script&gt;") >= 0 && html.indexOf("<script>") < 0, "error HTML was not escaped");
    assert(html.indexOf("0s") >= 0, "zero-duration run hidden");
  },
  function cancelledQueueEntryPollsUntilOwnershipIsReleased() {
    var env = environment(), released = false;
    env.fetch = function () { return resolved(response({
      status: "cancelled", terminal: true, settled: released,
      actions: { resume: released }
    })); };
    env.ui.initStatus();
    assert(env.timers.length === 1, "polling stopped before cleanup finished");
    released = true;
    env.timers[0].fn();
    assert(env.timers.length === 1, "settled terminal scan kept polling");
    assert(env.element("resume-action").style.display === "inline", "resume never became available");
  },
  function activeTaskPanelShowsStatesAndClearsWhenDone() {
    var env = environment();
    env.ui.renderStatus({ status: "running", actions: {}, active_tasks: [
      { label: "nmap_tcp", command: "nmap -Pn <b>", pid: 4242, process_alive: true,
        state: "streaming", elapsed_seconds: 5, seconds_since_output: 2, output_bytes: 2048 },
      { label: "nuclei", command: "nuclei -l x", pid: 999999, process_alive: false,
        state: "orphaned", elapsed_seconds: 600, seconds_since_output: 600, output_bytes: 0 }
    ] });
    var html = env.element("st-active").innerHTML;
    assert(html.indexOf("nmap_tcp") >= 0 && html.indexOf("nuclei") >= 0, "active tasks missing");
    assert(html.indexOf("streaming output") >= 0, "streaming badge missing");
    assert(html.indexOf("process exited") >= 0, "orphaned badge missing");
    assert(html.indexOf("&lt;b&gt;") >= 0, "command HTML was not escaped");
    assert(html.indexOf("2.0 KiB") >= 0, "captured volume missing");
    assert(env.element("st-active-count").textContent.indexOf("2 running") >= 0, "running count missing");
    env.ui.renderStatus({ status: "running", actions: {}, active_tasks: [] });
    assert(env.element("st-active").innerHTML.indexOf("No task") >= 0, "running empty state missing");
    env.ui.renderStatus({ status: "done", actions: {}, terminal: true, active_tasks: [] });
    assert(env.element("st-active").innerHTML === "", "done scan did not clear the panel");
  }
];
tests.forEach(function (test) { test(); });
return tests.length + " frontend behavior checks passed";
