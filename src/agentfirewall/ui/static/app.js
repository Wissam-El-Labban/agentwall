/* agentfirewall dashboard — client-side interactivity */
(function () {
    "use strict";

    // ── Helpers ─────────────────────────────────────────────

    function apiCall(method, url, body) {
        var opts = {
            method: method,
            headers: { "Content-Type": "application/json" },
        };
        if (body !== undefined) {
            opts.body = JSON.stringify(body);
        }
        return fetch(url, opts).then(function (res) {
            if (!res.ok) {
                return res.json().then(function (data) {
                    throw new Error(data.error || "Request failed");
                });
            }
            return res.json();
        });
    }

    // ── Mode toggle (dashboard) ─────────────────────────────

    var modeToggle = document.getElementById("mode-toggle");
    if (modeToggle) {
        modeToggle.addEventListener("click", function (e) {
            var btn = e.target.closest(".mode-btn");
            if (!btn) return;
            var mode = btn.dataset.mode;
            apiCall("PUT", "/api/config", { mode: mode }).then(function () {
                modeToggle.querySelectorAll(".mode-btn").forEach(function (b) {
                    b.classList.remove("active");
                });
                btn.classList.add("active");
                var desc = document.getElementById("mode-description");
                if (desc) {
                    var messages = {
                        off: "Firewall is <strong>disabled</strong>. All actions are allowed.",
                        audit: "Firewall is in <strong>audit</strong> mode. Violations are logged but not blocked.",
                        enforce: "Firewall is in <strong>enforce</strong> mode. Violations are blocked.",
                    };
                    desc.innerHTML = messages[mode] || "";
                }
            });
        });
    }

    // ── Preset switch (dashboard) ───────────────────────────

    var presetBtn = document.getElementById("apply-preset-btn");
    if (presetBtn) {
        presetBtn.addEventListener("click", function () {
            var sel = document.getElementById("preset-select");
            if (!sel || !sel.value) return;
            apiCall("POST", "/api/preset", { preset: sel.value }).then(function () {
                window.location.reload();
            });
        });
    }

    // ── Config form ─────────────────────────────────────────

    var configForm = document.getElementById("config-form");
    if (configForm) {
        configForm.addEventListener("submit", function (e) {
            e.preventDefault();
            var config = buildConfigFromForm();
            apiCall("PUT", "/api/config", config).then(function () {
                var status = document.getElementById("save-status");
                if (status) {
                    status.textContent = "Saved!";
                    setTimeout(function () { status.textContent = ""; }, 2000);
                }
            }).catch(function (err) {
                var status = document.getElementById("save-status");
                if (status) {
                    status.textContent = "Error: " + err.message;
                    status.style.color = "#e63946";
                }
            });
        });

        // Preset switch on config page
        var configPresetBtn = document.getElementById("config-apply-preset");
        if (configPresetBtn) {
            configPresetBtn.addEventListener("click", function () {
                var sel = document.getElementById("config-preset-select");
                if (!sel || !sel.value) return;
                apiCall("POST", "/api/preset", { preset: sel.value }).then(function () {
                    window.location.reload();
                });
            });
        }
    }

    function buildConfigFromForm() {
        var config = {};

        // Mode
        var modeRadio = document.querySelector('input[name="mode"]:checked');
        if (modeRadio) config.mode = modeRadio.value;

        // Sandbox
        var sandboxRoot = document.getElementById("sandbox-root");
        var sandboxEscape = document.getElementById("sandbox-escape");
        if (sandboxRoot) {
            config.sandbox = {
                root: sandboxRoot.value,
                allow_escape: sandboxEscape ? sandboxEscape.checked : false,
            };
        }

        // Commands
        config.commands = {
            blocklist: getListValues("blocklist"),
            allowlist: getListValues("allowlist"),
        };

        // Filesystem
        var denyOps = [];
        document.querySelectorAll('input[name="deny_op"]:checked').forEach(function (cb) {
            denyOps.push(cb.value);
        });
        config.filesystem = {
            protected_paths: getListValues("protected-paths"),
            deny_operations: denyOps,
        };

        // Network
        config.network = {
            allowed_hosts: getListValues("allowed-hosts"),
            deny_egress_to: getListValues("deny-targets"),
        };

        // Logging
        var logEnabled = document.getElementById("logging-enabled");
        var logLevel = document.getElementById("logging-level");
        if (logEnabled) {
            config.logging = {
                enabled: logEnabled.checked,
                level: logLevel ? logLevel.value : "warn",
            };
        }

        return config;
    }

    function getListValues(listId) {
        var container = document.getElementById(listId);
        if (!container) return [];
        var values = [];
        container.querySelectorAll(".list-item input").forEach(function (inp) {
            var v = inp.value.trim();
            if (v) values.push(v);
        });
        return values;
    }

    // ── Editable list add/remove ────────────────────────────

    document.addEventListener("click", function (e) {
        // Remove item
        if (e.target.classList.contains("remove-item")) {
            var item = e.target.closest(".list-item");
            if (item) item.remove();
            return;
        }

        // Add item
        if (e.target.classList.contains("add-item")) {
            var addRow = e.target.closest(".list-add");
            if (!addRow) return;
            var input = addRow.querySelector(".add-input");
            if (!input || !input.value.trim()) return;

            var newItem = document.createElement("div");
            newItem.className = "list-item";
            newItem.innerHTML =
                '<input type="text" value="' + escapeHtml(input.value.trim()) + '" readonly>' +
                '<button type="button" class="btn btn-sm btn-danger remove-item">&#x2715;</button>';
            addRow.parentNode.insertBefore(newItem, addRow);
            input.value = "";
        }
    });

    function escapeHtml(str) {
        var div = document.createElement("div");
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    // ── Log viewer SSE ──────────────────────────────────────

    var logBody = document.getElementById("log-body");
    var logStatus = document.getElementById("log-status");
    if (logBody) {
        var paused = false;
        var allEntries = [];
        var maxEntries = 1000;

        // Load historical entries first
        fetch("/api/logs?limit=200")
            .then(function (res) { return res.json(); })
            .then(function (data) {
                if (data.entries && data.entries.length > 0) {
                    // entries come newest-first from API, reverse for display
                    var reversed = data.entries.slice().reverse();
                    reversed.forEach(function (entry) {
                        allEntries.push(entry);
                        appendLogRow(entry);
                    });
                }
                startSSE();
            })
            .catch(function () {
                startSSE();
            });

        function startSSE() {
            var source = new EventSource("/api/logs/stream");
            source.onopen = function () {
                if (logStatus) logStatus.textContent = "Connected — streaming live";
            };
            source.onmessage = function (e) {
                if (paused) return;
                try {
                    var entry = JSON.parse(e.data);
                    allEntries.push(entry);
                    if (allEntries.length > maxEntries) allEntries.shift();
                    if (matchesFilter(entry)) {
                        appendLogRow(entry);
                        autoScroll();
                    }
                } catch (err) { /* skip invalid */ }
            };
            source.onerror = function () {
                if (logStatus) logStatus.textContent = "Disconnected — retrying...";
            };
        }

        function appendLogRow(entry) {
            var tr = document.createElement("tr");
            var ts = entry.timestamp || "";
            if (ts.length > 19) ts = ts.substring(0, 19).replace("T", " ");
            tr.innerHTML =
                "<td>" + escapeHtml(ts) + "</td>" +
                "<td>" + escapeHtml(entry.action_type || "") + "</td>" +
                '<td class="target-cell" title="' + escapeHtml(entry.target || "") + '">' + escapeHtml(entry.target || "") + "</td>" +
                "<td>" + verdictBadge(entry.verdict || "") + "</td>" +
                "<td>" + escapeHtml(entry.rule || "") + "</td>" +
                '<td class="detail-cell" title="' + escapeHtml(entry.detail || "") + '">' + escapeHtml(entry.detail || "") + "</td>";
            logBody.appendChild(tr);
        }

        function verdictBadge(verdict) {
            var cls = "verdict-badge verdict-" + verdict;
            return '<span class="' + cls + '">' + escapeHtml(verdict) + '</span>';
        }

        function autoScroll() {
            var wrap = document.querySelector(".log-table-wrap");
            if (wrap) wrap.scrollTop = wrap.scrollHeight;
        }

        function matchesFilter(entry) {
            var verdictSel = document.getElementById("verdict-filter");
            var searchBox = document.getElementById("log-search");
            if (verdictSel && verdictSel.value && entry.verdict !== verdictSel.value) return false;
            if (searchBox && searchBox.value) {
                var q = searchBox.value.toLowerCase();
                var text = JSON.stringify(entry).toLowerCase();
                if (text.indexOf(q) === -1) return false;
            }
            return true;
        }

        // Pause / resume
        var pauseBtn = document.getElementById("pause-btn");
        if (pauseBtn) {
            pauseBtn.addEventListener("click", function () {
                paused = !paused;
                pauseBtn.textContent = paused ? "Resume" : "Pause";
                if (logStatus) logStatus.textContent = paused ? "Paused" : "Connected — streaming live";
            });
        }

        // Clear display
        var clearBtn = document.getElementById("clear-btn");
        if (clearBtn) {
            clearBtn.addEventListener("click", function () {
                logBody.innerHTML = "";
            });
        }

        // Filter change → rebuild table
        var verdictFilter = document.getElementById("verdict-filter");
        var logSearch = document.getElementById("log-search");
        function refilter() {
            logBody.innerHTML = "";
            allEntries.forEach(function (entry) {
                if (matchesFilter(entry)) appendLogRow(entry);
            });
        }
        if (verdictFilter) verdictFilter.addEventListener("change", refilter);
        if (logSearch) {
            var searchTimer;
            logSearch.addEventListener("input", function () {
                clearTimeout(searchTimer);
                searchTimer = setTimeout(refilter, 300);
            });
        }
    }
})();
