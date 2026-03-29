/* analytics.js — Chart rendering for the agentfirewall analytics page */
(function () {
    "use strict";

    var COLORS = {
        allow: "#2a9d8f",
        deny: "#e63946",
        warn: "#e9a100",
        primary: "#4361ee",
        muted: "#6c757d",
        command: "#4361ee",
        file: "#2a9d8f",
        network: "#e9c46a",
    };

    var charts = {};

    function loadAnalytics() {
        var range = document.getElementById("analytics-range");
        var rangeVal = range ? range.value : "24h";

        fetch("/api/logs/analytics?range=" + rangeVal)
            .then(function (res) { return res.json(); })
            .then(function (data) {
                renderSummary(data);
                renderCharts(data);

                var emptyMsg = document.getElementById("analytics-empty");
                if (emptyMsg) {
                    emptyMsg.style.display = data.total_events === 0 ? "" : "none";
                }
            })
            .catch(function () {});
    }

    function renderSummary(data) {
        setText("summary-total", data.total_events);
        setText("summary-deny", data.total_deny);
        setText("summary-warn", data.total_warn);
        setText("summary-rate", data.deny_rate + "%");
    }

    function setText(id, value) {
        var el = document.getElementById(id);
        if (el) el.textContent = value;
    }

    function renderCharts(data) {
        renderTimeline(data.verdicts_over_time);
        renderTopRules(data.top_rules);
        renderTopTargets(data.top_targets);
        renderActionTypes(data.action_type_counts);
        renderVerdictBreakdown(data.verdict_counts);
    }

    // ── Verdicts Over Time (line chart) ─────────────────────

    function renderTimeline(vot) {
        destroyChart("chart-timeline");
        var ctx = document.getElementById("chart-timeline");
        if (!ctx) return;
        charts["chart-timeline"] = new Chart(ctx, {
            type: "line",
            data: {
                labels: formatTimeLabels(vot.labels),
                datasets: [
                    {
                        label: "Deny",
                        data: vot.deny,
                        borderColor: COLORS.deny,
                        backgroundColor: COLORS.deny + "33",
                        fill: true,
                        tension: 0.3,
                    },
                    {
                        label: "Warn",
                        data: vot.warn,
                        borderColor: COLORS.warn,
                        backgroundColor: COLORS.warn + "33",
                        fill: true,
                        tension: 0.3,
                    },
                    {
                        label: "Allow",
                        data: vot.allow,
                        borderColor: COLORS.allow,
                        backgroundColor: COLORS.allow + "33",
                        fill: true,
                        tension: 0.3,
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: "index", intersect: false },
                plugins: { legend: { position: "bottom" } },
                scales: {
                    y: { beginAtZero: true, ticks: { precision: 0 } },
                },
            },
        });
    }

    function formatTimeLabels(labels) {
        return labels.map(function (l) {
            // "2026-03-29 14:00" → "Mar 29 14:00"
            var parts = l.split(" ");
            if (parts.length < 2) return l;
            var dateParts = parts[0].split("-");
            var months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
            var m = months[parseInt(dateParts[1], 10) - 1] || dateParts[1];
            return m + " " + parseInt(dateParts[2], 10) + " " + parts[1];
        });
    }

    // ── Top Rules (horizontal bar) ──────────────────────────

    function renderTopRules(rules) {
        destroyChart("chart-rules");
        var ctx = document.getElementById("chart-rules");
        if (!ctx) return;
        charts["chart-rules"] = new Chart(ctx, {
            type: "bar",
            data: {
                labels: rules.map(function (r) { return truncate(r.rule, 30); }),
                datasets: [{
                    label: "Violations",
                    data: rules.map(function (r) { return r.count; }),
                    backgroundColor: COLORS.deny,
                    borderRadius: 3,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: "y",
                plugins: { legend: { display: false } },
                scales: {
                    x: { beginAtZero: true, ticks: { precision: 0 } },
                },
            },
        });
    }

    // ── Top Targets (horizontal bar) ────────────────────────

    function renderTopTargets(targets) {
        destroyChart("chart-targets");
        var ctx = document.getElementById("chart-targets");
        if (!ctx) return;
        charts["chart-targets"] = new Chart(ctx, {
            type: "bar",
            data: {
                labels: targets.map(function (t) { return truncate(t.target, 30); }),
                datasets: [{
                    label: "Blocked",
                    data: targets.map(function (t) { return t.count; }),
                    backgroundColor: COLORS.warn,
                    borderRadius: 3,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: "y",
                plugins: { legend: { display: false } },
                scales: {
                    x: { beginAtZero: true, ticks: { precision: 0 } },
                },
            },
        });
    }

    // ── Action Types (donut) ────────────────────────────────

    function renderActionTypes(counts) {
        destroyChart("chart-actions");
        var ctx = document.getElementById("chart-actions");
        if (!ctx) return;
        var labels = Object.keys(counts);
        var values = Object.values(counts);
        var colors = labels.map(function (l) { return COLORS[l] || COLORS.muted; });
        charts["chart-actions"] = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels: labels,
                datasets: [{ data: values, backgroundColor: colors }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: "bottom" } },
            },
        });
    }

    // ── Verdict Breakdown (donut) ───────────────────────────

    function renderVerdictBreakdown(counts) {
        destroyChart("chart-verdicts");
        var ctx = document.getElementById("chart-verdicts");
        if (!ctx) return;
        var labels = Object.keys(counts);
        var values = Object.values(counts);
        var colors = labels.map(function (l) { return COLORS[l] || COLORS.muted; });
        charts["chart-verdicts"] = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels: labels,
                datasets: [{ data: values, backgroundColor: colors }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: "bottom" } },
            },
        });
    }

    // ── Helpers ──────────────────────────────────────────────

    function destroyChart(id) {
        if (charts[id]) {
            charts[id].destroy();
            delete charts[id];
        }
    }

    function truncate(str, max) {
        if (!str) return "";
        return str.length > max ? str.substring(0, max - 1) + "\u2026" : str;
    }

    // ── Init ────────────────────────────────────────────────

    if (document.getElementById("chart-timeline")) {
        loadAnalytics();

        var refreshBtn = document.getElementById("analytics-refresh-btn");
        if (refreshBtn) {
            refreshBtn.addEventListener("click", loadAnalytics);
        }

        var rangeSelect = document.getElementById("analytics-range");
        if (rangeSelect) {
            rangeSelect.addEventListener("change", loadAnalytics);
        }
    }
})();
