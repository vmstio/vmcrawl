(function () {
  "use strict";

  const API_BASE =
    (window.VMCRAWL_API || "").replace(/\/$/, "") || window.location.origin;
  const colorSchemeQuery = window.matchMedia("(prefers-color-scheme: dark)");
  const THEME_KEY = "vmcrawl-theme";
  const THEME_MODES = ["auto", "light", "dark"];

  function getStoredTheme() {
    const stored = localStorage.getItem(THEME_KEY);
    return THEME_MODES.includes(stored) ? stored : "auto";
  }

  function applySystemTheme() {
    const themeName = colorSchemeQuery.matches ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", themeName);
  }

  function applyTheme(mode) {
    if (mode === "auto") {
      applySystemTheme();
    } else {
      document.documentElement.setAttribute("data-theme", mode);
    }
  }

  applyTheme(getStoredTheme());

  function cssVar(name, fallback) {
    const value = getComputedStyle(document.documentElement)
      .getPropertyValue(name)
      .trim();
    return value || fallback;
  }

  function getThemePalette() {
    const purple = cssVar("--purple", "#9b59b6");
    const blue = cssVar("--blue", "#3498db");
    const green = cssVar("--green", "#2ecc71");
    const orange = cssVar("--orange", "#f39c12");
    const red = cssVar("--red", "#e74c3c");
    return {
      purple,
      green,
      orange,
      red,
      redDark: cssVar("--red-dark", "#922b21"),
      blue,
      chartColors: [purple, blue, green, orange, "#1abc9c", "#e67e22", "#95a5a6"],
      text: cssVar("--text", "#e0e0e8"),
      textMuted: cssVar("--text-muted", "#8888a0"),
      border: cssVar("--border", "#2a2a3a"),
      bgCard: cssVar("--bg-card", "#1a1a24"),
      bgChartRest: cssVar("--bg-chart-rest", "#2e2e3e"),
    };
  }

  const theme = getThemePalette();

  // Colors
  const PURPLE = theme.purple;
  const GREEN = theme.green;
  const ORANGE = theme.orange;
  const RED = theme.red;
  const BLUE = theme.blue;
  const CHART_COLORS = theme.chartColors;

  Chart.defaults.color = theme.textMuted;
  Chart.defaults.borderColor = theme.border;

  // Match the bar/pie chart tooltips to the sparkline's HTML tooltip styling.
  const tooltipDefaults = Chart.defaults.plugins.tooltip;
  tooltipDefaults.backgroundColor = theme.bgCard;
  tooltipDefaults.borderColor = theme.border;
  tooltipDefaults.borderWidth = 1;
  tooltipDefaults.cornerRadius = 4;
  tooltipDefaults.padding = { top: 6, bottom: 6, left: 10, right: 10 };
  tooltipDefaults.titleColor = theme.textMuted;
  tooltipDefaults.titleFont = { size: 11, weight: "500" };
  tooltipDefaults.bodyColor = theme.text;
  tooltipDefaults.bodyFont = { size: 12, weight: "600" };
  tooltipDefaults.boxPadding = 4;

  function fmt(n) {
    if (n == null) return "--";
    return Number(n).toLocaleString();
  }

  function pct(n) {
    if (n == null) return "--";
    return Number(n).toFixed(1) + "%";
  }

  async function api(path) {
    const resp = await fetch(API_BASE + path);
    if (!resp.ok) throw new Error(`API error: ${resp.status}`);
    return resp.json();
  }

  // Gauge color based on percentage
  function gaugeColor(value, max) {
    if (!max) return RED;
    const ratio = value / max;
    if (ratio >= 0.66) return GREEN;
    if (ratio >= 0.33) return ORANGE;
    return RED;
  }

  function createGauge(canvasId, value, max) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    const color = gaugeColor(value, max);
    const remaining = Math.max(0, max - value);
    new Chart(ctx, {
      type: "doughnut",
      data: {
        datasets: [
          {
            data: [value, remaining],
            backgroundColor: [color, theme.bgChartRest],
            borderWidth: 0,
            circumference: 180,
            rotation: 270,
          },
        ],
      },
      options: {
        responsive: true,
        cutout: "75%",
        plugins: {
          legend: { display: false },
          tooltip: { enabled: false },
        },
        layout: { padding: 0 },
      },
      plugins: [
        {
          id: "gaugeText",
          afterDraw(chart) {
            const { ctx: c, chartArea } = chart;
            const cx = (chartArea.left + chartArea.right) / 2;
            const cy = chartArea.bottom - 10;
            c.save();
            c.textAlign = "center";
            c.textBaseline = "bottom";
            c.fillStyle = color;
            c.font = "bold 18px -apple-system, sans-serif";
            c.fillText(fmt(value), cx, cy);
            c.restore();
          },
        },
      ],
    });
  }

  function ensureSparklineTooltip() {
    let el = document.getElementById("spark-tooltip");
    if (el) return el;
    el = document.createElement("div");
    el.id = "spark-tooltip";
    el.className = "spark-tooltip";
    document.body.appendChild(el);
    return el;
  }

  function sparklineExternalTooltip(context) {
    const el = ensureSparklineTooltip();
    const t = context.tooltip;
    if (!t || t.opacity === 0) {
      el.style.opacity = 0;
      return;
    }
    const dp = t.dataPoints && t.dataPoints[0];
    if (!dp) {
      el.style.opacity = 0;
      return;
    }
    el.innerHTML =
      `<div class="spark-tooltip-title">${esc(dp.label)}</div>` +
      `<div class="spark-tooltip-value">${esc(fmt(dp.parsed.y))}</div>`;
    const canvas = context.chart.canvas;
    const rect = canvas.getBoundingClientRect();
    el.style.left = rect.left + window.scrollX + t.caretX + "px";
    el.style.top = rect.top + window.scrollY - 6 + "px";
    el.style.opacity = 1;
  }

  function createSparkline(canvasId, labels, data, color) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    new Chart(ctx, {
      type: "line",
      data: {
        labels: labels,
        datasets: [
          {
            data: data,
            borderColor: color || PURPLE,
            backgroundColor: (color || PURPLE) + "20",
            fill: true,
            borderWidth: 1.5,
            pointRadius: 0,
            pointHoverRadius: 3,
            tension: 0.4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { intersect: false, mode: "index" },
        scales: { x: { display: false }, y: { display: false } },
        plugins: {
          legend: { display: false },
          tooltip: {
            enabled: false,
            external: sparklineExternalTooltip,
          },
        },
        layout: { padding: 0 },
      },
    });
  }

  function createBarGauge(canvasId, labels, values) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [
          {
            data: values,
            backgroundColor: PURPLE,
            borderRadius: 4,
          },
        ],
      },
      options: {
        indexAxis: "y",
        responsive: true,
        scales: {
          x: {
            min: 0,
            max: 100,
            ticks: { callback: (v) => v + "%" },
            grid: { color: theme.border },
          },
          y: { grid: { display: false } },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (ctx) => ctx.parsed.x.toFixed(1) + "%",
            },
          },
        },
      },
    });
  }

  function createPieChart(canvasId, labels, values, colors, opts = {}) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    const bgColors = labels.map((l, i) => {
      if (colors) return colors[i % colors.length];
      if (l === "EOL") return RED;
      if (l === "Unpatched") return ORANGE;
      return CHART_COLORS[i % CHART_COLORS.length];
    });
    new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [
          {
            data: values,
            backgroundColor: bgColors,
            borderWidth: 1,
            borderColor: theme.bgCard,
          },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              padding: 12,
              usePointStyle: true,
              font: { size: 11 },
            },
          },
          tooltip: {
            callbacks: {
              title: () => "",
              label: function (ctx) {
                const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                const pctVal = total
                  ? ((ctx.parsed / total) * 100).toFixed(1)
                  : 0;
                return (
                  ctx.label + ": " + fmt(ctx.parsed) + " (" + pctVal + "%)"
                );
              },
              afterBody: opts.afterBody,
            },
          },
        },
      },
    });
  }

  // Treemap of categorical counts. `items` is [{ [key]: label, value }, ...];
  // `total` is used for tooltip percentages. Fills its sized container.
  function createTreemap(canvasId, items, total, key = "label", colorFor) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    new Chart(ctx, {
      type: "treemap",
      data: {
        datasets: [
          {
            tree: items,
            key: "value",
            groups: [key],
            spacing: 1,
            borderWidth: 1,
            borderColor: theme.bgCard,
            backgroundColor(c) {
              if (c.type !== "data") return "transparent";
              const name = (c.raw && c.raw.g) || "";
              return colorFor
                ? colorFor(name, c.dataIndex)
                : CHART_COLORS[c.dataIndex % CHART_COLORS.length];
            },
            labels: {
              display: true,
              overflow: "hidden",
              color: "#fff",
              font: { size: 11 },
              formatter: (c) => [c.raw.g, fmt(c.raw.v)],
            },
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            displayColors: false,
            callbacks: {
              title: () => "",
              label(c) {
                const v = c.raw.v;
                const p = total ? ((v / total) * 100).toFixed(1) : "0";
                return `${c.raw.g}: ${fmt(v)} (${p}%)`;
              },
            },
          },
        },
      },
    });
  }

  function darkenHex(hex, factor) {
    const m = /^#([0-9a-f]{6})$/i.exec(hex || "");
    if (!m) return hex;
    const v = parseInt(m[1], 16);
    const r = Math.round(((v >> 16) & 0xff) * (1 - factor));
    const g = Math.round(((v >> 8) & 0xff) * (1 - factor));
    const b = Math.round((v & 0xff) * (1 - factor));
    return (
      "#" + [r, g, b].map((x) => x.toString(16).padStart(2, "0")).join("")
    );
  }

  // Generate `count` shades darkening from the base color (0% darken at i=0)
  // through `maxDarken` (default 55%) at i=count-1. Used to differentiate
  // branches within a single-family stacked chart.
  function makeShades(base, count, maxDarken = 0.55) {
    if (count <= 1) return [base];
    const step = maxDarken / (count - 1);
    return Array.from({ length: count }, (_, i) => darkenHex(base, i * step));
  }

  function createStackedBar(canvasId, labels, datasets, options = {}) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    const flags = options.flags || [];
    const reasons = options.reasons || [];
    // Drop datasets that have no data across the entire range so they don't
    // clutter the legend with empty entries.
    const populated = datasets.filter((d) =>
      (d.data || []).some((v) => Number(v) > 0),
    );
    new Chart(ctx, {
      type: "bar",
      data: { labels: labels, datasets: populated },
      options: {
        indexAxis: "x",
        responsive: true,
        scales: {
          x: {
            stacked: true,
            grid: { display: false },
            ticks: {
              autoSkip: true,
              maxRotation: 0,
              // Flag impacted days with a ⚠ on the axis label rather than
              // fading the bars, so the data stays at full color.
              callback(value, index) {
                const label = this.getLabelForValue(value);
                return flags[index] ? `⚠ ${label}` : label;
              },
            },
          },
          y: {
            stacked: true,
            grid: { color: theme.border },
            ticks: { callback: (v) => fmt(v) },
          },
        },
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              usePointStyle: true,
              font: { size: 11 },
            },
          },
          tooltip: {
            callbacks: {
              label: (ctx) => ctx.dataset.label + ": " + fmt(ctx.parsed.y),
              afterBody: (items) => {
                if (!items.length) return "";
                const idx = items[0].dataIndex;
                if (!flags[idx]) return "";
                return reasons[idx]
                  ? `⚠ Data flagged invalid: ${reasons[idx]}`
                  : "⚠ Data flagged invalid";
              },
            },
          },
        },
      },
    });
  }

  // Table state. Persisted to sessionStorage so the periodic auto-refresh
  // (full page reload) preserves the user's search, filter, sort, and page.
  const TABLE_STATE_KEY = "vmcrawl-table-state";
  const SCROLL_KEY = "vmcrawl-scroll";
  let tableState = {
    offset: 0,
    limit: 100,
    sort_by: "mau",
    order: "desc",
    q: "",
    filter: "",
    total: 0,
  };

  function restoreTableState() {
    let saved;
    try {
      saved = JSON.parse(sessionStorage.getItem(TABLE_STATE_KEY) || "null");
    } catch (_) {
      saved = null;
    }
    if (!saved) return;
    // total is recomputed by loadTable; everything else is user-driven.
    for (const key of ["offset", "limit", "sort_by", "order", "q", "filter"]) {
      if (saved[key] != null) tableState[key] = saved[key];
    }
    const searchInput = document.getElementById("search-input");
    if (searchInput) searchInput.value = tableState.q;
    const filterSelect = document.getElementById("filter-select");
    if (filterSelect) filterSelect.value = tableState.filter;
  }
  restoreTableState();

  function persistTableState() {
    try {
      sessionStorage.setItem(TABLE_STATE_KEY, JSON.stringify(tableState));
    } catch (_) {
      /* sessionStorage unavailable (e.g. private mode) — refresh still works */
    }
  }

  async function loadTable() {
    const s = tableState;
    persistTableState();
    const params = new URLSearchParams({
      limit: s.limit,
      offset: s.offset,
      sort_by: s.sort_by,
      order: s.order,
    });
    if (s.q) params.set("q", s.q);
    if (s.filter) params.set("filter", s.filter);

    const data = await api("/instances/table?" + params);
    s.total = data.total;

    const tbody = document.getElementById("instances-tbody");
    tbody.innerHTML = data.instances
      .map(
        (i) => `<tr>
            <td>${esc(i.domain)}</td>
            <td>${esc(i.version || "")}</td>
            <td>${esc(i.full_version || "")}</td>
            <td>${esc(i.software || "")}</td>
            <td style="text-align:right">${i.monthly_active_users != null ? fmt(i.monthly_active_users) : ""}</td>
            <td style="text-align:right">${i.last_updated ? new Date(i.last_updated.endsWith("Z") ? i.last_updated : i.last_updated + "Z").toLocaleString() : ""}</td>
        </tr>`,
      )
      .join("");

    const pageInfo = document.getElementById("page-info");
    const start = s.total ? s.offset + 1 : 0;
    const end = Math.min(s.offset + s.limit, s.total);
    pageInfo.textContent = `${fmt(start)}-${fmt(end)} of ${fmt(s.total)}`;

    document.getElementById("prev-btn").disabled = s.offset === 0;
    document.getElementById("next-btn").disabled =
      s.offset + s.limit >= s.total;
    updateSortIndicators();
  }

  function esc(str) {
    const d = document.createElement("div");
    d.textContent = str;
    return d.innerHTML;
  }

  function severityBadge(sev) {
    const s = (sev || "unknown").toLowerCase();
    const label = s.charAt(0).toUpperCase() + s.slice(1);
    return `<span class="sev-badge sev-${esc(s)}">${esc(label)}</span>`;
  }

  const ADV_PAGE_SIZE = 10;
  const ADV_SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
  // Numeric/date columns read best high-to-low; text columns A-to-Z.
  const ADV_DEFAULT_DESC = new Set([
    "severity",
    "published_at",
    "instances_percent",
    "mau_percent",
  ]);
  let advisoriesData = [];
  let advisoriesPage = 0;
  let advSort = { key: "published_at", order: "desc" };

  function advSortValue(a, key) {
    switch (key) {
      case "severity":
        return ADV_SEVERITY_RANK[(a.severity || "").toLowerCase()] || 0;
      case "published_at":
        return a.published_at ? new Date(a.published_at).getTime() : 0;
      case "instances_percent":
        return a.instances_percent || 0;
      case "mau_percent":
        return a.mau_percent || 0;
      case "summary":
        return (a.summary || "").toLowerCase();
      default:
        return (a.ghsa_id || "").toLowerCase();
    }
  }

  function sortAdvisories() {
    const dir = advSort.order === "asc" ? 1 : -1;
    advisoriesData.sort((x, y) => {
      const vx = advSortValue(x, advSort.key);
      const vy = advSortValue(y, advSort.key);
      if (vx < vy) return -dir;
      if (vx > vy) return dir;
      // Stable tie-break so equal rows keep a deterministic order.
      return (x.ghsa_id || "").localeCompare(y.ghsa_id || "");
    });
  }

  function updateAdvSortIndicators() {
    document
      .querySelectorAll("#advisories-table th[data-adv-sort]")
      .forEach((th) => {
        const existing = th.querySelector(".sort-icon");
        if (existing) existing.remove();
        if (th.dataset.advSort === advSort.key) {
          const icon = document.createElement("span");
          icon.className = "sort-icon sort-icon--active";
          icon.textContent = advSort.order === "asc" ? " ↑" : " ↓";
          th.appendChild(icon);
        }
      });
  }

  function advisoryRow(a) {
    const published = a.published_at
      ? new Date(a.published_at).toLocaleDateString(undefined, {
          year: "numeric",
          month: "short",
          day: "numeric",
        })
      : "";
    const ghsa = a.url
      ? `<a href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.ghsa_id)}</a>`
      : esc(a.ghsa_id);
    const cve = a.cve_id
      ? `<br /><span class="adv-cve">${esc(a.cve_id)}</span>`
      : "";
    const specBtn = a.affected_spec
      ? `<button type="button" class="adv-spec-btn" data-spec="${esc(a.affected_spec)}" aria-label="Show affected version spec" title="Show affected version spec">i</button>`
      : "";
    let instCell;
    let mauCell;
    if (a.parse_status === "needs_review") {
      instCell = mauCell =
        '<span class="adv-review" title="Affected range needs manual review">review</span>';
    } else {
      instCell = `${pct(a.instances_percent)}<br /><span class="adv-count">${fmt(a.affected_instances)}</span>`;
      mauCell = `${pct(a.mau_percent)}<br /><span class="adv-count">${fmt(a.affected_mau)}</span>`;
    }
    return `<tr>
        <td class="adv-info" style="text-align:center">${specBtn}</td>
        <td class="adv-nowrap">${ghsa}${cve}</td>
        <td>${severityBadge(a.severity)}</td>
        <td class="adv-nowrap" style="text-align:right">${esc(published)}</td>
        <td class="adv-summary">${esc(a.summary || "")}</td>
        <td style="text-align:right">${instCell}</td>
        <td style="text-align:right">${mauCell}</td>
    </tr>`;
  }

  // Click-to-reveal popover showing the PEP 440 affected-version spec used to
  // compute an advisory's impact. A single shared element is repositioned next
  // to whichever icon is active.
  let advSpecPopover = null;
  let advSpecOwner = null;

  function closeAdvSpecPopover() {
    if (advSpecPopover) advSpecPopover.remove();
    advSpecPopover = null;
    advSpecOwner = null;
  }

  function openAdvSpecPopover(btn) {
    closeAdvSpecPopover();
    const pop = document.createElement("div");
    pop.className = "adv-spec-popover";
    pop.innerHTML =
      `<div class="adv-spec-popover-label">Affected version spec (PEP 440)</div>` +
      `<code>${esc(btn.dataset.spec || "")}</code>`;
    document.body.appendChild(pop);

    const rect = btn.getBoundingClientRect();
    pop.style.top = `${window.scrollY + rect.bottom + 6}px`;
    let left = window.scrollX + rect.left;
    // Keep the popover inside the viewport's right edge.
    const overflow = left + pop.offsetWidth - (window.scrollX + window.innerWidth) + 8;
    if (overflow > 0) left -= overflow;
    pop.style.left = `${Math.max(window.scrollX + 8, left)}px`;

    advSpecPopover = pop;
    advSpecOwner = btn;
  }

  function renderAdvisoriesPage() {
    const tbody = document.getElementById("advisories-tbody");
    if (!tbody) return;
    closeAdvSpecPopover();

    const total = advisoriesData.length;
    const pageCount = Math.max(1, Math.ceil(total / ADV_PAGE_SIZE));
    advisoriesPage = Math.min(advisoriesPage, pageCount - 1);

    const start = advisoriesPage * ADV_PAGE_SIZE;
    const end = Math.min(start + ADV_PAGE_SIZE, total);
    tbody.innerHTML = advisoriesData
      .slice(start, end)
      .map(advisoryRow)
      .join("");

    const pageInfo = document.getElementById("adv-page-info");
    if (pageInfo) {
      pageInfo.textContent = total
        ? `${fmt(start + 1)}-${fmt(end)} of ${fmt(total)}`
        : "0 of 0";
    }
    const prevBtn = document.getElementById("adv-prev-btn");
    const nextBtn = document.getElementById("adv-next-btn");
    if (prevBtn) prevBtn.disabled = advisoriesPage === 0;
    if (nextBtn) nextBtn.disabled = end >= total;

    updateAdvSortIndicators();
  }

  function renderAdvisories(data) {
    advisoriesData = (data && data.advisories) || [];
    sortAdvisories();
    advisoriesPage = 0;
    renderAdvisoriesPage();
  }

  function handleTableError(err) {
    console.error("Table load error:", err);
  }

  // Table event handlers
  document.getElementById("search-btn").addEventListener("click", () => {
    tableState.q = document.getElementById("search-input").value.trim();
    tableState.offset = 0;
    loadTable().catch(handleTableError);
  });

  document.getElementById("search-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      tableState.q = e.target.value.trim();
      tableState.offset = 0;
      loadTable().catch(handleTableError);
    }
  });

  document.getElementById("filter-select").addEventListener("change", (e) => {
    tableState.filter = e.target.value;
    tableState.offset = 0;
    loadTable().catch(handleTableError);
  });

  document.getElementById("prev-btn").addEventListener("click", () => {
    tableState.offset = Math.max(0, tableState.offset - tableState.limit);
    loadTable().catch(handleTableError);
  });

  document.getElementById("next-btn").addEventListener("click", () => {
    tableState.offset += tableState.limit;
    loadTable().catch(handleTableError);
  });

  document.getElementById("adv-prev-btn").addEventListener("click", () => {
    if (advisoriesPage > 0) {
      advisoriesPage -= 1;
      renderAdvisoriesPage();
    }
  });

  document.getElementById("adv-next-btn").addEventListener("click", () => {
    advisoriesPage += 1;
    renderAdvisoriesPage();
  });

  // Toggle the affected-spec popover from the per-row info icons. Delegated on
  // the tbody so it survives re-renders; document handlers dismiss it.
  const advTbodyEl = document.getElementById("advisories-tbody");
  if (advTbodyEl) {
    advTbodyEl.addEventListener("click", (e) => {
      const btn = e.target.closest(".adv-spec-btn");
      if (!btn) return;
      e.stopPropagation();
      if (advSpecOwner === btn) {
        closeAdvSpecPopover();
      } else {
        openAdvSpecPopover(btn);
      }
    });
  }
  document.addEventListener("click", (e) => {
    if (advSpecPopover && !advSpecPopover.contains(e.target)) {
      closeAdvSpecPopover();
    }
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeAdvSpecPopover();
  });

  document
    .querySelectorAll("#advisories-table th[data-adv-sort]")
    .forEach((th) => {
      th.addEventListener("click", () => {
        const key = th.dataset.advSort;
        if (advSort.key === key) {
          advSort.order = advSort.order === "desc" ? "asc" : "desc";
        } else {
          advSort.key = key;
          advSort.order = ADV_DEFAULT_DESC.has(key) ? "desc" : "asc";
        }
        sortAdvisories();
        advisoriesPage = 0;
        renderAdvisoriesPage();
      });
    });

  function updateSortIndicators() {
    document.querySelectorAll("th[data-sort]").forEach((th) => {
      const field = th.dataset.sort;
      const existing = th.querySelector(".sort-icon");
      if (existing) existing.remove();
      if (field === tableState.sort_by) {
        const icon = document.createElement("span");
        icon.className = "sort-icon sort-icon--active";
        icon.textContent = tableState.order === "asc" ? " ↑" : " ↓";
        th.appendChild(icon);
      }
    });
  }

  document.querySelectorAll("th[data-sort]").forEach((th) => {
    th.addEventListener("click", () => {
      const field = th.dataset.sort;
      if (tableState.sort_by === field) {
        tableState.order = tableState.order === "desc" ? "asc" : "desc";
      } else {
        tableState.sort_by = field;
        tableState.order = ["mau", "last_crawled"].includes(field)
          ? "desc"
          : "asc";
      }
      tableState.offset = 0;
      loadTable().catch(handleTableError);
    });
  });

  // Load all data
  async function init() {
    const [
      summary,
      patchAdoption,
      supportedBranches,
      patchDetail,
      patchDist,
      branchDist,
      eolDist,
      branchAdoption,
      history,
      versionsData,
      advisories,
    ] = await Promise.all([
      api("/stats/summary"),
      api("/stats/patch-adoption"),
      api("/stats/supported-branches"),
      api("/stats/patch-detail"),
      api("/stats/patch-distribution"),
      api("/stats/branch-distribution"),
      api("/stats/eol-distribution"),
      api("/stats/branch-adoption"),
      api("/stats/history?days=365"),
      api("/stats/versions"),
      api("/stats/advisories"),
    ]);

    renderAdvisories(advisories);

    // Big numbers
    document.getElementById("total-instances").textContent = fmt(
      summary.total_instances,
    );
    document.getElementById("total-mau").textContent = fmt(
      summary.monthly_active_users,
    );
    document.getElementById("patch-instances").textContent = pct(
      patchAdoption.instances_patched_percent,
    );
    document.getElementById("patch-mau").textContent = pct(
      patchAdoption.mau_patched_percent,
    );
    document.getElementById("supported-instances").textContent = pct(
      supportedBranches.instances_percent,
    );
    document.getElementById("supported-mau").textContent = pct(
      supportedBranches.mau_percent,
    );

    // Sparklines from history
    const hist = history.history.slice().reverse();
    if (hist.length > 1) {
      const sparkLabels = hist.map((h) => {
        const [y, m, day] = h.date.split("-").map(Number);
        const d = new Date(y, m - 1, day);
        return d.toLocaleDateString("en-US", {
          day: "2-digit",
          month: "short",
          year: "numeric",
        });
      });
      const instanceTotals = hist.map(
        (h) =>
          h.main_instances +
          h.latest_instances +
          h.previous_instances +
          h.deprecated_instances +
          h.eol_instances,
      );
      const mauTotals = hist.map((h) => h.mau);
      createSparkline("spark-instances", sparkLabels, instanceTotals, PURPLE);
      createSparkline("spark-mau", sparkLabels, mauTotals, PURPLE);
    }

    // Gauges
    const branches = patchDetail.branches;
    for (const branch of ["main", "latest", "previous", "deprecated"]) {
      const b = branches[branch];
      const titleEl = document.getElementById(`gauge-title-${branch}`);
      if (!b.version) {
        const pair = titleEl && titleEl.parentElement
          ? titleEl.parentElement.querySelector(".gauge-pair")
          : null;
        if (pair) {
          pair.innerHTML =
            '<div class="gauge-empty">There are no supported versions in this branch at this time.' +
            '<br><a href="https://mastoreqs.com/lifecycle" target="_blank" rel="noopener">' +
            "Learn about the Mastodon version lifecycle</a></div>";
        }
        continue;
      }
      if (titleEl) titleEl.textContent = b.version;
      createGauge(`gauge-${branch}-instances`, b.patched, b.total);
      createGauge(`gauge-${branch}-mau`, b.mau_patched, b.mau_total);
    }

    // Branch adoption bar gauges
    const adoption = branchAdoption.adoption;
    createBarGauge(
      "chart-adoption-instances",
      adoption.map((a) => a.branch),
      adoption.map((a) => a.instances_percent),
    );
    createBarGauge(
      "chart-adoption-mau",
      adoption.map((a) => a.branch),
      adoption.map((a) => a.mau_percent),
    );

    // Patch distribution pies. The "EOL" slice gets an expanded tooltip
    // listing the top individual EOL versions (point-release granularity
    // from /stats/versions, filtered to versions whose branch is EOL).
    // Order slices by version number (highest first), with the aggregated
    // "Unpatched" and "EOL" buckets always pinned to the end.
    function compareVersionDesc(a, b) {
      const pa = String(a).split(".").map(Number);
      const pb = String(b).split(".").map(Number);
      for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
        const da = pa[i] || 0;
        const db = pb[i] || 0;
        if (da !== db) return db - da;
      }
      return 0;
    }
    const aggregateRank = (label) =>
      label === "EOL" ? 2 : label === "Unpatched" ? 1 : 0;
    const pd = patchDist.distribution.slice().sort((a, b) => {
      const ra = aggregateRank(a.version);
      const rb = aggregateRank(b.version);
      if (ra !== rb) return ra - rb;
      if (ra !== 0) return 0;
      return compareVersionDesc(a.version, b.version);
    });
    // Shade the per-version slices by semantic version (newest = brightest
    // purple). EOL stays RED, Unpatched stays ORANGE.
    const pdVersionEntries = pd
      .filter((d) => d.version !== "EOL" && d.version !== "Unpatched")
      .slice()
      .sort((a, b) => compareVersionDesc(a.version, b.version));
    const pdShades = makeShades(PURPLE, pdVersionEntries.length);
    const pdVersionColors = new Map(
      pdVersionEntries.map((d, i) => [d.version, pdShades[i]]),
    );
    const pdColors = pd.map((d) => {
      if (d.version === "EOL") return RED;
      if (d.version === "Unpatched") return ORANGE;
      return pdVersionColors.get(d.version) || PURPLE;
    });

    const eolBranchPrefixes = eolDist.distribution.map((d) => d.branch);
    function isEolVersion(v) {
      return eolBranchPrefixes.some((b) => v.startsWith(b + "."));
    }
    // The aggregated slice labels in patchDist are everything that isn't a
    // literal version — i.e. "EOL" and "Unpatched". Any literal version in
    // patchDist is by definition the current latest of its branch.
    const supportedLatestVersions = new Set(
      patchDist.distribution
        .filter((d) => d.version !== "EOL" && d.version !== "Unpatched")
        .map((d) => d.version),
    );
    function isUnpatchedVersion(v) {
      return !supportedLatestVersions.has(v) && !isEolVersion(v);
    }

    function detailedFor(predicate) {
      return (versionsData.versions || [])
        .filter((v) => predicate(v.version))
        .map((v) => ({
          version: v.version,
          instances: v.instances,
          mau: v.monthly_active_users || 0,
        }));
    }
    const eolDetailed = detailedFor(isEolVersion);
    const unpatchedDetailed = detailedFor(isUnpatchedVersion);

    const PATCH_EXPAND_TOP_N = 10;
    const expandableSlices = {
      EOL: { pool: eolDetailed, title: "Top EOL versions:" },
      Unpatched: { pool: unpatchedDetailed, title: "Top Unpatched versions:" },
    };

    function patchExpandAfterBody(field) {
      return (items) => {
        if (!items.length) return undefined;
        const config = expandableSlices[items[0].label];
        if (!config) return undefined;
        const sliceTotal = items[0].parsed || 0;
        if (!sliceTotal) return undefined;
        const sorted = config.pool
          .filter((v) => v[field] > 0)
          .sort((a, b) => b[field] - a[field]);
        if (!sorted.length) return undefined;
        const top = sorted.slice(0, PATCH_EXPAND_TOP_N);
        const lines = ["", config.title];
        for (const v of top) {
          const pctVal = ((v[field] / sliceTotal) * 100).toFixed(1);
          lines.push(`  ${v.version}: ${fmt(v[field])} (${pctVal}%)`);
        }
        if (sorted.length > PATCH_EXPAND_TOP_N) {
          lines.push(`  + ${sorted.length - PATCH_EXPAND_TOP_N} more`);
        }
        return lines;
      };
    }

    createPieChart(
      "pie-patch-instances",
      pd.map((d) => d.version),
      pd.map((d) => d.instances),
      pdColors,
      { afterBody: patchExpandAfterBody("instances") },
    );
    createPieChart(
      "pie-patch-mau",
      pd.map((d) => d.version),
      pd.map((d) => d.mau),
      pdColors,
      { afterBody: patchExpandAfterBody("mau") },
    );

    // Branch distribution donuts — single aggregated EOL slice, with the
    // per-version EOL breakdown surfaced inside the EOL slice's tooltip.
    // Supported branches shaded by branch (newest = brightest green).
    const bd = branchDist.distribution.slice().sort((a, b) => {
      const ra = aggregateRank(a.branch);
      const rb = aggregateRank(b.branch);
      if (ra !== rb) return ra - rb;
      if (ra !== 0) return 0;
      return compareVersionDesc(a.branch, b.branch);
    });
    const bdSupportedDesc = bd
      .filter((d) => d.branch !== "EOL")
      .slice()
      .sort((a, b) => compareVersionDesc(a.branch, b.branch));
    const bdShades = makeShades(GREEN, bdSupportedDesc.length);
    const bdBranchColors = new Map(
      bdSupportedDesc.map((d, i) => [d.branch, bdShades[i]]),
    );
    const bdColors = bd.map((d) =>
      d.branch === "EOL" ? RED : bdBranchColors.get(d.branch) || GREEN,
    );
    const eolVersions = eolDist.distribution
      .filter((d) => d.instances > 0)
      .slice();

    function eolBreakdownAfterBody(field) {
      return (items) => {
        if (!items.length || items[0].label !== "EOL") return undefined;
        const eolTotal = items[0].parsed || 0;
        if (!eolTotal) return undefined;
        const sorted = eolVersions
          .filter((d) => d[field] > 0)
          .sort((a, b) => b[field] - a[field]);
        if (!sorted.length) return undefined;
        const lines = ["", "Breakdown:"];
        for (const d of sorted) {
          const pctVal = ((d[field] / eolTotal) * 100).toFixed(1);
          lines.push(`  ${d.branch}: ${fmt(d[field])} (${pctVal}%)`);
        }
        return lines;
      };
    }

    createPieChart(
      "pie-branch-instances",
      bd.map((d) => d.branch),
      bd.map((d) => d.instances),
      bdColors,
      { afterBody: eolBreakdownAfterBody("instances") },
    );
    createPieChart(
      "pie-branch-mau",
      bd.map((d) => d.branch),
      bd.map((d) => d.mau),
      bdColors,
      { afterBody: eolBreakdownAfterBody("mau") },
    );

    // Historical charts
    const histSlice = hist.slice(-30);
    const histLabels = histSlice.map((h) => {
      const [y, m, day] = h.date.split("-").map(Number);
      const d = new Date(y, m - 1, day);
      return d.toLocaleDateString("en-US", { day: "2-digit", month: "short" });
    });
    const histFlags = histSlice.map((h) => Boolean(h.invalid));
    const histReasons = histSlice.map((h) => h.invalid_reason || "");
    const histOptions = { flags: histFlags, reasons: histReasons };

    const histBranchNames = [
      "Main Branch",
      "Latest Branch",
      "Previous Branch",
      "Deprecated Branch",
    ];
    // Historical Trends palette: shaded BLUE for Main/Latest/Previous so the
    // section reads as its own visual unit, then ORANGE for Deprecated to
    // echo the "Unpatched" slice in the Patch Distribution donut, and RED for
    // EOL throughout.
    const histShades = [...makeShades(BLUE, 3), ORANGE];

    // Patch adoption by instance
    createStackedBar(
      "chart-hist-patch-instances",
      histLabels,
      [
        {
          label: histBranchNames[0],
          data: histSlice.map((h) => h.main_patched_instances),
          backgroundColor: histShades[0],
        },
        {
          label: histBranchNames[1],
          data: histSlice.map((h) => h.latest_patched_instances),
          backgroundColor: histShades[1],
        },
        {
          label: histBranchNames[2],
          data: histSlice.map((h) => h.previous_patched_instances),
          backgroundColor: histShades[2],
        },
        {
          label: histBranchNames[3],
          data: histSlice.map((h) => h.deprecated_patched_instances),
          backgroundColor: histShades[3],
        },
      ],
      histOptions,
    );

    // Patch adoption by MAU
    createStackedBar(
      "chart-hist-patch-mau",
      histLabels,
      [
        {
          label: histBranchNames[0],
          data: histSlice.map((h) => h.main_patched_mau),
          backgroundColor: histShades[0],
        },
        {
          label: histBranchNames[1],
          data: histSlice.map((h) => h.latest_patched_mau),
          backgroundColor: histShades[1],
        },
        {
          label: histBranchNames[2],
          data: histSlice.map((h) => h.previous_patched_mau),
          backgroundColor: histShades[2],
        },
        {
          label: histBranchNames[3],
          data: histSlice.map((h) => h.deprecated_patched_mau),
          backgroundColor: histShades[3],
        },
      ],
      histOptions,
    );

    // Branch deployments by instance
    createStackedBar(
      "chart-hist-branch-instances",
      histLabels,
      [
        {
          label: histBranchNames[0],
          data: histSlice.map((h) => h.main_instances),
          backgroundColor: histShades[0],
        },
        {
          label: histBranchNames[1],
          data: histSlice.map((h) => h.latest_instances),
          backgroundColor: histShades[1],
        },
        {
          label: histBranchNames[2],
          data: histSlice.map((h) => h.previous_instances),
          backgroundColor: histShades[2],
        },
        {
          label: histBranchNames[3],
          data: histSlice.map((h) => h.deprecated_instances),
          backgroundColor: histShades[3],
        },
        {
          label: "EOL Branches",
          data: histSlice.map((h) => h.eol_instances),
          backgroundColor: RED,
        },
      ],
      histOptions,
    );

    // Branch deployments by MAU
    createStackedBar(
      "chart-hist-branch-mau",
      histLabels,
      [
        {
          label: histBranchNames[0],
          data: histSlice.map((h) => h.main_branch_mau),
          backgroundColor: histShades[0],
        },
        {
          label: histBranchNames[1],
          data: histSlice.map((h) => h.latest_branch_mau),
          backgroundColor: histShades[1],
        },
        {
          label: histBranchNames[2],
          data: histSlice.map((h) => h.previous_branch_mau),
          backgroundColor: histShades[2],
        },
        {
          label: histBranchNames[3],
          data: histSlice.map((h) => h.deprecated_branch_mau),
          backgroundColor: histShades[3],
        },
        {
          label: "EOL Branches",
          data: histSlice.map((h) => h.eol_branch_mau),
          backgroundColor: RED,
        },
      ],
      histOptions,
    );

    // Load table
    await loadTable().catch(handleTableError);

    // Stamp the footer with the crawl data's age and when the page last
    // fetched it. The crawl timestamp may lack a trailing "Z"; treat it as
    // UTC (matching the table) so it renders in the viewer's local time.
    const tsEl = document.getElementById("data-timestamp");
    if (tsEl) {
      const parts = [];
      if (summary.last_updated) {
        const raw = summary.last_updated;
        const crawled = new Date(raw.endsWith("Z") ? raw : raw + "Z");
        parts.push("Crawl data as of " + crawled.toLocaleString());
      }
      parts.push("Page refreshed " + new Date().toLocaleString());
      tsEl.textContent = parts.join(" · ");
    }

    // Restore scroll position saved by an auto-refresh. One-shot: consume it
    // so a later manual reload starts at the top as usual.
    let savedScroll;
    try {
      savedScroll = sessionStorage.getItem(SCROLL_KEY);
      if (savedScroll != null) sessionStorage.removeItem(SCROLL_KEY);
    } catch (_) {
      savedScroll = null;
    }
    if (savedScroll != null) {
      window.scrollTo(0, parseInt(savedScroll, 10) || 0);
    }
  }

  init().catch((err) => {
    console.error("Dashboard load error:", err);
  });

  // Auto-refresh so the displayed crawl data stays current without a manual
  // reload. A full reload (matching the theme-toggle pattern) avoids leaking
  // Chart.js instances and correctly re-renders branches that gain/lose a
  // supported version. Table state is preserved via sessionStorage; scroll
  // position is saved here so the refresh lands where the user was (and only
  // an auto-refresh restores scroll — a manual reload still starts at top).
  // Skip while the tab is hidden to avoid churning background tabs, then catch
  // up when it next becomes visible.
  function autoRefresh() {
    try {
      sessionStorage.setItem(SCROLL_KEY, String(window.scrollY));
    } catch (_) {
      /* sessionStorage unavailable — refresh still works, just no scroll */
    }
    window.location.reload();
  }

  const REFRESH_INTERVAL_MS = 5 * 60 * 1000;
  let refreshPending = false;
  setInterval(() => {
    if (document.hidden) {
      refreshPending = true;
    } else {
      autoRefresh();
    }
  }, REFRESH_INTERVAL_MS);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && refreshPending) {
      autoRefresh();
    }
  });

  const themeToggle = document.querySelector(".theme-toggle");
  if (themeToggle) {
    const current = getStoredTheme();
    themeToggle.dataset.mode = current;
    themeToggle.title =
      "Theme: " + current.charAt(0).toUpperCase() + current.slice(1);
    themeToggle.addEventListener("click", () => {
      const next =
        THEME_MODES[(THEME_MODES.indexOf(getStoredTheme()) + 1) % THEME_MODES.length];
      localStorage.setItem(THEME_KEY, next);
      window.location.reload();
    });
  }

  if (typeof colorSchemeQuery.addEventListener === "function") {
    colorSchemeQuery.addEventListener("change", () => {
      if (getStoredTheme() === "auto") {
        window.location.reload();
      }
    });
  }
})();
