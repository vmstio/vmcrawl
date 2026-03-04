(function () {
    'use strict';

    const API_BASE = (window.VMCRAWL_API || '').replace(/\/$/, '') || window.location.origin;

    // Colors
    const PURPLE = '#9b59b6';
    const PURPLE_LIGHT = '#c39bd3';
    const GREEN = '#2ecc71';
    const ORANGE = '#f39c12';
    const RED = '#e74c3c';
    const RED_DARK = '#922b21';
    const BLUE = '#3498db';
    const TEAL = '#1abc9c';
    const CHART_COLORS = [PURPLE, BLUE, GREEN, ORANGE, TEAL, '#e67e22', '#95a5a6'];
    const BRANCH_COLORS = ['#2ecc71', '#3498db', '#9b59b6', '#f39c12', '#1abc9c', '#e67e22'];
    const TEXT_MUTED = '#8888a0';

    Chart.defaults.color = TEXT_MUTED;
    Chart.defaults.borderColor = '#2a2a3a';

    function fmt(n) {
        if (n == null) return '--';
        return Number(n).toLocaleString();
    }

    function pct(n) {
        if (n == null) return '--';
        return Number(n).toFixed(1) + '%';
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
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [value, remaining],
                    backgroundColor: [color, '#2e2e3e'],
                    borderWidth: 0,
                    circumference: 180,
                    rotation: 270,
                }]
            },
            options: {
                responsive: true,
                cutout: '75%',
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: false },
                },
                layout: { padding: 0 },
            },
            plugins: [{
                id: 'gaugeText',
                afterDraw(chart) {
                    const { ctx: c, chartArea } = chart;
                    const cx = (chartArea.left + chartArea.right) / 2;
                    const cy = chartArea.bottom - 10;
                    c.save();
                    c.textAlign = 'center';
                    c.textBaseline = 'bottom';
                    c.fillStyle = color;
                    c.font = 'bold 18px -apple-system, sans-serif';
                    c.fillText(fmt(value), cx, cy);
                    c.restore();
                }
            }]
        });
    }

    function createSparkline(canvasId, data, color) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return;
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.map((_, i) => i),
                datasets: [{
                    data: data,
                    borderColor: color || PURPLE,
                    backgroundColor: (color || PURPLE) + '20',
                    fill: true,
                    borderWidth: 1.5,
                    pointRadius: 0,
                    tension: 0.4,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: { x: { display: false }, y: { display: false } },
                plugins: { legend: { display: false }, tooltip: { enabled: false } },
                layout: { padding: 0 },
            }
        });
    }

    function createBarGauge(canvasId, labels, values) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return;
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: PURPLE,
                    borderRadius: 4,
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                scales: {
                    x: {
                        min: 0,
                        max: 100,
                        ticks: { callback: v => v + '%' },
                        grid: { color: '#2a2a3a' },
                    },
                    y: { grid: { display: false } }
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: ctx => ctx.parsed.x.toFixed(1) + '%'
                        }
                    }
                },
            }
        });
    }

    function createPieChart(canvasId, labels, values, colors) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return;
        const bgColors = labels.map((l, i) => {
            if (colors) return colors[i % colors.length];
            if (l === 'EOL') return RED;
            if (l === 'Unpatched') return ORANGE;
            return CHART_COLORS[i % CHART_COLORS.length];
        });
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: bgColors,
                    borderWidth: 1,
                    borderColor: '#1a1a24',
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 12,
                            usePointStyle: true,
                            font: { size: 11 },
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function (ctx) {
                                const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                                const pctVal = total ? ((ctx.parsed / total) * 100).toFixed(1) : 0;
                                return ctx.label + ': ' + fmt(ctx.parsed) + ' (' + pctVal + '%)';
                            }
                        }
                    }
                }
            }
        });
    }

    function createStackedBar(canvasId, labels, datasets) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return;
        new Chart(ctx, {
            type: 'bar',
            data: { labels: labels, datasets: datasets },
            options: {
                indexAxis: 'y',
                responsive: true,
                scales: {
                    x: {
                        stacked: true,
                        grid: { color: '#2a2a3a' },
                        ticks: { callback: v => fmt(v) },
                    },
                    y: {
                        stacked: true,
                        grid: { display: false },
                    }
                },
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { usePointStyle: true, font: { size: 11 } }
                    },
                    tooltip: {
                        callbacks: {
                            label: ctx => ctx.dataset.label + ': ' + fmt(ctx.parsed.x)
                        }
                    }
                }
            }
        });
    }

    // Table state
    let tableState = {
        offset: 0,
        limit: 100,
        sort_by: 'mau',
        order: 'desc',
        q: '',
        total: 0,
    };

    async function loadTable() {
        const s = tableState;
        const params = new URLSearchParams({
            limit: s.limit,
            offset: s.offset,
            sort_by: s.sort_by,
            order: s.order,
        });
        if (s.q) params.set('q', s.q);

        const data = await api('/instances/table?' + params);
        s.total = data.total;

        const tbody = document.getElementById('instances-tbody');
        tbody.innerHTML = data.instances.map(i => `<tr>
            <td>${esc(i.domain)}</td>
            <td>${esc(i.version || '')}</td>
            <td>${esc(i.full_version || '')}</td>
            <td>${esc(i.software || '')}</td>
            <td style="text-align:right">${i.monthly_active_users != null ? fmt(i.monthly_active_users) : ''}</td>
            <td style="text-align:right">${i.last_updated ? new Date(i.last_updated.endsWith('Z') ? i.last_updated : i.last_updated + 'Z').toLocaleString() : ''}</td>
        </tr>`).join('');

        const pageInfo = document.getElementById('page-info');
        const start = s.total ? s.offset + 1 : 0;
        const end = Math.min(s.offset + s.limit, s.total);
        pageInfo.textContent = `${fmt(start)}-${fmt(end)} of ${fmt(s.total)}`;

        document.getElementById('prev-btn').disabled = s.offset === 0;
        document.getElementById('next-btn').disabled = s.offset + s.limit >= s.total;
        updateSortIndicators();
    }

    function esc(str) {
        const d = document.createElement('div');
        d.textContent = str;
        return d.innerHTML;
    }

    // Table event handlers
    document.getElementById('search-btn').addEventListener('click', () => {
        tableState.q = document.getElementById('search-input').value.trim();
        tableState.offset = 0;
        loadTable();
    });

    document.getElementById('search-input').addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            tableState.q = e.target.value.trim();
            tableState.offset = 0;
            loadTable();
        }
    });

    document.getElementById('prev-btn').addEventListener('click', () => {
        tableState.offset = Math.max(0, tableState.offset - tableState.limit);
        loadTable();
    });

    document.getElementById('next-btn').addEventListener('click', () => {
        tableState.offset += tableState.limit;
        loadTable();
    });

    function updateSortIndicators() {
        document.querySelectorAll('th[data-sort]').forEach(th => {
            const field = th.dataset.sort;
            const existing = th.querySelector('.sort-icon');
            if (existing) existing.remove();
            const icon = document.createElement('span');
            icon.className = 'sort-icon';
            if (field === tableState.sort_by) {
                icon.textContent = tableState.order === 'asc' ? ' ↑' : ' ↓';
                icon.classList.add('sort-icon--active');
            } else {
                icon.textContent = ' ↕';
            }
            th.appendChild(icon);
        });
    }

    document.querySelectorAll('th[data-sort]').forEach(th => {
        th.addEventListener('click', () => {
            const field = th.dataset.sort;
            if (tableState.sort_by === field) {
                tableState.order = tableState.order === 'desc' ? 'asc' : 'desc';
            } else {
                tableState.sort_by = field;
                tableState.order = ['mau', 'last_crawled'].includes(field) ? 'desc' : 'asc';
            }
            tableState.offset = 0;
            loadTable();
        });
    });

    // Load all data
    async function init() {
        const [summary, patchAdoption, supportedBranches, patchDetail,
            patchDist, branchDist, eolDist, branchAdoption, history] =
            await Promise.all([
                api('/stats/summary'),
                api('/stats/patch-adoption'),
                api('/stats/supported-branches'),
                api('/stats/patch-detail'),
                api('/stats/patch-distribution'),
                api('/stats/branch-distribution'),
                api('/stats/eol-distribution'),
                api('/stats/branch-adoption'),
                api('/stats/history?days=30'),
            ]);

        // Big numbers
        document.getElementById('total-instances').textContent = fmt(summary.total_instances);
        document.getElementById('total-mau').textContent = fmt(summary.monthly_active_users);
        document.getElementById('patch-instances').textContent = pct(patchAdoption.instances_patched_percent);
        document.getElementById('patch-mau').textContent = pct(patchAdoption.mau_patched_percent);
        document.getElementById('supported-instances').textContent = pct(supportedBranches.instances_percent);
        document.getElementById('supported-mau').textContent = pct(supportedBranches.mau_percent);

        // Sparklines from history
        const hist = history.history.slice().reverse();
        if (hist.length > 1) {
            const instanceTotals = hist.map(h =>
                h.main_instances + h.latest_instances + h.previous_instances +
                h.deprecated_instances + h.eol_instances
            );
            const mauTotals = hist.map(h => h.mau);
            createSparkline('spark-instances', instanceTotals, PURPLE);
            createSparkline('spark-mau', mauTotals, PURPLE);
        }

        // Gauges
        const branches = patchDetail.branches;
        for (const branch of ['main', 'latest', 'previous', 'deprecated']) {
            const b = branches[branch];
            createGauge(`gauge-${branch}-instances`, b.patched, b.total);
            createGauge(`gauge-${branch}-mau`, b.mau_patched, b.mau_total);
        }

        // Branch adoption bar gauges
        const adoption = branchAdoption.adoption;
        createBarGauge(
            'chart-adoption-instances',
            adoption.map(a => a.branch),
            adoption.map(a => a.instances_percent)
        );
        createBarGauge(
            'chart-adoption-mau',
            adoption.map(a => a.branch),
            adoption.map(a => a.mau_percent)
        );

        // Patch distribution pies
        const pd = patchDist.distribution.sort((a, b) => b.instances - a.instances);
        const pdColors = pd.map(d => {
            if (d.version === 'EOL') return RED;
            if (d.version === 'Unpatched') return ORANGE;
            return PURPLE;
        });
        createPieChart(
            'pie-patch-instances',
            pd.map(d => d.version),
            pd.map(d => d.instances),
            pdColors
        );
        createPieChart(
            'pie-patch-mau',
            pd.map(d => d.version),
            pd.map(d => d.mau),
            pdColors
        );

        // Branch distribution pies
        const bd = branchDist.distribution;
        const bdColors = bd.map(d => d.branch === 'EOL' ? RED : PURPLE);
        createPieChart(
            'pie-branch-instances',
            bd.map(d => d.branch),
            bd.map(d => d.instances),
            bdColors
        );
        createPieChart(
            'pie-branch-mau',
            bd.map(d => d.branch),
            bd.map(d => d.mau),
            bdColors
        );

        // EOL distribution pies
        const eol = eolDist.distribution.filter(d => d.instances > 0);
        const eolColors = eol.map(d => d.branch.startsWith('3') ? RED_DARK : RED);
        createPieChart(
            'pie-eol-instances',
            eol.map(d => d.branch),
            eol.map(d => d.instances),
            eolColors
        );
        createPieChart(
            'pie-eol-mau',
            eol.map(d => d.branch),
            eol.map(d => d.mau),
            eolColors
        );

        // Historical charts
        const histSlice = hist.slice(-10);
        const histLabels = histSlice.map(h => {
            const d = new Date(h.date);
            return d.toLocaleDateString('en-US', { day: '2-digit', month: 'short' });
        });

        const histBranchNames = ['Main Branch', 'Latest Branch', 'Previous Branch', 'Deprecated Branch'];
        const histColors = [BLUE, GREEN, PURPLE, ORANGE];

        // Patch adoption by instance
        createStackedBar('chart-hist-patch-instances', histLabels, [
            { label: histBranchNames[0], data: histSlice.map(h => h.main_patched_instances), backgroundColor: histColors[0] },
            { label: histBranchNames[1], data: histSlice.map(h => h.latest_patched_instances), backgroundColor: histColors[1] },
            { label: histBranchNames[2], data: histSlice.map(h => h.previous_patched_instances), backgroundColor: histColors[2] },
            { label: histBranchNames[3], data: histSlice.map(h => h.deprecated_patched_instances), backgroundColor: histColors[3] },
        ]);

        // Patch adoption by MAU
        createStackedBar('chart-hist-patch-mau', histLabels, [
            { label: histBranchNames[0], data: histSlice.map(h => h.main_patched_mau), backgroundColor: histColors[0] },
            { label: histBranchNames[1], data: histSlice.map(h => h.latest_patched_mau), backgroundColor: histColors[1] },
            { label: histBranchNames[2], data: histSlice.map(h => h.previous_patched_mau), backgroundColor: histColors[2] },
            { label: histBranchNames[3], data: histSlice.map(h => h.deprecated_patched_mau), backgroundColor: histColors[3] },
        ]);

        // Branch deployments by instance
        createStackedBar('chart-hist-branch-instances', histLabels, [
            { label: histBranchNames[0], data: histSlice.map(h => h.main_instances), backgroundColor: histColors[0] },
            { label: histBranchNames[1], data: histSlice.map(h => h.latest_instances), backgroundColor: histColors[1] },
            { label: histBranchNames[2], data: histSlice.map(h => h.previous_instances), backgroundColor: histColors[2] },
            { label: histBranchNames[3], data: histSlice.map(h => h.deprecated_instances), backgroundColor: histColors[3] },
            { label: 'EOL Branches', data: histSlice.map(h => h.eol_instances), backgroundColor: RED },
        ]);

        // Branch deployments by MAU
        createStackedBar('chart-hist-branch-mau', histLabels, [
            { label: histBranchNames[0], data: histSlice.map(h => h.main_branch_mau), backgroundColor: histColors[0] },
            { label: histBranchNames[1], data: histSlice.map(h => h.latest_branch_mau), backgroundColor: histColors[1] },
            { label: histBranchNames[2], data: histSlice.map(h => h.previous_branch_mau), backgroundColor: histColors[2] },
            { label: histBranchNames[3], data: histSlice.map(h => h.deprecated_branch_mau), backgroundColor: histColors[3] },
            { label: 'EOL Branches', data: histSlice.map(h => h.eol_branch_mau), backgroundColor: RED },
        ]);

        // Load table
        loadTable();
    }

    init().catch(err => {
        console.error('Dashboard load error:', err);
    });
})();
