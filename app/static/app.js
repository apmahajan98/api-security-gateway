const navItems = document.querySelectorAll('.nav-item');
const viewPanels = document.querySelectorAll('[data-view-panel]');
const drawer = document.querySelector('#playgroundDrawer');
const backdrop = document.querySelector('#drawerBackdrop');
const playgroundForm = document.querySelector('#playgroundForm');
const scenarioSelect = document.querySelector('#scenario');
const toast = document.querySelector('#toast');

const scenarios = {
  'high-volume': {
    label: 'High-volume API access',
    description: 'Simulates sustained search traffic that can indicate automated abuse or a rate-limit bypass.',
    method: 'GET',
    route: '/users/search',
    requestCount: 900,
    duration: '30 seconds',
    clientProfile: 'consumer',
    expected: 'Anomaly review',
    risk: 'High',
    query: 'page=1&sort=recent',
    body: null,
    simulation: { requests_per_minute: 900, failed_logins_per_minute: 4, unique_routes: 18, average_request_bytes: 1400, average_response_bytes: 18000, error_rate: 0.18, client_profile: 'consumer', hour_of_day: 14, session_age_minutes: 8, new_routes: 11, location_changed: 1 },
  },
  'credential-abuse': {
    label: 'Credential abuse',
    description: 'Simulates repeated failed sign-ins from a synthetic identity to test account-protection controls.',
    method: 'POST',
    route: '/auth/login',
    requestCount: 60,
    duration: '15 seconds',
    clientProfile: 'consumer',
    expected: 'Anomaly review',
    risk: 'High',
    query: '',
    body: { username: 'synthetic.user', password: '[redacted]' },
    simulation: { requests_per_minute: 60, failed_logins_per_minute: 35, unique_routes: 2, average_request_bytes: 520, average_response_bytes: 1400, error_rate: 0.65, client_profile: 'consumer', hour_of_day: 2, session_age_minutes: 3, new_routes: 0, location_changed: 1 },
  },
  'data-export': {
    label: 'Suspicious data export',
    description: 'Simulates an unusually large export response outside the normal consumer traffic profile.',
    method: 'GET',
    route: '/customers/export',
    requestCount: 120,
    duration: '20 seconds',
    clientProfile: 'consumer',
    expected: 'Anomaly review',
    risk: 'Medium',
    query: 'format=csv&scope=all',
    body: null,
    simulation: { requests_per_minute: 120, failed_logins_per_minute: 2, unique_routes: 12, average_request_bytes: 8000, average_response_bytes: 250000, error_rate: 0.24, client_profile: 'consumer', hour_of_day: 3, session_age_minutes: 12, new_routes: 8, location_changed: 1 },
  },
  'sql-injection': {
    label: 'SQL injection payload',
    description: 'Sends a synthetic injection pattern so the static rule engine can demonstrate an immediate block.',
    method: 'GET',
    route: '/users/search',
    requestCount: 1,
    duration: 'Single request',
    clientProfile: 'consumer',
    expected: 'Blocked',
    risk: 'Critical',
    query: "q=' OR 1=1 --",
    body: null,
    simulation: { requests_per_minute: 6, failed_logins_per_minute: 0, unique_routes: 1, average_request_bytes: 180, average_response_bytes: 1200, error_rate: 0.01, client_profile: 'consumer', hour_of_day: 12, session_age_minutes: 30, new_routes: 0, location_changed: 0 },
  },
  'xss-attempt': {
    label: 'Cross-site scripting payload',
    description: 'Sends a synthetic script tag so the static rule engine can demonstrate an immediate block.',
    method: 'POST',
    route: '/users/profile',
    requestCount: 1,
    duration: 'Single request',
    clientProfile: 'consumer',
    expected: 'Blocked',
    risk: 'Critical',
    query: '',
    body: { display_name: '<script>alert(1)</script>' },
    simulation: { requests_per_minute: 6, failed_logins_per_minute: 0, unique_routes: 1, average_request_bytes: 180, average_response_bytes: 1200, error_rate: 0.01, client_profile: 'consumer', hour_of_day: 12, session_age_minutes: 30, new_routes: 0, location_changed: 0 },
  },
  'normal-activity': {
    label: 'Normal user activity',
    description: 'Provides a benign baseline so the team can compare normal traffic with security events.',
    method: 'GET',
    route: '/products',
    requestCount: 6,
    duration: '30 seconds',
    clientProfile: 'consumer',
    expected: 'Allowed',
    risk: 'Low',
    query: 'category=office&page=1',
    body: null,
    simulation: { requests_per_minute: 6, failed_logins_per_minute: 0, unique_routes: 2, average_request_bytes: 430, average_response_bytes: 2150, error_rate: 0.02, client_profile: 'consumer', hour_of_day: 12, session_age_minutes: 30, new_routes: 0, location_changed: 0 },
  },
};

Object.entries(scenarios).forEach(([value, scenario]) => {
  if (scenarioSelect.querySelector(`option[value="${value}"]`)) return;
  const option = document.createElement('option');
  option.value = value;
  option.textContent = scenario.label;
  scenarioSelect.append(option);
});

let eventLog = [];

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character]);
}

function formatNumber(value) {
  return Number(value).toLocaleString('en-US');
}

function formatEventTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleTimeString('en-US', { hour12: false });
}

function resetSimulationResult() {
  const simulationResult = document.querySelector('#simulationResult');
  simulationResult.classList.add('hidden');
  simulationResult.classList.remove('anomaly-result', 'blocked-result');
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add('show');
  window.clearTimeout(window.toastTimer);
  window.toastTimer = window.setTimeout(() => toast.classList.remove('show'), 3200);
}

function decisionClass(decision) {
  if (decision === 'Blocked') return 'blocked';
  if (decision === 'Anomaly review') return 'review';
  return 'allowed';
}

function renderEventRows(targetId, audit = false) {
  const target = document.querySelector(`#${targetId}`);
  if (!target) return;
  if (!eventLog.length) {
    const columns = audit ? 6 : 6;
    target.innerHTML = `<tr><td class="empty-table" colspan="${columns}">No events recorded yet.</td></tr>`;
    return;
  }
  target.innerHTML = eventLog.map((event) => audit
    ? `<tr><td>${escapeHtml(event.time)}</td><td><code>${escapeHtml(event.requestId)}</code></td><td><code>${escapeHtml(event.method)} ${escapeHtml(event.path)}</code></td><td><span class="decision ${decisionClass(event.decision)}"><i></i>${escapeHtml(event.decision)}</span></td><td>${escapeHtml(event.reason || 'No rule match')}</td><td>${escapeHtml(event.latency)}</td></tr>`
    : `<tr><td>${escapeHtml(event.time)}</td><td><code>${escapeHtml(event.method)} ${escapeHtml(event.path)}</code></td><td><span class="decision ${decisionClass(event.decision)}"><i></i>${escapeHtml(event.decision)}</span></td><td>${escapeHtml(event.detector)}</td><td><span class="risk ${event.risk.toLowerCase()}">${escapeHtml(event.risk)}</span></td><td>${escapeHtml(event.latency)}</td></tr>`
  ).join('');
}

function renderEmptyState(target, message) {
  if (!target) return;
  target.innerHTML = `<div class="empty-state">${escapeHtml(message)}</div>`;
}

function renderMarkup(target, markup) {
  if (!target) return;
  target.innerHTML = markup;
}

function clearInitialDemoState() {
  document.querySelector('#requestsMetric').textContent = '0';
  document.querySelector('#blockedMetric').textContent = '0';
  document.querySelector('#anomaliesMetric').textContent = '0';
  document.querySelector('#latencyMetric').innerHTML = '0 <b>ms</b>';
  document.querySelectorAll('.metric-card small').forEach((element) => {
    element.textContent = 'Waiting for stored events';
  });
  renderEmptyState(document.querySelector('.chart-wrap'), 'No traffic recorded yet.');
  renderEmptyState(document.querySelector('.incidents-panel .incident-list'), 'No open incidents.');
  renderEmptyState(document.querySelector('.incident-cards'), 'No incidents recorded yet.');
  renderEmptyState(document.querySelector('.api-grid'), 'No API inventory data available yet.');
  renderEmptyState(document.querySelector('.analytics-grid'), 'No evaluation metrics available yet.');
  document.querySelector('.incidents-panel .panel-heading p').textContent = 'No open incidents';
  document.querySelector('.page-tag').textContent = '0 OPEN';
  document.querySelector('.alert-count').textContent = '0';
  renderEvents();
}

function renderEvents() {
  renderEventRows('eventsBody');
  renderEventRows('auditBody', true);
}

function renderTrafficSeries(series) {
  const chart = document.querySelector('.chart-wrap');
  if (!chart) return;
  if (!series?.length || !series.some((bucket) => bucket.allowed + bucket.review + bucket.blocked > 0)) {
    renderEmptyState(chart, 'No traffic recorded yet.');
    return;
  }
  const width = 760;
  const height = 220;
  const padding = { left: 42, right: 16, top: 18, bottom: 28 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  const maximum = Math.max(...series.map((bucket) => bucket.allowed + bucket.review + bucket.blocked), 1);
  const scaleY = (value) => {
    const scaled = Math.log1p(value) / Math.log1p(maximum);
    return padding.top + plotHeight - scaled * plotHeight;
  };
  const pointsFor = (key) => series.map((bucket, index) => {
    const x = padding.left + (index / (series.length - 1)) * plotWidth;
    const y = scaleY(bucket[key]);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((ratio) => {
    const y = padding.top + plotHeight - ratio * plotHeight;
    const value = Math.round(Math.expm1(Math.log1p(maximum) * ratio));
    return `<line class="chart-grid-line" x1="${padding.left}" y1="${y.toFixed(1)}" x2="${width - padding.right}" y2="${y.toFixed(1)}" /><text class="chart-axis-label" text-anchor="end" x="${padding.left - 8}" y="${(y + 3).toFixed(1)}">${formatNumber(value)}</text>`;
  }).join('');
  const labelStep = Math.max(1, Math.floor(series.length / 6));
  const labels = series.filter((_, index) => index % labelStep === 0).map((bucket) => new Date(bucket.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false }));
  chart.innerHTML = `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="Stored gateway traffic over the last 24 hours on a logarithmic scale"><g aria-hidden="true">${yTicks}</g><line class="chart-axis" x1="${padding.left}" y1="${padding.top}" x2="${padding.left}" y2="${padding.top + plotHeight}" /><line class="chart-axis" x1="${padding.left}" y1="${padding.top + plotHeight}" x2="${width - padding.right}" y2="${padding.top + plotHeight}" /><polyline class="line allowed-line" points="${pointsFor('allowed')}" /><polyline class="line anomaly-line" points="${pointsFor('review')}" /><polyline class="line blocked-line" points="${pointsFor('blocked')}" /><text class="chart-axis-label" x="${padding.left}" y="${padding.top - 6}">log scale</text><text class="chart-axis-label" x="${padding.left}" y="${height - 6}">${escapeHtml(labels[0] || '')}</text><text class="chart-axis-label" text-anchor="middle" x="${width / 2}" y="${height - 6}">${escapeHtml(labels[Math.floor(labels.length / 2)] || '')}</text><text class="chart-axis-label" text-anchor="end" x="${width - padding.right}" y="${height - 6}">${escapeHtml(labels[labels.length - 1] || '')}</text></svg>`;
}

function renderApiInventory(apis) {
  const grid = document.querySelector('.api-grid');
  if (!grid) return;
  if (!apis?.length) {
    renderEmptyState(grid, 'No API activity recorded yet.');
    return;
  }
  grid.innerHTML = apis.map((api) => `<article class="panel api-card"><div class="api-title"><span class="api-status ${api.status === 'Critical' || api.status === 'Blocked' ? 'blocked' : api.status === 'Review' ? 'warning' : ''}"></span><div><h2>${escapeHtml(api.name)}</h2></div><span class="${api.status === 'Critical' || api.status === 'Blocked' ? 'blocked-text' : api.status === 'Review' ? 'warning-text' : 'healthy-text'}">${escapeHtml(api.status)}</span></div><div class="api-summary"><b>${formatNumber(api.requests)}</b> total requests · <b>${formatNumber(api.blocked)}</b> blocked · <b>${formatNumber(api.review)}</b> review</div><div class="api-meta"><span><b>${formatNumber(api.route_count)}</b> routes</span><span><b>${api.allowed_percent}%</b> allowed</span><span><b>${api.p95_latency_ms} ms</b> p95</span></div>${api.routes.map((route) => `<span class="route-chip">${escapeHtml(route)}</span>`).join('')}</article>`).join('');
}

function renderAnalytics(analytics) {
  const grid = document.querySelector('.analytics-grid');
  if (!grid) return;
  if (!analytics || !analytics.stored_events) {
    renderEmptyState(grid, 'No detector activity recorded yet.');
    return;
  }
  const rule = analytics.rule;
  const ml = analytics.ml;
  grid.innerHTML = `<article class="panel detector-card"><div class="detector-heading"><div><h2>Rule-based detector</h2><p>Deterministic request inspection</p></div><span class="healthy-text">Active</span></div><div class="analytics-stat"><span>Median latency</span><strong>${rule.median_latency_ms} <small>ms</small></strong></div><div class="meter"><span style="width:${rule.evaluated ? 100 : 0}%"></span></div><div class="analytics-foot"><span>${formatNumber(rule.evaluated)} evaluated</span><b>${formatNumber(rule.blocked)} blocked</b></div></article><article class="panel detector-card"><div class="detector-heading"><div><h2>ML anomaly detector</h2><p>Profile-aware behavioral scoring</p></div><span class="${analytics.model_status === 'ready' ? 'healthy-text' : 'warning-text'}">${analytics.model_status === 'ready' ? 'Ready' : 'Unavailable'}</span></div><div class="analytics-stat"><span>Anomaly rate</span><strong>${ml.anomaly_rate} <small>%</small></strong></div><div class="meter ml-meter"><span style="width:${Math.min(100, ml.anomaly_rate)}%"></span></div><div class="analytics-foot"><span>${formatNumber(ml.evaluated)} evaluated</span><b>${formatNumber(ml.anomalies)} anomalies</b></div></article><article class="panel benchmark-card"><h2>Live evaluation summary</h2><p>Model ${escapeHtml(analytics.model_version || 'unavailable')} · persisted gateway activity</p><div class="benchmark-row"><span>Stored requests</span><b>${formatNumber(analytics.stored_events)}</b></div><div class="benchmark-row"><span>Active routes</span><b>${formatNumber(analytics.active_routes)}</b></div><div class="benchmark-row"><span>ML evaluations</span><b>${formatNumber(ml.evaluated)}</b></div></article>`;
}

function showView(viewName) {
  viewPanels.forEach((panel) => panel.classList.toggle('active', panel.dataset.viewPanel === viewName));
  navItems.forEach((item) => item.classList.toggle('active', item.dataset.view === viewName));
  const activeItem = document.querySelector(`.nav-item[data-view="${viewName}"]`);
  document.querySelector('#viewLabel').textContent = activeItem ? activeItem.innerText.replace(/LIVE|\d+$/g, '').trim() : 'Overview';
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function openPlayground() {
  drawer.classList.add('open');
  backdrop.classList.add('open');
  drawer.setAttribute('aria-hidden', 'false');
  renderScenarioDetails();
}

function closePlayground() {
  drawer.classList.remove('open');
  backdrop.classList.remove('open');
  drawer.setAttribute('aria-hidden', 'true');
}

function renderScenarioDetails() {
  const scenario = scenarios[scenarioSelect.value];
  document.querySelector('#scenarioDescription').textContent = scenario.description;
  document.querySelector('#scenarioParameters').innerHTML = [
    ['Route', `${scenario.method} ${scenario.route}`],
    ['Modeled rate', `${formatNumber(scenario.requestCount)} req/min`],
    ['Duration', scenario.duration],
    ['User profile', scenario.clientProfile],
    ['Expected check', scenario.expected],
  ].map(([label, value]) => `<div class="parameter-row"><span>${escapeHtml(label)}</span><b>${escapeHtml(value)}</b></div>`).join('');
}

async function runSimulation(event) {
  event.preventDefault();
  const button = document.querySelector('#runSimulation');
  const scenario = scenarios[scenarioSelect.value];
  button.disabled = true;
  button.innerHTML = '<span>…</span> Inspecting pipeline';
  try {
    const response = await fetch('/inspect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ method: scenario.method, path: scenario.route, query: scenario.query, body: scenario.body, simulation: scenario.simulation, request_count: scenario.requestCount }) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail?.[0]?.msg || 'Simulation failed');
    const databaseLoaded = await loadDatabaseData();
    if (!databaseLoaded) {
      showToast('Simulation evaluated, but the result was not persisted');
    }
    const outcome = result.decision === 'block' ? 'Blocked by gateway' : result.decision === 'review' ? 'Anomaly review created' : 'Allowed by gateway';
    document.querySelector('#simulationOutcome').textContent = outcome;
    document.querySelector('#simulationSummary').textContent = result.ml ? `Rules and ML evaluated ${scenario.label.toLowerCase()}.` : 'Rule engine evaluated the representative request.';
    document.querySelector('#simulationDecision').textContent = result.decision.toUpperCase();
    document.querySelector('#simulationDetector').textContent = result.detector || (result.ml ? 'rule + ml-anomaly' : 'rule-detector');
    document.querySelector('#simulationLatency').textContent = `${result.latency_ms} ms`;
    const simulationResult = document.querySelector('#simulationResult');
    simulationResult.classList.remove('hidden', 'anomaly-result', 'blocked-result');
    simulationResult.classList.toggle('anomaly-result', result.decision === 'review');
    simulationResult.classList.toggle('blocked-result', result.decision === 'block');
    showToast('Synthetic request evaluated successfully');
  } catch (error) {
    showToast(error.message || 'Simulation failed');
  } finally {
    button.disabled = false;
    button.innerHTML = 'Run simulation';
  }
}

navItems.forEach((item) => item.addEventListener('click', () => {
  if (item.dataset.playground) {
    openPlayground();
    return;
  }
  showView(item.dataset.view);
}));

document.querySelectorAll('[data-view-link]').forEach((button) => button.addEventListener('click', () => showView(button.dataset.viewLink)));
document.querySelectorAll('[data-open-playground]').forEach((button) => button.addEventListener('click', openPlayground));
document.querySelector('#closePlayground').addEventListener('click', closePlayground);
document.querySelector('#cancelPlayground').addEventListener('click', closePlayground);
backdrop.addEventListener('click', closePlayground);
scenarioSelect.addEventListener('change', () => {
  renderScenarioDetails();
  resetSimulationResult();
});
playgroundForm.addEventListener('submit', runSimulation);
document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closePlayground(); });

async function loadSystemStatus() {
  try {
    const response = await fetch('/system/status');
    if (!response.ok) throw new Error('status unavailable');
    const status = await response.json();
    const gatewayHealthy = status.gateway === 'healthy';
    const ruleEngineLoaded = status.rule_engine === 'loaded';
    const loaded = status.ml?.status === 'loaded';
    document.querySelector('#gatewayHealthStatus').textContent = gatewayHealthy ? 'Gateway healthy' : 'Gateway unavailable';
    document.querySelector('#gatewayHealthIndicator').classList.toggle('amber-indicator', !gatewayHealthy);
    document.querySelector('#gatewayPillStatus').textContent = gatewayHealthy ? 'Gateway healthy' : 'Gateway unavailable';
    document.querySelector('#gatewayPillIndicator').classList.toggle('amber-indicator', !gatewayHealthy);
    document.querySelector('#gatewayCardStatus').textContent = gatewayHealthy ? 'Operational' : 'Unavailable';
    document.querySelector('#gatewayCardIndicator').classList.toggle('amber-indicator', !gatewayHealthy);
    document.querySelector('#ruleHealthStatus').textContent = ruleEngineLoaded ? 'Loaded' : 'Unavailable';
    document.querySelector('#ruleHealthIndicator').classList.toggle('amber-indicator', !ruleEngineLoaded);
    document.querySelector('#mlHealthStatus').textContent = loaded ? `Loaded · v${status.ml.model_version}` : 'Unavailable · rules only';
    document.querySelector('#mlHealthMeta').textContent = loaded ? status.ml.embedding_model : 'Train the local artifact to enable ML review';
    document.querySelector('#mlHealthIndicator').classList.toggle('amber-indicator', !loaded);
    const databaseConnected = status.database?.status === 'connected';
    document.querySelector('#databaseHealthStatus').textContent = databaseConnected ? 'Connected' : 'Unavailable';
    document.querySelector('#databaseHealthMeta').textContent = databaseConnected ? 'Audit persistence active' : 'Events will not be persisted';
    document.querySelector('#databaseHealthIndicator').classList.toggle('amber-indicator', !databaseConnected);
  } catch {
    document.querySelector('#gatewayHealthStatus').textContent = 'Gateway unavailable';
    document.querySelector('#gatewayHealthIndicator').classList.add('amber-indicator');
    document.querySelector('#gatewayPillStatus').textContent = 'Gateway unavailable';
    document.querySelector('#gatewayPillIndicator').classList.add('amber-indicator');
    document.querySelector('#gatewayCardStatus').textContent = 'Unavailable';
    document.querySelector('#gatewayCardIndicator').classList.add('amber-indicator');
    document.querySelector('#ruleHealthStatus').textContent = 'Unavailable';
    document.querySelector('#ruleHealthIndicator').classList.add('amber-indicator');
    document.querySelector('#mlHealthStatus').textContent = 'Unavailable · rules only';
    document.querySelector('#mlHealthIndicator').classList.add('amber-indicator');
    document.querySelector('#databaseHealthStatus').textContent = 'Unavailable';
    document.querySelector('#databaseHealthMeta').textContent = 'Status unavailable';
    document.querySelector('#databaseHealthIndicator').classList.add('amber-indicator');
  }
}

async function loadDatabaseData() {
  try {
    const [eventsResponse, overviewResponse, incidentsResponse, trafficResponse, apisResponse, analyticsResponse] = await Promise.all([
      fetch('/api/events?limit=50'),
      fetch('/api/overview'),
      fetch('/api/incidents?limit=20'),
      fetch('/api/traffic'),
      fetch('/api/apis'),
      fetch('/api/analytics'),
    ]);
    if (!eventsResponse.ok || !overviewResponse.ok || !incidentsResponse.ok || !trafficResponse.ok || !apisResponse.ok || !analyticsResponse.ok) throw new Error('database unavailable');
    const eventsPayload = await eventsResponse.json();
    const overviewPayload = await overviewResponse.json();
    const incidentsPayload = await incidentsResponse.json();
    const trafficPayload = await trafficResponse.json();
    const apisPayload = await apisResponse.json();
    const analyticsPayload = await analyticsResponse.json();
    const databaseConnected = eventsPayload.database === 'connected'
      && overviewPayload.database === 'connected'
      && incidentsPayload.database === 'connected'
      && trafficPayload.database === 'connected'
      && apisPayload.database === 'connected'
      && analyticsPayload.database === 'connected';
    if (eventsPayload.database === 'connected') {
      eventLog = eventsPayload.events.map((event) => ({ ...event, occurredAt: event.time, time: formatEventTime(event.time) }));
      renderEvents();
    }
    if (overviewPayload.database === 'connected') {
      const metrics = overviewPayload.metrics;
      document.querySelector('#requestsMetric').textContent = formatNumber(metrics.requests_today);
      document.querySelector('#blockedMetric').textContent = formatNumber(metrics.blocked_today);
      document.querySelector('#anomaliesMetric').textContent = formatNumber(metrics.anomalies_today);
      document.querySelector('#latencyMetric').innerHTML = `${metrics.p95_latency_ms} <b>ms</b>`;
      document.querySelectorAll('.metric-card small').forEach((element) => {
        element.style.display = Number(metrics.requests_today) > 0 ? 'none' : '';
      });
    }
    if (trafficPayload.database === 'connected') {
      renderTrafficSeries(trafficPayload.traffic);
    }
    if (apisPayload.database === 'connected') {
      renderApiInventory(apisPayload.apis);
    }
    if (analyticsPayload.database === 'connected') {
      renderAnalytics(analyticsPayload.analytics);
    }
    if (incidentsPayload.database === 'connected') {
      const incidents = incidentsPayload.incidents;
      document.querySelector('.incidents-panel .panel-heading p').textContent = `${incidents.length} open incident${incidents.length === 1 ? '' : 's'}`;
      document.querySelector('.page-tag').textContent = `${incidents.length} OPEN`;
      document.querySelector('.alert-count').textContent = incidents.length;
      renderMarkup(document.querySelector('.incidents-panel .incident-list'), incidents.length ? incidents.map((incident) => `<div class="incident-row"><span class="incident-symbol ${incident.severity.toLowerCase()}"></span><div><strong>${escapeHtml(incident.title)}</strong><small>${escapeHtml(incident.endpoint)} · ${incident.event_count} event${incident.event_count === 1 ? '' : 's'}</small></div><b class="severity ${incident.severity.toLowerCase()}-tag">${escapeHtml(incident.severity)}</b></div>`).join('') : '<div class="empty-state">No open incidents.</div>');
      renderMarkup(document.querySelector('.incident-cards'), incidents.length ? incidents.map((incident) => `<article class="panel incident-card"><div class="incident-card-heading"><span class="incident-symbol ${incident.severity.toLowerCase()}"></span><div><span class="eyebrow">${escapeHtml(incident.severity)} · ${escapeHtml(incident.status)}</span><h2>${escapeHtml(incident.title)}</h2><p>${escapeHtml(incident.endpoint)} · ${incident.event_count} event${incident.event_count === 1 ? '' : 's'}</p></div></div></article>`).join('') : '<div class="empty-state">No incidents recorded yet.</div>');
    }
    return databaseConnected;
  } catch {
    return false;
  }
}

clearInitialDemoState();
renderScenarioDetails();
loadSystemStatus();
loadDatabaseData();
