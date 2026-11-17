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
  renderEventRows('trafficBody');
  renderEventRows('auditBody', true);
  renderTrafficChart();
}

function renderTrafficChart() {
  const chart = document.querySelector('.chart-wrap');
  if (!chart) return;
  const points = eventLog
    .map((event) => ({
      ...event,
      timestamp: new Date(event.occurredAt || event.time).getTime(),
    }))
    .filter((event) => Number.isFinite(event.timestamp));
  if (!points.length) {
    renderEmptyState(chart, 'No traffic recorded yet.');
    return;
  }

  const bucketCount = 12;
  const latest = Math.max(...points.map((event) => event.timestamp));
  const earliest = Math.min(...points.map((event) => event.timestamp));
  const windowSize = Math.max(latest - earliest, 15 * 60 * 1000);
  const bucketSize = windowSize / bucketCount;
  const buckets = Array.from({ length: bucketCount }, () => ({ allowed: 0, review: 0, blocked: 0 }));
  points.forEach((event) => {
    const index = Math.min(bucketCount - 1, Math.floor((event.timestamp - (latest - windowSize)) / bucketSize));
    const key = event.decision === 'Blocked' ? 'blocked' : event.decision === 'Anomaly review' ? 'review' : 'allowed';
    buckets[index][key] += 1;
  });
  const maximum = Math.max(...buckets.map((bucket) => bucket.allowed + bucket.review + bucket.blocked), 1);
  const start = latest - windowSize;
  const labels = buckets.map((_, index) => new Date(start + index * bucketSize).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false }));
  chart.innerHTML = `<div class="traffic-bars" aria-label="Stored gateway events over time">${buckets.map((bucket, index) => {
    const total = bucket.allowed + bucket.review + bucket.blocked;
    const scale = (value) => value ? Math.max(4, (value / maximum) * 170) : 0;
    return `<div class="traffic-bar-group" title="${total} stored event${total === 1 ? '' : 's'}"><div class="traffic-bar"><span class="bar-segment allowed-bar" style="height:${scale(bucket.allowed)}px"></span><span class="bar-segment review-bar" style="height:${scale(bucket.review)}px"></span><span class="bar-segment blocked-bar" style="height:${scale(bucket.blocked)}px"></span></div><small>${escapeHtml(labels[index])}</small></div>`;
  }).join('')}</div>`;
}

function showView(viewName) {
  viewPanels.forEach((panel) => panel.classList.toggle('active', panel.dataset.viewPanel === viewName));
  navItems.forEach((item) => item.classList.toggle('active', item.dataset.view === viewName));
  const activeItem = document.querySelector(`.nav-item[data-view="${viewName}"]`);
  document.querySelector('#viewLabel').textContent = activeItem ? activeItem.innerText.replace(/LIVE|3/g, '').trim() : 'Overview';
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
    const response = await fetch('/inspect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ method: scenario.method, path: scenario.route, query: scenario.query, body: scenario.body, simulation: scenario.simulation }) });
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
    document.querySelector('#simulationResult').classList.remove('hidden');
    document.querySelector('#simulationResult').classList.toggle('anomaly-result', result.decision !== 'allow');
    showToast('Synthetic request evaluated successfully');
  } catch (error) {
    showToast(error.message || 'Simulation failed');
  } finally {
    button.disabled = false;
    button.innerHTML = '<span>▷</span> Run simulation';
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
scenarioSelect.addEventListener('change', renderScenarioDetails);
playgroundForm.addEventListener('submit', runSimulation);
document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closePlayground(); });

async function loadSystemStatus() {
  try {
    const response = await fetch('/system/status');
    if (!response.ok) throw new Error('status unavailable');
    const status = await response.json();
    const loaded = status.ml?.status === 'loaded';
    document.querySelector('#mlHealthStatus').textContent = loaded ? `Loaded · v${status.ml.model_version}` : 'Unavailable · rules only';
    document.querySelector('#mlHealthMeta').textContent = loaded ? status.ml.embedding_model : 'Train the local artifact to enable ML review';
    document.querySelector('#mlHealthIndicator').classList.toggle('amber-indicator', !loaded);
  } catch {
    document.querySelector('#mlHealthStatus').textContent = 'Unavailable · rules only';
    document.querySelector('#mlHealthIndicator').classList.add('amber-indicator');
  }
}

async function loadDatabaseData() {
  try {
    const [eventsResponse, overviewResponse, incidentsResponse] = await Promise.all([
      fetch('/api/events?limit=50'),
      fetch('/api/overview'),
      fetch('/api/incidents?limit=20'),
    ]);
    if (!eventsResponse.ok || !overviewResponse.ok || !incidentsResponse.ok) throw new Error('database unavailable');
    const eventsPayload = await eventsResponse.json();
    const overviewPayload = await overviewResponse.json();
    const incidentsPayload = await incidentsResponse.json();
    const databaseConnected = eventsPayload.database === 'connected'
      && overviewPayload.database === 'connected'
      && incidentsPayload.database === 'connected';
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
    }
    if (incidentsPayload.database === 'connected') {
      const incidents = incidentsPayload.incidents;
      document.querySelector('.incidents-panel .panel-heading p').textContent = `${incidents.length} open incident${incidents.length === 1 ? '' : 's'}`;
      document.querySelector('.page-tag').textContent = `${incidents.length} OPEN`;
      document.querySelector('.alert-count').textContent = incidents.length;
      renderMarkup(document.querySelector('.incidents-panel .incident-list'), incidents.length ? incidents.map((incident) => `<div class="incident-row"><span class="incident-symbol ${incident.severity.toLowerCase()}">△</span><div><strong>${escapeHtml(incident.title)}</strong><small>${escapeHtml(incident.endpoint)} · ${incident.event_count} event${incident.event_count === 1 ? '' : 's'}</small></div><b class="severity ${incident.severity.toLowerCase()}-tag">${escapeHtml(incident.severity)}</b></div>`).join('') : '<div class="empty-state">No open incidents.</div>');
      renderMarkup(document.querySelector('.incident-cards'), incidents.length ? incidents.map((incident) => `<article class="panel incident-card"><div class="incident-card-heading"><span class="incident-symbol ${incident.severity.toLowerCase()}">△</span><div><span class="eyebrow">${escapeHtml(incident.severity)} · ${escapeHtml(incident.status)}</span><h2>${escapeHtml(incident.title)}</h2><p>${escapeHtml(incident.endpoint)} · ${incident.event_count} event${incident.event_count === 1 ? '' : 's'}</p></div></div></article>`).join('') : '<div class="empty-state">No incidents recorded yet.</div>');
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
