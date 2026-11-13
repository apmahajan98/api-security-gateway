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

let eventLog = [
  { time: '14:37:21', requestId: 'req_7a31f04b2c', method: 'GET', path: '/users/search', decision: 'Blocked', detector: 'API abuse (Rate Limit)', risk: 'High', latency: '38 ms', reason: 'API_ABUSE' },
  { time: '14:36:48', requestId: 'req_91d052c4a8', method: 'GET', path: '/customers/export', decision: 'Blocked', detector: 'Data Exfiltration (Policy)', risk: 'High', latency: '71 ms', reason: 'DATA_EXPORT' },
  { time: '14:36:15', requestId: 'req_46bc2e119f', method: 'POST', path: '/auth/login', decision: 'Anomaly review', detector: 'Credential Stuffing (ML)', risk: 'Medium', latency: '45 ms', reason: 'UNUSUAL_BEHAVIOR' },
  { time: '14:35:52', requestId: 'req_d200c9e5bb', method: 'GET', path: '/users/search', decision: 'Allowed', detector: 'Normal Traffic', risk: 'Low', latency: '32 ms', reason: '' },
  { time: '14:35:09', requestId: 'req_20a8b5d810', method: 'POST', path: '/auth/login', decision: 'Blocked', detector: 'Brute Force (Rules)', risk: 'High', latency: '49 ms', reason: 'BRUTE_FORCE' },
];

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character]);
}

function formatNumber(value) {
  return Number(value).toLocaleString('en-US');
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
  target.innerHTML = eventLog.map((event) => audit
    ? `<tr><td>${escapeHtml(event.time)}</td><td><code>${escapeHtml(event.requestId)}</code></td><td><code>${escapeHtml(event.method)} ${escapeHtml(event.path)}</code></td><td><span class="decision ${decisionClass(event.decision)}"><i></i>${escapeHtml(event.decision)}</span></td><td>${escapeHtml(event.reason || 'No rule match')}</td><td>${escapeHtml(event.latency)}</td></tr>`
    : `<tr><td>${escapeHtml(event.time)}</td><td><code>${escapeHtml(event.method)} ${escapeHtml(event.path)}</code></td><td><span class="decision ${decisionClass(event.decision)}"><i></i>${escapeHtml(event.decision)}</span></td><td>${escapeHtml(event.detector)}</td><td><span class="risk ${event.risk.toLowerCase()}">${escapeHtml(event.risk)}</span></td><td>${escapeHtml(event.latency)}</td></tr>`
  ).join('');
}

function renderEvents() {
  renderEventRows('eventsBody');
  renderEventRows('trafficBody');
  renderEventRows('auditBody', true);
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
    ['Requests', formatNumber(scenario.requestCount)],
    ['Duration', scenario.duration],
    ['User profile', scenario.clientProfile],
    ['Expected check', scenario.expected],
  ].map(([label, value]) => `<div class="parameter-row"><span>${escapeHtml(label)}</span><b>${escapeHtml(value)}</b></div>`).join('');
}

function updateMetrics(result, scenario) {
  const requests = Number(document.querySelector('#requestsMetric').textContent.replace(/,/g, '')) + scenario.requestCount;
  document.querySelector('#requestsMetric').textContent = formatNumber(requests);
  if (result.decision === 'block') {
    const blocked = Number(document.querySelector('#blockedMetric').textContent.replace(/,/g, '')) + scenario.requestCount;
    document.querySelector('#blockedMetric').textContent = formatNumber(blocked);
  }
  if (result.decision === 'review' || result.ml?.status === 'anomaly') {
    const anomalies = Number(document.querySelector('#anomaliesMetric').textContent.replace(/,/g, '')) + 1;
    document.querySelector('#anomaliesMetric').textContent = formatNumber(anomalies);
  }
}

function addSimulationEvent(result, scenario) {
  const outcome = result.decision === 'block' ? 'Blocked' : result.decision === 'review' ? 'Anomaly review' : 'Allowed';
  const detector = result.decision === 'block' ? 'Static rules' : result.ml ? (result.ml.status === 'anomaly' ? 'ML anomaly' : 'Rules + ML') : 'Rule engine';
  eventLog.unshift({
    time: new Date().toLocaleTimeString('en-US', { hour12: false }),
    requestId: result.request_id,
    method: scenario.method,
    path: scenario.route,
    decision: outcome,
    detector,
    risk: outcome === 'Blocked' ? 'High' : outcome === 'Anomaly review' ? scenario.risk : 'Low',
    latency: `${result.latency_ms} ms`,
    reason: result.reason_code || '',
  });
  eventLog = eventLog.slice(0, 12);
  renderEvents();
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
    addSimulationEvent(result, scenario);
    updateMetrics(result, scenario);
    const outcome = result.decision === 'block' ? 'Blocked by gateway' : result.decision === 'review' ? 'Anomaly review created' : 'Allowed by gateway';
    document.querySelector('#simulationOutcome').textContent = outcome;
    document.querySelector('#simulationSummary').textContent = result.ml ? `Rules and ML evaluated ${scenario.label.toLowerCase()}.` : 'Rule engine evaluated the representative request.';
    document.querySelector('#simulationDecision').textContent = result.decision.toUpperCase();
    document.querySelector('#simulationDetector').textContent = result.ml ? 'Rules + ML' : 'Rules only';
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

renderScenarioDetails();
renderEvents();
loadSystemStatus();
