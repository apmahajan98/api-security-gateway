const form = document.querySelector('#inspectForm');
const toast = document.querySelector('#toast');
const requestHistory = [];

function showToast(message) {
  toast.textContent = message;
  toast.classList.add('show');
  window.clearTimeout(window.toastTimer);
  window.toastTimer = window.setTimeout(() => toast.classList.remove('show'), 3000);
}

function renderResult(result) {
  const blocked = result.decision === 'block';
  document.querySelector('#emptyResult').classList.add('hidden');
  document.querySelector('#resultDetails').classList.remove('hidden');
  document.querySelector('#resultIcon').textContent = blocked ? '!' : '✓';
  document.querySelector('#resultIcon').className = `result-icon ${blocked ? 'blocked-icon' : 'allowed-icon'}`;
  document.querySelector('#resultSubtitle').textContent = blocked ? 'The rule detector found a suspicious pattern.' : 'No configured rule matched this request.';
  document.querySelector('#decisionBanner').className = `decision-banner ${blocked ? 'blocked-banner' : 'allowed-banner'}`;
  document.querySelector('#decisionLabel').textContent = blocked ? 'Blocked' : 'Allowed';
  document.querySelector('#decisionReason').textContent = result.reason_code || 'No rule match';
  document.querySelector('#requestId').textContent = result.request_id;
  document.querySelector('#detector').textContent = result.detector;
  document.querySelector('#classification').textContent = result.classification;
  document.querySelector('#latency').textContent = `${result.latency_ms}ms`;
}

function renderHistory() {
  document.querySelector('#emptyHistory').classList.toggle('hidden', requestHistory.length > 0);
  document.querySelector('#historyTableWrap').classList.toggle('hidden', requestHistory.length === 0);
  document.querySelector('#historyBody').innerHTML = requestHistory.map((item) => `
    <tr><td><code>${item.request_id}</code></td><td><code>${item.method} ${item.path}</code></td>
    <td><span class="decision ${item.decision}"><i></i>${item.decision}</span></td>
    <td>${item.reason_code || item.detector}</td><td>${item.latency_ms}ms</td></tr>`).join('');
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const submitButton = form.querySelector('button[type="submit"]');
  submitButton.disabled = true;
  submitButton.innerHTML = '<span>…</span> Inspecting';
  let body = null;
  const rawBody = document.querySelector('#body').value.trim();
  try {
    if (rawBody) body = JSON.parse(rawBody);
    const response = await fetch('/inspect', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({
      method: document.querySelector('#method').value,
      path: document.querySelector('#path').value,
      query: document.querySelector('#query').value,
      body,
    })});
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail?.[0]?.msg || 'Inspection failed');
    renderResult(result);
    requestHistory.unshift(result);
    renderHistory();
    document.querySelector('#history').scrollIntoView({behavior: 'smooth', block: 'nearest'});
  } catch (error) {
    showToast(error instanceof SyntaxError ? 'JSON body is not valid' : error.message);
  } finally {
    submitButton.disabled = false;
    submitButton.innerHTML = '<span>→</span> Inspect request';
  }
});

document.querySelector('#benignExample').addEventListener('click', () => {
  document.querySelector('#method').value = 'GET';
  document.querySelector('#path').value = '/v1/users';
  document.querySelector('#query').value = 'alice';
  document.querySelector('#body').value = '';
});
