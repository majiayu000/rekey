function renderTableRows(tbody, rows) {
  tbody.replaceChildren();

  rows.forEach(cells => {
    const row = document.createElement('tr');
    cells.forEach(value => {
      const cell = document.createElement('td');
      cell.textContent = value;
      row.appendChild(cell);
    });
    tbody.appendChild(row);
  });
}

function renderSecrets(data, tbody = document.querySelector('#secrets-table tbody')) {
  renderTableRows(tbody, data.map(s => [
    s.name,
    s.provider,
    s.host_pattern,
    new Date(s.created_at * 1000).toLocaleDateString(),
  ]));
}

function renderAudit(data, tbody = document.querySelector('#audit-table tbody')) {
  renderTableRows(tbody, data.map(a => [
    new Date(a.timestamp * 1000).toLocaleTimeString(),
    a.secret_name,
    a.target_host,
    a.target_path,
    a.status_code ?? '-',
    a.source,
  ]));
}

function renderStats(data, stats = document.getElementById('stats')) {
  stats.textContent = `Today: ${data.today_requests} requests, ${data.today_errors} errors`;
}

async function loadSecrets() {
  const resp = await fetch('/api/secrets');
  const data = await resp.json();
  renderSecrets(data);
}

async function loadAudit() {
  const resp = await fetch('/api/audit');
  const data = await resp.json();
  renderAudit(data);
}

async function loadStats() {
  const resp = await fetch('/api/stats');
  const data = await resp.json();
  renderStats(data);
  loadAudit();
}

function initDashboard() {
  document.querySelectorAll('nav button').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.tab).classList.add('active');

      if (btn.dataset.tab === 'secrets') loadSecrets();
      if (btn.dataset.tab === 'audit') loadAudit();
      if (btn.dataset.tab === 'traffic') loadStats();
    });
  });

  loadSecrets();
}

if (typeof document !== 'undefined') {
  initDashboard();
}

if (typeof module !== 'undefined') {
  module.exports = {
    renderAudit,
    renderSecrets,
    renderStats,
  };
}
