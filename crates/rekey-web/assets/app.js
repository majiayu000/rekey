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

async function loadSecrets() {
  const resp = await fetch('/api/secrets');
  const data = await resp.json();
  const tbody = document.querySelector('#secrets-table tbody');
  tbody.innerHTML = data.map(s =>
    `<tr><td>${s.name}</td><td>${s.provider}</td><td>${s.host_pattern}</td><td>${new Date(s.created_at * 1000).toLocaleDateString()}</td></tr>`
  ).join('');
}

async function loadAudit() {
  const resp = await fetch('/api/audit');
  const data = await resp.json();
  const tbody = document.querySelector('#audit-table tbody');
  tbody.innerHTML = data.map(a =>
    `<tr><td>${new Date(a.timestamp * 1000).toLocaleTimeString()}</td><td>${a.secret_name}</td><td>${a.target_host}</td><td>${a.target_path}</td><td>${a.status_code || '-'}</td><td>${a.source}</td></tr>`
  ).join('');
}

async function loadStats() {
  const resp = await fetch('/api/stats');
  const data = await resp.json();
  document.getElementById('stats').innerHTML =
    `<p>Today: ${data.today_requests} requests, ${data.today_errors} errors</p>`;
  loadAudit();
}

loadSecrets();
