const assert = require('node:assert/strict');
const { renderAudit, renderSecrets, renderStats } = require('../assets/app.js');

class TestElement {
  constructor(tagName) {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this._textContent = '';
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  replaceChildren(...children) {
    this.children = children;
    this._textContent = '';
  }

  set textContent(value) {
    this._textContent = String(value);
    this.children = [];
  }

  get textContent() {
    if (this.children.length === 0) {
      return this._textContent;
    }
    return this.children.map(child => child.textContent).join('');
  }

  set innerHTML(_value) {
    throw new Error('dashboard rendering must not assign innerHTML');
  }
}

global.document = {
  createElement(tagName) {
    return new TestElement(tagName);
  },
};

function cellText(row, index) {
  return row.children[index].textContent;
}

const payload = '<img src=x onerror=alert(1)><script>alert(2)</script>';

const secretsBody = new TestElement('tbody');
renderSecrets([
  {
    name: payload,
    provider: `custom-${payload}`,
    host_pattern: `api.example.com/${payload}`,
    created_at: 1_700_000_000,
  },
], secretsBody);

assert.equal(secretsBody.children.length, 1);
assert.equal(cellText(secretsBody.children[0], 0), payload);
assert.equal(cellText(secretsBody.children[0], 1), `custom-${payload}`);
assert.equal(cellText(secretsBody.children[0], 2), `api.example.com/${payload}`);

const auditBody = new TestElement('tbody');
renderAudit([
  {
    timestamp: 1_700_000_000,
    secret_name: payload,
    target_host: `target-${payload}`,
    target_path: `/v1/${payload}`,
    status_code: 0,
    source: `proxy-${payload}`,
  },
], auditBody);

assert.equal(auditBody.children.length, 1);
assert.equal(cellText(auditBody.children[0], 1), payload);
assert.equal(cellText(auditBody.children[0], 2), `target-${payload}`);
assert.equal(cellText(auditBody.children[0], 3), `/v1/${payload}`);
assert.equal(cellText(auditBody.children[0], 4), '0');
assert.equal(cellText(auditBody.children[0], 5), `proxy-${payload}`);

const stats = new TestElement('div');
renderStats({ today_requests: payload, today_errors: 3 }, stats);
assert.equal(stats.textContent, `Today: ${payload} requests, 3 errors`);
