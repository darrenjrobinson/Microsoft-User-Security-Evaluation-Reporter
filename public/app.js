// MS USER front end. All server data is rendered with textContent / DOM nodes – never innerHTML.

/* global bootstrap */

const $ = (sel, root = document) => root.querySelector(sel);

/** Tiny element builder: h('td', { class: 'x', 'aria-label': 'y', onClick }, 'text', childNode) */
function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props ?? {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') el.className = value;
    else if (key.startsWith('on') && typeof value === 'function') el.addEventListener(key.slice(2).toLowerCase(), value);
    else el.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

const icon = (name, extra = '') => h('i', { class: `bi bi-${name} ${extra}`.trim(), 'aria-hidden': 'true' });

// ---------- formatting ----------

const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const dayFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
const fmtDate = (iso) => (iso ? dateFmt.format(new Date(iso)) : '—');
const fmtDay = (iso) => (iso ? dayFmt.format(new Date(iso)) : '—');
const dash = (v) => (v === undefined || v === null || v === '' ? '—' : v);
const yesNo = (v) => (v === null || v === undefined ? '—' : v ? 'Yes' : 'No');

const LEVEL_ICONS = {
  good: 'check-circle-fill',
  warning: 'exclamation-triangle-fill',
  danger: 'x-octagon-fill',
  info: 'info-circle-fill',
  unknown: 'question-circle',
};
const LEVEL_TEXT = { good: 'Good', warning: 'Review', danger: 'Action needed', info: 'Info', unknown: 'Unknown' };
const RISK_LEVEL = { high: 'danger', medium: 'warning', low: 'info', none: 'good', hidden: 'unknown' };

const METHOD_LABELS = {
  push: 'Microsoft Authenticator (push)',
  oath: 'Authenticator app / OATH code',
  microsoftAuthenticatorPush: 'Microsoft Authenticator (push)',
  microsoftAuthenticatorPasswordless: 'Microsoft Authenticator (passwordless)',
  softwareOneTimePasscode: 'Authenticator app code',
  hardwareOneTimePasscode: 'Hardware token',
  fido2: 'FIDO2 security key',
  passKeyDeviceBound: 'Passkey',
  passKeyDeviceBoundAuthenticator: 'Passkey (Authenticator)',
  passKeyDeviceBoundWindowsHello: 'Passkey (Windows Hello)',
  windowsHelloForBusiness: 'Windows Hello for Business',
  sms: 'Text message (SMS)',
  mobilePhone: 'Mobile phone (SMS/voice)',
  voiceMobile: 'Voice call (mobile)',
  voiceAlternateMobile: 'Voice call (alternate mobile)',
  voiceOffice: 'Voice call (office)',
  alternateMobilePhone: 'Alternate mobile phone',
  officePhone: 'Office phone',
  email: 'Email',
  securityQuestion: 'Security questions',
  temporaryAccessPass: 'Temporary Access Pass',
  appPassword: 'App password',
  none: 'None',
};
const methodLabel = (m) => METHOD_LABELS[m] ?? m;

function levelBadge(level, text = LEVEL_TEXT[level]) {
  return h('span', { class: `badge rounded-pill lvl-badge lvl-${level}` }, icon(LEVEL_ICONS[level], 'me-1'), text);
}
function riskBadge(riskLevel) {
  const level = RISK_LEVEL[riskLevel] ?? 'unknown';
  return levelBadge(level, riskLevel ? riskLevel[0].toUpperCase() + riskLevel.slice(1) : 'Unknown');
}

// ---------- feedback ----------

function toast(message, level = 'danger') {
  const el = h(
    'div',
    { class: 'toast align-items-center border-0 shadow', role: 'alert', 'aria-live': 'assertive', 'aria-atomic': 'true' },
    h(
      'div',
      { class: 'd-flex' },
      h('div', { class: `toast-body d-flex gap-2 align-items-start lvl-${level}` }, icon(LEVEL_ICONS[level], 'lvl-text mt-1'), h('span', {}, message)),
      h('button', { type: 'button', class: 'btn-close me-2 m-auto', 'data-bs-dismiss': 'toast', 'aria-label': 'Close' }),
    ),
  );
  $('#toasts').append(el);
  el.addEventListener('hidden.bs.toast', () => el.remove());
  new bootstrap.Toast(el, { delay: 8000 }).show();
}

function emptyState(message, iconName = 'inbox') {
  return h('div', { class: 'empty' }, icon(iconName, 'fs-5'), h('span', {}, message));
}

function unavailableState(section) {
  const icons = { notLicensed: 'patch-exclamation', forbidden: 'shield-lock', disabled: 'toggle-off', notFound: 'inbox' };
  return emptyState(section.message, icons[section.reason] ?? 'exclamation-circle');
}

// ---------- API ----------

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function api(path) {
  const res = await fetch(path, { headers: { accept: 'application/json', 'x-requested-with': 'XMLHttpRequest' } });
  if (res.status === 401) {
    // Easy Auth session expired – sign in again and come back here
    window.location.assign(`/.auth/login/aad?post_login_redirect_uri=${encodeURIComponent(window.location.pathname)}`);
    throw new ApiError(401, 'Signing in…');
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, body.message ?? `Request failed (${res.status})`);
  return body;
}

// ---------- tables ----------

/** `wideOnly` lists column indexes hidden on phones so key columns (and Lookup) stay on screen. */
function table(headers, rows, { caption, wideOnly = [] } = {}) {
  const cls = (i) => (wideOnly.includes(i) ? 'd-none d-md-table-cell' : undefined);
  return h(
    'div',
    { class: 'table-responsive' },
    h(
      'table',
      { class: 'table table-hover align-middle' },
      caption ? h('caption', { class: 'visually-hidden' }, caption) : null,
      h('thead', {}, h('tr', {}, headers.map((t, i) => h('th', { scope: 'col', class: cls(i) }, t)))),
      h('tbody', {}, rows.map((cells) => h('tr', {}, cells.map((c, i) => h('td', { class: cls(i) }, c))))),
    ),
  );
}

const lookupButton = (user) =>
  h(
    'button',
    {
      type: 'button',
      class: 'btn btn-sm btn-outline-primary text-nowrap',
      'aria-label': `Look up ${user.displayName}`,
      onClick: () => loadProfile(user.id, user.displayName),
    },
    icon('search', 'me-sm-1'),
    h('span', { class: 'd-none d-sm-inline' }, 'Lookup'),
  );

const userCell = (name, upn) => h('div', {}, h('div', { class: 'fw-semibold' }, dash(name)), h('div', { class: 'small text-body-secondary text-break' }, upn));

// ---------- Secure Score ----------

async function loadSecureScore() {
  const target = $('#secureScore');
  try {
    const { data } = await api('/api/securescore');
    if (!data) {
      target.replaceChildren(emptyState('No Secure Score has been calculated for this tenant yet.'));
      return;
    }
    const level = data.percentage >= 70 ? 'good' : data.percentage >= 40 ? 'warning' : 'danger';
    const gauge = h(
      'div',
      { class: `gauge lvl-${level}`, role: 'img', 'aria-label': `Secure Score ${data.percentage} percent` },
      h('div', { class: 'gauge-value' }, String(data.percentage), h('small', {}, '%')),
    );
    gauge.style.setProperty('--pct', String(data.percentage));
    gauge.style.setProperty('--gauge-color', 'var(--lvl)');

    const stars = h(
      'div',
      { class: 'stars fs-5 mb-1', 'aria-label': `${data.stars} out of 5 stars` },
      Array.from({ length: 5 }, (_, i) => icon(i < data.stars ? 'star-fill' : 'star')),
    );
    const message =
      level === 'good' ? 'Looking good – keep it up.' : level === 'warning' ? 'It needs improvement, and we can do better.' : 'Needs urgent attention.';

    target.replaceChildren(
      h(
        'div',
        { class: 'd-flex align-items-center gap-4' },
        gauge,
        h(
          'div',
          {},
          stars,
          h('div', { class: 'fw-semibold' }, `${data.currentScore} of ${data.maxScore} points`),
          data.allTenantsAveragePercentage !== null
            ? h('div', { class: 'small text-body-secondary' }, `All tenants average: ${data.allTenantsAveragePercentage}%`)
            : null,
          h('div', { class: 'small text-body-secondary' }, `Updated ${fmtDay(data.createdDateTime)}`),
        ),
      ),
      h('p', { class: `small mt-3 mb-0 lvl-${level} lvl-text` }, message),
    );
  } catch (err) {
    target.replaceChildren(emptyState(err.message, 'exclamation-circle'));
  }
}

// ---------- recent risks ----------

async function loadRecentRisks() {
  const target = $('#recentRisks');
  try {
    const { data } = await api('/api/risk/recent');
    if (data.length === 0) {
      target.replaceChildren(emptyState('No active risk events in the last 30 days.', 'shield-check'));
      return;
    }
    target.replaceChildren(
      table(
        ['Detected', 'User', 'Risk', 'Level', 'Location', ''],
        data.map((r) => [
          h('span', { class: 'text-nowrap' }, fmtDate(r.detectedDateTime)),
          userCell(r.userDisplayName, r.userPrincipalName),
          r.typeLabel,
          riskBadge(r.level),
          h('div', {}, dash(r.location), h('div', { class: 'small text-body-secondary' }, r.ipAddress)),
          lookupButton({ id: r.userId, displayName: r.userDisplayName || r.userPrincipalName }),
        ]),
        { caption: 'Recent active risk events', wideOnly: [0, 3, 4] },
      ),
    );
  } catch (err) {
    target.replaceChildren(emptyState(err.message, 'exclamation-circle'));
  }
}

// ---------- user search ----------

const ACCOUNT_ICONS = { Hybrid: 'diagram-3', Cloud: 'cloud', B2B: 'person-badge' };
const accountBadge = (type) =>
  h('span', { class: 'badge rounded-pill bg-body-tertiary text-body border', title: `${type} account` }, icon(ACCOUNT_ICONS[type] ?? 'person', 'me-1'), type);

let searchSeq = 0;
async function runSearch(text) {
  const target = $('#searchResults');
  const seq = ++searchSeq;
  target.replaceChildren(h('div', { class: 'px-3 pb-3' }, h('div', { class: 'skeleton skeleton-line' }), h('div', { class: 'skeleton skeleton-line w-75' })));
  try {
    const { data } = await api(`/api/users?q=${encodeURIComponent(text)}`);
    if (seq !== searchSeq) return; // a newer search superseded this one
    if (data.length === 0) {
      target.replaceChildren(emptyState(`No users found matching “${text}”.`, 'person-x'));
      return;
    }
    target.replaceChildren(
      table(
        ['User', 'Email', 'Department', 'Account', ''],
        data.map((u) => [
          userCell(u.displayName, u.userPrincipalName),
          dash(u.mail),
          h('div', {}, dash(u.department), h('div', { class: 'small text-body-secondary' }, u.jobTitle)),
          h('div', { class: 'd-flex gap-1 flex-wrap' }, accountBadge(u.accountType), u.accountEnabled ? null : levelBadge('danger', 'Disabled')),
          lookupButton(u),
        ]),
        { caption: 'User search results', wideOnly: [1, 2] },
      ),
    );
  } catch (err) {
    if (seq === searchSeq) target.replaceChildren(emptyState(err.message, 'exclamation-circle'));
  }
}

function initSearch() {
  const input = $('#searchInput');
  let timer;
  input.addEventListener('input', () => {
    clearTimeout(timer);
    const text = input.value.trim();
    if (text.length >= 3) timer = setTimeout(() => runSearch(text), 400);
  });
  $('#searchForm').addEventListener('submit', (e) => {
    e.preventDefault();
    clearTimeout(timer);
    const text = input.value.trim();
    if (text.length >= 2) runSearch(text);
  });
}

// ---------- user profile ----------

const CHECKS = [
  ['risk', 'Risk events', 'exclamation-diamond'],
  ['password', 'Password exposure', 'incognito'],
  ['mfa', 'MFA configuration', 'person-lock'],
  ['devices', 'Devices', 'laptop'],
  ['sspr', 'Password resets', 'unlock'],
];
const BAR_WIDTH = { good: 100, warning: 66, danger: 100, info: 100, unknown: 100 };
const VERDICT_ICONS = { good: 'person-check-fill', warning: 'person-exclamation', danger: 'person-x-fill' };

function checkRow(name, iconName, check) {
  const bar = h('div', { class: 'progress-bar' });
  bar.style.width = `${BAR_WIDTH[check.level]}%`;
  return h(
    'div',
    { class: `check-row lvl-${check.level}` },
    h(
      'div',
      { class: 'd-flex align-items-center gap-2 mb-1' },
      icon(iconName, 'text-body-secondary'),
      h('span', { class: 'fw-semibold' }, name),
      h('span', { class: 'ms-auto small lvl-text text-end' }, icon(LEVEL_ICONS[check.level], 'me-1'), check.label),
    ),
    h('div', { class: 'progress', role: 'progressbar', 'aria-label': `${name}: ${check.label}` }, bar),
  );
}

function stat(target, count, noun, check) {
  target.replaceChildren(
    h('span', { class: 'stat-number' }, count === null ? '—' : String(count)),
    h('span', { class: 'text-body-secondary' }, noun),
    h('span', { class: 'ms-auto' }, levelBadge(check.level, check.label)),
  );
  target.className = `stat flex-wrap lvl-${check.level}`;
}

const detailBody = (id) => $(`#${id} .detail-body`);
const sectionOr = (section, render) => (section.status === 'ok' ? render(section.data) : unavailableState(section));

function kv(pairs) {
  return h('dl', { class: 'kv' }, pairs.flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v instanceof Node ? v : dash(v))]));
}

function renderProfile(p) {
  const u = p.user;
  const a = p.assessment;

  const initials = u.displayName
    .split(/\s+/)
    .filter((w) => /^\p{L}/u.test(w))
    .slice(0, 2)
    .map((w) => w[0].toUpperCase())
    .join('');
  $('#profileAvatar').textContent = initials || '?';
  $('#profileName').textContent = u.displayName;
  $('#profileUpn').textContent = u.userPrincipalName;
  $('#profileBadges').replaceChildren(
    accountBadge(u.accountType),
    u.accountEnabled ? levelBadge('good', 'Enabled') : levelBadge('danger', 'Disabled'),
  );

  // Overall verdict + summary
  $('#overall').replaceChildren(
    h(
      'div',
      { class: `lvl-${a.overall.level}` },
      icon(VERDICT_ICONS[a.overall.level], 'verdict-icon'),
      h('div', { class: 'h5 mt-2 mb-1 lvl-text' }, a.overall.label),
      h('div', { class: 'small text-body-secondary' }, 'User Secure Score risk profile'),
    ),
  );
  $('#summaryChecks').replaceChildren(...CHECKS.map(([key, name, ic]) => checkRow(name, ic, a[key])));

  // Risk
  const risks = p.riskDetections;
  stat($('#riskStat'), risks.status === 'ok' ? risks.data.length : null, 'events found', a.risk);
  detailBody('riskDetails').replaceChildren(
    p.riskyUser.status === 'ok' && p.riskyUser.data
      ? h(
          'div',
          { class: 'px-3 pt-3 d-flex gap-2 align-items-center flex-wrap' },
          h('span', { class: 'fw-semibold' }, 'User risk:'),
          riskBadge(p.riskyUser.data.riskLevel),
          h('span', { class: 'small text-body-secondary' }, `${p.riskyUser.data.riskState} · updated ${fmtDate(p.riskyUser.data.riskLastUpdatedDateTime)}`),
        )
      : null,
    sectionOr(risks, (list) =>
      list.length === 0
        ? emptyState('No risk events recorded for this user.', 'shield-check')
        : table(
            ['Detected', 'Risk', 'Level', 'State', 'Location', 'IP address'],
            list.map((r) => [fmtDate(r.detectedDateTime), r.typeLabel, riskBadge(r.level), r.state, dash(r.location), dash(r.ipAddress)]),
          ),
    ),
  );

  // MFA
  const mfa = p.mfa;
  stat($('#mfaStat'), mfa.status === 'ok' && mfa.data ? mfa.data.methodsRegistered.length : null, 'methods registered', a.mfa);
  detailBody('mfaDetails').replaceChildren(
    sectionOr(mfa, (m) =>
      !m
        ? emptyState('No MFA registration details for this user.')
        : kv([
            ['MFA registered', yesNo(m.isMfaRegistered)],
            ['MFA capable', yesNo(m.isMfaCapable)],
            ['Passwordless capable', yesNo(m.isPasswordlessCapable)],
            ['SSPR registered', yesNo(m.isSsprRegistered)],
            ['Default MFA method', methodLabel(m.defaultMfaMethod)],
            ['User preferred method', methodLabel(m.userPreferredMethod)],
            ['System preferred', m.systemPreferredMethods.map(methodLabel).join(', ')],
            [
              'Methods registered',
              m.methodsRegistered.length
                ? h('div', { class: 'd-flex flex-wrap gap-1' }, m.methodsRegistered.map((x) => h('span', { class: 'badge text-bg-secondary' }, methodLabel(x))))
                : 'None',
            ],
            ['Report updated', fmtDate(m.lastUpdatedDateTime)],
          ]),
    ),
  );

  // Pwned / HIBP
  const hibp = p.hibp;
  stat($('#pwnedStat'), hibp.status === 'ok' ? hibp.data.breaches.length : null, 'breaches found', a.password);
  const leaked = risks.status === 'ok' && risks.data.some((r) => r.type === 'leakedCredentials');
  detailBody('pwnedDetails').replaceChildren(
    leaked
      ? h('div', { class: 'alert alert-danger m-3 mb-0 d-flex gap-2' }, icon('key-fill'), 'Microsoft Entra ID Protection detected leaked credentials for this user. Require a password change.')
      : null,
    sectionOr(hibp, (d) =>
      h(
        'div',
        {},
        h('p', { class: 'small text-body-secondary px-3 pt-3 mb-2' }, `Checked ${d.account} · ${d.pasteCount} paste(s) found.`),
        d.breaches.length === 0
          ? emptyState('This email address was not found in any breach.', 'shield-check')
          : table(
              ['Breach', 'Date', 'Data exposed', 'Passwords'],
              d.breaches.map((b) => [
                h('div', {}, h('div', { class: 'fw-semibold' }, b.title), h('div', { class: 'small text-body-secondary' }, b.domain)),
                fmtDay(b.breachDate),
                h('div', { class: 'd-flex flex-wrap gap-1' }, b.dataClasses.map((c) => h('span', { class: 'badge text-bg-secondary' }, c))),
                b.includesPasswords ? levelBadge('danger', 'Exposed') : levelBadge('good', 'No'),
              ]),
            ),
      ),
    ),
  );

  // Sign-ins
  const signIns = p.signIns;
  stat($('#signInStat'), signIns.status === 'ok' ? signIns.data.length : null, 'sign-ins (30 days)', {
    level: signIns.status !== 'ok' ? 'unknown' : signIns.data.some((s) => !s.succeeded) ? 'warning' : 'good',
    label: signIns.status !== 'ok' ? 'Unavailable' : `${signIns.data.filter((s) => !s.succeeded).length} failed`,
  });
  detailBody('signInDetails').replaceChildren(
    sectionOr(signIns, (list) =>
      list.length === 0
        ? emptyState('No sign-ins in the last 30 days.')
        : table(
            ['Time', 'Application', 'Result', 'Location', 'Device', 'Conditional Access'],
            list.map((s) => [
              h('span', { class: 'text-nowrap' }, fmtDate(s.createdDateTime)),
              h('div', {}, s.appDisplayName, h('div', { class: 'small text-body-secondary' }, s.clientAppUsed)),
              s.succeeded ? levelBadge('good', 'Success') : h('div', {}, levelBadge('danger', 'Failure'), h('div', { class: 'small text-body-secondary mt-1' }, s.failureReason)),
              h('div', {}, dash(s.location), h('div', { class: 'small text-body-secondary' }, s.ipAddress)),
              h('div', {}, [s.operatingSystem, s.browser].filter(Boolean).join(' · ') || '—', h('div', { class: 'small text-body-secondary' }, s.deviceTrustType || 'Not joined/registered')),
              dash(s.conditionalAccessStatus),
            ]),
          ),
    ),
  );

  // SSPR
  const sspr = p.sspr;
  stat($('#ssprStat'), sspr.status === 'ok' ? sspr.data.length : null, 'events found', a.sspr);
  detailBody('ssprDetails').replaceChildren(
    sectionOr(sspr, (list) =>
      list.length === 0
        ? emptyState('No self-service password reset activity in the last 30 days.')
        : table(
            ['Time', 'Activity', 'Result', 'Reason'],
            list.map((e) => [
              h('span', { class: 'text-nowrap' }, fmtDate(e.activityDateTime)),
              e.activity,
              e.result === 'success' ? levelBadge('good', 'Success') : levelBadge('danger', e.result || 'Failure'),
              dash(e.resultReason),
            ]),
          ),
    ),
  );

  // User & devices
  const devices = p.devices;
  stat($('#deviceStat'), devices.status === 'ok' ? devices.data.length : null, 'device(s) found', a.devices);
  detailBody('userDetails').replaceChildren(
    kv([
      ['Account enabled', yesNo(u.accountEnabled)],
      ['Account type', u.accountType],
      ['Job title', u.jobTitle],
      ['Department', u.department],
      ['Office', u.officeLocation],
      ['City', u.city],
      ['Email', u.mail],
      ['Mobile', u.mobilePhone],
      ['Manager', u.manager],
      ['Created', fmtDate(u.createdDateTime)],
      ['Password last changed', fmtDate(u.lastPasswordChangeDateTime)],
      ['sAMAccountName', u.onPremisesSamAccountName],
      ['Distinguished name', u.onPremisesDistinguishedName],
      ['On-premises SID', u.onPremisesSecurityIdentifier],
    ]),
    h('div', { class: 'border-top' }),
    sectionOr(devices, (list) =>
      list.length === 0
        ? emptyState('No registered devices.', 'laptop')
        : table(
            ['Device', 'Join type', 'Compliant', 'Managed', 'Last sign-in'],
            list.map((d) => [
              h('div', {}, h('div', { class: 'fw-semibold' }, d.displayName), h('div', { class: 'small text-body-secondary' }, d.operatingSystem)),
              d.trustType === 'Workplace' ? levelBadge('warning', d.joinType) : levelBadge('good', d.joinType),
              yesNo(d.isCompliant),
              yesNo(d.isManaged),
              fmtDate(d.lastSignIn),
            ]),
          ),
    ),
  );
}

function showProfileView(show) {
  $('#discovery').hidden = show;
  $('#profile').hidden = !show;
}

let profileSeq = 0;
async function loadProfile(id, displayName) {
  const seq = ++profileSeq;
  showProfileView(true);
  // collapse any open detail panels from a previous user
  document.querySelectorAll('#profile .collapse.show').forEach((el) => bootstrap.Collapse.getOrCreateInstance(el).hide());
  $('#profileName').textContent = displayName ?? '';
  $('#profileUpn').textContent = '';
  $('#profileBadges').replaceChildren();
  $('#profileAvatar').textContent = '';
  $('#profileLoading').hidden = false;
  $('#profileBody').hidden = true;
  $('#profile').scrollIntoView({ behavior: 'smooth', block: 'start' });
  try {
    const profile = await api(`/api/users/${encodeURIComponent(id)}/profile`);
    if (seq !== profileSeq) return;
    renderProfile(profile);
    $('#profileBody').hidden = false;
  } catch (err) {
    if (seq !== profileSeq) return;
    toast(err.message);
    showProfileView(false);
  } finally {
    if (seq === profileSeq) $('#profileLoading').hidden = true;
  }
}

// ---------- boot ----------

async function loadOperator() {
  try {
    const me = await api('/api/me');
    $('#operatorName span').textContent = me.name;
    $('#mockBadge').classList.toggle('d-none', !me.mock);
  } catch (err) {
    if (err.status === 403) toast(err.message, 'warning');
  }
}

$('#newSearch').addEventListener('click', () => {
  profileSeq++;
  showProfileView(false);
  $('#searchInput').focus();
});

initSearch();
loadOperator();
loadSecureScore();
loadRecentRisks();
