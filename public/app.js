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

// The weighted checks behind the overall verdict, in display order
const CHECKS = [
  ['risk', 'Risk events', 'exclamation-diamond'],
  ['password', 'Password exposure', 'incognito'],
  ['mfa', 'MFA registration', 'person-lock'],
  ['authStrength', 'Authentication strength', 'fingerprint'],
  ['privilege', 'Privilege exposure', 'shield-shaded'],
  ['guests', 'Guest footprint', 'people'],
  ['membership', 'Group memberships', 'diagram-3'],
];
const BAR_WIDTH = { good: 100, warning: 66, danger: 100, info: 100, unknown: 100 };
const VERDICT_ICONS = { good: 'person-check-fill', warning: 'person-exclamation', danger: 'person-x-fill' };

const IMPACT_LEVEL = { high: 'danger', medium: 'warning', low: 'info' };
const ROLE_STATES = {
  permanentActive: ['Permanent', 'danger'],
  timeBoundActive: ['Time-bound', 'warning'],
  activated: ['Activated (PIM)', 'info'],
  eligible: ['Eligible (PIM)', 'good'],
};
const OWNED_KINDS = {
  application: 'App registration',
  servicePrincipal: 'Enterprise app',
  agent: 'Agent identity',
  roleAssignableGroup: 'Role-assignable group',
  team: 'Team',
  m365Group: 'Microsoft 365 group',
  securityGroup: 'Security group',
  mailGroup: 'Distribution / mail-enabled group',
  other: 'Other',
};
const VERDICTS = {
  phishingResistant: ['Phishing-resistant', 'good'],
  passwordlessCapable: ['Passwordless-capable', 'info'],
  phishable: ['MFA only – phishable', 'warning'],
  none: ['No strong method', 'danger'],
};

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
const count = (section, fn) => (section.status === 'ok' ? fn(section.data) : null);

function kv(pairs) {
  return h('dl', { class: 'kv' }, pairs.flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v instanceof Node ? v : dash(v))]));
}

const badges = (items, cls = 'text-bg-secondary') =>
  items.length ? h('div', { class: 'd-flex flex-wrap gap-1' }, items.map((x) => h('span', { class: `badge ${cls}` }, x))) : 'None';

/** A labelled check result inside a detail panel */
const checkLine = (name, check) =>
  h('div', { class: 'px-3 pt-3 d-flex gap-2 align-items-center flex-wrap' }, h('span', { class: 'fw-semibold' }, `${name}:`), levelBadge(check.level, check.label));

const subheading = (text) => h('h4', { class: 'h6 px-3 pt-3 mb-0' }, text);

/** Lookups that failed or were truncated, so the operator knows the list may be incomplete */
const gapNote = (gaps) =>
  gaps.length
    ? h('div', { class: 'alert alert-warning small m-3 mb-0 d-flex gap-2' }, icon('exclamation-triangle'), h('ul', { class: 'mb-0 ps-3' }, gaps.map((g) => h('li', {}, g))))
    : null;

function renderAuthentication(p, a) {
  const auth = p.authStrength;
  const mfa = p.mfa;
  stat($('#mfaStat'), count(auth, (d) => d.methods?.length ?? null), 'methods registered', a.authStrength);
  detailBody('mfaDetails').replaceChildren(
    sectionOr(auth, (d) =>
      h(
        'div',
        {},
        h(
          'div',
          { class: 'px-3 pt-3 d-flex gap-2 align-items-center flex-wrap' },
          h('span', { class: 'fw-semibold' }, 'Verdict:'),
          levelBadge(VERDICTS[d.verdict][1], VERDICTS[d.verdict][0]),
        ),
        h('p', { class: 'px-3 pt-2 mb-0' }, d.summary),
        subheading('Observed in recent sign-ins'),
        d.observed === null
          ? emptyState('Sign-in authentication details are unavailable (Graph beta), so actual usage can’t be confirmed.', 'question-circle')
          : d.observed.total === 0
            ? emptyState('No recent interactive sign-ins with authentication details.')
            : h(
                'div',
                { class: 'px-3 pt-2' },
                badges(d.observed.methods.map((m) => `${m.method} × ${m.count}`)),
                h('div', { class: 'small text-body-secondary mt-1' }, `${d.observed.total} interactive sign-in(s) · ${d.observed.counts.phishingResistant} phishing-resistant`),
              ),
        subheading('Registered methods'),
        d.methods === null
          ? emptyState('The method inventory is unavailable – the app needs UserAuthenticationMethod.Read.All.', 'shield-lock')
          : d.methods.length === 0
            ? emptyState('No authentication methods registered.')
            : table(
                ['Method', 'Detail', 'Registered'],
                d.methods.map((m) => [
                  h('span', {}, m.kind === 'phishingResistant' ? icon('patch-check-fill', 'me-1 lvl-good lvl-text') : null, m.label),
                  dash(m.detail),
                  fmtDay(m.createdDateTime),
                ]),
                { caption: 'Registered authentication methods', wideOnly: [2] },
              ),
      ),
    ),
    checkLine('Recovery paths', a.recovery),
    sectionOr(p.recovery, (r) => (r.weakPaths.length ? h('ul', { class: 'px-5 pt-2 mb-0 small' }, r.weakPaths.map((w) => h('li', {}, w))) : null)),
    subheading('Registration report'),
    sectionOr(mfa, (m) =>
      !m
        ? emptyState('No MFA registration details for this user.')
        : kv([
            ['MFA registered', yesNo(m.isMfaRegistered)],
            ['Passwordless capable', yesNo(m.isPasswordlessCapable)],
            ['SSPR registered', yesNo(m.isSsprRegistered)],
            ['Default MFA method', methodLabel(m.defaultMfaMethod)],
            ['User preferred method', methodLabel(m.userPreferredMethod)],
            ['System preferred', m.systemPreferredMethods.map(methodLabel).join(', ')],
            ['Methods registered', badges(m.methodsRegistered.map(methodLabel))],
            ['Report updated', fmtDate(m.lastUpdatedDateTime)],
          ]),
    ),
  );
}

function renderPrivilege(p, a) {
  const priv = p.privilege;
  stat($('#privilegeStat'), count(priv, (d) => d.assignments.length), 'role(s)', a.privilege);
  detailBody('privilegeDetails').replaceChildren(
    checkLine('Requires PIM', a.pimDrift),
    checkLine('Admin account hygiene', a.adminHygiene),
    sectionOr(priv, (d) =>
      h(
        'div',
        { class: 'pt-3' },
        d.pimDetail ? null : h('p', { class: 'small text-body-secondary px-3 mb-2' }, 'PIM schedules are unavailable, so every role is shown as a permanent assignment.'),
        gapNote(d.gaps),
        d.assignments.length === 0
          ? emptyState('No Entra roles assigned or eligible.', 'shield-check')
          : table(
              ['Role', 'Assignment', 'Impact', 'Reach', 'PIM'],
              d.assignments.map((r) => [
                h('div', {}, h('div', { class: 'fw-semibold' }, r.roleName), h('div', { class: 'small text-body-secondary' }, [r.scope, r.via === 'group' ? `via ${r.groupName || 'a group'}` : ''].filter(Boolean).join(' · '))),
                h(
                  'div',
                  {},
                  levelBadge(ROLE_STATES[r.state][1], ROLE_STATES[r.state][0]),
                  r.endDateTime ? h('div', { class: 'small text-body-secondary mt-1' }, `until ${fmtDate(r.endDateTime)}`) : null,
                ),
                levelBadge(IMPACT_LEVEL[r.impact], r.impact[0].toUpperCase() + r.impact.slice(1)),
                r.themes.length ? badges(r.themes, 'bg-body-tertiary text-body border fw-normal') : '—',
                r.pimDrift ? levelBadge('warning', 'Should be eligible') : r.pimRequired ? levelBadge('good', 'Required') : '—',
              ]),
              { caption: 'Entra role assignments', wideOnly: [3, 4] },
            ),
      ),
    ),
  );
}

function renderOwnership(p, a) {
  const own = p.ownership;
  stat($('#ownershipStat'), count(own, (d) => d.objects.length), 'owned object(s)', a.ownership);
  detailBody('ownershipDetails').replaceChildren(
    sectionOr(own, (d) => (d.complete ? null : gapNote(['Only the first pages of owned objects were read – there are more.']))),
    sectionOr(own, (d) =>
      d.objects.length === 0
        ? emptyState('This user owns no apps, agents or groups.', 'shield-check')
        : table(
            ['Name', 'Type', ''],
            d.objects.map((o) => [
              h('span', { class: 'fw-semibold' }, o.displayName),
              OWNED_KINDS[o.kind] ?? o.kind,
              o.kind === 'roleAssignableGroup'
                ? levelBadge('danger', 'Grants roles')
                : o.sensitive
                  ? levelBadge('danger', 'Sensitive')
                  : o.kind === 'agent' || o.kind === 'application' || o.kind === 'servicePrincipal'
                    ? levelBadge('warning', 'Non-human identity')
                    : null,
            ]),
            { caption: 'Objects owned by this user' },
          ),
    ),
  );
}

function renderGuestsAndMembership(p, a) {
  const guests = p.guests;
  const worst = [a.guests, a.membership].sort((x, y) => LEVEL_RANK[y.level] - LEVEL_RANK[x.level])[0];
  stat($('#guestStat'), count(guests, (d) => d.footprint), 'guest(s) linked', worst);
  detailBody('guestDetails').replaceChildren(
    checkLine('Guest footprint', a.guests),
    sectionOr(guests, (g) =>
      h(
        'div',
        {},
        gapNote(g.gaps),
        subheading(`Guests sponsored${g.sponsored ? ` (${g.sponsored.length})` : ''}`),
        g.sponsored === null
          ? emptyState('Not available – see the note above.', 'shield-lock')
          : g.sponsored.length === 0
            ? emptyState('Sponsors no guests.')
            : table(['Guest', 'User principal name'], g.sponsored.map((s) => [s.displayName, h('span', { class: 'text-break' }, s.userPrincipalName)]), { wideOnly: [1] }),
        subheading(`Guests invited in 30 days${g.invites ? ` (${g.invites.length})` : ''}`),
        g.invites === null
          ? emptyState('Invitation audit data unavailable.')
          : g.invites.length === 0
            ? emptyState('No guest invitations in the last 30 days.')
            : table(['Invited', 'Guest'], g.invites.map((i) => [h('span', { class: 'text-nowrap' }, fmtDate(i.activityDateTime)), h('span', { class: 'text-break' }, i.invitee)])),
      ),
    ),
    h('div', { class: 'border-top mt-3' }),
    checkLine('Memberships', a.membership),
    sectionOr(p.membership, (m) =>
      kv([
        ['Direct groups', `${m.complete ? '' : 'At least '}${m.directGroups} (${m.m365Groups} Microsoft 365)`],
        ['Including nested', m.transitiveGroups ?? '—'],
        ['Administrative units', badges(m.adminUnits)],
        ['Active directory roles', badges(m.directoryRoles)],
        ['Role-assignable groups', badges(m.roleAssignableGroups.map((g) => g.displayName), 'text-bg-danger')],
        ['Sensitive groups', badges(m.sensitiveGroups.map((g) => g.displayName), 'text-bg-warning')],
        ['Review thresholds', m.exceeded.length ? h('ul', { class: 'mb-0 ps-3' }, m.exceeded.map((e) => h('li', {}, e))) : 'Within thresholds'],
      ]),
    ),
  );
}

function renderCredentialChanges(p, a) {
  const changes = p.credentialChanges;
  stat($('#credentialStat'), count(changes, (d) => d.events.length), 'change(s)', a.credentialChanges);
  detailBody('credentialDetails').replaceChildren(
    sectionOr(changes, (c) =>
      h(
        'div',
        {},
        c.suspiciousDetections.length
          ? h(
              'div',
              { class: 'alert alert-danger m-3 mb-0 d-flex gap-2' },
              icon('key-fill'),
              `Microsoft Entra ID Protection flagged a suspicious credential addition (${fmtDate(c.suspiciousDetections[0].detectedDateTime)}). Review the change below and remove any method the user doesn’t recognise.`,
            )
          : null,
        c.events.length === 0
          ? emptyState('No security info changes in the last 30 days.', 'shield-check')
          : table(
              ['When', 'Change', 'By', 'Signals'],
              c.events.map((e) => [
                h('span', { class: 'text-nowrap' }, fmtDate(e.dateTime)),
                h('div', {}, e.activity, h('div', { class: 'small text-body-secondary' }, e.source === 'audit' ? 'Audit log' : 'Method inventory')),
                e.source === 'audit' ? (e.bySelf ? 'User' : h('span', { class: 'text-break' }, e.initiatedBy)) : '—',
                e.flags.length ? h('div', { class: 'vstack gap-1' }, e.flags.map((f) => levelBadge('warning', f))) : '—',
              ]),
              { caption: 'Security info changes', wideOnly: [2] },
            ),
      ),
    ),
  );
}

function renderSignIns(p) {
  const signIns = p.signIns;
  const a = p.assessment;
  stat($('#signInStat'), signIns.status === 'ok' ? signIns.data.length : null, 'sign-ins (30 days)', a.caPosture);
  const ca = p.caPosture;
  detailBody('signInDetails').replaceChildren(
    checkLine('Conditional Access', a.caPosture),
    sectionOr(ca, (c) =>
      h(
        'p',
        { class: 'small text-body-secondary px-3 pt-2 mb-0' },
        `${c.total} interactive sign-in(s): ${c.mfaSatisfied} with MFA, ${c.singleFactor} single-factor (${c.unprotected} with no policy applied), ${c.caFailures} Conditional Access failure(s).`,
      ),
    ),
    sectionOr(signIns, (list) =>
      list.length === 0
        ? emptyState('No sign-ins in the last 30 days.')
        : table(
            ['Time', 'Application', 'Result', 'Methods', 'Location', 'Device', 'Conditional Access'],
            list.map((s) => [
              h('span', { class: 'text-nowrap' }, fmtDate(s.createdDateTime)),
              h('div', {}, s.appDisplayName, h('div', { class: 'small text-body-secondary' }, s.clientAppUsed)),
              s.succeeded ? levelBadge('good', 'Success') : h('div', {}, levelBadge('danger', 'Failure'), h('div', { class: 'small text-body-secondary mt-1' }, s.failureReason)),
              s.authMethods.length ? s.authMethods.join(' + ') : '—',
              h('div', {}, dash(s.location), h('div', { class: 'small text-body-secondary' }, s.ipAddress)),
              h('div', {}, [s.operatingSystem, s.browser].filter(Boolean).join(' · ') || '—', h('div', { class: 'small text-body-secondary' }, s.deviceTrustType || 'Not joined/registered')),
              dash(s.conditionalAccessStatus),
            ]),
            { wideOnly: [4, 5, 6] },
          ),
    ),
  );
}

const LEVEL_RANK = { good: 0, info: 1, unknown: 2, warning: 3, danger: 4 };

function identityBadges(u, identity) {
  return [
    accountBadge(u.accountType),
    u.accountEnabled ? levelBadge('good', 'Enabled') : levelBadge('danger', 'Disabled'),
    identity.isBreakGlass ? levelBadge('info', 'Emergency access') : null,
    identity.isPrivileged && !identity.isBreakGlass ? levelBadge('warning', 'Privileged') : null,
    identity.isServiceAccount ? levelBadge('info', 'Service account') : null,
  ].filter(Boolean);
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
  $('#profileBadges').replaceChildren(...identityBadges(u, p.identity));

  // Overall verdict + summary
  $('#overall').replaceChildren(
    h(
      'div',
      { class: `lvl-${a.overall.level}` },
      icon(VERDICT_ICONS[a.overall.level], 'verdict-icon'),
      h('div', { class: 'h5 mt-2 mb-1 lvl-text' }, a.overall.label),
      a.overall.reasons.length ? h('div', { class: 'small' }, a.overall.reasons.join(' + ')) : null,
      h('div', { class: 'small text-body-secondary mt-1' }, 'User Secure Score risk profile'),
    ),
  );
  $('#summaryChecks').replaceChildren(...CHECKS.map(([key, name, ic]) => checkRow(name, ic, a[key])));
  const notes = p.tenant.notes;
  $('#tenantNotes').hidden = notes.length === 0;
  $('#tenantNotes').replaceChildren(
    h('div', { class: 'fw-semibold mb-1' }, icon('building', 'me-1'), 'Tenant context'),
    h('ul', { class: 'mb-0 ps-3' }, notes.map((n) => h('li', {}, n))),
  );

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

  renderAuthentication(p, a);

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

  renderSignIns(p);
  renderCredentialChanges(p, a);

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

  renderPrivilege(p, a);
  renderOwnership(p, a);
  renderGuestsAndMembership(p, a);
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
