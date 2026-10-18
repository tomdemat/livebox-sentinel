/* Livebox Sentinel shared UI: Wi-Fi, newcomers, Livebox connection, retention, second factor.
   User and device data only ever enter the DOM through textContent / properties. */
(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  const node = (tag, cls, value) => { const n = document.createElement(tag); if (cls) n.className = cls; if (value !== undefined) n.textContent = value; return n; };
  const date = ts => ts ? new Date(ts * 1000).toLocaleString('fr-FR', {dateStyle: 'short', timeStyle: 'short'}) : '—';
  const time = ts => new Date(ts * 1000).toLocaleTimeString('fr-FR', {hour: '2-digit', minute: '2-digit'});
  const ago = ts => { const s = Math.max(0, Date.now() / 1000 - ts); return s < 90 ? 'à l’instant' : s < 3600 ? 'il y a ' + Math.round(s / 60) + ' min' : s < 86400 ? 'il y a ' + Math.round(s / 3600) + ' h' : 'le ' + date(ts); };
  const size = value => { if (!value) return '0 o'; const u = ['o', 'Kio', 'Mio', 'Gio', 'Tio']; const i = Math.min(4, Math.floor(Math.log(value) / Math.log(1024))); return (value / 1024 ** i).toLocaleString('fr-FR', {maximumFractionDigits: 1}) + ' ' + u[i]; };
  const path = location.pathname;

  async function api(url, options = {}) {
    if (options.json !== undefined) options = {...options, method: options.method || 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(options.json)};
    const response = await fetch(url, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Cette opération n’a pas abouti. Réessayez.');
    return data;
  }
  function say(target, message, error = false) { if (!target) return; target.textContent = message; target.dataset.state = error ? 'error' : 'success'; target.hidden = !message; }

  function signalTone(rssi) { return rssi === null || rssi === undefined ? 'unknown' : rssi >= -60 ? 'ok' : rssi >= -67 ? 'ok' : rssi > -75 ? 'info' : 'warning'; }
  function bars(rssi) {
    const level = rssi === null || rssi === undefined ? 0 : rssi >= -60 ? 4 : rssi >= -67 ? 3 : rssi > -75 ? 2 : 1;
    const wrap = node('span', 'sn-bars'); wrap.dataset.status = signalTone(rssi); wrap.setAttribute('aria-hidden', 'true');
    for (let i = 1; i <= 4; i++) { const bar = node('i'); if (i <= level) bar.dataset.on = ''; wrap.append(bar); }
    return wrap;
  }

  // ---------- Opening a device card, from anywhere ----------
  function openDevice(mac, focus) {
    if (path === '/' && typeof selectDevice === 'function' && typeof allDevices !== 'undefined' && allDevices.some(d => d.mac === mac)) {
      if (focus === 'wifi') pendingFocus = mac;
      selectDevice(mac);
      return true;
    }
    location.href = '/?device=' + encodeURIComponent(mac) + (focus ? '&focus=' + focus : '');
    return false;
  }
  let pendingFocus = null;

  // ---------- Recognising a newcomer (device card) ----------
  async function acknowledge(mac, name, recognised) {
    await api('/api/devices/' + encodeURIComponent(mac) + '/acknowledge', {method: recognised ? 'POST' : 'DELETE'});
    if (typeof refresh === 'function') await refresh();
    const device = typeof allDevices !== 'undefined' ? allDevices.find(d => d.mac === mac) : null;
    if (device && typeof selectedMac !== 'undefined' && selectedMac === mac) window.renderNewcomer(device);
    toast(recognised ? name + ' est reconnu : il n’est plus signalé comme nouveau.' : name + ' est de nouveau signalé comme nouvel équipement.', recognised ? () => acknowledge(mac, name, false) : null);
  }
  let toastTimer = null;
  function toast(message, undo) {
    // Inside an open modal the rest of the page is inert: the message must live in the dialog to stay usable.
    const host = document.querySelector('dialog[open]') || document.body;
    let box = byId('snToast'); if (!box) { box = node('div', 'sn-toast'); box.id = 'snToast'; box.setAttribute('role', 'status'); }
    if (box.parentElement !== host) host.append(box);
    box.replaceChildren(node('span', '', message)); box.hidden = false;
    if (undo) { const button = node('button', '', 'Annuler'); button.type = 'button'; button.addEventListener('click', () => { box.hidden = true; undo().catch(error => toast(error.message)); }); box.append(button); }
    clearTimeout(toastTimer); toastTimer = setTimeout(() => { box.hidden = true; }, 9000);
  }

  // ---------- Newcomer banner in the device card ----------
  window.renderNewcomer = device => {
    const box = byId('deviceNewcomer'); if (!box || !device) return;
    const recent = device.first_seen_at && Date.now() / 1000 - device.first_seen_at < 7 * 86400;
    box.hidden = !recent; if (!recent) return;
    box.replaceChildren(); box.dataset.status = device.acknowledged ? 'ok' : 'info';
    const text = node('p'); text.append(node('strong', '', device.acknowledged ? 'Reconnu par vous' : 'Nouvel équipement'), document.createTextNode(' · arrivé ' + ago(device.first_seen_at) + (device.acknowledged ? '' : '. Il reste signalé pendant 7 jours, sauf si vous le reconnaissez.')));
    const button = node('button', device.acknowledged ? 'quiet-button' : 'sn-ack', device.acknowledged ? 'Le signaler de nouveau' : 'Je le reconnais'); button.type = 'button';
    button.addEventListener('click', async () => { button.disabled = true; try { await acknowledge(device.mac, device.name, !device.acknowledged); } catch (error) { button.disabled = false; toast(error.message); } });
    box.append(text, button);
  };

  // ---------- Recognition suggestion (device card) ----------
  // A suggestion only fills an empty category; the owner applies or dismisses it.
  async function saveCategory(device, category) {
    const query = new URLSearchParams({custom_name: device.custom_name || '', category, location: device.location || ''});
    await api('/api/devices/' + encodeURIComponent(device.mac) + '/profile?' + query, {method: 'PUT'});
    if (typeof refresh === 'function') await refresh();
    const fresh = typeof allDevices !== 'undefined' ? allDevices.find(d => d.mac === device.mac) : null;
    if (fresh && typeof selectedMac !== 'undefined' && selectedMac === device.mac) {
      if (typeof prepareProfileChoice === 'function' && typeof CATEGORY_PRESETS !== 'undefined') prepareProfileChoice('Category', fresh.category, CATEGORY_PRESETS);
      window.renderSuggestion(fresh);
    }
    return fresh || device;
  }
  async function setDismissed(device, category, dismissed) {
    await api('/api/devices/' + encodeURIComponent(device.mac) + '/suggestion/dismiss', dismissed ? {json: {category}} : {method: 'DELETE'});
    if (typeof refresh === 'function') await refresh();
    const fresh = typeof allDevices !== 'undefined' ? allDevices.find(d => d.mac === device.mac) : null;
    if (fresh && typeof selectedMac !== 'undefined' && selectedMac === device.mac) window.renderSuggestion(fresh);
  }
  window.renderSuggestion = device => {
    const box = byId('deviceSuggestion'); if (!box || !device) return;
    const guess = device.recognition && device.recognition.suggestion;
    box.hidden = !guess; if (!guess) return;
    box.replaceChildren(); box.dataset.status = 'info';
    const text = node('div', 'sn-suggestion-text');
    const title = node('p'); title.append(node('strong', '', 'Suggestion'), document.createTextNode(' · catégorie probable : '), node('strong', '', guess.category));
    const confidence = node('span', 'sn-badge', 'Confiance ' + guess.confidence); confidence.dataset.status = guess.confidence === 'élevée' ? 'ok' : guess.confidence === 'moyenne' ? 'info' : 'warning';
    title.append(document.createTextNode(' '), confidence);
    text.append(title);
    if (guess.reasons && guess.reasons.length) {
      const why = node('details', 'sn-why'); why.append(node('summary', '', 'Pourquoi ?'));
      const list = node('ul'); for (const reason of guess.reasons) list.append(node('li', '', reason.charAt(0).toUpperCase() + reason.slice(1)));
      why.append(list); text.append(why);
    }
    const actions = node('div', 'sn-suggestion-actions');
    const apply = node('button', 'sn-ack', 'Utiliser « ' + guess.category + ' »'); apply.type = 'button';
    const ignore = node('button', 'quiet-button', 'Ignorer'); ignore.type = 'button';
    apply.addEventListener('click', async () => {
      apply.disabled = ignore.disabled = true;
      try { await saveCategory(device, guess.category); toast('Catégorie « ' + guess.category + ' » enregistrée pour ' + device.name + '.', () => saveCategory(device, '')); }
      catch (error) { apply.disabled = ignore.disabled = false; toast(error.message); }
    });
    ignore.addEventListener('click', async () => {
      apply.disabled = ignore.disabled = true;
      try { await setDismissed(device, guess.category, true); toast('Suggestion ignorée pour ' + device.name + '.', () => setDismissed(device, guess.category, false)); }
      catch (error) { apply.disabled = ignore.disabled = false; toast(error.message); }
    });
    actions.append(apply, ignore);
    box.append(text, actions);
  };

  // ---------- Wi-Fi chart (real dBm scale, -130 to 0) ----------
  function wifiChart(history, threshold) {
    const samples = history.filter(p => p.rssi !== null);
    if (samples.length < 2) return node('p', 'muted', 'Le graphique apparaîtra après deux mesures de signal fournies par la Livebox.');
    const ns = 'http://www.w3.org/2000/svg', svg = document.createElementNS(ns, 'svg');
    const W = 640, H = 200, L = 58, R = 12, T = 12, B = 30;
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`); svg.classList.add('sn-chart'); svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Signal Wi-Fi sur 24 heures, échelle fixe de moins 130 à 0 dBm. Dernière valeur ' + samples.at(-1).rssi + ' dBm.');
    const t0 = samples[0].ts, t1 = Math.max(t0 + 1, samples.at(-1).ts);
    const x = ts => L + (ts - t0) / (t1 - t0) * (W - L - R), y = dbm => T + (-dbm) / 130 * (H - T - B);
    const el = (tag, attrs, textValue) => { const e = document.createElementNS(ns, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); if (textValue !== undefined) e.textContent = textValue; svg.append(e); return e; };
    for (const dbm of [0, -40, -70, -100, -130]) { el('line', {x1: L, x2: W - R, y1: y(dbm), y2: y(dbm), class: 'sn-grid'}); el('text', {x: L - 8, y: y(dbm) + 4, 'text-anchor': 'end', class: 'sn-axis'}, dbm + ' dBm'); }
    el('rect', {x: L, y: y(threshold), width: W - L - R, height: y(-130) - y(threshold), class: 'sn-weak-zone'});
    el('text', {x: W - R - 4, y: y(-130) - 6, 'text-anchor': 'end', class: 'sn-axis sn-weak-label'}, 'zone de signal faible (≤ ' + threshold + ' dBm)');
    el('polyline', {points: samples.map(p => x(p.ts) + ',' + y(p.rssi)).join(' '), class: 'sn-line'});
    el('text', {x: L, y: H - 8, class: 'sn-axis'}, time(t0)); el('text', {x: W - R, y: H - 8, 'text-anchor': 'end', class: 'sn-axis'}, time(t1));
    const cursor = el('line', {x1: 0, x2: 0, y1: T, y2: H - B, class: 'sn-cursor', visibility: 'hidden'});
    const dot = el('circle', {r: 5, class: 'sn-dot', visibility: 'hidden'});
    const wrap = node('div', 'sn-chart-wrap'), readout = node('p', 'sn-readout', 'Touchez ou survolez la courbe pour lire une mesure.');
    readout.setAttribute('aria-live', 'polite');
    const show = event => {
      const box = svg.getBoundingClientRect(), px = (event.clientX - box.left) / box.width * W;
      const target = t0 + Math.max(0, Math.min(1, (px - L) / (W - L - R))) * (t1 - t0);
      const p = samples.reduce((best, s) => Math.abs(s.ts - target) < Math.abs(best.ts - target) ? s : best, samples[0]);
      for (const [k, v] of Object.entries({x1: x(p.ts), x2: x(p.ts)})) cursor.setAttribute(k, v);
      dot.setAttribute('cx', x(p.ts)); dot.setAttribute('cy', y(p.rssi)); cursor.setAttribute('visibility', 'visible'); dot.setAttribute('visibility', 'visible');
      readout.textContent = date(p.ts) + ' · ' + Math.round(p.rssi) + ' dBm' + (p.access_point ? ' · ' + p.access_point : '');
    };
    svg.addEventListener('pointermove', show); svg.addEventListener('pointerdown', show);
    svg.tabIndex = 0;
    let index = samples.length - 1;
    svg.addEventListener('keydown', event => { if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return; event.preventDefault(); index = Math.max(0, Math.min(samples.length - 1, index + (event.key === 'ArrowLeft' ? -1 : 1))); const box = svg.getBoundingClientRect(); show({clientX: box.left + x(samples[index].ts) / W * box.width}); });
    wrap.append(svg); const out = node('div'); out.append(wrap, readout); return out;
  }

  // ---------- Wi-Fi section in the device card ----------
  let wifiRequest = 0;
  window.loadDeviceWifi = async mac => {
    const section = byId('deviceWifi'), body = byId('deviceWifiBody'); if (!section) return;
    const request = ++wifiRequest; body.replaceChildren(node('p', 'muted', 'Chargement du signal…'));
    try {
      const data = await api('/api/wifi/' + encodeURIComponent(mac));
      if (request !== wifiRequest) return;
      section.hidden = !data.history.length && data.link !== 'Wi-Fi';
      body.replaceChildren();
      const rssi = data.latest ? data.latest.rssi : null;
      const top = node('div', 'sn-wifi-top'); top.dataset.status = signalTone(rssi);
      const value = node('div', 'sn-wifi-value'); value.append(bars(rssi), node('strong', '', rssi === null ? '—' : Math.round(rssi) + ' dBm'), node('span', 'sn-badge', data.quality));
      top.append(value);
      const facts = node('dl', 'sn-facts');
      const fact = (label, text) => { const d = node('div'); d.append(node('dt', '', label), node('dd', '', text)); facts.append(d); };
      if (data.latest) { fact('Dernière mesure', ago(data.latest.ts)); fact('Connexion', data.connection || 'Non communiquée'); if (data.latest.access_point) fact('Point d’accès', data.latest.access_point); }
      if (data.min !== null) fact('Sur 24 h', 'de ' + Math.round(data.min) + ' à ' + Math.round(data.max) + ' dBm');
      if (data.roaming) fact('Itinérance', 'A changé de point d’accès');
      top.append(facts); body.append(top, node('p', 'sn-advice', data.advice));
      if (data.history.length) body.append(wifiChart(data.history, data.threshold));
      if (pendingFocus === mac) { pendingFocus = null; section.scrollIntoView({block: 'start', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'}); }
    } catch (error) { if (request === wifiRequest) body.replaceChildren(node('p', 'muted', error.message)); }
  };

  // ---------- Wi-Fi page ----------
  async function setupWifiPage() {
    const list = byId('wifiList'), summary = byId('wifiSummary'), weakOnly = byId('wifiWeakOnly'), stale = byId('wifiShowStale');
    let data = null;
    const render = () => {
      if (!data) return;
      const fresh = data.devices.filter(d => d.fresh), weak = fresh.filter(d => d.rssi !== null && d.rssi <= data.threshold);
      summary.replaceChildren();
      const stat = (label, value, tone) => { const a = node('article', 'sn-stat'); if (tone) a.dataset.status = tone; a.append(node('span', '', label), node('strong', '', String(value))); summary.append(a); };
      stat('Mesurés ces 15 min', fresh.length); stat('Signal faible', weak.length, weak.length ? 'warning' : 'ok'); stat('Bon ou excellent', fresh.filter(d => d.rssi !== null && d.rssi >= -67).length, 'ok');
      const shown = data.devices.filter(d => (stale.checked || d.fresh) && (!weakOnly.checked || (d.rssi !== null && d.rssi <= data.threshold)));
      list.replaceChildren();
      if (!shown.length) { const li = node('li', 'sn-empty', weakOnly.checked ? 'Aucun signal faible en ce moment. Bonne nouvelle !' : 'Aucune mesure Wi-Fi récente. La Livebox ne communique peut-être pas le signal, ou aucun appareil sans fil n’est en ligne.'); list.append(li); return; }
      for (const device of shown) {
        const li = node('li'), button = node('button', 'sn-wifi-row'); button.type = 'button'; button.dataset.status = device.fresh ? signalTone(device.rssi) : 'unknown';
        const symbol = typeof categorySymbol === 'function' ? categorySymbol(device.category) : node('span');
        const identity = node('span', 'sn-wifi-identity'); identity.append(node('strong', '', device.name), node('small', '', [device.location, device.ip, device.fresh ? ago(device.ts) : 'hors ligne · dernière mesure ' + ago(device.ts)].filter(Boolean).join(' · ')));
        const reading = node('span', 'sn-wifi-reading'); reading.append(bars(device.rssi), node('strong', '', device.rssi === null ? '—' : Math.round(device.rssi) + ' dBm'), node('small', '', device.quality));
        const meter = node('span', 'sn-meter'); const fill = node('i'); fill.style.width = device.rssi === null ? '0%' : Math.max(2, Math.min(100, (device.rssi + 100) / 70 * 100)) + '%'; meter.append(fill); meter.setAttribute('aria-hidden', 'true');
        button.append(symbol, identity, reading, meter, node('span', 'sn-chevron', '›'));
        button.setAttribute('aria-label', device.name + ' : ' + (device.rssi === null ? 'signal non communiqué' : Math.round(device.rssi) + ' dBm, ' + device.quality.toLowerCase()) + '. Ouvrir la fiche.');
        button.addEventListener('click', () => openDevice(device.mac, 'wifi'));
        li.append(button); list.append(li);
      }
    };
    const load = async () => { try { data = await api('/api/wifi'); byId('wifiNote').textContent = data.note + ' Faible : au niveau ou sous ' + data.threshold + ' dBm.'; render(); } catch (error) { if (!data) summary.replaceChildren(node('p', 'muted', error.message)); } };
    try { weakOnly.checked = new URLSearchParams(location.search).get('weak') === '1'; } catch (_) {}
    weakOnly.addEventListener('change', render); stale.addEventListener('change', render);
    await load(); setInterval(() => { if (!document.hidden) load(); }, 60000);
  }

  // ---------- Network page: connection journal ----------
  // Grouped by day (or by device), paged by 20, 50 or 100, with how long each device stayed.
  async function setupJournal() {
    const list = byId('journalList'), status = byId('journalStatus'), summary = byId('journalSummary');
    const search = byId('journalSearch'), period = byId('journalPeriod'), kind = byId('journalConnection'), type = byId('journalType'), order = byId('journalSort'), size = byId('journalPageSize');
    const pages = byId('journalPages'), range = byId('journalRange');
    const store = {get: k => { try { return localStorage.getItem(k); } catch (_) { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch (_) {} }};
    let events = [], truncated = false, page = 1;
    try {
      const saved = JSON.parse(store.get('sentinel-journal') || '{}');
      if (saved.period && [...period.options].some(o => o.value === saved.period)) period.value = saved.period;
      if (saved.order && [...order.options].some(o => o.value === saved.order)) order.value = saved.order;
      if (saved.size && [...size.options].some(o => o.value === String(saved.size))) size.value = String(saved.size);
    } catch (_) {}
    const remember = () => store.set('sentinel-journal', JSON.stringify({period: period.value, order: order.value, size: Number(size.value)}));
    const duration = seconds => { const m = Math.round(seconds / 60); if (m < 1) return 'moins d’une minute'; if (m < 60) return m + ' min'; const h = Math.floor(m / 60), r = m % 60; if (h < 48) return h + ' h' + (r ? ' ' + String(r).padStart(2, '0') : ''); return Math.round(h / 24) + ' jours'; };
    const dayLabel = ts => { const d = new Date(ts * 1000), today = new Date(); const start = x => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime(); const diff = Math.round((start(today) - start(d)) / 86400000); if (diff === 0) return 'Aujourd’hui'; if (diff === 1) return 'Hier'; const text = d.toLocaleDateString('fr-FR', {weekday: 'long', day: 'numeric', month: 'long', year: d.getFullYear() === today.getFullYear() ? undefined : 'numeric'}); return text.charAt(0).toUpperCase() + text.slice(1); };
    const linkTone = label => /ethernet/i.test(label) ? 'eth' : /2,4/.test(label) ? 'w24' : /6 ghz/i.test(label) ? 'w6' : /wi-fi/i.test(label) ? 'w5' : 'other';
    // What happened just before, for the same device: how long it was online or away.
    const annotate = () => {
      const byDevice = new Map();
      for (const e of [...events].sort((a, b) => a.ts - b.ts)) { const previous = byDevice.get(e.mac); e.after = previous && previous.event_type !== e.event_type ? e.ts - previous.ts : null; byDevice.set(e.mac, e); }
    };
    const filtered = () => {
      const query = search.value.trim().toLowerCase();
      const visible = events.filter(e => (!kind.value || e.connection === kind.value) && (!type.value || e.event_type === type.value) && (!query || [e.name, e.mac, e.ip].some(v => String(v || '').toLowerCase().includes(query))));
      if (order.value === 'oldest') visible.sort((a, b) => a.ts - b.ts);
      else if (order.value === 'device') visible.sort((a, b) => String(a.name || a.mac).localeCompare(String(b.name || b.mac), 'fr', {sensitivity: 'base'}) || b.ts - a.ts);
      else visible.sort((a, b) => b.ts - a.ts);
      return visible;
    };
    const row = e => {
      const item = node('li', 'journal-item'); item.dataset.event = e.event_type;
      const time = node('time', 'journal-time', new Date(e.ts * 1000).toLocaleTimeString('fr-FR', {hour: '2-digit', minute: '2-digit'})); time.dateTime = new Date(e.ts * 1000).toISOString();
      if (order.value === 'device') time.textContent = new Date(e.ts * 1000).toLocaleString('fr-FR', {day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit'});
      const mark = node('span', 'journal-mark'); mark.dataset.status = e.event_type === 'connected' ? 'ok' : 'unknown'; mark.setAttribute('aria-hidden', 'true'); mark.textContent = e.event_type === 'connected' ? '↗' : '↘';
      const link = node('a', 'journal-device'); link.href = '/?device=' + encodeURIComponent(e.mac);
      if (typeof categorySymbol === 'function') link.append(categorySymbol(e.category || e.device_type));
      const text = node('span', 'journal-text');
      const title = node('span', 'journal-title'); title.append(node('strong', '', e.name || e.mac), node('span', 'journal-verb', e.event_type === 'connected' ? 's’est connecté' : 's’est déconnecté'));
      const detail = [e.ip, e.after ? (e.event_type === 'connected' ? 'après ' + duration(e.after) + ' d’absence' : 'après ' + duration(e.after) + ' en ligne') : ''].filter(Boolean).join(' · ');
      text.append(title, node('small', '', detail || '—')); link.append(text);
      const via = node('span', 'journal-link', e.connection || 'Liaison inconnue'); via.dataset.link = linkTone(e.connection || '');
      item.append(time, mark, link, via);
      return item;
    };
    const render = () => {
      const visible = filtered(), perPage = Number(size.value) || 20, count = Math.max(1, Math.ceil(visible.length / perPage));
      page = Math.min(Math.max(1, page), count);
      const slice = visible.slice((page - 1) * perPage, page * perPage);
      list.replaceChildren();
      if (!slice.length) list.append(node('p', 'journal-empty', events.length ? 'Aucun événement ne correspond à ces filtres.' : 'Aucune connexion ni déconnexion sur cette période.'));
      let group = null, current = '';
      for (const e of slice) {
        const key = order.value === 'device' ? (e.name || e.mac) : dayLabel(e.ts);
        if (key !== current) { current = key; const section = node('section', 'journal-group'); section.append(node('h3', '', key)); group = node('ol'); section.append(group); list.append(section); }
        group.append(row(e));
      }
      // Pages: first, last and the neighbours of the current one.
      pages.replaceChildren();
      const button = (label, target, extra) => { const b = node('button', 'journal-page' + (extra ? ' ' + extra : ''), label); b.type = 'button'; b.disabled = target === page || target < 1 || target > count; if (target === page && !extra) b.setAttribute('aria-current', 'page'); b.setAttribute('aria-label', extra ? label : 'Page ' + target); b.addEventListener('click', () => { page = target; render(); byId('journal').scrollIntoView({block: 'start', behavior: 'smooth'}); }); return b; };
      if (count > 1) {
        pages.append(button('‹ Précédent', page - 1, 'is-step'));
        const shown = [...new Set([1, page - 1, page, page + 1, count])].filter(n => n >= 1 && n <= count).sort((a, b) => a - b);
        shown.forEach((n, i) => { if (i && n - shown[i - 1] > 1) pages.append(node('span', 'journal-gap', '…')); pages.append(button(String(n), n)); });
        pages.append(button('Suivant ›', page + 1, 'is-step'));
      }
      range.textContent = visible.length ? ((page - 1) * perPage + 1) + '–' + Math.min(page * perPage, visible.length) + ' sur ' + visible.length.toLocaleString('fr-FR') : '';
      const connections = events.filter(e => e.event_type === 'connected').length;
      summary.replaceChildren();
      for (const [value, label, tone] of [[events.length, 'événements', ''], [connections, 'connexions', 'ok'], [events.length - connections, 'déconnexions', 'unknown'], [new Set(events.map(e => e.mac)).size, 'appareils concernés', 'info']]) {
        const box = node('div', 'journal-stat'); if (tone) box.dataset.status = tone; box.append(node('strong', '', value.toLocaleString('fr-FR')), node('span', '', label)); summary.append(box);
      }
      status.textContent = (truncated ? 'Les 2 000 plus récents de la période · ' : '') + 'actualisé toutes les 30 s';
    };
    const load = async () => {
      try {
        const data = await api('/api/device-events?' + new URLSearchParams({period: period.value, limit: 2000}));
        events = data.events; truncated = data.truncated; annotate();
        const labels = [...new Set(events.map(e => e.connection))].sort((a, b) => a.localeCompare(b, 'fr'));
        const current = [...kind.options].slice(1).map(o => o.value);
        // Rebuilding a native menu while it is open breaks Safari: only rebuild when the choices change.
        if (JSON.stringify(current) !== JSON.stringify(labels) && document.activeElement !== kind) { const value = kind.value; kind.replaceChildren(new Option('Toutes', ''), ...labels.map(l => new Option(l, l))); kind.value = labels.includes(value) ? value : ''; }
        render();
      } catch (error) { status.textContent = 'Historique momentanément indisponible. Nouvel essai dans 30 s.'; }
    };
    search.addEventListener('input', () => { page = 1; render(); });
    for (const select of [kind, type]) select.addEventListener('change', () => { page = 1; render(); });
    order.addEventListener('change', () => { page = 1; remember(); render(); });
    size.addEventListener('change', () => { page = 1; remember(); render(); });
    period.addEventListener('change', () => { page = 1; remember(); load(); });
    await load();
    setInterval(() => { if (!document.hidden) load(); }, 30000);
  }

  // ---------- Confirmation dialog ----------
  function confirmDialog(title, content, confirmText, action) {
    const dialog = node('dialog', 'sn-dialog'), form = node('form'); form.method = 'dialog';
    const error = node('p', 'sn-dialog-error'); error.setAttribute('role', 'alert'); error.hidden = true;
    const actions = node('div', 'sn-dialog-actions'), cancel = node('button', '', 'Annuler'), confirm = node('button', 'sn-primary', confirmText);
    cancel.type = 'button'; cancel.value = 'cancel'; confirm.type = 'submit';
    actions.append(cancel, confirm); form.append(node('h2', '', title), content, error, actions); dialog.append(form); document.body.append(dialog);
    const close = () => { dialog.close(); dialog.remove(); };
    cancel.addEventListener('click', close); dialog.addEventListener('cancel', event => { if (confirm.disabled) event.preventDefault(); else setTimeout(() => dialog.remove()); });
    form.addEventListener('submit', async event => { event.preventDefault(); confirm.disabled = cancel.disabled = true; try { await action(); close(); } catch (e) { error.textContent = e.message; error.hidden = false; confirm.disabled = cancel.disabled = false; } });
    dialog.showModal(); confirm.focus();
  }

  // ---------- Settings: Livebox connection ----------
  async function setupLivebox() {
    const form = byId('liveboxForm'), message = byId('liveboxMessage'), reset = byId('liveboxReset');
    let dirty = false; form.addEventListener('input', () => { dirty = true; });
    const load = async () => {
      const data = await api('/api/livebox-connection');
      if (!dirty) { form.elements.url.value = data.url; form.elements.username.value = data.username; form.elements.password.value = ''; }
      byId('liveboxSource').textContent = (data.source === 'application' ? 'Paramètres enregistrés dans Sentinel (chiffrés). Ils priment sur le fichier .env.' : 'Paramètres lus dans le fichier .env.') + (data.password_set ? ' Un mot de passe est enregistré.' : ' Aucun mot de passe enregistré.');
      reset.hidden = data.source !== 'application';
    };
    form.addEventListener('submit', async event => {
      event.preventDefault(); if (!form.reportValidity()) return;
      const button = byId('liveboxTest'); button.disabled = true; say(message, 'Test en lecture seule auprès de la Livebox…');
      try {
        const result = await api('/api/livebox-connection/test', {json: {url: form.elements.url.value, username: form.elements.username.value, password: form.elements.password.value}});
        form.elements.password.value = ''; say(message, '');
        const content = node('div'); content.append(node('p', '', result.message));
        const box = node('dl', 'sn-facts'); for (const [k, v] of [['Modèle', result.model], ['Équipements vus', String(result.devices)], ['Adresse', form.elements.url.value]]) { const d = node('div'); d.append(node('dt', '', k), node('dd', '', v)); box.append(d); }
        content.append(box, node('p', 'field-hint', 'Cet aperçu expire dans deux minutes.'));
        confirmDialog('Utiliser cette connexion ?', content, 'Enregistrer', async () => { const saved = await api('/api/livebox-connection/confirm', {json: {token: result.token}}); dirty = false; await load(); say(message, saved.message); });
      } catch (error) { say(message, error.message, true); } finally { button.disabled = false; }
    });
    reset.addEventListener('click', () => confirmDialog('Revenir au fichier .env ?', node('p', '', 'Les paramètres enregistrés dans Sentinel seront supprimés. Ceux du fichier .env seront utilisés au prochain relevé.'), 'Revenir au .env', async () => { const done = await api('/api/livebox-connection', {method: 'DELETE'}); dirty = false; await load(); say(message, done.message); }));
    try { await load(); } catch (error) { say(message, error.message, true); }
  }

  // ---------- Data: retention and journal ----------
  const retentionLabels = {wifi_samples: 'Mesures de signal Wi-Fi', traffic: 'Débits détaillés des équipements', traffic_15m: 'Débits agrégés par quart d’heure', wan_traffic: 'Compteurs de la connexion Internet', livebox_health: 'Relevés de santé de la Livebox', internet_checks: 'Sondes de connectivité', internet_events: 'Incidents Internet terminés', device_incidents: 'Absences d’équipements terminées', notifications: 'Anciennes notifications', activity_log: 'Journal des actions', device_presence_events: 'Arrivées et départs d’équipements'};
  const auditLabels = {'connection.updated': 'Connexion Livebox enregistrée', 'connection.removed': 'Retour aux paramètres .env', 'account.password': 'Mot de passe modifié', 'account.totp-enabled': 'Validation en deux étapes activée', 'account.totp-disabled': 'Validation en deux étapes désactivée', 'retention.applied': 'Durées de conservation modifiées'};
  function auditLabel(action) { if (auditLabels[action]) return auditLabels[action]; if (action.endsWith('/acknowledge')) return action.startsWith('delete.') ? 'Équipement de nouveau signalé comme nouveau' : 'Nouvel équipement reconnu'; if (action.includes('/profile')) return 'Fiche d’équipement modifiée'; if (action.includes('/watch')) return 'Surveillance d’un équipement modifiée'; if (action.includes('/account/')) return 'Compte modifié'; if (action.includes('/auth/logout')) return 'Déconnexion'; if (action.includes('/backups')) return 'Sauvegardes'; if (action.includes('/settings')) return 'Paramètres modifiés'; if (action.startsWith('delete./api/devices/')) return 'Équipement supprimé'; return 'Ancienne fonction (version précédente)'; }
  async function setupData() {
    const form = byId('retentionForm'), message = byId('retentionMessage');
    let dirty = false; form.addEventListener('input', () => { dirty = true; });
    const load = async () => {
      const [data, audit] = await Promise.all([api('/api/retention'), api('/api/audit')]);
      if (!dirty) for (const key of ['raw_days', 'aggregate_days', 'events_days']) form.elements[key].value = data.settings[key];
      const g = data.growth; byId('storageSummary').textContent = 'Base SQLite : ' + size(data.storage.storage_bytes) + ' (hors sauvegardes). ' + (g.bytes_per_day === null ? g.note : (g.bytes_per_day >= 0 ? '+' : '−') + size(Math.abs(g.bytes_per_day)) + ' par jour, environ ' + size(g.projection_30d) + ' dans 30 jours. ' + g.note);
      const list = byId('auditList'); list.replaceChildren();
      if (!audit.length) list.append(node('li', 'muted', 'Aucune action enregistrée.'));
      for (const entry of audit) { const li = node('li'); const t = node('time', '', date(entry.ts)); t.dateTime = new Date(entry.ts * 1000).toISOString(); li.append(node('strong', '', auditLabel(entry.action)), t); list.append(li); }
    };
    form.addEventListener('submit', async event => {
      event.preventDefault(); if (!form.reportValidity()) return;
      const payload = Object.fromEntries(['raw_days', 'aggregate_days', 'events_days'].map(k => [k, Number(form.elements[k].value)]));
      try {
        const preview = await api('/api/retention/preview', {json: payload}); say(message, '');
        const entries = Object.entries(preview.eligible_rows).filter(([, n]) => n), total = entries.reduce((s, [, n]) => s + n, 0);
        const content = node('div'); content.append(node('p', 'sn-strong', total ? total.toLocaleString('fr-FR') + ' élément(s) seront supprimés définitivement.' : 'Aucune donnée ne sera supprimée avec ces durées.'));
        const ul = node('ul', 'sn-plain'); for (const [table, n] of entries) { const li = node('li'); li.append(node('span', '', retentionLabels[table] || 'Autres données'), node('strong', '', n.toLocaleString('fr-FR'))); ul.append(li); } if (entries.length) content.append(ul);
        content.append(node('p', 'field-hint', 'Les sauvegardes ne sont pas concernées. Cet aperçu expire dans deux minutes.'));
        confirmDialog('Appliquer ces durées ?', content, total ? 'Supprimer et appliquer' : 'Appliquer', async () => { const done = await api('/api/retention/confirm', {json: {token: preview.token}}); dirty = false; await load(); say(message, done.message); });
      } catch (error) { say(message, error.message, true); }
    });
    try { await load(); } catch (error) { say(message, error.message, true); }
  }

  // ---------- Account: second factor ----------
  async function setupTotp() {
    const status = byId('totpStatus'), message = byId('totpMessage'), forms = {setup: byId('totpSetup'), confirm: byId('totpConfirm'), disable: byId('totpDisable')};
    const show = name => { for (const [key, form] of Object.entries(forms)) form.hidden = key !== name; };
    const load = async () => { const state = await api('/api/totp'); status.textContent = state.enabled ? 'Activée : un code vous est demandé à chaque connexion.' : 'Désactivée : seul le mot de passe protège votre compte.'; status.dataset.state = state.enabled ? 'on' : 'off'; byId('totpSecret').textContent = ''; show(state.enabled ? 'disable' : 'setup'); };
    const submit = (form, handler) => form.addEventListener('submit', async event => { event.preventDefault(); const button = form.querySelector('button'); button.disabled = true; try { await handler(Object.fromEntries(new FormData(form))); form.reset(); } catch (error) { say(message, error.message, true); } finally { button.disabled = false; } });
    submit(forms.setup, async data => { const result = await api('/api/totp/setup', {json: data}); byId('totpSecret').textContent = result.secret.replace(/(.{4})/g, '$1 ').trim(); show('confirm'); say(message, 'Saisissez le code affiché par votre application pour terminer.'); byId('totpCode').focus(); });
    submit(forms.confirm, async data => { await api('/api/totp/confirm', {json: data}); await load(); say(message, 'Validation en deux étapes activée. Vos autres appareils ont été déconnectés.'); });
    submit(forms.disable, async data => { await api('/api/totp/disable', {json: data}); await load(); say(message, 'Validation en deux étapes désactivée.'); });
    try { await load(); } catch (error) { say(message, error.message, true); }
  }

  // ---------- Dashboard deep link: /?device=mac&focus=wifi ----------
  async function openRequestedDevice() {
    const params = new URLSearchParams(location.search), mac = (params.get('device') || '').toLowerCase();
    if (!/^(?:[a-f0-9]{2}:){5}[a-f0-9]{2}$/.test(mac) || typeof refresh !== 'function' || typeof selectDevice !== 'function') return;
    await refresh();
    if (params.get('focus') === 'wifi') pendingFocus = mac;
    selectDevice(mac);
    history.replaceState(null, '', '/');
  }

  async function init() {
    if (path === '/login' || path === '/offline') return;
    try { for (const key of ['sentinel-offline-summary', 'sentinel-offline-optin']) localStorage.removeItem(key); } catch (_) {}
    if (path === '/') await openRequestedDevice();
    if (path === '/wifi') await setupWifiPage();
    if (path === '/network' && byId('journalList')) await setupJournal();
    if (byId('liveboxForm')) await setupLivebox();
    if (byId('retentionForm')) await setupData();
    if (byId('totpSection')) await setupTotp();
    if ('serviceWorker' in navigator && isSecureContext) navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => init().catch(() => {}));
  else init().catch(() => {});
})();
