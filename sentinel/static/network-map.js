/* Livebox Sentinel network map.
   PC: an orbital view, the Livebox at the centre, each repeater with its own system.
   Phone: a foldable tree. Device data only ever enters the DOM through textContent. */
(() => {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';
  const byId = id => document.getElementById(id);
  const html = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = text; return n; };
  const svg = (tag, attrs, text) => { const n = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v); if (text !== undefined) n.textContent = text; return n; };
  const short = (text, max) => (text || '').length > max ? text.slice(0, max - 1) + '…' : (text || '');
  const plural = (n, word) => n + ' ' + word + (n > 1 ? 's' : '');
  const rate = bps => bps === null || bps === undefined ? '—' : bps >= 1e9 ? (bps / 1e9).toLocaleString('fr-FR', {maximumFractionDigits: 1}) + ' Gbit/s' : bps >= 1e6 ? (bps / 1e6).toLocaleString('fr-FR', {maximumFractionDigits: 1}) + ' Mbit/s' : bps >= 1e3 ? Math.round(bps / 1e3) + ' kbit/s' : Math.round(bps) + ' bit/s';
  const clock = ts => new Date(ts * 1000).toLocaleTimeString('fr-FR', {hour: '2-digit', minute: '2-digit'});
  const day = ts => new Date(ts * 1000).toLocaleDateString('fr-FR', {day: 'numeric', month: 'long', year: 'numeric'});
  const STORE = 'sentinel-topology';
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem(STORE) || '{}') || {}; } catch (_) {}
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  const state = {
    tree: null, ts: null, devices: new Map(), filter: saved.filter || 'all', hideOffline: !!saved.hideOffline,
    collapsed: new Set(saved.collapsed || []), query: '', selected: null, hovered: null,
    motion: saved.motion !== undefined ? !!saved.motion : !reduced.matches, view: null, introDone: false, layout: null,
  };
  const remember = () => { try { localStorage.setItem(STORE, JSON.stringify({collapsed: [...state.collapsed], filter: state.filter, hideOffline: state.hideOffline, motion: state.motion})); } catch (_) {} };

  // ---------- Tree helpers ----------
  const isDevice = node => node.kind === 'device' || node.kind === 'repeater';
  function walk(node, visit) { visit(node); (node.children || []).forEach(child => walk(child, visit)); }
  function prepare(node, parent, id) {
    node.id = id; node.parent = parent;
    node.ap = !parent || parent.kind === 'unplaced' ? null : parent.kind === 'repeater' || parent.kind === 'livebox' ? parent : parent.ap;
    node.band = node.band || ''; node.link = node.link || ''; node.port = node.port || '';
    (node.children || []).forEach((child, index) => prepare(child, node, id + '.' + index));
  }
  function attachUnplaced(root) {
    const placed = new Set(); walk(root, node => { if (node.mac) placed.add(node.mac); });
    const missing = [...state.devices.values()].filter(d => !placed.has(d.mac));
    if (missing.length) root.children.push({kind: 'unplaced', label: 'Raccordement inconnu', children: missing.map(d => ({kind: 'device', mac: d.mac, label: d.name, link: '', band: '', port: '', children: []}))});
  }
  function info(node) {
    if (node.kind === 'livebox') return {name: 'Livebox', category: 'Réseau', active: true, known: false};
    const d = state.devices.get(node.mac) || {};
    return {name: d.name || node.label, category: d.category || (node.kind === 'repeater' ? 'Réseau' : ''), location: d.location || '', active: !!d.active, ip: d.ip || '', known: !!d.mac,
      vendor: d.recognition ? d.recognition.vendor : '', model: d.recognition ? d.recognition.model : '', rx: d.rx_bps, tx: d.tx_bps, firstSeen: d.first_seen_at, isNew: !!d.is_new};
  }
  const devicesOf = ap => { const list = []; walk(ap, n => { if (n !== ap && isDevice(n) && n.ap === ap) list.push(n); }); return list; };
  const linkKey = node => node.link === 'ethernet' ? 'eth' : node.link === 'wifi' ? (node.band.startsWith('2,4') ? 'w24' : node.band.startsWith('6') ? 'w6' : 'w5') : 'other';
  const LINK_LABEL = {eth: 'Ethernet', w24: 'Wi-Fi 2,4 GHz', w5: 'Wi-Fi 5 GHz', w6: 'Wi-Fi 6 GHz', other: 'Liaison non précisée'};
  function linkLabel(node) { const key = linkKey(node); return key === 'eth' ? 'Ethernet · ' + (node.port || 'port') : LINK_LABEL[key]; }
  function apName(ap) { return !ap || ap.kind === 'livebox' ? 'Livebox' : info(ap).name; }
  function matchesFilter(node) {
    const f = state.filter;
    if (f === 'all') return true;
    if (f === 'ap:livebox') return node.ap && node.ap.kind === 'livebox';
    if (f.startsWith('ap:')) return node.ap && node.ap.mac === f.slice(3);
    return linkKey(node) === f;
  }
  function matchesQuery(node) {
    if (!state.query || !isDevice(node)) return false;
    const i = info(node);
    return [i.name, i.ip, node.mac, i.category, i.location, i.vendor, i.model].join(' ').toLowerCase().includes(state.query);
  }

  // ---------- Filters (shared by both views) ----------
  function drawFilters() {
    const box = byId('topoFilters'); box.replaceChildren();
    const count = test => { let n = 0; walk(state.tree, node => { if (isDevice(node) && test(node)) n++; }); return n; };
    const chips = [['all', 'Tous', count(() => true)], ['ap:livebox', 'Sur la Livebox', count(n => n.ap && n.ap.kind === 'livebox')]];
    walk(state.tree, node => { if (node.kind === 'repeater') chips.push(['ap:' + node.mac, 'Via ' + info(node).name, count(n => n.ap === node)]); });
    for (const key of ['eth', 'w24', 'w5', 'w6']) chips.push([key, LINK_LABEL[key], count(n => linkKey(n) === key)]);
    if (!chips.some(([key]) => key === state.filter)) state.filter = 'all';
    for (const [key, label, n] of chips) {
      if (!n && key !== 'all') continue;
      const chip = html('button', 'topo-chip'); chip.type = 'button'; chip.dataset.key = key; chip.setAttribute('aria-pressed', String(state.filter === key));
      if (key.startsWith('w') || key === 'eth') chip.dataset.link = key;
      chip.append(document.createTextNode(label + ' '), html('span', 'topo-chip-count', String(n)));
      chip.addEventListener('click', () => { state.filter = key; remember(); render(); });
      box.append(chip);
    }
  }

  // ---------- Orbital map (PC) ----------
  const RINGS = {livebox: {eth: 150, w5: 250, w24: 360, w6: 250, other: 450}, repeater: {eth: 95, w5: 150, w24: 235, w6: 150, other: 300}};
  const RING_ORDER = ['eth', 'w5', 'w6', 'w24', 'other'];
  const GAP = 64, LIVEBOX_R = 58, REPEATER_R = 40, NODE_R = 21;

  // Places devices on rings by link type, leaving room towards the repeaters.
  function placeSystem(center, nodes, radii, avoid, gapAngle) {
    const rings = {};
    for (const node of nodes) (rings[linkKey(node)] = rings[linkKey(node)] || []).push(node);
    const used = [];
    let outer = 0, ringIndex = 0;
    for (const key of RING_ORDER) {
      const list = rings[key]; if (!list) continue;
      // The same link type stays together; similar devices sit side by side.
      list.sort((a, b) => (info(a).category || 'zz').localeCompare(info(b).category || 'zz', 'fr') || info(a).name.localeCompare(info(b).name, 'fr'));
      let r = radii[key];
      const arc = Math.PI * 2 - (avoid.length ? avoid.length * gapAngle : 0);
      const capacity = Math.max(1, Math.floor(arc * r / GAP));
      const zigzag = list.length > capacity;
      if (zigzag) r = Math.max(r, (list.length / 2) * GAP / arc);
      const start = avoid.length ? avoid[0] + gapAngle / 2 : -Math.PI / 2;
      // Free arcs between the directions to avoid.
      const free = avoid.length ? splitArcs(avoid, gapAngle) : [[start, start + Math.PI * 2]];
      const total = free.reduce((s, [a, b]) => s + b - a, 0);
      // Consecutive rings are offset by half a step so labels do not stack radially.
      const shift = ringIndex++ % 2 ? 0.5 : 0;
      list.forEach((node, i) => {
        let offset = ((i + 0.5 + shift) / list.length % 1) * total, angle = free[0][0];
        for (const [a, b] of free) { if (offset <= b - a) { angle = a + offset; break; } offset -= b - a; }
        const radius = r + (zigzag && i % 2 ? 50 : 0);
        node.x = center.x + Math.cos(angle) * radius; node.y = center.y + Math.sin(angle) * radius; node.angle = angle; node.home = center;
        outer = Math.max(outer, radius);
      });
      used.push({key, r, zig: zigzag, labelAngle: avoid.length ? avoid[0] + gapAngle * 0.3 : -Math.PI / 2});
    }
    return {rings: used, outer};
  }
  function splitArcs(avoid, gap) {
    const sorted = [...avoid].sort((a, b) => a - b), arcs = [];
    for (let i = 0; i < sorted.length; i++) {
      const from = sorted[i] + gap / 2, to = (i + 1 < sorted.length ? sorted[i + 1] : sorted[0] + Math.PI * 2) - gap / 2;
      if (to > from) arcs.push([from, to]);
    }
    return arcs;
  }
  function layoutOrbit() {
    const root = state.tree, keep = node => !(state.hideOffline && !info(node).active);
    const repeaters = devicesOf(root).filter(n => n.kind === 'repeater');
    const direct = [];
    walk(root, n => { if (isDevice(n) && n.kind !== 'repeater' && (n.ap === root || n.ap === null) && keep(n)) direct.push(n); });
    const repAngles = repeaters.map((_, k) => (k - (repeaters.length - 1) / 2) * (Math.PI / 2.6));
    root.x = 0; root.y = 0;
    const main = placeSystem(root, direct, RINGS.livebox, repAngles, Math.PI / 3.2);
    const systems = [{ap: root, rings: main.rings, r: LIVEBOX_R}];
    repeaters.forEach((rep, k) => {
      const own = devicesOf(rep).filter(keep);
      const probe = placeSystem({x: 0, y: 0}, own, RINGS.repeater, [Math.PI + repAngles[k]], Math.PI / 2.4);
      const distance = main.outer + probe.outer + 150;
      rep.x = Math.cos(repAngles[k]) * distance; rep.y = Math.sin(repAngles[k]) * distance; rep.angle = repAngles[k]; rep.home = root;
      const placed = placeSystem(rep, own, RINGS.repeater, [Math.PI + repAngles[k]], Math.PI / 2.4);
      systems.push({ap: rep, rings: placed.rings, r: REPEATER_R});
    });
    const shown = [];
    walk(root, n => { if (isDevice(n) && n.kind !== 'repeater' && keep(n) && n.x !== undefined && (n.ap === root || n.ap === null || repeaters.includes(n.ap))) shown.push(n); });
    let minX = -120, maxX = 120, minY = -120, maxY = 120;
    for (const n of [...shown, ...repeaters]) { minX = Math.min(minX, n.x - 150); maxX = Math.max(maxX, n.x + 150); minY = Math.min(minY, n.y - 70); maxY = Math.max(maxY, n.y + 70); }
    return {systems, shown, repeaters, bounds: {x: minX, y: minY, w: maxX - minX, h: maxY - minY}};
  }

  const ICONS = {
    livebox: '<rect x="2.5" y="8" width="19" height="9" rx="3"/><path d="M6.5 12.5h.01M10 12.5h.01M14 12.5h4"/><path d="M8.5 5a5 5 0 0 1 7 0M6 2.6a8.5 8.5 0 0 1 12 0"/>',
    repeater: '<path d="M12 21V11"/><circle cx="12" cy="9" r="2"/><path d="M8.5 5.5a5 5 0 0 0 0 7M15.5 5.5a5 5 0 0 1 0 7M5.8 3a9 9 0 0 0 0 12M18.2 3a9 9 0 0 1 0 12"/><path d="M8 21h8"/>',
    internet: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  };
  function staticIcon(name, size) {
    const icon = svg('svg', {viewBox: '0 0 24 24', width: size, height: size, x: -size / 2, y: -size / 2, fill: 'none', stroke: 'currentColor', 'stroke-width': 1.5, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', class: 'o-icon'});
    icon.innerHTML = ICONS[name]; // Static markup only.
    return icon;
  }
  function categoryIcon(label, size) {
    const span = typeof categorySymbol === 'function' ? categorySymbol(label) : null;
    const icon = span && span.querySelector('svg');
    if (!icon) return staticIcon('internet', size);
    for (const [k, v] of Object.entries({width: size, height: size, x: -size / 2, y: -size / 2, class: 'o-icon'})) icon.setAttribute(k, v);
    return icon;
  }
  function curve(from, to, bend) {
    const mx = (from.x + to.x) / 2, my = (from.y + to.y) / 2, dx = to.x - from.x, dy = to.y - from.y;
    return 'M' + from.x.toFixed(1) + ' ' + from.y.toFixed(1) + ' Q' + (mx - dy * bend).toFixed(1) + ' ' + (my + dx * bend).toFixed(1) + ' ' + to.x.toFixed(1) + ' ' + to.y.toFixed(1);
  }
  function particles(group, pathId, node, d) {
    if (!state.motion || !d.active) return;
    const flows = [['down', d.rx, 'o-packet'], ['up', d.tx, 'o-packet o-packet-up']];
    for (const [direction, bps, cls] of flows) {
      if (!bps || bps < 2000) continue;
      const level = Math.min(1, Math.log10(bps / 2000) / 4); // 2 kbit/s … 20 Mbit/s and more
      const count = 1 + Math.round(level * 2), duration = (3.6 - level * 2.4).toFixed(2);
      for (let i = 0; i < count; i++) {
        const dot = svg('circle', {r: direction === 'down' ? 2.6 : 1.9, class: cls});
        const motion = svg('animateMotion', {dur: duration + 's', repeatCount: 'indefinite', begin: (-i * duration / count).toFixed(2) + 's', rotate: 'auto'});
        if (direction === 'up') { motion.setAttribute('keyPoints', '1;0'); motion.setAttribute('keyTimes', '0;1'); motion.setAttribute('calcMode', 'linear'); }
        const ref = svg('mpath', {href: '#' + pathId}); ref.setAttributeNS('http://www.w3.org/1999/xlink', 'xlink:href', '#' + pathId);
        motion.append(ref); dot.append(motion); group.append(dot);
      }
    }
  }

  function drawOrbit() {
    const map = byId('orbitMap'); if (!map || !state.tree) return;
    const layout = state.layout = layoutOrbit();
    map.replaceChildren();
    const defs = svg('defs');
    defs.innerHTML = // Static gradients and filters only.
      '<radialGradient id="oCore" cx="50%" cy="40%" r="65%"><stop offset="0" stop-color="#7fe7ff"/><stop offset=".45" stop-color="#1f7fd8"/><stop offset="1" stop-color="#0a1f4a"/></radialGradient>' +
      '<radialGradient id="oCoreRep" cx="50%" cy="40%" r="65%"><stop offset="0" stop-color="#e2c6ff"/><stop offset=".5" stop-color="#7b4fe0"/><stop offset="1" stop-color="#1d1145"/></radialGradient>' +
      '<radialGradient id="oHalo"><stop offset="0" stop-color="#46c8ff" stop-opacity=".45"/><stop offset=".6" stop-color="#46c8ff" stop-opacity=".08"/><stop offset="1" stop-color="#46c8ff" stop-opacity="0"/></radialGradient>' +
      '<radialGradient id="oHaloRep"><stop offset="0" stop-color="#a77dff" stop-opacity=".45"/><stop offset=".6" stop-color="#a77dff" stop-opacity=".08"/><stop offset="1" stop-color="#a77dff" stop-opacity="0"/></radialGradient>' +
      '<radialGradient id="oDisc" cx="35%" cy="30%" r="80%"><stop offset="0" stop-color="#2a3d63"/><stop offset="1" stop-color="#0d1730"/></radialGradient>' +
      '<linearGradient id="oBeam" x1="0" x2="1"><stop offset="0" stop-color="#46c8ff"/><stop offset="1" stop-color="#a77dff"/></linearGradient>' +
      '<filter id="oGlow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="6" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>' +
      '<filter id="oSoft" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="2.5"/></filter>';
    map.append(defs);
    const lRings = svg('g', {class: 'o-rings'}), lBeams = svg('g', {class: 'o-beams'}), lLinks = svg('g', {class: 'o-links'}), lNodes = svg('g', {class: 'o-nodes'}), lCores = svg('g', {class: 'o-cores'});
    map.append(lRings, lBeams, lLinks, lNodes, lCores);
    const intro = !state.introDone && state.motion;
    map.classList.toggle('is-intro', intro);
    map.classList.toggle('is-still', !state.motion);
    // Orbits, with their names written along the circle.
    for (const system of layout.systems) {
      const c = system.ap;
      for (const ring of system.rings) {
        const r = ring.r + (ring.zig ? 25 : 0);
        lRings.append(svg('circle', {cx: c.x, cy: c.y, r, class: 'o-orbit o-orbit-' + ring.key + (ring.zig ? ' o-orbit-wide' : '')}));
        const a = ring.labelAngle;
        lRings.append(svg('text', {x: (c.x + Math.cos(a) * r).toFixed(1), y: (c.y + Math.sin(a) * r + 3).toFixed(1), 'text-anchor': 'middle', class: 'o-orbit-label o-label-' + ring.key}, LINK_LABEL[ring.key].toUpperCase()));
      }
    }

    // Repeater backhaul: a luminous beam from the Livebox.
    for (const rep of layout.repeaters) {
      const d = info(rep), id = 'oBeam' + rep.id.replace(/[^a-z0-9]/gi, '');
      const from = {x: Math.cos(rep.angle) * (LIVEBOX_R + 6), y: Math.sin(rep.angle) * (LIVEBOX_R + 6)};
      const to = {x: rep.x - Math.cos(rep.angle) * (REPEATER_R + 6), y: rep.y - Math.sin(rep.angle) * (REPEATER_R + 6)};
      const group = svg('g', {class: 'o-beam o-' + linkKey(rep) + (d.active ? '' : ' is-off'), 'data-id': rep.id});
      const path = 'M' + from.x + ' ' + from.y + ' L' + to.x + ' ' + to.y;
      group.append(svg('path', {d: path, class: 'o-beam-glow'}), svg('path', {d: path, class: 'o-beam-core', id}), svg('path', {d: path, class: 'o-beam-flow'}));
      particles(group, id, rep, d);
      const label = svg('text', {class: 'o-beam-label', dy: -10});
      const along = svg('textPath', {href: '#' + id, startOffset: '50%', 'text-anchor': 'middle'}, 'LIAISON ' + LINK_LABEL[linkKey(rep)].toUpperCase());
      along.setAttributeNS('http://www.w3.org/1999/xlink', 'xlink:href', '#' + id);
      label.append(along); group.append(label);
      lBeams.append(group);
    }

    // Devices and their links.
    layout.shown.forEach((node, index) => {
      const d = info(node), key = linkKey(node), center = node.home || state.tree;
      const ap = node.ap || state.tree, coreR = ap.kind === 'repeater' ? REPEATER_R : LIVEBOX_R;
      const angle = Math.atan2(node.y - center.y, node.x - center.x);
      const start = {x: center.x + Math.cos(angle) * (coreR + 4), y: center.y + Math.sin(angle) * (coreR + 4)};
      const end = {x: node.x - Math.cos(angle) * (NODE_R + 3), y: node.y - Math.sin(angle) * (NODE_R + 3)};
      const id = 'oLink' + node.id.replace(/[^a-z0-9]/gi, '');
      const link = svg('g', {class: 'o-link o-' + key + (d.active ? '' : ' is-off'), 'data-id': node.id});
      const path = curve(start, end, 0.08);
      link.append(svg('path', {d: path, class: 'o-link-glow'}), svg('path', {d: path, class: 'o-link-line', id}));
      particles(link, id, node, d);
      if (intro) link.style.animationDelay = (0.25 + index * 0.025).toFixed(2) + 's';
      lLinks.append(link);

      const group = svg('g', {class: 'o-node o-' + key + (d.active ? '' : ' is-off') + (d.isNew ? ' is-new' : ''), transform: 'translate(' + node.x.toFixed(1) + ' ' + node.y.toFixed(1) + ')', tabindex: '0', role: 'button', 'data-id': node.id});
      group.setAttribute('aria-label', d.name + ', ' + (d.active ? 'en ligne' : 'hors ligne') + ', ' + linkLabel(node) + ', raccordé à ' + apName(node.ap));
      const body = svg('g', {class: 'o-body'});
      if (intro) body.style.animationDelay = (0.2 + index * 0.025).toFixed(2) + 's';
      group.append(svg('circle', {r: NODE_R + 16, class: 'o-hit'}));
      body.append(svg('circle', {r: NODE_R + 9, class: 'o-aura'}), svg('circle', {r: NODE_R, class: 'o-disc'}), svg('circle', {r: NODE_R, class: 'o-rim'}));
      body.append(categoryIcon(d.category || d.name, 20));
      body.append(svg('circle', {cx: NODE_R * 0.72, cy: -NODE_R * 0.72, r: 4.2, class: 'o-status'}));
      if (d.isNew) body.append(svg('circle', {r: NODE_R + 5, class: 'o-new-ring'}));
      group.append(body);
      // Labels sit outside the orbit, on the side the device points to.
      const cos = Math.cos(angle), sin = Math.sin(angle), lx = cos * (NODE_R + 12), ly = sin * (NODE_R + 12) + 4;
      const anchor = cos > 0.3 ? 'start' : cos < -0.3 ? 'end' : 'middle';
      const label = svg('text', {x: lx.toFixed(1), y: (anchor === 'middle' ? (sin > 0 ? NODE_R + 18 : -NODE_R - 10) : ly).toFixed(1), 'text-anchor': anchor, class: 'o-name'}, short(d.name, 22));
      group.append(label);
      bindNode(group, node);
      lNodes.append(group);
    });

    // Cores: the Livebox and each repeater.
    const core = (node, kind) => {
      const d = info(node), radius = kind === 'livebox' ? LIVEBOX_R : REPEATER_R;
      const group = svg('g', {class: 'o-core o-core-' + kind + (d.active ? '' : ' is-off'), transform: 'translate(' + node.x + ' ' + node.y + ')', tabindex: '0', role: 'button', 'data-id': node.id});
      group.append(svg('circle', {r: radius * 2.6, class: 'o-core-halo', fill: kind === 'livebox' ? 'url(#oHalo)' : 'url(#oHaloRep)'}));
      group.append(svg('circle', {r: radius + 16, class: 'o-core-spin'}), svg('circle', {r: radius + 26, class: 'o-core-spin o-core-spin-rev'}));
      group.append(svg('circle', {r: radius + 6, class: 'o-core-pulse'}));
      group.append(svg('circle', {r: radius, class: 'o-core-disc', fill: kind === 'livebox' ? 'url(#oCore)' : 'url(#oCoreRep)', filter: 'url(#oGlow)'}));
      group.append(svg('circle', {r: radius - 7, class: 'o-core-inner'}));
      group.append(staticIcon(kind === 'livebox' ? 'livebox' : 'repeater', kind === 'livebox' ? 40 : 28));
      const count = kind === 'livebox' ? layout.shown.filter(n => n.ap === node).length + layout.repeaters.length : devicesOf(node).filter(n => !(state.hideOffline && !info(n).active)).length;
      // The name sits in the free sector, beside the beam, away from the orbiting devices.
      const beam = kind === 'livebox' ? (layout.repeaters.length ? layout.repeaters[0].angle : null) : node.angle + Math.PI;
      let nx = 0, ny = radius + 44, anchor = 'middle';
      if (beam !== null && beam !== undefined) { const side = Math.cos(beam) >= 0 ? 1 : -1; nx = side * (radius + 34); ny = -30; anchor = side > 0 ? 'start' : 'end'; }
      group.append(svg('text', {x: nx, y: ny, 'text-anchor': anchor, class: 'o-core-name'}, kind === 'livebox' ? 'LIVEBOX' : short(d.name, 22).toUpperCase()));
      group.append(svg('text', {x: nx, y: ny + 16, 'text-anchor': anchor, class: 'o-core-sub'}, kind === 'livebox' ? plural(count, 'équipement') + ' en direct' : 'Répéteur · ' + plural(count, 'appareil')));
      group.setAttribute('aria-label', (kind === 'livebox' ? 'Livebox' : d.name + ', répéteur Wi-Fi') + ', ' + plural(count, 'appareil'));
      bindNode(group, node);
      lCores.append(group);
    };
    core(state.tree, 'livebox');
    layout.repeaters.forEach(rep => core(rep, 'repeater'));
    if (!state.view) fit(false); else applyView();
    if (intro) { state.introDone = true; setTimeout(() => map.classList.remove('is-intro'), 2600); }
    paintFocus();
  }

  function bindNode(group, node) {
    group.addEventListener('pointerenter', event => { if (event.pointerType !== 'mouse') return; state.hovered = node; paintFocus(); tooltip(node, event); });
    group.addEventListener('pointermove', event => { if (event.pointerType === 'mouse') tooltip(node, event); });
    group.addEventListener('pointerleave', () => { if (state.hovered === node) { state.hovered = null; paintFocus(); tooltip(null); } });
    group.addEventListener('focus', () => { state.hovered = node; paintFocus(); });
    group.addEventListener('blur', () => { if (state.hovered === node) { state.hovered = null; paintFocus(); } });
    group.addEventListener('click', event => { event.stopPropagation(); if (dragMoved) return; select(node); });
    group.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select(node); } });
  }

  // Highlights the chain from a device to the Livebox; filters and search dim the rest.
  function chain(node) { const ids = new Set(); for (let n = node; n; n = n.ap) { ids.add(n.id); if (n.kind === 'livebox') break; } if (!node.ap && node.kind !== 'livebox') ids.add(state.tree.id); return ids; }
  function paintFocus() {
    const map = byId('orbitMap'); if (!map) return;
    const focus = state.hovered || state.selected;
    const hot = focus ? chain(focus) : null;
    if (focus && focus.kind !== 'device') for (const n of devicesOf(focus)) hot.add(n.id);
    const nodes = new Map(); walk(state.tree, n => nodes.set(n.id, n));
    for (const element of map.querySelectorAll('[data-id]')) {
      const node = nodes.get(element.dataset.id); if (!node) continue;
      const filtered = isDevice(node) && node.kind !== 'repeater' && !matchesFilter(node);
      const searched = state.query && isDevice(node) && !matchesQuery(node);
      element.classList.toggle('is-out', filtered || (!!searched && node.kind !== 'repeater'));
      element.classList.toggle('is-match', matchesQuery(node));
      element.classList.toggle('is-hot', !!hot && hot.has(node.id));
      element.classList.toggle('is-selected', state.selected === node);
    }
    map.classList.toggle('is-focus', !!hot);
  }

  // ---------- Tooltip and details panel ----------
  function tooltip(node, event) {
    const tip = byId('orbitTip'), frame = byId('orbit');
    if (!node || !event) { tip.hidden = true; return; }
    const d = info(node);
    tip.replaceChildren(html('strong', '', d.name), html('span', '', node.kind === 'livebox' ? 'Point central du réseau' : [node.kind === 'repeater' ? 'Répéteur Wi-Fi' : linkLabel(node), d.ip].filter(Boolean).join(' · ')));
    if (isDevice(node) && d.active && (d.rx || d.tx)) tip.append(html('span', 'o-tip-rate', '↓ ' + rate(d.rx) + '   ↑ ' + rate(d.tx)));
    const box = frame.getBoundingClientRect();
    tip.hidden = false;
    const x = Math.min(event.clientX - box.left + 16, box.width - tip.offsetWidth - 12), y = Math.max(12, event.clientY - box.top - tip.offsetHeight - 14);
    tip.style.transform = 'translate(' + x + 'px,' + y + 'px)';
  }

  let panelController = null;
  function select(node) {
    state.selected = state.selected === node ? null : node;
    paintFocus(); showPanel();
    if (state.selected) revealBesidePanel(state.selected);
  }
  // The panel covers the right of the map: slide the camera if the selection is underneath.
  // On a narrow screen (tablet in portrait) the panel rises from the bottom instead.
  const sheetMode = () => { const box = byId('orbitMap').getBoundingClientRect(); return box.width < 1100; };
  function revealBesidePanel(node) {
    const box = byId('orbitMap').getBoundingClientRect(), v = state.view; if (!box.width) return;
    if (sheetMode()) {
      const sy = (node.y - v.y) / v.h * box.height, limit = box.height * 0.44;
      if (sy < limit - 30 && sy > 70) return;
      animateTo({...v, y: node.y - limit / 2 / box.height * v.h}, true); return;
    }
    const sx = (node.x - v.x) / v.w * box.width, limit = box.width - 400;
    if (sx < limit - 30 && sx > 40) return;
    animateTo({...v, x: node.x - (limit / 2) / box.width * v.w}, true);
  }
  function fact(list, label, value) { if (value === undefined || value === null || value === '') return; const row = html('div'); row.append(html('dt', '', label), html('dd', '', value)); list.append(row); }
  function showPanel() {
    const panel = byId('orbitPanel'), node = state.selected;
    if (panelController) panelController.abort();
    byId('orbit').classList.toggle('has-panel', !!node);
    if (!node) { panel.classList.remove('is-open'); panel.setAttribute('aria-hidden', 'true'); return; }
    panel.replaceChildren(); panel.classList.add('is-open'); panel.removeAttribute('aria-hidden');
    const d = info(node);
    const close = html('button', 'o-panel-close', '✕'); close.type = 'button'; close.setAttribute('aria-label', 'Fermer les détails');
    close.addEventListener('click', () => { state.selected = null; paintFocus(); showPanel(); });
    const head = html('div', 'o-panel-head');
    const badge = html('div', 'o-panel-icon o-' + (node.kind === 'livebox' ? 'core' : node.kind === 'repeater' ? 'rep' : linkKey(node)));
    const icon = document.createElementNS(NS, 'svg'); icon.setAttribute('viewBox', '-20 -20 40 40');
    icon.append(node.kind === 'livebox' ? staticIcon('livebox', 26) : node.kind === 'repeater' ? staticIcon('repeater', 24) : categoryIcon(d.category || d.name, 22));
    badge.append(icon);
    const titles = html('div');
    titles.append(html('p', 'o-panel-kicker', node.kind === 'livebox' ? 'CŒUR DU RÉSEAU' : node.kind === 'repeater' ? 'RÉPÉTEUR WI-FI' : (d.category || 'ÉQUIPEMENT').toUpperCase()), html('h2', '', d.name));
    if (d.location) titles.append(html('p', 'o-panel-place', d.location));
    head.append(badge, titles, close); panel.append(head);
    const status = html('div', 'o-panel-status');
    const pill = html('span', 'o-pill ' + (d.active ? 'is-on' : 'is-off'), d.active ? 'En ligne' : 'Hors ligne'); status.append(pill);
    if (d.isNew) status.append(html('span', 'o-pill is-new', 'Nouveau'));
    panel.append(status);

    if (node.kind === 'livebox') {
      const counts = html('div', 'o-panel-grid');
      const all = []; walk(state.tree, n => { if (isDevice(n)) all.push(n); });
      const stat = (value, label) => { const box = html('div', 'o-stat'); box.append(html('strong', '', String(value)), html('span', '', label)); counts.append(box); };
      stat(all.length, 'équipements'); stat(all.filter(n => info(n).active).length, 'en ligne');
      stat(devicesOf(state.tree).filter(n => n.kind !== 'repeater').length, 'en direct'); stat(all.filter(n => n.ap && n.ap.kind === 'repeater').length, 'via répéteur');
      panel.append(counts);
      const facts = html('dl', 'o-facts');
      fact(facts, 'Modèle', state.tree.model || 'Livebox');
      for (const key of ['eth', 'w5', 'w24', 'w6']) { const n = all.filter(x => linkKey(x) === key).length; if (n) fact(facts, LINK_LABEL[key], plural(n, 'appareil')); }
      const down = all.reduce((s, n) => s + (info(n).active ? info(n).rx || 0 : 0), 0), up = all.reduce((s, n) => s + (info(n).active ? info(n).tx || 0 : 0), 0);
      fact(facts, 'Trafic local estimé', '↓ ' + rate(down) + ' · ↑ ' + rate(up));
      panel.append(facts);
      const actions = html('div', 'o-panel-actions'); const health = html('a', 'o-action', 'Santé de la Livebox'); health.href = '/livebox-health'; actions.append(health); panel.append(actions);
      return;
    }
    // Route: device → repeater → Livebox.
    const route = html('div', 'o-route'); route.setAttribute('aria-label', 'Chemin jusqu’à la Livebox');
    const hops = []; for (let n = node; n; n = n.ap) { hops.push(n); if (n.kind === 'livebox') break; }
    if (hops[hops.length - 1].kind !== 'livebox') hops.push(state.tree);
    hops.forEach((hop, i) => {
      const step = html('span', 'o-hop' + (hop.kind === 'livebox' ? ' is-core' : hop.kind === 'repeater' ? ' is-rep' : ''), hop === node ? 'Cet appareil' : apName(hop));
      route.append(step);
      if (i < hops.length - 1) { const via = html('span', 'o-via o-' + linkKey(hop), linkKey(hop) === 'eth' ? (hop.port || 'Ethernet') : LINK_LABEL[linkKey(hop)]); route.append(via); }
    });
    panel.append(route);
    const facts = html('dl', 'o-facts');
    fact(facts, 'Raccordé à', apName(node.ap) + (node.ap && node.ap.kind === 'repeater' ? ' (répéteur)' : ''));
    fact(facts, 'Liaison', linkLabel(node));
    fact(facts, 'Adresse IP', d.ip || 'Non attribuée');
    fact(facts, 'Adresse MAC', node.mac);
    fact(facts, 'Fabricant', d.vendor);
    fact(facts, 'Modèle annoncé', d.model);
    if (d.firstSeen) fact(facts, 'Connu depuis le', day(d.firstSeen));
    if (node.kind === 'repeater') {
      const own = devicesOf(node);
      fact(facts, 'Appareils raccordés', plural(own.length, 'appareil') + ' · 5 GHz : ' + own.filter(n => linkKey(n) === 'w5').length + ' · 2,4 GHz : ' + own.filter(n => linkKey(n) === 'w24').length);
    }
    panel.append(facts);
    const live = html('section', 'o-live'); live.append(html('p', 'o-panel-kicker', 'TRAFIC · DERNIÈRE HEURE'));
    const now = html('div', 'o-live-now');
    const down = html('div', 'o-rate is-down'); down.append(html('span', '', 'Réception'), html('strong', '', d.active ? rate(d.rx) : '—'));
    const up = html('div', 'o-rate is-up'); up.append(html('span', '', 'Émission'), html('strong', '', d.active ? rate(d.tx) : '—'));
    now.append(down, up); live.append(now);
    const chart = html('div', 'o-spark'); chart.append(html('p', 'o-muted', 'Chargement de l’historique…')); live.append(chart);
    panel.append(live);
    const signal = html('section', 'o-signal'); if (node.link === 'wifi' && node.kind !== 'repeater') panel.append(signal);
    if (node.kind === 'repeater') {
      const list = html('ul', 'o-members');
      for (const member of devicesOf(node)) {
        const m = info(member), li = html('li'), button = html('button', 'o-member o-' + linkKey(member)); button.type = 'button';
        button.append(html('i', m.active ? 'is-on' : 'is-off'), html('span', '', m.name), html('small', '', LINK_LABEL[linkKey(member)]));
        button.addEventListener('click', () => { state.selected = null; select(member); centerOn(member); });
        li.append(button); list.append(li);
      }
      const block = html('section', 'o-members-block'); block.append(html('p', 'o-panel-kicker', 'APPAREILS DE CE RÉPÉTEUR'), list); panel.append(block);
    }
    const actions = html('div', 'o-panel-actions');
    if (d.known) { const open = html('a', 'o-action is-primary', 'Ouvrir la fiche complète'); open.href = '/?device=' + encodeURIComponent(node.mac); actions.append(open); }
    const focus = html('button', 'o-action', 'Centrer sur la carte'); focus.type = 'button'; focus.addEventListener('click', () => centerOn(node)); actions.append(focus);
    panel.append(actions);
    if (!d.known) return;
    const controller = panelController = new AbortController();
    fetch('/api/history?' + new URLSearchParams({mac: node.mac, period: '1h'}), {signal: controller.signal}).then(r => r.ok ? r.json() : Promise.reject()).then(history => {
      if (controller.signal.aborted) return; chart.replaceChildren(spark(history.points || []));
    }).catch(() => { if (!controller.signal.aborted) chart.replaceChildren(html('p', 'o-muted', 'Historique indisponible.')); });
    if (node.link === 'wifi' && node.kind !== 'repeater') {
      signal.append(html('p', 'o-panel-kicker', 'SIGNAL WI-FI'), html('p', 'o-muted', 'Lecture du signal…'));
      fetch('/api/wifi/' + encodeURIComponent(node.mac), {signal: controller.signal}).then(r => r.ok ? r.json() : Promise.reject()).then(wifi => {
        if (controller.signal.aborted) return;
        const rssi = wifi.latest ? wifi.latest.rssi : null;
        signal.replaceChildren(html('p', 'o-panel-kicker', 'SIGNAL WI-FI'));
        const meter = html('div', 'o-meter'); const level = rssi === null ? 0 : Math.max(0, Math.min(1, (rssi + 90) / 50));
        const bar = html('i'); bar.style.width = Math.round(level * 100) + '%'; meter.append(bar);
        if (rssi === null) { signal.append(html('p', 'o-muted', wifi.advice || 'La Livebox ne communique pas le niveau de signal.')); return; }
        const row = html('div', 'o-signal-row'); row.append(html('strong', '', Math.round(rssi) + ' dBm'), html('span', '', wifi.quality || ''));
        signal.append(row, meter, html('p', 'o-muted', wifi.advice || ''));
      }).catch(() => { if (!controller.signal.aborted) signal.replaceChildren(html('p', 'o-panel-kicker', 'SIGNAL WI-FI'), html('p', 'o-muted', 'Signal indisponible.')); });
    }
  }
  function spark(points) {
    if (points.length < 2) return html('p', 'o-muted', 'Pas encore assez de relevés sur l’heure écoulée.');
    const W = 300, H = 74, max = Math.max(1, ...points.map(p => Math.max(p.rx_bps, p.tx_bps)));
    const t0 = points[0].ts, t1 = Math.max(t0 + 1, points[points.length - 1].ts);
    const xy = (p, key) => ((p.ts - t0) / (t1 - t0) * W).toFixed(1) + ',' + (H - 4 - p[key] / max * (H - 10)).toFixed(1);
    const chart = svg('svg', {viewBox: '0 0 ' + W + ' ' + H, class: 'o-spark-svg', role: 'img', 'aria-label': 'Débits de la dernière heure, maximum ' + rate(max)});
    chart.append(svg('polygon', {points: '0,' + H + ' ' + points.map(p => xy(p, 'rx_bps')).join(' ') + ' ' + W + ',' + H, class: 'o-spark-area'}));
    chart.append(svg('polyline', {points: points.map(p => xy(p, 'rx_bps')).join(' '), class: 'o-spark-down'}), svg('polyline', {points: points.map(p => xy(p, 'tx_bps')).join(' '), class: 'o-spark-up'}));
    const box = html('div'); box.append(chart, html('p', 'o-muted', 'Pic : ' + rate(max) + ' · ' + clock(t0) + ' – ' + clock(t1)));
    return box;
  }

  // ---------- Camera: zoom, pan, fit, fullscreen ----------
  let dragMoved = false;
  function frameRatio() { const box = byId('orbitMap').getBoundingClientRect(); return box.width ? box.height / box.width : 0.62; }
  function applyView() { const v = state.view; byId('orbitMap').setAttribute('viewBox', v.x.toFixed(1) + ' ' + v.y.toFixed(1) + ' ' + v.w.toFixed(1) + ' ' + v.h.toFixed(1)); drawStars(); }
  function fit(animated) {
    // Room for the summary above and the legend below.
    const b = state.layout.bounds, ratio = frameRatio();
    let w = b.w * 1.1, h = w * ratio; if (h < b.h * 1.32) { h = b.h * 1.32; w = h / ratio; }
    animateTo({x: b.x + b.w / 2 - w / 2, y: b.y + b.h / 2 - h / 2 - h * 0.015, w, h}, animated);
  }
  function centerOn(node) {
    const box = byId('orbitMap').getBoundingClientRect(), v = state.view, w = Math.min(v.w, 900), h = w * frameRatio();
    const sheet = state.selected && box.width && sheetMode(), visible = state.selected && box.width && !sheet ? (box.width - 400) / box.width : 1;
    animateTo({x: node.x - w * visible / 2, y: node.y - h * (sheet ? 0.22 : 0.5), w, h}, true);
  }
  function zoom(factor, cx, cy) {
    const v = state.view, b = state.layout.bounds;
    const w = Math.max(320, Math.min(Math.max(b.w, b.h) * 2.4, v.w * factor)), h = w * frameRatio();
    const px = cx === undefined ? 0.5 : cx, py = cy === undefined ? 0.5 : cy;
    state.view = {x: v.x + (v.w - w) * px, y: v.y + (v.h - h) * py, w, h}; applyView();
  }
  let cameraFrame = null;
  function animateTo(target, animated) {
    cancelAnimationFrame(cameraFrame);
    if (!state.view || !animated || !state.motion) { state.view = target; applyView(); return; }
    const from = {...state.view}, start = performance.now();
    const step = now => {
      const t = Math.min(1, (now - start) / 650), e = 1 - Math.pow(1 - t, 3);
      state.view = {x: from.x + (target.x - from.x) * e, y: from.y + (target.y - from.y) * e, w: from.w + (target.w - from.w) * e, h: from.h + (target.h - from.h) * e};
      applyView(); if (t < 1) cameraFrame = requestAnimationFrame(step);
    };
    cameraFrame = requestAnimationFrame(step);
  }
  function setupCamera() {
    const map = byId('orbitMap'); let drag = null, pinch = null;
    const touches = new Map();
    const worldAt = (x, y, view) => { const box = map.getBoundingClientRect(); return {x: view.x + (x - box.left) / box.width * view.w, y: view.y + (y - box.top) / box.height * view.h}; };
    const pair = () => { const [a, b] = [...touches.values()]; return {mid: {x: (a.x + b.x) / 2, y: (a.y + b.y) / 2}, dist: Math.max(1, Math.hypot(a.x - b.x, a.y - b.y))}; };
    map.addEventListener('wheel', event => {
      event.preventDefault(); const box = map.getBoundingClientRect();
      zoom(Math.exp(event.deltaY * 0.0015), (event.clientX - box.left) / box.width, (event.clientY - box.top) / box.height);
    }, {passive: false});
    map.addEventListener('pointerdown', event => {
      if (event.button !== 0) return;
      touches.set(event.pointerId, {x: event.clientX, y: event.clientY});
      if (touches.size === 2) {
        // Two fingers: pinch to zoom around the point between them.
        const p = pair(); pinch = {...p, view: {...state.view}, anchor: worldAt(p.mid.x, p.mid.y, state.view)}; drag = null; dragMoved = true; tooltip(null);
        for (const id of touches.keys()) { try { map.setPointerCapture(id); } catch (_) {} }
        return;
      }
      dragMoved = false;
      drag = {x: event.clientX, y: event.clientY, view: {...state.view}, id: event.pointerId};
    });
    map.addEventListener('pointermove', event => {
      if (touches.has(event.pointerId)) touches.set(event.pointerId, {x: event.clientX, y: event.clientY});
      if (pinch && touches.size === 2) {
        const p = pair(), b = state.layout.bounds, box = map.getBoundingClientRect();
        const w = Math.max(320, Math.min(Math.max(b.w, b.h) * 2.4, pinch.view.w * pinch.dist / p.dist)), h = w * frameRatio();
        state.view = {x: pinch.anchor.x - (p.mid.x - box.left) / box.width * w, y: pinch.anchor.y - (p.mid.y - box.top) / box.height * h, w, h}; applyView();
        return;
      }
      if (!drag || drag.id !== event.pointerId) return;
      const dx = event.clientX - drag.x, dy = event.clientY - drag.y;
      if (!dragMoved && Math.hypot(dx, dy) < 5) return;
      if (!dragMoved) { dragMoved = true; map.setPointerCapture(event.pointerId); map.classList.add('is-dragging'); tooltip(null); }
      const box = map.getBoundingClientRect(), scale = drag.view.w / box.width;
      state.view = {...drag.view, x: drag.view.x - dx * scale, y: drag.view.y - dy * scale}; applyView();
    });
    const end = event => {
      touches.delete(event.pointerId);
      if (pinch && touches.size < 2) { pinch = null; drag = null; setTimeout(() => { dragMoved = false; }, 0); return; }
      if (drag) { map.classList.remove('is-dragging'); drag = null; setTimeout(() => { dragMoved = false; }, 0); }
    };
    map.addEventListener('pointerup', end); map.addEventListener('pointercancel', end);
    map.addEventListener('click', event => { if (!dragMoved && !event.target.closest('[data-id]') && state.selected) { state.selected = null; paintFocus(); showPanel(); } });
    byId('orbitZoomIn').addEventListener('click', () => zoom(0.8));
    byId('orbitZoomOut').addEventListener('click', () => zoom(1.25));
    byId('orbitFit').addEventListener('click', () => fit(true));
    const motion = byId('orbitMotion');
    const paintMotion = () => { motion.setAttribute('aria-pressed', String(state.motion)); motion.title = state.motion ? 'Figer les animations' : 'Animer les flux'; motion.setAttribute('aria-label', motion.title); };
    paintMotion();
    motion.addEventListener('click', () => { state.motion = !state.motion; remember(); paintMotion(); drawOrbit(); });
    const full = byId('orbitFull'), frame = byId('orbit');
    const request = frame.requestFullscreen || frame.webkitRequestFullscreen, current = () => document.fullscreenElement || document.webkitFullscreenElement;
    if (!request) full.hidden = true;
    full.addEventListener('click', () => {
      if (current()) (document.exitFullscreen || document.webkitExitFullscreen).call(document);
      else { const result = request.call(frame); if (result && result.catch) result.catch(() => {}); }
    });
    const changed = () => { full.setAttribute('aria-pressed', String(!!current())); frame.classList.toggle('is-full', !!current()); setTimeout(() => fit(false), 80); };
    document.addEventListener('fullscreenchange', changed); document.addEventListener('webkitfullscreenchange', changed);
    let resizeTimer = null;
    new ResizeObserver(() => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => { if (state.layout && state.view) { state.view.h = state.view.w * frameRatio(); applyView(); } }, 80); }).observe(map);
  }

  // A quiet starfield behind the map, drifting slightly with the camera.
  let stars = null;
  function drawStars() {
    const canvas = byId('orbitStars'); if (!canvas) return;
    const box = canvas.getBoundingClientRect(), ratio = window.devicePixelRatio || 1;
    if (!box.width) return;
    if (canvas.width !== Math.round(box.width * ratio)) { canvas.width = Math.round(box.width * ratio); canvas.height = Math.round(box.height * ratio); }
    if (!stars) { let seed = 7; const random = () => (seed = (seed * 16807) % 2147483647) / 2147483647; stars = Array.from({length: 260}, () => ({x: random(), y: random(), r: random() * 1.2 + 0.2, a: random() * 0.6 + 0.15, depth: random() * 0.5 + 0.2})); }
    const ctx = canvas.getContext('2d'), v = state.view || {x: 0, y: 0};
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (const s of stars) {
      const x = ((s.x * canvas.width - v.x * s.depth * 0.3 * ratio) % canvas.width + canvas.width) % canvas.width;
      const y = ((s.y * canvas.height - v.y * s.depth * 0.3 * ratio) % canvas.height + canvas.height) % canvas.height;
      ctx.globalAlpha = s.a; ctx.fillStyle = s.r > 1.1 ? '#bfe6ff' : '#ffffff';
      ctx.beginPath(); ctx.arc(x, y, s.r * ratio, 0, Math.PI * 2); ctx.fill();
    }
    ctx.globalAlpha = 1;
  }

  function drawHud() {
    const hud = byId('orbitStats'); if (!hud) return; hud.replaceChildren();
    const all = []; walk(state.tree, n => { if (isDevice(n)) all.push(n); });
    const online = all.filter(n => info(n).active);
    const down = online.reduce((s, n) => s + (info(n).rx || 0), 0), up = online.reduce((s, n) => s + (info(n).tx || 0), 0);
    const cell = (value, label, cls) => { const box = html('div', 'o-hud-cell' + (cls ? ' ' + cls : '')); box.append(html('strong', '', value), html('span', '', label)); hud.append(box); };
    cell(String(all.length), 'équipements'); cell(String(online.length), 'en ligne', 'is-on');
    cell(String(all.filter(n => n.ap && n.ap.kind === 'repeater').length), 'via répéteur', 'is-rep');
    cell('↓ ' + rate(down), 'trafic local', 'is-rate'); cell('↑ ' + rate(up), 'émission', 'is-rate');
    byId('orbitClock').textContent = state.ts ? 'RELEVÉ ' + clock(state.ts) : '';
  }

  // ---------- Foldable tree (phone) ----------
  function visible(node) {
    const kids = (node.children || []).map(visible).filter(Boolean);
    const keep = isDevice(node) && matchesFilter(node) && !(state.hideOffline && !info(node).active);
    if (isDevice(node) && !keep && !kids.length) return null;
    if (!isDevice(node) && node.kind !== 'livebox' && !kids.length) return null;
    return {node, kids};
  }
  const countDevices = items => items.reduce((n, item) => n + (isDevice(item.node) ? 1 : 0) + countDevices(item.kids), 0);
  const edgeClass = node => node.kind === 'livebox' ? '' : node.kind === 'port' ? 'e-eth' : node.kind === 'wifi' ? 'e-' + (node.band.startsWith('2,4') ? 'w24' : node.band.startsWith('6') ? 'w6' : 'w5') : 'e-' + linkKey(node) + (node.kind === 'repeater' ? ' e-back' : '');
  function drawList() {
    const box = byId('topoList'); if (!box) return; box.replaceChildren();
    const view = visible(state.tree); if (!view) return;
    const build = item => {
      const node = item.node;
      if (isDevice(node) && !item.kids.length) {
        const d = info(node), li = html('li', 'topo-row ' + edgeClass(node) + (d.active ? '' : ' is-off') + (state.query && !matchesQuery(node) ? ' is-dim' : ''));
        const link = html(d.known ? 'a' : 'div', 'topo-row-link'); if (d.known) link.href = '/?device=' + encodeURIComponent(node.mac);
        if (typeof categorySymbol === 'function') link.append(categorySymbol(d.category || d.name));
        const text = html('span', 'topo-row-text'); text.append(html('strong', '', d.name), html('small', '', [linkLabel(node), d.ip || (d.active ? '' : 'hors ligne')].filter(Boolean).join(' · ')));
        const dot = html('i', 'topo-row-dot'); dot.dataset.status = d.active ? 'ok' : 'unknown';
        link.append(text, dot); li.append(link); return li;
      }
      const li = html('li', 'topo-branch ' + edgeClass(node));
      const details = html('details'); details.open = !state.collapsed.has(node.id);
      const summary = html('summary'); summary.append(html('strong', '', node.kind === 'repeater' ? info(node).name + ' · répéteur' : node.label), html('span', 'topo-chip-count', String(countDevices(item.kids))));
      details.append(summary);
      details.addEventListener('toggle', () => { if (details.open) state.collapsed.delete(node.id); else state.collapsed.add(node.id); remember(); });
      const ul = html('ul');
      if (node.kind === 'repeater') ul.append(html('li', 'topo-note', 'Relié à la Livebox en ' + linkLabel(node).toLowerCase() + '.'));
      item.kids.forEach(kid => ul.append(build(kid)));
      details.append(ul); li.append(details); return li;
    };
    const root = html('ul', 'topo-tree'); root.append(build(view)); box.append(root);
  }

  // ---------- Loading ----------
  const desktop = window.matchMedia('(min-width: 768px)');
  function render() {
    if (!state.tree) return;
    drawFilters(); drawList(); drawHud();
    if (desktop.matches) drawOrbit();
    if (state.selected) showPanel();
  }
  async function load() {
    const status = byId('topoStatus');
    try {
      const [topology, devices] = await Promise.all([fetch('/api/network/topology').then(r => r.ok ? r.json() : Promise.reject()), fetch('/api/devices').then(r => r.ok ? r.json() : Promise.reject())]);
      state.devices = new Map(devices.map(d => [d.mac, d]));
      if (!topology.available) { status.textContent = 'La carte apparaîtra après le prochain relevé de la Livebox (toutes les 30 secondes).'; return; }
      const selectedMac = state.selected && (state.selected.mac || state.selected.kind);
      state.tree = topology.root; attachUnplaced(state.tree); prepare(state.tree, null, 'r'); state.ts = topology.ts;
      state.selected = null; state.hovered = null;
      if (selectedMac) walk(state.tree, n => { if (n.mac === selectedMac || (!n.mac && n.kind === selectedMac && n.kind === 'livebox')) state.selected = n; });
      status.textContent = 'Raccordements relevés à ' + clock(topology.ts) + ' · actualisation automatique';
      render();
    } catch (_) {
      status.textContent = 'Carte momentanément indisponible. Nouvel essai dans 30 secondes.';
    }
  }
  function init() {
    if (!byId('topoFilters')) return;
    const search = byId('topoSearch');
    search.addEventListener('input', () => { state.query = search.value.trim().toLowerCase(); drawList(); paintFocus(); });
    search.addEventListener('keydown', event => {
      if (event.key !== 'Enter' || !state.tree || !desktop.matches) return;
      let first = null; walk(state.tree, n => { if (!first && matchesQuery(n)) first = n; });
      if (first) { event.preventDefault(); state.selected = null; select(first); centerOn(first); }
    });
    const hide = byId('topoHideOffline'); hide.checked = state.hideOffline;
    hide.addEventListener('change', () => { state.hideOffline = hide.checked; state.view = null; remember(); render(); });
    byId('topoExpand').addEventListener('click', () => { state.collapsed.clear(); remember(); drawList(); });
    document.addEventListener('keydown', event => { if (event.key === 'Escape' && state.selected) { state.selected = null; paintFocus(); showPanel(); } });
    if (byId('orbitMap')) setupCamera();
    desktop.addEventListener('change', () => { state.view = null; state.introDone = false; render(); });
    load();
    setInterval(() => { if (!document.hidden) load(); }, 30000);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
