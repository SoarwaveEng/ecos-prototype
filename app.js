'use strict';
// Client side decryption for a static site. Nothing here is secret: the protection is the
// password, stretched with PBKDF2-SHA256, which unwraps one AES-256-GCM content key.
(() => {
  const KEY_SLOT = 'k';
  const USER_SLOT = 'u';
  const GENERIC_ERROR = 'That username and password do not match an account.';
  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder();

  let accountsDoc = null;
  let contentKey = null;
  let manifest = null;
  const flat = [];
  const urls = new Map();
  const pending = new Map();

  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const toB64 = (u8) => { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s); };
  const normUser = (u) => u.trim().toLowerCase();

  const store = {
    get(k) { try { return sessionStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { sessionStorage.setItem(k, v); } catch (e) { /* memory only */ } },
    clear() { try { sessionStorage.removeItem(KEY_SLOT); sessionStorage.removeItem(USER_SLOT); } catch (e) { /* ignore */ } },
  };

  async function loadAccounts() {
    if (accountsDoc) return accountsDoc;
    const r = await fetch('accounts.json', { cache: 'no-store', credentials: 'same-origin' });
    if (!r.ok) throw new Error('accounts');
    accountsDoc = await r.json();
    return accountsDoc;
  }

  async function deriveKek(password, salt, iterations) {
    const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  }

  function importContentKey(raw) {
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
  }

  // Returns the raw content key, or null. Unknown users cost the same as wrong passwords.
  async function unwrap(username, password) {
    const doc = await loadAccounts();
    const list = doc.accounts || [];
    const acc = list.find((a) => a.username === username);
    const ref = acc || list[0];
    if (!ref) return null;
    const salt = acc ? fromB64(acc.salt) : crypto.getRandomValues(new Uint8Array(16));
    const kek = await deriveKek(password, salt, ref.iterations);
    try {
      const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(ref.iv) }, kek, fromB64(ref.wrapped));
      return acc ? new Uint8Array(raw) : null;
    } catch (e) {
      return null;
    }
  }

  async function fetchPlain(path) {
    const r = await fetch(path, { credentials: 'same-origin' });
    if (!r.ok) throw new Error('fetch ' + r.status);
    const buf = new Uint8Array(await r.arrayBuffer());
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.subarray(0, 12) }, contentKey, buf.subarray(12));
  }

  function blobUrl(path) {
    if (urls.has(path)) return Promise.resolve(urls.get(path));
    if (pending.has(path)) return pending.get(path);
    const p = fetchPlain(path).then((plain) => {
      const u = URL.createObjectURL(new Blob([plain], { type: 'image/webp' }));
      urls.set(path, u);
      pending.delete(path);
      return u;
    }, (err) => { pending.delete(path); throw err; });
    pending.set(path, p);
    return p;
  }

  async function openSession(raw, username) {
    contentKey = await importContentKey(raw);
    const doc = await loadAccounts();
    const plain = await fetchPlain(doc.manifest);
    manifest = JSON.parse(new TextDecoder().decode(plain));
    store.set(KEY_SLOT, toB64(raw));
    store.set(USER_SLOT, username);
    raw.fill(0);
    showApp(username);
  }

  // ---------- sign in ----------
  function showLogin() {
    document.title = 'Sign in';
    $('app').hidden = true;
    $('login').hidden = false;
    $('user').focus();
  }

  function setError(msg) {
    $('login-error').textContent = msg;
    const bad = msg ? 'true' : 'false';
    $('user').setAttribute('aria-invalid', bad);
    $('pass').setAttribute('aria-invalid', bad);
  }

  async function onSubmit(ev) {
    ev.preventDefault();
    const username = normUser($('user').value);
    const password = $('pass').value;
    if (!username || !password) {
      setError(!username ? 'Enter your username.' : 'Enter your password.');
      (!username ? $('user') : $('pass')).focus();
      return;
    }
    if (!window.crypto || !crypto.subtle) {
      setError('This browser cannot sign in here. Use a recent Chrome, Safari, Edge or Firefox.');
      return;
    }
    const btn = $('login-btn');
    btn.disabled = true;
    btn.textContent = 'Checking';
    setError('');
    try {
      const raw = await unwrap(username, password);
      if (!raw) {
        setError(GENERIC_ERROR);
        $('pass').select();
        return;
      }
      $('pass').value = '';
      await openSession(raw, username);
    } catch (e) {
      setError('Could not reach the site. Check your connection and try again.');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Sign in';
    }
  }

  function togglePass() {
    const input = $('pass');
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    $('toggle-pass').textContent = show ? 'Hide' : 'Show';
    $('toggle-pass').setAttribute('aria-pressed', String(show));
    input.focus();
  }

  function signOut() {
    store.clear();
    for (const u of urls.values()) URL.revokeObjectURL(u);
    urls.clear();
    contentKey = null;
    manifest = null;
    location.replace(location.pathname);
  }

  // ---------- board list ----------
  function showApp(username) {
    document.title = manifest.title || 'Prototype';
    $('login').hidden = true;
    $('app').hidden = false;
    $('app-title').textContent = manifest.title || 'Prototype';
    $('who').textContent = 'Signed in as ' + username;
    $('notice').textContent = manifest.footer || '';
    $('foot').textContent = (manifest.footer || '') + (manifest.built ? ' Built ' + manifest.built + '.' : '');
    const rowsEl = $('rows');
    rowsEl.textContent = '';
    flat.length = 0;
    const thumbs = [];
    manifest.rows.forEach((row) => {
      const sec = document.createElement('section');
      sec.className = 'row';
      const h = document.createElement('h2');
      h.textContent = row.title;
      sec.appendChild(h);
      const grid = document.createElement('div');
      grid.className = 'grid';
      row.boards.forEach((b) => {
        const index = flat.length;
        flat.push(Object.assign({ row: row.title }, b));
        const card = document.createElement('button');
        card.type = 'button';
        card.className = 'card';
        card.dataset.index = String(index);
        const tw = document.createElement('span');
        tw.className = 'thumb';
        const img = document.createElement('img');
        img.alt = '';
        img.decoding = 'async';
        tw.appendChild(img);
        const text = document.createElement('span');
        text.className = 'card-text';
        const t = document.createElement('span');
        t.className = 'card-title';
        t.textContent = b.title;
        const m = document.createElement('span');
        m.className = 'card-meta';
        m.textContent = (index + 1) + ' · ' + b.w + ' × ' + b.h;
        text.append(t, m);
        card.append(tw, text);
        card.addEventListener('click', () => openViewer(index, card));
        grid.appendChild(card);
        thumbs.push([img, b.thumb]);
      });
      sec.appendChild(grid);
      rowsEl.appendChild(sec);
    });
    loadThumbs(thumbs);
  }

  async function loadThumbs(list) {
    let next = 0;
    const worker = async () => {
      while (next < list.length) {
        const [img, path] = list[next++];
        try { img.src = await blobUrl(path); } catch (e) { img.alt = 'Could not load'; }
      }
    };
    await Promise.all([worker(), worker(), worker(), worker()]);
  }

  // ---------- viewer ----------
  const v = { index: -1, s: 1, x: 0, y: 0, fit: 1, w: 0, h: 0, opener: null, token: 0 };
  const pointers = new Map();
  let gesture = null;

  function stageRect() { return $('v-stage').getBoundingClientRect(); }

  function apply() {
    $('v-img').style.transform = 'translate(' + v.x + 'px,' + v.y + 'px) scale(' + v.s + ')';
  }

  function clamp() {
    const r = stageRect();
    const iw = v.w * v.s;
    const ih = v.h * v.s;
    const pad = 24;
    v.x = iw <= r.width ? (r.width - iw) / 2 : Math.min(pad, Math.max(r.width - iw - pad, v.x));
    v.y = ih <= r.height ? (r.height - ih) / 2 : Math.min(pad, Math.max(r.height - ih - pad, v.y));
  }

  function fitScale() {
    const r = stageRect();
    const pad = window.innerWidth <= 640 ? 8 : 32;
    return Math.min((r.width - 2 * pad) / v.w, (r.height - 2 * pad) / v.h);
  }

  function fit() {
    v.fit = fitScale();
    v.s = v.fit;
    clamp();
    apply();
  }

  function zoomAt(factor, cx, cy) {
    const r = stageRect();
    if (cx === undefined) { cx = r.width / 2; cy = r.height / 2; }
    const min = Math.min(v.fit, 1) * 0.5;
    const max = 4;
    const s = Math.min(max, Math.max(min, v.s * factor));
    v.x = cx - (cx - v.x) * (s / v.s);
    v.y = cy - (cy - v.y) * (s / v.s);
    v.s = s;
    clamp();
    apply();
  }

  async function showBoard(index) {
    const b = flat[index];
    v.index = index;
    const token = ++v.token;
    v.w = b.w * 2;
    v.h = b.h * 2;
    const img = $('v-img');
    img.style.width = v.w + 'px';
    img.style.height = v.h + 'px';
    img.alt = b.title;
    $('v-title').textContent = b.title;
    $('v-count').textContent = (index + 1) + ' of ' + flat.length + ' · ' + b.row;
    $('v-prev').disabled = index === 0;
    $('v-next').disabled = index === flat.length - 1;
    img.removeAttribute('src');
    if (urls.has(b.thumb)) img.src = urls.get(b.thumb);
    fit();
    const loading = $('v-loading');
    loading.hidden = urls.has(b.full);
    try {
      const u = await blobUrl(b.full);
      if (token === v.token) img.src = u;
    } catch (e) {
      if (token === v.token) loading.textContent = 'Could not load this board';
      return;
    }
    if (token === v.token) loading.hidden = true;
    [index + 1, index - 1].forEach((n) => { if (flat[n]) blobUrl(flat[n].full).catch(() => {}); });
  }

  function openViewer(index, opener) {
    v.opener = opener || null;
    const viewer = $('viewer');
    if (viewer.hidden) {
      viewer.hidden = false;
      document.body.classList.add('viewing');
      try { history.pushState({ viewer: true }, ''); } catch (e) { /* ignore */ }
    }
    $('v-loading').textContent = 'Loading';
    showBoard(index);
    $('v-close').focus();
  }

  function closeViewer(fromHistory) {
    const viewer = $('viewer');
    if (viewer.hidden) return;
    viewer.hidden = true;
    document.body.classList.remove('viewing');
    v.token++;
    if (!fromHistory && history.state && history.state.viewer) history.back();
    const card = document.querySelector('.card[data-index="' + v.index + '"]');
    if (card) card.focus();
  }

  function step(d) {
    const n = v.index + d;
    if (n >= 0 && n < flat.length) showBoard(n);
  }

  function onKey(ev) {
    if ($('viewer').hidden) return;
    switch (ev.key) {
      case 'ArrowRight': step(1); break;
      case 'ArrowLeft': step(-1); break;
      case 'Escape': closeViewer(false); break;
      case '+': case '=': zoomAt(1.25); break;
      case '-': case '_': zoomAt(0.8); break;
      case '0': fit(); break;
      default: return;
    }
    ev.preventDefault();
  }

  function local(ev) {
    const r = stageRect();
    return { x: ev.clientX - r.left, y: ev.clientY - r.top };
  }

  function onPointerDown(ev) {
    if (ev.button !== undefined && ev.button !== 0 && ev.pointerType === 'mouse') return;
    $('v-stage').setPointerCapture(ev.pointerId);
    pointers.set(ev.pointerId, local(ev));
    startGesture();
  }

  function startGesture() {
    const pts = [...pointers.values()];
    if (pts.length === 1) {
      gesture = { kind: 'pan', sx: pts[0].x, sy: pts[0].y, ox: v.x, oy: v.y, moved: 0, startS: v.s };
    } else if (pts.length >= 2) {
      const [a, b] = pts;
      gesture = {
        kind: 'pinch',
        d: Math.hypot(a.x - b.x, a.y - b.y) || 1,
        mx: (a.x + b.x) / 2, my: (a.y + b.y) / 2,
        s: v.s, ox: v.x, oy: v.y,
      };
    }
    $('v-stage').classList.add('dragging');
  }

  function onPointerMove(ev) {
    if (!pointers.has(ev.pointerId) || !gesture) return;
    pointers.set(ev.pointerId, local(ev));
    const pts = [...pointers.values()];
    if (gesture.kind === 'pan' && pts.length === 1) {
      const dx = pts[0].x - gesture.sx;
      const dy = pts[0].y - gesture.sy;
      gesture.moved = Math.max(gesture.moved, Math.hypot(dx, dy));
      gesture.dx = dx;
      gesture.dy = dy;
      v.x = gesture.ox + dx;
      v.y = gesture.oy + dy;
      clamp();
      apply();
    } else if (gesture.kind === 'pinch' && pts.length >= 2) {
      const [a, b] = pts;
      const d = Math.hypot(a.x - b.x, a.y - b.y) || 1;
      const mx = (a.x + b.x) / 2;
      const my = (a.y + b.y) / 2;
      const min = Math.min(v.fit, 1) * 0.5;
      const s = Math.min(4, Math.max(min, gesture.s * d / gesture.d));
      v.x = mx - (gesture.mx - gesture.ox) * (s / gesture.s);
      v.y = my - (gesture.my - gesture.oy) * (s / gesture.s);
      v.s = s;
      clamp();
      apply();
    }
  }

  function onPointerUp(ev) {
    if (!pointers.has(ev.pointerId)) return;
    pointers.delete(ev.pointerId);
    const g = gesture;
    if (pointers.size === 0) {
      $('v-stage').classList.remove('dragging');
      gesture = null;
      // Swipe left or right to change board when the board fits the width.
      if (g && g.kind === 'pan' && ev.pointerType !== 'mouse' && g.startS <= v.fit * 1.02 &&
          Math.abs(g.dx || 0) > 60 && Math.abs(g.dx) > 1.5 * Math.abs(g.dy || 0)) {
        step(g.dx < 0 ? 1 : -1);
      }
    } else {
      startGesture();
    }
  }

  function onWheel(ev) {
    ev.preventDefault();
    const p = local(ev);
    if (ev.ctrlKey || ev.metaKey) {
      zoomAt(Math.exp(-ev.deltaY * 0.01), p.x, p.y);
    } else {
      v.x -= ev.deltaX;
      v.y -= ev.deltaY;
      clamp();
      apply();
    }
  }

  function onDouble(ev) {
    const p = local(ev);
    const actual = 0.5; // board at its design size
    if (v.s < actual * 0.95) zoomAt(actual / v.s, p.x, p.y);
    else fit();
  }

  // ---------- start ----------
  async function start() {
    $('login-form').addEventListener('submit', onSubmit);
    $('toggle-pass').addEventListener('click', togglePass);
    $('signout').addEventListener('click', signOut);
    $('v-close').addEventListener('click', () => closeViewer(false));
    $('v-prev').addEventListener('click', () => step(-1));
    $('v-next').addEventListener('click', () => step(1));
    $('v-in').addEventListener('click', () => zoomAt(1.25));
    $('v-out').addEventListener('click', () => zoomAt(0.8));
    $('v-fit').addEventListener('click', fit);
    const stage = $('v-stage');
    stage.addEventListener('pointerdown', onPointerDown);
    stage.addEventListener('pointermove', onPointerMove);
    stage.addEventListener('pointerup', onPointerUp);
    stage.addEventListener('pointercancel', onPointerUp);
    stage.addEventListener('wheel', onWheel, { passive: false });
    stage.addEventListener('dblclick', onDouble);
    document.addEventListener('keydown', onKey);
    window.addEventListener('popstate', () => closeViewer(true));
    window.addEventListener('resize', () => {
      if ($('viewer').hidden) return;
      const atFit = Math.abs(v.s - v.fit) < 1e-3;
      v.fit = fitScale();
      if (atFit) v.s = v.fit;
      clamp();
      apply();
    });

    const saved = store.get(KEY_SLOT);
    if (saved && window.crypto && crypto.subtle) {
      try {
        await openSession(fromB64(saved), store.get(USER_SLOT) || '');
        return;
      } catch (e) {
        store.clear();
        contentKey = null;
        manifest = null;
      }
    }
    showLogin();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
