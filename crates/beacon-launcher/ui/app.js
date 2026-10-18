/* BFME Beacon – browser UI (plain JavaScript, no build step, no external code).
 *
 * Security rules of this file:
 *  - Server and player data (names, chat, MOTD, map names, file paths, error
 *    texts) reach the DOM only through textContent / createElement / append of
 *    strings – never innerHTML or similar.
 *  - Text written by players is bidi-isolated (<bdi> or dir="auto").
 *  - The access token arrives in the URL fragment (#t=…), is kept in
 *    sessionStorage and sent as the X-Beacon-Token header with every API call.
 */
'use strict';

(() => {
  // ================================================================ constants
  const VIEWS = ['verbinden', 'lobby', 'einstellungen', 'diagnose'];
  const TOKEN_KEY = 'beacon.token';
  const DEFAULT_PORT = '28086';
  const NAME_MAX = 12; // UTF-16 units, as BFME's LAN name
  const NAME_PUNCT = " -_.!?#()[]{}+*'&@~^=$%";
  const RES_MIN = 320;
  const RES_MAX = 16384;
  const FILES_SHOWN = 100;
  const MAX_TOASTS = 5;

  // ==================================================================== token
  /** `#t=<token>` or `#t=<token>&v=<view>` (the view to show first). */
  function takeToken() {
    const m = /^#t=([0-9a-f]{32})(?:&v=([a-z]+))?$/.exec(location.hash);
    if (m) {
      try {
        sessionStorage.setItem(TOKEN_KEY, m[1]);
      } catch (_) {
        /* storage blocked: the token only lives in this page */
      }
      const view = VIEWS.includes(m[2]) ? m[2] : 'verbinden';
      history.replaceState(null, '', `${location.pathname}#${view}`);
      return m[1];
    }
    try {
      return sessionStorage.getItem(TOKEN_KEY);
    } catch (_) {
      return null;
    }
  }
  const TOKEN = takeToken();

  // ================================================================== helpers
  const $ = (id) => document.getElementById(id);

  /** Creates an element; strings among `children` become text nodes. */
  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [key, value] of Object.entries(attrs)) {
        if (value === null || value === undefined || value === false) continue;
        if (key === 'class') node.className = value;
        else if (key === 'text') node.textContent = value;
        else node.setAttribute(key, value === true ? '' : String(value));
      }
    }
    append(node, children);
    return node;
  }

  /** Appends nodes and strings (as text), skipping null/undefined/false. */
  function append(node, children) {
    for (const child of children) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child);
    }
    return node;
  }

  /** Replaces the children (nodes or strings), skipping null/undefined/false. */
  function fill(node, ...children) {
    node.replaceChildren();
    return append(node, children);
  }

  const bdi = (text) => el('bdi', { text });
  const path = (text) => el('span', { class: 'mono', dir: 'ltr', text });
  const badge = (cls, text) => el('span', { class: `badge ${cls}`.trim(), text });

  function setText(node, text) {
    if (node.textContent !== text) node.textContent = text;
  }

  const SVG_NS = 'http://www.w3.org/2000/svg';
  function crown() {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 18');
    svg.setAttribute('class', 'crown');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Host');
    const title = document.createElementNS(SVG_NS, 'title');
    title.textContent = 'Host';
    const shape = document.createElementNS(SVG_NS, 'path');
    shape.setAttribute('d', 'M2 17h20l-1.6-11.5-5.2 4.6L12 2 8.8 10.1 3.6 5.5z');
    svg.append(title, shape);
    return svg;
  }

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  // =============================================================== formatting
  const NF = new Intl.NumberFormat('de-DE');
  const NF1 = new Intl.NumberFormat('de-DE', { maximumFractionDigits: 1 });

  function fmtBytes(n) {
    if (typeof n !== 'number' || !Number.isFinite(n)) return '–';
    if (n < 1024) return `${NF.format(n)} B`;
    const units = ['KB', 'MB', 'GB', 'TB'];
    let v = n / 1024;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i += 1;
    }
    return `${NF1.format(v)} ${units[i]}`;
  }

  function validDate(ms) {
    const d = new Date(ms);
    return Number.isFinite(d.getTime()) ? d : null;
  }

  function fmtTime(ms) {
    const d = validDate(ms);
    return d ? d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' }) : '–';
  }

  function fmtDateTime(ms) {
    const d = validDate(ms);
    return d ? d.toLocaleString('de-DE', { dateStyle: 'medium', timeStyle: 'short' }) : '–';
  }

  function timeEl(ms) {
    const d = validDate(ms);
    return el('time', { datetime: d ? d.toISOString() : null, text: fmtTime(ms) });
  }

  const count = (n, one, many) => `${NF.format(n)} ${n === 1 ? one : many}`;

  function fmtAgo(ms) {
    const s = Math.max(0, Math.round(ms / 1000));
    if (s < 60) return `vor ${s} s`;
    const m = Math.round(s / 60);
    if (m < 60) return `vor ${m} min`;
    return `vor ${Math.round(m / 60)} h`;
  }

  /** Canonical `host:port` like Beacon stores it (to find a known server). */
  function canonical(text) {
    const t = text.trim();
    if (!t) return '';
    if (t.startsWith('[')) {
      const end = t.indexOf(']');
      if (end < 0) return t.toLowerCase();
      const rest = t.slice(end + 1);
      const port = rest.startsWith(':') && rest.length > 1 ? rest.slice(1) : DEFAULT_PORT;
      return `[${t.slice(1, end).toLowerCase()}]:${String(Number(port))}`;
    }
    const colons = t.split(':').length - 1;
    if (colons > 1) return `[${t.toLowerCase()}]:${DEFAULT_PORT}`;
    const [host, port] = colons === 1 ? t.split(':') : [t, DEFAULT_PORT];
    return `${host.toLowerCase()}:${String(Number(port))}`;
  }

  /** Mirrors Beacon's name rule; returns a reason code or null. */
  function checkName(name) {
    if (!name) return 'name_empty';
    if (name.length > NAME_MAX) return 'name_too_long';
    if (name.startsWith(' ') || name.endsWith(' ') || name.includes('  ')) return 'name_spaces';
    for (const ch of name) {
      if (!(/^[\p{Alphabetic}\p{N}]$/u.test(ch) || NAME_PUNCT.includes(ch))) return 'name_invalid_char';
    }
    return null;
  }

  const isAbsolutePath = (p) => /^[a-zA-Z]:[\\/]/.test(p) || /^\\\\[^\\]+\\[^\\]+/.test(p);

  // ==================================================================== texts
  const ERRORS = {
    invalid_input: 'Ungültige Eingabe.',
    not_connected: 'Du bist mit keinem Server verbunden.',
    not_host: 'Das darf nur der Host.',
    game_not_found:
      'Spiel nicht gefunden: Beacon hat keine BFME-Installation gefunden. Lege den Spielordner unter „Einstellungen“ fest.',
    game_running: 'BFME läuft bereits.',
    hook_foreign:
      'Im Spielordner liegt eine fremde wsock32.dll (zum Beispiel von einem anderen Mod oder Tool). Beacon überschreibt sie nicht. Benenne sie um oder entferne sie und starte dann erneut.',
    hook_in_use:
      'Die wsock32.dll im Spielordner ist gerade in Benutzung – läuft BFME noch? Beende das Spiel und versuche es erneut.',
    hook_missing:
      'Beacons wsock32.dll fehlt neben Beacon.exe oder ist beschädigt. Entpacke Beacon bitte vollständig neu.',
    smart_app_control_blocked: 'Smart App Control hat den Start von BFME blockiert.',
    launch_failed: 'BFME konnte nicht gestartet werden.',
    busy: 'Das läuft bereits – bitte einen Moment warten.',
    io: 'Datei- oder Systemfehler.',
    forbidden: 'Zugriff verweigert.',
    bad_request: 'Ungültige Anfrage.',
    not_found: 'Unbekannte Anfrage.',
    too_many_streams: 'Zu viele offene Beacon-Fenster. Schließe nicht benötigte Tabs.',
    internal: 'Interner Fehler.',
    offline: 'Beacon ist nicht erreichbar.',
  };

  const SAC_EXPLAIN = [
    'Smart App Control ist eine Schutzfunktion von Windows 11: Sie lässt nur Programme starten, die Microsoft als vertrauenswürdig einstuft. Veränderte (gepatchte) Programmdateien werden dabei häufig blockiert.',
    'Beacon verändert lotrbfme.exe nicht. Prüfe unter „Diagnose“, ob deine lotrbfme.exe als bekannte Version erkannt wird, und verwende sonst eine unveränderte lotrbfme.exe.',
  ];

  const LAUNCH_HINTS = [
    [
      /os error 740/,
      'lotrbfme.exe ist auf „Als Administrator ausführen“ gestellt. Entferne diese Einstellung (Rechtsklick auf lotrbfme.exe → Eigenschaften → Kompatibilität), damit Beacon das Spiel starten kann.',
    ],
    [/os error 1260/, 'Eine Systemrichtlinie (zum Beispiel eine Softwareeinschränkung) hat den Start blockiert.'],
  ];

  const REASONS = {
    invalid_address: 'Ungültige Server-Adresse. Beispiel: mein-server.de oder 203.0.113.5:28086',
    name_empty: 'Bitte einen Spielernamen eingeben.',
    name_too_long: `Der Spielername darf höchstens ${NAME_MAX} Zeichen lang sein.`,
    name_spaces:
      'Der Spielername darf nicht mit einem Leerzeichen beginnen oder enden und keine doppelten Leerzeichen enthalten.',
    name_invalid_char: 'Der Spielername enthält ein nicht erlaubtes Zeichen.',
    name_missing: 'Kein Spieler angegeben.',
    password_missing: 'Bitte das Server-Passwort eingeben.',
    chat_empty: 'Die Nachricht ist leer.',
    path_not_absolute: 'Bitte einen vollständigen Pfad angeben, zum Beispiel C:\\Spiele\\BFME.',
    resolution_range: `Breite und Höhe müssen zwischen ${RES_MIN} und ${RES_MAX} Pixeln liegen.`,
    redundancy_range: 'Die Redundanz muss 1, 2 oder 3 sein.',
  };

  const REJECTED = {
    name_taken: 'Dieser Spielername ist auf dem Server bereits vergeben. Wähle einen anderen Namen.',
    bad_name: 'Der Server lehnt diesen Spielernamen ab.',
    server_full: 'Der Server ist voll.',
    unsupported_version: 'Diese Beacon-Version wird vom Server nicht unterstützt. Bitte Beacon aktualisieren.',
    rate_limited: 'Zu viele Anfragen – bitte kurz warten.',
    not_host: 'Das darf nur der Host.',
    bad_request: 'Der Server hat eine Anfrage nicht verstanden.',
    internal: 'Interner Fehler auf dem Server.',
  };

  /** German text of an API error. */
  function errorText(err) {
    if (err.kind === 'invalid_input' && err.reason && REASONS[err.reason]) return REASONS[err.reason];
    return ERRORS[err.kind] || 'Unbekannter Fehler.';
  }

  /** German text of a connection error (`connection.error`). */
  function controlErrorText(e) {
    switch (e && e.kind) {
      case 'resolve':
        return `Server nicht erreichbar: Die Adresse „${e.host}“ wurde nicht gefunden. Stimmt die Schreibweise?`;
      case 'connect':
        return 'Server nicht erreichbar. Läuft der Server, und ist sein Port (TCP und UDP) im Router freigegeben?';
      case 'timeout':
        return 'Server nicht erreichbar: keine Antwort (Zeitüberschreitung).';
      case 'closed':
        return 'Der Server hat die Verbindung beendet.';
      case 'not_beacon':
        return 'Unter dieser Adresse antwortet kein Beacon-Server.';
      case 'unsupported_server':
        return `Der Server verwendet eine andere Protokollversion (${e.version}). Bitte Beacon aktualisieren.`;
      case 'insecure_kdf':
        return 'Der Server verlangt unsichere Schlüsselparameter. Beacon meldet sich dort aus Sicherheitsgründen nicht an.';
      case 'identity_changed':
        return 'Server-Identität geändert – Beacon hat die Anmeldung gestoppt.';
      case 'no_remembered_password':
        return 'Für diesen Server ist kein Passwort gespeichert. Bitte das Passwort eingeben.';
      case 'remembered_password_unusable':
        return 'Das gespeicherte Passwort lässt sich nicht mehr verwenden (zum Beispiel nach einem Wechsel des Windows-Kontos). Bitte das Passwort neu eingeben.';
      case 'auth_failed':
        return 'Falsches Passwort. Nach mehreren Fehlversuchen sperrt der Server deine IP-Adresse für kurze Zeit.';
      case 'rejected':
        return REJECTED[e.code] || 'Der Server hat die Anmeldung abgelehnt.';
      case 'kicked':
        return 'Du wurdest vom Server entfernt.';
      case 'server_stopped':
        return 'Der Server wurde beendet (Neustart oder Update). Beacon verbindet sich neu, sobald er wieder läuft.';
      case 'protocol':
        return 'Protokollfehler: Der Server sendet unerwartete Daten.';
      case 'io':
        return 'Verbindungsfehler.';
      case 'idle_timeout':
        return 'Der Server antwortet nicht mehr.';
      default:
        return 'Verbindungsfehler.';
    }
  }

  /** German connection-error texts by Beacon's English message (for notices). */
  const connectionTexts = new Map();

  const NOTICE_RULES = [
    [/^the identity of (.+) will be pinned again at the next login$/, (m) => `Die Identität von ${m[1]} wird bei der nächsten Anmeldung neu gespeichert.`],
    [/^the host started the game$/, () => 'Der Host hat das Spiel gestartet.'],
    [/^cannot start BFME: ([\s\S]*)$/, (m) => `BFME konnte nicht gestartet werden: ${m[1]}`],
    [/^map sync: ([\s\S]*)$/, (m) => `Kartenabgleich: ${m[1]}`],
    [/^server: ([\s\S]*)$/, (m) => `Meldung des Servers: ${m[1]}`],
    [/^game detection failed$/, () => 'Die Spielerkennung ist fehlgeschlagen.'],
    [/^hook DLL Installed: ([\s\S]*)$/, (m) => `Hook installiert: ${m[1]}`],
    [/^hook DLL Updated: ([\s\S]*)$/, (m) => `Hook aktualisiert: ${m[1]}`],
    [/^BFME LAN name set to "([\s\S]*)" \(was "([\s\S]*)"\)$/, (m) => `BFME-LAN-Name auf „${m[1]}“ gesetzt (vorher „${m[2]}“).`],
    [/^cannot set the BFME LAN name: ([\s\S]*)$/, (m) => `Der BFME-LAN-Name konnte nicht gesetzt werden: ${m[1]}`],
    [/^test mode: copied ([\s\S]*) into ([\s\S]*)$/, (m) => `Testmodus: ${m[1]} nach ${m[2]} kopiert.`],
    [/^cannot start the fingerprint thread: ([\s\S]*)$/, (m) => `Der Fingerabdruck kann nicht berechnet werden: ${m[1]}`],
  ];

  function noticeText(text) {
    if (connectionTexts.has(text)) return connectionTexts.get(text);
    for (const [re, make] of NOTICE_RULES) {
      const m = re.exec(text);
      if (m) return make(m);
    }
    return text;
  }

  // ====================================================================== API
  class ApiError extends Error {
    constructor(status, e) {
      super((e && e.message) || `HTTP ${status}`);
      this.status = status;
      this.kind = (e && e.kind) || (status === 0 ? 'offline' : 'internal');
      this.reason = (e && e.reason) || null;
      this.field = (e && e.field) || null;
      this.detail = (e && e.message) || '';
    }
  }

  async function api(name, body) {
    const init = {
      method: body === undefined ? 'GET' : 'POST',
      headers: { 'X-Beacon-Token': TOKEN || '' },
      cache: 'no-store',
      credentials: 'same-origin',
    };
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    let res;
    try {
      res = await fetch(`/api/${name}`, init);
    } catch (e) {
      throw new ApiError(0, { kind: 'offline', message: String(e) });
    }
    let data = null;
    try {
      data = await res.json();
    } catch (_) {
      data = null;
    }
    if (res.status === 403) showFatal('auth');
    if (!res.ok || !data || data.ok !== true) throw new ApiError(res.status, data && data.error);
    return data;
  }

  /** Buttons with a command in flight (by id): they stay disabled. */
  const busy = new Set();

  /** Runs a command; errors go to `onError` or a toast. */
  async function run(button, action, onError) {
    const id = button && button.id;
    if (id) {
      busy.add(id);
      button.disabled = true;
    }
    try {
      return await action();
    } catch (e) {
      const err = e instanceof ApiError ? e : new ApiError(0, { kind: 'internal', message: String(e) });
      if (err.kind === 'forbidden') return undefined;
      if (onError) onError(err);
      else toast(errorText(err), 'error', err.detail);
      return undefined;
    } finally {
      if (id) {
        busy.delete(id);
        button.disabled = false;
        if (S) render(S);
      }
    }
  }

  // ============================================================ toasts, fatal
  function toast(text, level = 'info', detail = '') {
    const box = $('toasts');
    while (box.children.length >= MAX_TOASTS) box.firstElementChild.remove();
    const close = el('button', { type: 'button', class: 'toast-close', 'aria-label': 'Meldung schließen', text: '×' });
    const node = el(
      'div',
      { class: `toast ${level}` },
      el('div', null, el('div', { text }), detail ? el('div', { class: 'muted small', text: detail }) : null),
      close,
    );
    close.addEventListener('click', () => node.remove());
    box.append(node);
    setTimeout(() => node.remove(), level === 'error' ? 15000 : 8000);
  }

  let fatalShown = false;
  let streamStop = false;

  function showFatal(kind) {
    const texts = {
      auth: [
        'Sitzung ungültig',
        'Diese Seite gehört zu einer beendeten oder anderen Beacon-Sitzung. Öffne die Oberfläche neu über Beacon.exe oder über das Beacon-Symbol im Infobereich der Taskleiste.',
      ],
      quit: ['Beacon wurde beendet', 'Du kannst dieses Fenster schließen. Zum Weiterspielen Beacon.exe erneut starten.'],
    };
    const [title, text] = texts[kind] || texts.auth;
    setText($('fatal-title'), title);
    setText($('fatal-text'), text);
    $('fatal').hidden = false;
    $('offline-banner').hidden = true;
    $('fatal-box').focus();
    fatalShown = true;
    streamStop = true;
  }

  function showCallout(node, title, detail, ...extra) {
    fill(
      node,
      el('strong', { text: title }),
      ...extra.map((x) => (typeof x === 'string' ? el('p', { text: x }) : x)),
      detail ? el('p', { class: 'detail', text: detail }) : null,
    );
    node.hidden = false;
  }

  function fieldError(id, text) {
    $(id).setAttribute('aria-invalid', 'true');
    const err = $(`${id}-err`);
    setText(err, text);
    err.hidden = false;
  }

  function clearFieldErrors(...ids) {
    for (const id of ids) {
      $(id).removeAttribute('aria-invalid');
      const err = $(`${id}-err`);
      err.hidden = true;
      err.textContent = '';
    }
  }

  // =================================================================== router
  function currentView() {
    const v = location.hash.slice(1);
    return VIEWS.includes(v) ? v : 'verbinden';
  }

  function applyView(focus) {
    const view = currentView();
    for (const v of VIEWS) $(`view-${v}`).hidden = v !== view;
    for (const a of document.querySelectorAll('.tabs a')) {
      if (a.dataset.view === view) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    }
    if (focus) {
      const h = $(`view-${view}`).querySelector('h1');
      if (h) {
        h.setAttribute('tabindex', '-1');
        h.focus();
      }
    }
  }

  function go(view) {
    if (currentView() !== view) location.hash = view;
  }

  window.addEventListener('hashchange', () => applyView(true));

  // ============================================================ state access
  /** The latest state. */
  let S = null;
  /** JSON of the last rendered input per part (skip unchanged parts). */
  const seen = Object.create(null);

  function changed(part, value) {
    const json = JSON.stringify(value === undefined ? null : value);
    if (seen[part] === json) return false;
    seen[part] = json;
    return true;
  }

  const isConnected = (st) => st.connection.state === 'connected';
  const myPlayer = (st) => (st.server ? st.players.find((p) => p.vip === st.server.vip) || null : null);
  const hostPlayer = (st) => st.players.find((p) => p.is_host) || null;

  function knownServer(text) {
    const key = canonical(text);
    if (!S || !key) return null;
    return S.settings.servers.find((s) => s.address === key) || null;
  }

  // =================================================================== render
  function render(st) {
    S = st;
    renderConnection(st);
    renderServers(st);
    renderLobby(st);
    renderSettings(st);
    renderDiagnose(st);
    renderNotices(st);
  }

  // -------------------------------------------------------------- connection
  let lastConnState = null;
  let reconnectAt = 0;
  let prefilled = false;

  function connLabel(c, srv) {
    switch (c.state) {
      case 'disconnected':
        return 'Nicht verbunden';
      case 'connecting':
        return c.attempt > 1 ? `Verbinde … (Versuch ${c.attempt})` : 'Verbinde …';
      case 'authenticating':
        return 'Anmeldung …';
      case 'connected':
        return srv && srv.name ? `Verbunden: ${srv.name}` : 'Verbunden';
      case 'reconnecting':
        return 'Verbindung unterbrochen';
      case 'failed':
        return 'Verbindung fehlgeschlagen';
      default:
        return String(c.state);
    }
  }

  function countdownText() {
    const s = Math.max(0, Math.ceil((reconnectAt - Date.now()) / 1000));
    return s > 0 ? `Neuer Versuch in ${s} s.` : 'Neuer Versuch …';
  }

  function renderConnection(st) {
    const c = st.connection;
    const pill = $('conn-pill');
    pill.dataset.state = c.state;
    setText(pill, connLabel(c, st.server));
    if (c.error && c.message) {
      if (connectionTexts.size > 64) connectionTexts.clear();
      connectionTexts.set(c.message, controlErrorText(c.error));
    }

    const active = ['connecting', 'authenticating', 'connected', 'reconnecting'].includes(c.state);
    $('btn-disconnect').hidden = !active;
    $('btn-disconnect').disabled = busy.has('btn-disconnect');
    $('btn-connect').disabled = busy.has('btn-connect');

    if (!prefilled) {
      prefilled = true;
      if (!$('f-server').value && st.settings.last_server) $('f-server').value = st.settings.last_server;
      if (!$('f-name').value && st.settings.player_name) $('f-name').value = st.settings.player_name;
      updatePasswordHint();
    }

    if (changed('connection', [c, st.server])) {
      if (c.state === 'reconnecting') reconnectAt = Date.now() + (c.retry_in_ms || 0);
      renderConnDetail(st);
      renderLobbyBanner(st);
      const box = $('connect-error');
      if (c.state === 'failed') {
        const extra = c.error && c.error.kind === 'kicked' && c.error.reason ? [el('p', { dir: 'auto', text: `Grund: ${c.error.reason}` })] : [];
        showCallout(box, controlErrorText(c.error), c.message, ...extra);
      } else if (c.state !== 'disconnected') {
        box.hidden = true;
      }
      renderIdentityBox(c);
    }

    // Views follow the connection: lobby once in, back to the form on failure.
    if (lastConnState !== c.state) {
      if (c.state === 'connected' && currentView() === 'verbinden') go('lobby');
      if (c.state === 'failed' && lastConnState !== null && currentView() === 'lobby') go('verbinden');
      lastConnState = c.state;
    }
  }

  function renderConnDetail(st) {
    const c = st.connection;
    const srv = st.server;
    const box = $('conn-detail');
    const server = c.server ? el('span', { dir: 'ltr', text: c.server }) : null;
    switch (c.state) {
      case 'disconnected':
        fill(box, el('p', { text: 'Nicht verbunden.' }));
        break;
      case 'connecting':
        fill(box, el('p', null, 'Verbinde mit ', server, c.attempt > 1 ? ` (Versuch ${c.attempt})` : '', ' …'));
        break;
      case 'authenticating':
        fill(box, el('p', null, 'Anmeldung bei ', server, ' …'));
        break;
      case 'connected':
        fill(
          box,
          el('p', null, badge('ok', 'Verbunden'), ' mit „', bdi(srv ? srv.name : ''), '“ (', server, ')'),
          srv ? el('p', { class: 'small muted' }, 'Deine virtuelle IP: ', el('span', { dir: 'ltr', text: srv.vip })) : null,
          srv && srv.newly_pinned
            ? el('p', {
                class: 'small muted',
                text: 'Beacon hat sich die Identität dieses Servers gemerkt. Ändert sie sich später, warnt Beacon dich, bevor es dein Passwort verwendet.',
              })
            : null,
        );
        break;
      case 'reconnecting':
        fill(
          box,
          el('p', null, badge('warn', 'Unterbrochen'), ' Verbindung zu ', server, ' verloren: ', controlErrorText(c.error)),
          el('p', { class: 'small countdown', 'aria-live': 'off', text: countdownText() }),
        );
        break;
      case 'failed':
        fill(box, el('p', null, badge('err', 'Fehlgeschlagen'), ' Verbindung zu ', server, ' fehlgeschlagen.'));
        break;
      default:
        fill(box);
    }
  }

  function renderIdentityBox(c) {
    const box = $('identity-box');
    const e = c.state === 'failed' ? c.error : null;
    if (!e || e.kind !== 'identity_changed') {
      box.hidden = true;
      return;
    }
    fill(
      $('identity-text'),
      'Beacon kennt den Server ',
      el('span', { dir: 'ltr', text: e.address }),
      ' unter dem Namen „',
      bdi(e.pinned_name),
      `“ (gespeichert am ${fmtDateTime(e.pinned_at_ms)}). Jetzt meldet er sich mit anderen Schlüsseldaten und dem Namen „`,
      bdi(e.server_name),
      '“.',
    );
    $('btn-identity-reset').dataset.server = e.address;
    box.hidden = false;
  }

  function renderLobbyBanner(st) {
    const c = st.connection;
    const box = $('lobby-banner');
    box.className = 'callout';
    switch (c.state) {
      case 'connected':
        box.hidden = true;
        return;
      case 'connecting':
      case 'authenticating':
        box.classList.add('callout-info');
        fill(box, el('strong', { text: 'Verbinde …' }), ' ', el('span', { dir: 'ltr', text: c.server || '' }));
        break;
      case 'reconnecting':
        box.classList.add('callout-warning');
        fill(
          box,
          el('strong', { text: 'Verbindung unterbrochen. ' }),
          controlErrorText(c.error),
          ' ',
          el('span', { class: 'countdown', 'aria-live': 'off', text: countdownText() }),
        );
        break;
      default:
        box.classList.add('callout-info');
        fill(box, el('strong', { text: 'Nicht verbunden. ' }), el('a', { href: '#verbinden', text: 'Zur Anmeldung' }));
    }
    box.hidden = false;
  }

  function updatePasswordHint() {
    const srv = knownServer($('f-server').value);
    const remembered = !!(srv && srv.remembered);
    setText(
      $('f-password-hint'),
      remembered
        ? 'Für diesen Server ist ein Passwort gespeichert. Leer lassen, um es zu verwenden.'
        : 'Das Server-Passwort bekommst du vom Betreiber des Servers.',
    );
    $('f-password').placeholder = remembered ? 'gespeichert' : '';
  }

  // ---------------------------------------------------------------- servers
  function renderServers(st) {
    const s = st.settings;
    if (!changed('servers', [s.servers, s.last_server])) return;
    const servers = s.servers.slice().sort((a, b) => {
      if (a.address === s.last_server) return -1;
      if (b.address === s.last_server) return 1;
      return (b.pinned_at_ms || 0) - (a.pinned_at_ms || 0);
    });
    const list = $('server-list');
    fill(list, ...servers.map((srv) => serverItem(srv, srv.address === s.last_server)));
    $('server-list-empty').hidden = servers.length > 0;
    fill($('f-server-list'), ...servers.map((srv) => el('option', { value: srv.address })));
    updatePasswordHint();
  }

  function serverItem(srv, last) {
    const pick = el('button', { type: 'button', class: 'server-pick', title: 'Adresse übernehmen' }, el('span', { dir: 'ltr', text: srv.address }));
    pick.addEventListener('click', () => {
      $('f-server').value = srv.address;
      updatePasswordHint();
      clearFieldErrors('f-server');
      ($('f-name').value ? $('f-password') : $('f-name')).focus();
    });
    const meta = el(
      'div',
      { class: 'server-meta' },
      srv.pinned_name
        ? el('span', null, 'Name: „', bdi(srv.pinned_name), '“')
        : el('span', { text: 'Noch nie angemeldet' }),
      srv.pinned_at_ms ? el('span', { text: `bekannt seit ${fmtDateTime(srv.pinned_at_ms)}` }) : null,
      srv.remembered ? badge('ok', 'Passwort gespeichert') : null,
      last ? badge('', 'zuletzt benutzt') : null,
    );
    const actions = el('div', { class: 'server-actions' });
    if (srv.remembered) {
      const forget = el('button', { type: 'button', class: 'btn btn-small', text: 'Passwort vergessen' });
      forget.addEventListener('click', () =>
        run(null, async () => {
          await api('password/forget', { server: srv.address });
          toast('Das gespeicherte Passwort wurde gelöscht.', 'success');
        }),
      );
      actions.append(forget);
    }
    if (srv.pinned_name) {
      const reset = el('button', { type: 'button', class: 'btn btn-small', text: 'Identität zurücksetzen' });
      reset.addEventListener('click', () => resetPin(srv.address, true));
      actions.append(reset);
    }
    return el('li', null, pick, meta, actions.childElementCount ? actions : null);
  }

  async function resetPin(address, ask) {
    if (
      ask &&
      !window.confirm(
        `Gespeicherte Identität von ${address} zurücksetzen?\n\nBeacon merkt sich bei der nächsten Anmeldung die dann gemeldete Identität. Ein gespeichertes Passwort wird ebenfalls gelöscht.`,
      )
    ) {
      return;
    }
    await run(ask ? null : $('btn-identity-reset'), async () => {
      await api('pin/reset', { server: address });
      toast('Identität zurückgesetzt. Gib das (neue) Passwort ein und verbinde dich erneut.', 'success');
      $('identity-box').hidden = true;
      $('connect-error').hidden = true;
      $('f-server').value = address;
      updatePasswordHint();
      go('verbinden');
      $('f-password').focus();
    });
  }

  // ------------------------------------------------------------------ lobby
  function renderLobby(st) {
    const srv = st.server;
    const connected = isConnected(st);
    setText($('lobby-server-name'), srv ? srv.name || srv.address : 'Lobby');
    const motd = $('lobby-motd');
    motd.hidden = !(srv && srv.motd);
    if (srv && srv.motd) setText(motd, srv.motd);
    $('lobby-meta').hidden = !srv;
    if (srv) setText($('lobby-vip'), srv.vip);
    const navCount = $('nav-lobby-count');
    navCount.hidden = !(connected && st.players.length);
    setText(navCount, String(st.players.length));
    renderLobbyButtons(st);
    if (changed('players', [st.players, srv && srv.vip, srv && srv.you_are_host, st.peer_files, st.fingerprint.state])) {
      renderPlayers(st);
    }
    if (changed('data-warning', [st.players, srv && srv.vip, st.peer_files])) renderDataWarning(st);
    if (changed('chat', st.chat)) renderChat(st.chat);
    if (changed('maps', [st.maps, connected])) renderMaps(st);
  }

  function renderLobbyButtons(st) {
    const connected = isConnected(st);
    const me = myPlayer(st);
    const ready = !!(me && me.ready);
    const btnReady = $('btn-ready');
    btnReady.setAttribute('aria-pressed', String(ready));
    btnReady.disabled = !connected || busy.has('btn-ready');
    const running = !!(st.game_process && st.game_process.running);
    const launch = $('btn-launch');
    setText(launch, running ? 'BFME läuft' : 'BFME starten');
    launch.disabled = !connected || running || busy.has('btn-launch');
    const all = $('btn-launch-all');
    all.hidden = !(connected && st.server && st.server.you_are_host);
    all.disabled = busy.has('btn-launch-all');
    $('btn-sync').disabled = !connected || st.maps.sync.running || !st.maps.maps_dir || busy.has('btn-sync');
  }

  function dataStatus(p, host, ctx) {
    const fp = p.fingerprint ? ` (Fingerabdruck ${p.fingerprint.slice(0, 12)})` : '';
    if (!p.fingerprint && ctx.isMe && ctx.fpComputing) {
      return { cls: 'info', text: 'wird geprüft …', title: 'Beacon berechnet gerade den Fingerabdruck deiner Spieldaten.' };
    }
    if (!p.fingerprint) return { cls: '', text: 'unbekannt', title: 'Die Spieldaten dieses Spielers sind noch nicht bekannt.' };
    if (!host || !host.fingerprint) return { cls: '', text: 'Host unbekannt', title: `Die Spieldaten des Hosts sind noch nicht bekannt${fp}.` };
    if (p.name === host.name) return { cls: 'info', text: 'Referenz', title: `Die Spieldaten des Hosts sind die Referenz${fp}.` };
    if (p.fingerprint === host.fingerprint) return { cls: 'ok', text: '✓ wie Host', title: `Gleiche Spieldaten wie der Host${fp}.` };
    return {
      cls: 'warn',
      text: '✗ weicht ab',
      title: `Andere Spieldaten als der Host – BFME lässt diesen Spieler so nicht beitreten${fp}.`,
      differs: true,
    };
  }

  function fileList(files) {
    const shown = files.slice(0, FILES_SHOWN);
    const list = el('ul', { class: 'file-list' }, ...shown.map((f) => el('li', { dir: 'ltr', text: f })));
    if (files.length > shown.length) list.append(el('li', { text: `… und ${NF.format(files.length - shown.length)} weitere` }));
    return list;
  }

  function createPlayerRow() {
    const nameCell = el('th', { scope: 'row', class: 'p-name' });
    const ping = el('td', { class: 'p-ping' });
    const dataBadge = el('span', { class: 'badge' });
    const compare = el('button', { type: 'button', class: 'link-btn', text: 'Dateien vergleichen' });
    const summary = el('summary');
    const files = el('div');
    const details = el('details', { class: 'p-files' }, summary, files);
    const data = el('td', { class: 'p-data' }, dataBadge, ' ', compare, details);
    const status = el('td', { class: 'p-status' });
    const kick = el('button', { type: 'button', class: 'btn btn-small btn-danger', text: 'Kicken' });
    const actions = el('td', { class: 'p-actions' }, kick);
    const tr = el('tr', null, nameCell, ping, data, status, actions);
    tr.refs = { nameCell, ping, dataBadge, compare, details, summary, files, status, kick };
    compare.addEventListener('click', () => {
      const name = tr.dataset.key;
      run(null, async () => {
        compare.disabled = true;
        await api('fingerprint', { name });
      }).finally(() => {
        compare.disabled = false;
      });
    });
    kick.addEventListener('click', () => {
      const name = tr.dataset.key;
      if (!window.confirm(`${name} wirklich aus der Lobby kicken?`)) return;
      run(null, async () => {
        await api('kick', { name });
        toast(`${name} wurde gekickt.`, 'success');
      });
    });
    return tr;
  }

  function updatePlayerRow(tr, p, ctx) {
    const r = tr.refs;
    const isMe = ctx.myVip !== null && p.vip === ctx.myVip;
    fill(r.nameCell, p.is_host ? crown() : null, bdi(p.name), isMe ? el('span', { class: 'you', text: '(du)' }) : null);

    const pingParts = [];
    if (p.rtt_ms === null || p.rtt_ms === undefined) pingParts.push(el('span', { class: 'muted', text: '–' }));
    else {
      const cls = p.rtt_ms < 80 ? 'ping-good' : p.rtt_ms < 150 ? 'ping-ok' : 'ping-bad';
      pingParts.push(el('span', { class: cls, text: `${NF.format(p.rtt_ms)} ms` }));
    }
    if (p.loss_pct !== null && p.loss_pct !== undefined) {
      const cls = p.loss_pct > 5 ? 'ping-bad' : p.loss_pct > 1 ? 'ping-ok' : 'muted';
      pingParts.push(el('div', { class: `small ${cls}`, text: `${NF.format(p.loss_pct)} % Verlust` }));
    }
    fill(r.ping, ...pingParts);

    const ds = dataStatus(p, ctx.host, { isMe, fpComputing: ctx.fpComputing });
    r.dataBadge.className = `badge ${ds.cls}`.trim();
    setText(r.dataBadge, ds.text);
    r.dataBadge.title = ds.title;
    const peer = ctx.peerFiles[p.name];
    r.compare.hidden = !(ds.differs && !isMe && !peer);
    r.details.hidden = !peer;
    if (peer) {
      setText(
        r.summary,
        peer.differs.length
          ? `${count(peer.differs.length, 'Datei weicht', 'Dateien weichen')} von deinen ab`
          : 'Keine Unterschiede zu deinen Dateien',
      );
      fill(r.files, peer.differs.length ? fileList(peer.differs) : null, peer.complete ? null : el('p', { class: 'small muted', text: 'Die Liste ist unvollständig.' }));
    }

    fill(
      r.status,
      badge(p.ready ? 'ok' : '', p.ready ? 'Bereit' : 'Nicht bereit'),
      p.in_game ? badge('info', 'im Spiel') : null,
    );
    r.kick.hidden = !(ctx.amHost && !isMe);
    r.kick.setAttribute('aria-label', `${p.name} kicken`);
  }

  /** Reuses rows by key, adds, removes and reorders them. */
  function syncRows(parent, items, key, create, update) {
    const existing = new Map();
    for (const child of parent.children) existing.set(child.dataset.key, child);
    let prev = null;
    const keep = new Set();
    for (const item of items) {
      const k = key(item);
      keep.add(k);
      let row = existing.get(k);
      if (!row) {
        row = create(item);
        row.dataset.key = k;
      }
      update(row, item);
      const next = prev ? prev.nextSibling : parent.firstChild;
      if (row !== next) parent.insertBefore(row, next);
      prev = row;
    }
    for (const [k, row] of existing) if (!keep.has(k)) row.remove();
  }

  function renderPlayers(st) {
    const ctx = {
      myVip: st.server ? st.server.vip : null,
      host: hostPlayer(st),
      amHost: !!(st.server && st.server.you_are_host),
      peerFiles: st.peer_files || {},
      fpComputing: st.fingerprint.state === 'computing',
    };
    syncRows($('players-body'), st.players, (p) => p.name, createPlayerRow, (tr, p) => updatePlayerRow(tr, p, ctx));
    setText($('player-count'), st.players.length ? `(${st.players.length})` : '');
    $('players-empty').hidden = st.players.length > 0;
  }

  const requestedFiles = new Set();

  function requestFilesOnce(player) {
    const key = `${player.name}\u0000${player.fingerprint}`;
    if (requestedFiles.has(key)) return;
    requestedFiles.add(key);
    api('fingerprint', { name: player.name }).catch(() => requestedFiles.delete(key));
  }

  function renderDataWarning(st) {
    const box = $('data-warning');
    const me = myPlayer(st);
    const host = hostPlayer(st);
    if (!me || !host || me === host || !me.fingerprint || !host.fingerprint || me.fingerprint === host.fingerprint) {
      box.hidden = true;
      return;
    }
    const peer = (st.peer_files || {})[host.name];
    if (!peer) requestFilesOnce(host);
    const parts = [
      el('strong', { text: 'Deine Spieldaten weichen vom Host ab.' }),
      el('p', {
        text: 'BFME lässt dich so nicht beitreten (andere Spielversion oder andere Mod-Dateien). Gleiche deine Installation an die des Hosts an.',
      }),
    ];
    if (!peer) parts.push(el('p', { class: 'small', text: 'Die Liste der abweichenden Dateien wird geladen …' }));
    else if (!peer.differs.length) {
      parts.push(el('p', { class: 'small', text: 'Keine einzelne Datei unterscheidet sich – vermutlich verwendet ihr verschiedene Beacon-Versionen.' }));
    } else {
      parts.push(el('p', { class: 'small', text: `${count(peer.differs.length, 'Datei unterscheidet', 'Dateien unterscheiden')} sich:` }), fileList(peer.differs));
      if (!peer.complete) parts.push(el('p', { class: 'small muted', text: 'Die Liste des Hosts ist unvollständig.' }));
    }
    fill(box, ...parts);
    box.hidden = false;
  }

  // ------------------------------------------------------------------- chat
  let chatKeys = [];
  const chatKey = (l) => `${l.ts}\u0000${l.from}\u0000${l.text}`;

  function chatLine(l) {
    if (!l.from) {
      return el('li', { class: 'chat-line system' }, timeEl(l.ts), el('span', { class: 'chat-text', dir: 'auto', text: l.text }));
    }
    return el(
      'li',
      { class: 'chat-line' },
      timeEl(l.ts),
      el('bdi', { class: 'chat-from', text: l.from }),
      ': ',
      el('span', { class: 'chat-text', dir: 'auto', text: l.text }),
    );
  }

  function renderChat(chat) {
    const log = $('chat-log');
    const keys = chat.map(chatKey);
    const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 24;
    // Usual case: the old lines are a (front-trimmed) prefix of the new ones.
    let start = -1;
    for (let i = 0; i < chatKeys.length && keys.length; i += 1) {
      if (chatKeys[i] !== keys[0]) continue;
      const n = chatKeys.length - i;
      if (n <= keys.length && chatKeys.slice(i).every((k, j) => k === keys[j])) {
        start = i;
        break;
      }
    }
    if (start < 0) {
      // Full rebuild without announcing the whole history to screen readers.
      log.setAttribute('aria-live', 'off');
      fill(log, ...chat.map(chatLine));
      setTimeout(() => log.removeAttribute('aria-live'), 0);
    } else {
      for (let i = 0; i < start && log.firstElementChild; i += 1) log.firstElementChild.remove();
      append(log, chat.slice(chatKeys.length - start).map(chatLine));
    }
    chatKeys = keys;
    if (atBottom) log.scrollTop = log.scrollHeight;
  }

  // ------------------------------------------------------------------- maps
  const MAP_STATES = {
    installed: ['ok', 'Installiert'],
    missing: ['warn', 'Fehlt'],
    conflict: ['err', 'Konflikt'],
    invalid: ['err', 'Ungültig'],
    downloading: ['info', 'Wird geladen'],
    failed: ['err', 'Fehlgeschlagen'],
  };

  const MAP_HINTS = {
    conflict:
      'Im Maps-Ordner liegt bereits eine eigene Datei mit diesem Namen. Beacon überschreibt sie nicht – benenne deine Datei um, wenn du die Version vom Server möchtest.',
    invalid: 'Der Server bietet diese Karte mit unzulässigen Dateinamen an; Beacon lädt sie nicht.',
    failed: 'Der Download ist fehlgeschlagen. Versuche es noch einmal.',
  };

  function mapItem(m) {
    const [cls, label] = MAP_STATES[m.state] || ['', String(m.state)];
    const hint = MAP_HINTS[m.state];
    return el(
      'li',
      null,
      el('bdi', { class: 'map-name', text: m.name }),
      el('span', { class: `map-state badge ${cls}`.trim(), text: label }),
      el('span', { class: 'map-meta', text: `${fmtBytes(m.total_size)} · ${count(m.files, 'Datei', 'Dateien')}` }),
      hint || m.problem
        ? el('p', { class: 'map-problem' }, hint || '', m.problem ? el('span', { class: 'muted', dir: 'auto', text: `${hint ? ' ' : ''}(${m.problem})` }) : null)
        : null,
    );
  }

  let syncWasRunning = null;

  /** Announces the end of a map sync (the progress text itself is not live). */
  function announceSync(sync) {
    if (syncWasRunning && !sync.running) {
      if (sync.last_error) toast('Kartenabgleich fehlgeschlagen.', 'error', sync.last_error);
      else if (sync.downloaded.length) toast(`Kartenabgleich fertig: ${count(sync.downloaded.length, 'Karte', 'Karten')} geladen.`, 'success');
      else toast('Kartenabgleich fertig: Alles ist aktuell.', 'success');
    }
    syncWasRunning = sync.running;
  }

  function renderMaps(st) {
    const m = st.maps;
    announceSync(m.sync);
    const connected = isConnected(st);
    const list = $('maps-list');
    const empty = $('maps-empty');
    let note = '';
    if (!connected) note = 'Nicht verbunden.';
    else if (!m.listing_received) note = 'Kartenliste wird geladen …';
    else if (!m.maps.length) note = 'Der Server bietet keine Karten an.';
    if (note) {
      fill(list);
      setText(empty, note);
      empty.hidden = false;
    } else {
      fill(list, ...m.maps.map(mapItem));
      empty.hidden = true;
    }

    const s = m.sync;
    const progress = $('sync-progress');
    const text = $('sync-text');
    text.className = 'small';
    if (s.running) {
      progress.hidden = false;
      progress.max = Math.max(1, s.bytes_total);
      progress.value = Math.min(s.bytes_done, progress.max);
      if (s.current) fill(text, 'Lade ', bdi(s.current), ` … ${fmtBytes(s.bytes_done)} von ${fmtBytes(s.bytes_total)}`);
      else fill(text, 'Abgleich läuft …');
      return;
    }
    progress.hidden = true;
    if (!m.maps_dir) {
      text.className = 'small muted';
      fill(text, 'Der Maps-Ordner ist unbekannt (Spiel nicht gefunden).');
    } else if (s.last_error) {
      text.className = 'small ping-ok';
      fill(text, 'Letzter Abgleich fehlgeschlagen: ', el('span', { dir: 'auto', text: s.last_error }));
    } else if (s.downloaded.length) {
      const names = [];
      s.downloaded.forEach((n, i) => names.push(i ? ', ' : '', bdi(n)));
      fill(text, 'Zuletzt geladen: ', ...names);
    } else if (connected && m.listing_received && m.maps.length) {
      const installed = m.maps.filter((x) => x.state === 'installed').length;
      text.className = 'small muted';
      fill(text, installed === m.maps.length ? 'Alle Karten sind installiert.' : `${installed} von ${m.maps.length} Karten installiert.`);
    } else {
      fill(text);
    }
  }

  // --------------------------------------------------------------- settings
  let settingsDirty = false;

  function renderSettings(st) {
    const g = st.game;
    const det = $('s-detected');
    const src = $('s-detected-src');
    if (!g) {
      setText(det, 'Erkennung läuft …');
      src.hidden = true;
    } else if (g.game_dir && g.exe) {
      setText(det, g.game_dir);
      src.hidden = false;
      src.className = 'badge';
      setText(src, g.source === 'override' ? 'eigener Ordner' : 'aus der Registry');
    } else {
      setText(det, g.game_dir || 'nicht gefunden');
      src.hidden = false;
      src.className = 'badge warn';
      setText(src, 'Spiel nicht gefunden');
    }
    if (!settingsDirty && changed('settings-form', st.settings)) fillSettings(st.settings);
  }

  function fillSettings(s) {
    $('s-gamedir').value = s.game_dir || '';
    $('s-windowed').checked = !!s.launch.windowed;
    const sel = $('s-res');
    const res = `${s.launch.xres}x${s.launch.yres}`;
    if (!s.launch.xres && !s.launch.yres) sel.value = '';
    else if ([...sel.options].some((o) => o.value === res)) sel.value = res;
    else sel.value = 'custom';
    $('s-xres').value = s.launch.xres || '';
    $('s-yres').value = s.launch.yres || '';
    $('s-res-custom').hidden = sel.value !== 'custom';
    $('s-noshellmap').checked = !!s.launch.noshellmap;
    $('s-namesync').checked = !!s.name_sync;
    $('s-autolaunch').checked = !!s.auto_launch_on_host_start;
    for (const k of ['lobby', 'game', 'other']) {
      const v = s.redundancy[k];
      $(`s-red-${k}`).value = v === null || v === undefined ? '' : String(v);
    }
    clearFieldErrors('s-gamedir', 's-res');
    $('settings-error').hidden = true;
  }

  function markSettingsDirty() {
    settingsDirty = true;
    setText($('s-status'), 'Ungespeicherte Änderungen');
  }

  // --------------------------------------------------------------- diagnose
  function kv(dl, rows) {
    const nodes = [];
    for (const [key, value] of rows) {
      if (value === null || value === undefined) continue;
      nodes.push(el('dt', { text: key }), el('dd', null, value));
    }
    fill(dl, ...nodes);
  }

  const HOOK_STATES = {
    unknown: ['', 'Unbekannt'],
    source_missing: ['err', 'wsock32.dll fehlt neben Beacon.exe'],
    not_installed: ['', 'Nicht installiert – wird beim Spielstart installiert'],
    up_to_date: ['ok', 'Installiert und aktuell'],
    outdated: ['warn', 'Veraltet – wird beim nächsten Spielstart ersetzt'],
    foreign: ['err', 'Fremde wsock32.dll im Spielordner'],
    error: ['err', 'Fehler'],
  };

  const FP_REASONS = {
    'game detection running': 'Spielerkennung läuft …',
    disabled: 'Abgeschaltet.',
    'BFME not found': 'BFME wurde nicht gefunden.',
  };

  function renderDiagnose(st) {
    if (changed('d-game', st.game)) {
      const g = st.game;
      const rows = [];
      if (!g) rows.push(['Status', 'Erkennung läuft …']);
      else {
        rows.push(['Spielordner', g.game_dir ? path(g.game_dir) : badge('err', 'nicht gefunden')]);
        rows.push(['Quelle', { override: 'eigener Ordner (Einstellungen)', registry: 'Registry (InstallPath)', none: '–' }[g.source] || String(g.source)]);
        if (g.exe) {
          rows.push(['lotrbfme.exe', path(g.exe.path)]);
          rows.push(['Größe', fmtBytes(g.exe.size)]);
          rows.push(['Version', g.exe.known ? badge('ok', g.exe.known) : badge('warn', 'unbekannte Version')]);
          rows.push(['SHA-256', g.exe.sha256 ? el('span', { class: 'mono', text: g.exe.sha256 }) : '–']);
        } else if (g.game_dir) {
          rows.push(['lotrbfme.exe', badge('err', 'fehlt')]);
        }
        if (g.user) {
          rows.push(['Einstellungen', path(g.user.prefs_dir)]);
          rows.push(['Benutzerdaten', path(g.user.data_dir)]);
          rows.push(['Karten', path(g.user.maps_dir)]);
        }
      }
      kv($('d-game'), rows);
      fill($('d-game-warnings'), ...((g && g.warnings) || []).map((w) => el('li', { dir: 'auto', text: w })));
    }

    if (changed('d-hook', [st.hook, st.game_process])) {
      const h = st.hook;
      const [cls, label] = HOOK_STATES[h.state] || ['', String(h.state)];
      // Beacon's hook (the installed one or the one the next start installs).
      const ours = ['up_to_date', 'outdated', 'not_installed'].includes(h.state);
      kv($('d-hook'), [
        ['Status', badge(cls, label)],
        ['Version', h.version || null],
        ['Installiert', h.installed || null],
        ['Verfügbar', h.available || null],
        ['Datei', h.path ? path(h.path) : h.expected ? path(h.expected) : null],
        [
          'Firewall-Abfrage',
          ours
            ? el(
                'div',
                null,
                'übersprungen',
                el('p', {
                  class: 'hint',
                  text: 'BFME fragt im Mehrspieler-Menü die alte Windows-XP-Firewall ab und bleibt ohne passende Regel hängen. Der Hook beantwortet die Abfrage deshalb selbst; deine Windows-Einstellungen bleiben unverändert.',
                }),
              )
            : null,
        ],
        ['Fehler', h.message ? el('span', { dir: 'auto', text: h.message }) : null],
      ]);
      const gp = st.game_process;
      kv(
        $('d-process'),
        gp
          ? [
              ['Status', gp.running ? badge('ok', 'läuft') : badge('', gp.exit_code === null || gp.exit_code === undefined ? 'beendet' : `beendet (Code ${gp.exit_code})`)],
              ['PID', String(gp.pid)],
              ['Gestartet', fmtDateTime(gp.started_at_ms)],
              ['Hook-Log', gp.hook_log ? path(gp.hook_log) : null],
            ]
          : [['Status', 'Nicht von Beacon gestartet']],
      );
    }

    if (changed('d-agent', st.agent)) {
      const a = st.agent;
      const num = (n) => NF.format(n || 0);
      const dropped =
        (a.dropped_no_route || 0) + (a.dropped_oversize || 0) + (a.dropped_no_session || 0) + (a.dropped_bad_destination || 0) + (a.dropped_send || 0);
      kv($('d-agent'), [
        ['Relay-Sitzung', a.session_active ? badge('ok', 'aktiv') : badge('', 'keine')],
        ['Virtuelle IP', a.vip ? el('span', { dir: 'ltr', text: a.vip }) : '–'],
        ['Lokaler Port', a.local_port ? String(a.local_port) : '–'],
        ['Ping (RTT)', a.rtt_ms === null || a.rtt_ms === undefined ? '–' : `${num(a.rtt_ms)} ms`],
        ['Paketverlust', a.loss_pct === null || a.loss_pct === undefined ? '–' : `${num(a.loss_pct)} %`],
        ['Gesendet', `${num(a.data_sent)} Pakete (+${num(a.copies_sent)} Kopien, ${fmtBytes(a.bytes_sent || 0)})`],
        ['Empfangen', `${num(a.data_received)} Pakete, ${num(a.duplicates)} Duplikate verworfen`],
        ['Zugestellt', `${num(a.delivered)} ans Spiel (+${num(a.delivered_local)} lokal)`],
        [
          'Verworfen',
          el('span', {
            title: `ohne Ziel ${num(a.dropped_no_route)}, zu groß ${num(a.dropped_oversize)}, ohne Sitzung ${num(a.dropped_no_session)}, ungültiges Ziel ${num(a.dropped_bad_destination)}, Sendefehler ${num(a.dropped_send)}`,
            text: num(dropped),
          }),
        ],
        ['Hook-Pakete', `${num(a.hook_frames)} (${num(a.hook_malformed)} fehlerhaft, ${num(a.hook_rejected)} abgelehnt)`],
        ['Relay', `${num(a.relay_rejected)} abgelehnt, ${num(a.relay_foreign)} fremd, ${num(a.server_errors)} Serverfehler`],
        ['Pings', `${num(a.pings)} gesendet, ${num(a.pongs)} beantwortet`],
        ['Abgelaufen', num(a.expired)],
      ]);
      const regs = a.registrations || [];
      fill(
        $('d-ports'),
        ...regs.map((r) =>
          el(
            'tr',
            null,
            el('td', { text: String(r.vport) }),
            el('td', { text: String(r.local_port) }),
            el('td', null, r.acked ? badge('ok', 'ja') : badge('warn', 'nein')),
            el('td', { text: fmtAgo(r.idle_ms) }),
          ),
        ),
      );
      $('d-ports-empty').hidden = regs.length > 0;
    }

    if (changed('d-fp', st.fingerprint)) {
      const f = st.fingerprint;
      const progress = $('d-fp-progress');
      progress.hidden = f.state !== 'computing';
      switch (f.state) {
        case 'computing': {
          const p = f.progress;
          progress.max = Math.max(1, p.bytes_total);
          progress.value = Math.min(p.bytes_done, progress.max);
          kv($('d-fp'), [
            ['Status', badge('info', 'wird berechnet')],
            ['Fortschritt', `${count(p.files_done, 'Datei', 'Dateien')} von ${NF.format(p.files_total)}, ${fmtBytes(p.bytes_done)} von ${fmtBytes(p.bytes_total)}`],
          ]);
          break;
        }
        case 'ready':
          kv($('d-fp'), [
            ['Status', badge('ok', 'bereit')],
            ['Kurz', el('span', { class: 'mono', text: f.short })],
            ['Vollständig', el('span', { class: 'mono', text: f.digest })],
            ['Dateien', NF.format(f.files)],
          ]);
          break;
        case 'failed':
          kv($('d-fp'), [
            ['Status', badge('err', 'fehlgeschlagen')],
            ['Fehler', el('span', { dir: 'auto', text: f.error })],
          ]);
          break;
        default:
          kv($('d-fp'), [['Status', FP_REASONS[f.reason] || f.reason || 'nicht verfügbar']]);
      }
    }

    if (changed('d-beacon', [st.version, st.instance, st.test_mode, st.data_dir])) {
      kv($('d-beacon'), [
        ['Version', st.version],
        ['Instanz', st.test_mode ? `${st.instance} (Testmodus)` : String(st.instance)],
        ['Datenordner', path(st.data_dir)],
      ]);
    }

    const g = st.game;
    const alert =
      (g && (!g.exe || (g.exe && !g.exe.known) || (g.warnings && g.warnings.length))) ||
      ['foreign', 'error', 'source_missing'].includes(st.hook.state) ||
      st.fingerprint.state === 'failed';
    $('nav-diag-alert').hidden = !alert;
  }

  // ---------------------------------------------------------------- notices
  let lastNoticeId = null;
  let launchClickedAt = 0;
  const LEVELS = { info: ['', 'Info'], warning: ['warn', 'Warnung'], error: ['err', 'Fehler'] };

  function renderNotices(st) {
    const list = st.notices || [];
    if (changed('notices', list)) {
      fill(
        $('d-notices'),
        ...list
          .slice()
          .reverse()
          .map((n) => {
            const [cls, label] = LEVELS[n.level] || ['', String(n.level)];
            return el('li', null, timeEl(n.ts_ms), badge(cls, label), el('span', { dir: 'auto', text: noticeText(n.text) }));
          }),
      );
      $('d-notices-empty').hidden = list.length > 0;
    }
    const maxId = list.reduce((m, n) => Math.max(m, n.id), -1);
    if (lastNoticeId === null) {
      lastNoticeId = maxId; // history from before this page: no toasts
      return;
    }
    for (const n of list) {
      if (n.id <= lastNoticeId) continue;
      const failed = /^cannot start BFME: ([\s\S]*)$/.exec(n.text);
      // A launch from this page already shows its error next to the button.
      if (failed && Date.now() - launchClickedAt < 15000) continue;
      // A failed login is shown in the form on "Verbinden".
      if (connectionTexts.has(n.text) && currentView() === 'verbinden') continue;
      toast(noticeText(n.text), n.level === 'error' ? 'error' : n.level === 'warning' ? 'warning' : 'info');
      if (failed) showLaunchError(launchErrorFromText(failed[1]));
    }
    lastNoticeId = Math.max(lastNoticeId, maxId);
  }

  function launchErrorFromText(text) {
    let kind = 'launch_failed';
    if (/os error 4551/.test(text)) kind = 'smart_app_control_blocked';
    else if (/belongs to another program/.test(text)) kind = 'hook_foreign';
    return new ApiError(500, { kind, message: text });
  }

  function showLaunchError(err) {
    const extra = [];
    if (err.kind === 'smart_app_control_blocked') extra.push(...SAC_EXPLAIN);
    for (const [re, hint] of LAUNCH_HINTS) if (re.test(err.detail)) extra.push(hint);
    if (err.kind === 'game_not_found') extra.push(el('p', null, el('a', { href: '#einstellungen', text: 'Zu den Einstellungen' })));
    showCallout($('launch-error'), errorText(err), err.detail, ...extra);
  }

  // ================================================================= actions
  function wire() {
    // Connect form.
    $('f-server').addEventListener('input', () => {
      updatePasswordHint();
      clearFieldErrors('f-server');
    });
    $('f-name').addEventListener('input', () => clearFieldErrors('f-name'));
    $('f-password').addEventListener('input', () => clearFieldErrors('f-password'));
    $('connect-form').addEventListener('submit', (ev) => {
      ev.preventDefault();
      clearFieldErrors('f-server', 'f-name', 'f-password');
      $('connect-error').hidden = true;
      const server = $('f-server').value.trim();
      const name = $('f-name').value;
      const password = $('f-password').value;
      const known = knownServer(server);
      const problems = [];
      if (!server) problems.push(['f-server', 'Bitte die Server-Adresse eingeben.']);
      const nameProblem = checkName(name);
      if (nameProblem) problems.push(['f-name', REASONS[nameProblem]]);
      if (!password && !(known && known.remembered)) problems.push(['f-password', REASONS.password_missing]);
      if (problems.length) {
        for (const [id, text] of problems) fieldError(id, text);
        $(problems[0][0]).focus();
        return;
      }
      const body = { server, name, remember: $('f-remember').checked };
      if (password) body.password = password;
      else body.use_remembered = true;
      run($('btn-connect'), async () => {
        await api('connect', body);
        $('f-password').value = '';
      }, (err) => {
        if (['server', 'name', 'password'].includes(err.field)) {
          fieldError(`f-${err.field}`, errorText(err));
          $(`f-${err.field}`).focus();
        } else {
          showCallout($('connect-error'), errorText(err), err.detail);
        }
      });
    });
    $('btn-disconnect').addEventListener('click', () => run($('btn-disconnect'), () => api('disconnect', {})));
    $('btn-identity-reset').addEventListener('click', () => {
      const server = $('btn-identity-reset').dataset.server;
      if (server) resetPin(server, false);
    });

    // Lobby.
    $('btn-ready').addEventListener('click', () => {
      const me = S && myPlayer(S);
      run($('btn-ready'), () => api('ready', { ready: !(me && me.ready) }));
    });
    $('btn-launch').addEventListener('click', () =>
      run(
        $('btn-launch'),
        async () => {
          $('launch-error').hidden = true;
          launchClickedAt = Date.now();
          await api('launch', {});
          toast('BFME wird gestartet …', 'success');
        },
        showLaunchError,
      ),
    );
    $('btn-launch-all').addEventListener('click', () =>
      run($('btn-launch-all'), async () => {
        await api('launch_all', {});
        toast('Startsignal an alle Spieler gesendet.', 'success');
      }),
    );
    $('btn-sync').addEventListener('click', () => run($('btn-sync'), () => api('maps/sync', {})));
    $('chat-form').addEventListener('submit', (ev) => {
      ev.preventDefault();
      const input = $('chat-input');
      const text = input.value.trim();
      if (!text) return;
      run(null, async () => {
        await api('chat', { text });
        input.value = '';
      });
    });

    // Settings.
    const form = $('settings-form');
    form.addEventListener('input', markSettingsDirty);
    form.addEventListener('change', markSettingsDirty);
    $('s-res').addEventListener('change', () => {
      $('s-res-custom').hidden = $('s-res').value !== 'custom';
      clearFieldErrors('s-res');
    });
    $('s-discard').addEventListener('click', () => {
      settingsDirty = false;
      setText($('s-status'), '');
      if (S) fillSettings(S.settings);
    });
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      clearFieldErrors('s-gamedir', 's-res');
      $('settings-error').hidden = true;
      const sel = $('s-res').value;
      let xres = null;
      let yres = null;
      if (sel === 'custom') {
        xres = Number.parseInt($('s-xres').value, 10);
        yres = Number.parseInt($('s-yres').value, 10);
        const ok = (v) => Number.isInteger(v) && v >= RES_MIN && v <= RES_MAX;
        if (!ok(xres) || !ok(yres)) {
          fieldError('s-res', REASONS.resolution_range);
          $('s-xres').focus();
          return;
        }
      } else if (sel) {
        [xres, yres] = sel.split('x').map(Number);
      }
      const gameDir = $('s-gamedir').value.trim();
      if (gameDir && !isAbsolutePath(gameDir)) {
        fieldError('s-gamedir', REASONS.path_not_absolute);
        $('s-gamedir').focus();
        return;
      }
      const red = (k) => {
        const v = $(`s-red-${k}`).value;
        return v === '' ? null : Number(v);
      };
      const patch = {
        game_dir: gameDir,
        launch: { windowed: $('s-windowed').checked, xres, yres, noshellmap: $('s-noshellmap').checked },
        name_sync: $('s-namesync').checked,
        auto_launch_on_host_start: $('s-autolaunch').checked,
        redundancy: { lobby: red('lobby'), game: red('game'), other: red('other') },
      };
      const submit = form.querySelector('button[type="submit"]');
      run(
        submit,
        async () => {
          await api('settings', patch);
          settingsDirty = false;
          delete seen['settings-form'];
          setText($('s-status'), 'Gespeichert.');
          toast('Einstellungen gespeichert.', 'success');
          if (S) render(S);
        },
        (err) => {
          if (err.field === 'game_dir') fieldError('s-gamedir', errorText(err));
          else if (err.field === 'launch') fieldError('s-res', errorText(err));
          else showCallout($('settings-error'), errorText(err), err.detail);
        },
      );
    });
    $('btn-restore-name').addEventListener('click', () =>
      run($('btn-restore-name'), async () => {
        const res = await api('name/restore', {});
        toast(
          res.restored ? 'Der ursprüngliche LAN-Name wurde wiederhergestellt.' : 'Nichts zu tun: Beacon hat den LAN-Namen nicht geändert.',
          'success',
        );
      }),
    );

    // Diagnose.
    $('btn-logs').addEventListener('click', () => run($('btn-logs'), () => api('logs/open', {})));
    $('btn-quit').addEventListener('click', () => {
      const running = S && S.game_process && S.game_process.running;
      const question = running
        ? 'Beacon beenden? BFME läuft noch und hat danach keine Netzwerkverbindung mehr.'
        : 'Beacon beenden?';
      if (!window.confirm(question)) return;
      run($('btn-quit'), () => api('quit', {}));
    });

    // Countdown of the reconnect delay.
    setInterval(() => {
      if (!S || S.connection.state !== 'reconnecting') return;
      for (const node of document.querySelectorAll('.countdown')) setText(node, countdownText());
    }, 1000);
  }

  // ============================================================ event stream
  function setOffline(offline, failures) {
    $('offline-banner').hidden = !offline || fatalShown;
    if (offline) {
      setText(
        $('offline-text'),
        failures > 3 ? 'Läuft Beacon noch? Starte Beacon.exe, falls du es beendet hast.' : 'Neuer Versuch …',
      );
    }
  }

  /** Handles one SSE block; `true` if it carried an event. */
  function handleBlock(block) {
    let event = 'message';
    const data = [];
    for (const line of block.split('\n')) {
      if (!line || line.startsWith(':')) continue;
      const i = line.indexOf(':');
      const field = i < 0 ? line : line.slice(0, i);
      let value = i < 0 ? '' : line.slice(i + 1);
      if (value.startsWith(' ')) value = value.slice(1);
      if (field === 'event') event = value;
      else if (field === 'data') data.push(value);
    }
    if (event === 'state' && data.length) {
      let st;
      try {
        st = JSON.parse(data.join('\n'));
      } catch (_) {
        return false;
      }
      render(st);
      return true;
    }
    if (event === 'quit') {
      showFatal('quit');
      return true;
    }
    return false;
  }

  /** Server-sent events over fetch (EventSource cannot send the token header). */
  async function streamEvents() {
    let delay = 1000;
    let failures = 0;
    while (!streamStop) {
      try {
        const res = await fetch('/api/events', {
          headers: { 'X-Beacon-Token': TOKEN || '', Accept: 'text/event-stream' },
          cache: 'no-store',
          credentials: 'same-origin',
        });
        if (res.status === 403) {
          showFatal('auth');
          return;
        }
        if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buf = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true }).replace(/\r\n?/g, '\n');
          let idx = buf.indexOf('\n\n');
          while (idx >= 0) {
            const block = buf.slice(0, idx);
            buf = buf.slice(idx + 2);
            if (handleBlock(block)) {
              failures = 0;
              delay = 1000;
              setOffline(false, 0);
            }
            if (streamStop) {
              reader.cancel().catch(() => {});
              return;
            }
            idx = buf.indexOf('\n\n');
          }
          if (buf.length > 32 * 1024 * 1024) throw new Error('event too large');
        }
      } catch (_) {
        /* retried below */
      }
      if (streamStop) return;
      failures += 1;
      setOffline(true, failures);
      await sleep(delay);
      delay = Math.min(delay * 2, 10000);
    }
  }

  // ==================================================================== start
  function start() {
    applyView(false);
    wire();
    if (!TOKEN) {
      showFatal('auth');
      return;
    }
    streamEvents();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
