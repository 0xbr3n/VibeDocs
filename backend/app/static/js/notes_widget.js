/* ------------------------------------------------------------------
 * VAPT Notes Widget — floating terminal scratchpad.
 *
 * Persists per-user via /api/notes (server-side, survives sessions).
 * Renders bottom-right of every authenticated page. The UI is fully
 * self-contained — no global handlers / no framework dependency.
 *
 * Commands recognised in the prompt:
 *
 *   :help              show the command list
 *   :clear             wipe ALL notes (with a confirm)
 *   :done <n>          toggle done-state of note #n
 *   :rm <n>            delete note #n
 *   :ls                refresh the list from the server
 *
 * Anything that doesn't start with `:` is treated as a new note's
 * content. Press Enter to commit.
 *
 * Keyboard shortcuts (global):
 *   Ctrl+`     toggle the widget open/closed
 *   Esc        close (when expanded)
 * ------------------------------------------------------------------ */
(function () {
  'use strict';

  const widget = document.getElementById('vapt-notes-widget');
  if (!widget) return;

  const pill     = widget.querySelector('#vnw-pill');
  const panel    = widget.querySelector('#vnw-panel');
  const closeBtn = widget.querySelector('#vnw-close');
  const minBtn   = widget.querySelector('#vnw-min');
  const list     = widget.querySelector('#vnw-list');
  const empty    = widget.querySelector('#vnw-empty');
  const body     = widget.querySelector('#vnw-body');
  const form     = widget.querySelector('#vnw-form');
  const input    = widget.querySelector('#vnw-input');
  const status   = widget.querySelector('#vnw-status-left');
  const badge    = widget.querySelector('#vnw-pill-badge');
  const banner   = widget.querySelector('#vnw-banner');

  // ----- Injection-token blocklist (client-side mirror of the
  // server's `_BLOCKED_TOKENS` list in `routers/notes.py`).
  // First match wins — the user sees the human label of whichever
  // pattern triggered the reject. Server validates again as defence
  // in depth so a tampered client can't bypass.
  const BLOCKED = [
    { rx: /['"]/,                       label: "quote characters (' or \")" },
    { rx: /;/,                          label: "semicolon (;)" },
    { rx: /`/,                          label: "backtick (`)" },
    { rx: /--+/,                        label: "SQL-style comment (-- / --+)" },
    { rx: /\/\*|\*\//,                  label: "C-style comment (/* */)" },
    { rx: /\/\//,                       label: "line-comment marker (//)" },
    { rx: /(?:^|\s)#/,                  label: "hash comment (#)" },
    { rx: /\{\{|\}\}/,                  label: "Jinja2 expression braces ({{ }})" },
    { rx: /\{%|%\}/,                    label: "Jinja2 statement tags ({% %})" },
    { rx: /\$\{[^}]*\}/,                label: "shell template expansion (${...})" },
    { rx: /<\s*script/i,                label: "<script> tag" },
    { rx: /<[^>]+\son\w+\s*=/i,         label: "HTML on*= event handler" },
    { rx: /\bjavascript\s*:/i,          label: "javascript: URI" },
  ];

  function _findBlockedToken(s) {
    for (const b of BLOCKED) {
      if (b.rx.test(s)) return b.label;
    }
    return null;
  }

  let notes = [];
  let loaded = false;
  /** Index history for the `:rm` / `:done` commands keeps note numbers
   * stable between renders within a single open session. */

  // ----- Helpers ---------------------------------------------------

  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    }[c]));
  }

  function setStatus(text, cls) {
    status.textContent = text || 'ready';
    status.className = 'vnw-status-left' + (cls ? ' ' + cls : '');
    // Auto-clear error/ok status after 4s so the bar settles back to
    // a neutral "ready" between operations.
    if (cls) {
      clearTimeout(setStatus._t);
      setStatus._t = setTimeout(() => {
        status.textContent = 'ready';
        status.className = 'vnw-status-left';
      }, 4000);
    }
  }

  function formatTimestamp(iso) {
    if (!iso) return '';
    try {
      const d = new Date(iso);
      const pad = n => String(n).padStart(2, '0');
      return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} `
           + `${pad(d.getHours())}:${pad(d.getMinutes())}`;
    } catch (_) { return ''; }
  }

  function updateBadge() {
    const pending = notes.filter(n => !n.is_done).length;
    const txt = pending > 99 ? '99+' : String(pending);
    if (pending > 0) {
      badge.textContent = txt;
      badge.hidden = false;
    } else {
      badge.hidden = true;
    }
    // Mirror the count onto the minimized-bar badge so a minimized
    // widget still surfaces pending-note count without restoring.
    const mb = document.getElementById('vnw-minbar-badge');
    if (mb) {
      if (pending > 0) { mb.textContent = txt; mb.hidden = false; }
      else             { mb.hidden = true; }
    }
  }

  // Notes are stored newest-first internally (server returns
  // `ORDER BY created_at DESC`), but displayed oldest-at-top /
  // newest-at-bottom so the widget feels like a terminal log — each
  // new note appends BELOW the previous one. We build the display
  // list from a reversed copy. The `#N` label still numbers in
  // chronological order (1 = oldest visible), matching what the user
  // sees on screen, so `:rm 1` deletes the topmost note.
  function _displayOrder() {
    return notes.slice().reverse();
  }

  function _scrollBodyToBottom() {
    // requestAnimationFrame so we run AFTER the browser has applied
    // the DOM mutation — otherwise scrollHeight is still the
    // pre-update value and the auto-scroll lands one frame short.
    requestAnimationFrame(() => {
      body.scrollTop = body.scrollHeight;
    });
  }

  function render() {
    list.innerHTML = '';
    if (!notes.length) {
      empty.hidden = false;
    } else {
      empty.hidden = true;
      _displayOrder().forEach((n, idx) => {
        const li = document.createElement('li');
        li.className = 'vnw-note' + (n.is_done ? ' is-done' : '');
        li.dataset.id = n.id;
        li.innerHTML = ''
          + '<button class="vnw-note-check" type="button"'
          + '        title="Toggle done"'
          + '        aria-label="Toggle done">'
          + (n.is_done ? '[x]' : '[ ]')
          + '</button>'
          + '<span class="vnw-note-text">' + escapeHtml(n.content) + '</span>'
          + '<span class="vnw-note-meta">#' + (idx+1) + ' · '
          +   escapeHtml(formatTimestamp(n.created_at))
          + '</span>'
          + '<button class="vnw-note-del" type="button"'
          + '        title="Delete note" aria-label="Delete note">✕</button>';
        list.appendChild(li);
      });
    }
    updateBadge();
    _scrollBodyToBottom();
  }

  function printLine(text, cls) {
    const p = document.createElement('div');
    p.className = 'vnw-line' + (cls ? ' ' + cls : '');
    p.textContent = text;
    // Append AFTER the notes list so command output appears below
    // the most recent note — terminal-style "each new thing under
    // the last one" flow.
    body.appendChild(p);
    _scrollBodyToBottom();
  }

  // ----- Network ---------------------------------------------------

  async function api(method, path, body) {
    const opts = {
      method, credentials: 'include',
      headers: { 'Accept': 'application/json' },
    };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const r = await fetch(path, opts);
    if (!r.ok) {
      let detail = r.statusText;
      try { detail = (await r.json()).detail || detail; } catch (_) {}
      throw new Error(detail);
    }
    const text = await r.text();
    return text ? JSON.parse(text) : null;
  }

  async function load() {
    try {
      setStatus('loading…');
      notes = await api('GET', '/api/notes');
      loaded = true;
      render();
      setStatus(notes.length + ' note' + (notes.length === 1 ? '' : 's'), 'is-ok');
    } catch (e) {
      setStatus('load failed: ' + e.message, 'is-err');
    }
  }

  async function addNote(content) {
    try {
      setStatus('saving…');
      const created = await api('POST', '/api/notes', { content });
      notes.unshift(created);
      render();
      setStatus('saved', 'is-ok');
    } catch (e) {
      setStatus(e.message, 'is-err');
      printLine('error: ' + e.message, 'is-err');
    }
  }

  async function toggleDone(id) {
    const n = notes.find(x => x.id === id);
    if (!n) return;
    try {
      const updated = await api('PATCH', '/api/notes/' + id, { is_done: !n.is_done });
      Object.assign(n, updated);
      render();
    } catch (e) {
      setStatus('update failed: ' + e.message, 'is-err');
    }
  }

  async function removeNote(id) {
    try {
      await api('DELETE', '/api/notes/' + id);
      notes = notes.filter(n => n.id !== id);
      render();
      setStatus('deleted', 'is-ok');
    } catch (e) {
      setStatus('delete failed: ' + e.message, 'is-err');
    }
  }

  async function clearAll() {
    try {
      const r = await api('DELETE', '/api/notes');
      notes = [];
      render();
      setStatus('cleared ' + (r ? r.deleted : 0) + ' note(s)', 'is-ok');
    } catch (e) {
      setStatus('clear failed: ' + e.message, 'is-err');
    }
  }

  // ----- Commands --------------------------------------------------

  const COMMANDS = {
    'help': () => {
      printLine('available commands:');
      printLine('  :help          show this help');
      printLine('  :ls            refresh the list from the server');
      printLine('  :done <n>      toggle done-state of note #n');
      printLine('  :rm <n>        delete note #n');
      printLine('  :clear         delete ALL notes (with confirmation)');
      printLine('any other text  =>  new note');
    },
    'ls':   () => { load(); },
    'clear':() => {
      if (confirm('Delete ALL notes? This cannot be undone.')) clearAll();
    },
    'done': (args) => {
      const idx = parseInt(args[0], 10);
      if (!idx || idx < 1 || idx > notes.length) {
        printLine('usage: :done <n>   (where 1 <= n <= ' + notes.length + ')', 'is-err');
        return;
      }
      // `#N` labels are computed off `_displayOrder()` (notes reversed)
      // — `#1` is the topmost visible note (the oldest). Map back to
      // the internal array so the target id matches the user's intent.
      toggleDone(_displayOrder()[idx-1].id);
    },
    'rm': (args) => {
      const idx = parseInt(args[0], 10);
      if (!idx || idx < 1 || idx > notes.length) {
        printLine('usage: :rm <n>   (where 1 <= n <= ' + notes.length + ')', 'is-err');
        return;
      }
      removeNote(_displayOrder()[idx-1].id);
    },
  };

  function runCommand(raw) {
    const parts = raw.slice(1).trim().split(/\s+/);
    const cmd = parts.shift();
    const fn = COMMANDS[cmd];
    if (!fn) {
      printLine('unknown command: ' + cmd + ' (try :help)', 'is-err');
      return;
    }
    fn(parts);
  }

  // ----- Form submit -----------------------------------------------

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const val = (input.value || '').trim();
    if (!val) return;
    if (val.startsWith(':')) {
      runCommand(val);
      input.value = '';
      return;
    }
    // Pre-flight sanitisation — refuse known injection tokens BEFORE
    // we even hit the network. Server also validates so a tampered
    // client can't bypass.
    const bad = _findBlockedToken(val);
    if (bad) {
      printLine('blocked: input contains ' + bad, 'is-err');
      setStatus('blocked: ' + bad, 'is-err');
      // Keep the user's text in the input so they can edit + retry.
      return;
    }
    addNote(val);
    input.value = '';
  });

  // ----- Delegated clicks on the note list -------------------------

  list.addEventListener('click', (e) => {
    const li = e.target.closest('.vnw-note');
    if (!li) return;
    const id = parseInt(li.dataset.id, 10);
    if (!id) return;
    if (e.target.closest('.vnw-note-check')) {
      toggleDone(id);
    } else if (e.target.closest('.vnw-note-del')) {
      if (confirm('Delete this note?')) removeNote(id);
    }
  });

  // ----- Open / close ----------------------------------------------
  //
  // Renamed from `open` / `close` to `openWidget` / `closeWidget` to
  // sidestep any potential shadowing of `window.open` / `window.close`
  // when this script runs in a context that hoists them — a strict-mode
  // closure should make local hoisting win, but the rename costs us
  // nothing and rules out one whole class of "the button does nothing"
  // failure. (The original symptom: pill OPENED the widget fine, but
  // clicking × / `_` / pressing Esc did nothing — that fits a scenario
  // where `close()` was resolving to `window.close()`, which browsers
  // silently ignore on windows the script didn't open.)

  function openWidget() {
    if (!widget || !panel || !pill) return;
    widget.dataset.state = 'expanded';
    panel.hidden = false;
    pill.setAttribute('aria-expanded', 'true');
    // Fetch on first open so the page isn't slowed by a /api/notes
    // call on every page load. Subsequent opens reuse the cache.
    if (!loaded) load();
    // Focus the input so the user can type immediately.
    if (input) setTimeout(() => { try { input.focus(); } catch(_){} }, 40);
  }

  const minbar    = widget.querySelector('#vnw-minbar');
  const minbarBadge = widget.querySelector('#vnw-minbar-badge');

  function closeWidget() {
    if (!widget) return;
    widget.dataset.state = 'collapsed';
    if (panel)  panel.hidden = true;
    if (minbar) minbar.hidden = true;
    if (pill)   pill.setAttribute('aria-expanded', 'false');
  }

  // Minimise → smooth slide-down, then dock as a slim bar at the
  // bottom edge of the screen. This is now the ONLY chrome control
  // (the × close button was removed as redundant + reported dead).
  //
  // Animation: add `.is-minimizing` so the CSS keyframe slides the
  // panel down + fades it out (≈240ms). We wait for the animation to
  // finish (animationend, with a setTimeout safety net in case the
  // event doesn't fire — reduced-motion, background tab) BEFORE
  // hiding the panel and revealing the bottom bar, so the user sees
  // the panel physically drop to the bottom rather than just blink
  // out. Re-entrancy guarded by `_minimizing` so a double-click
  // doesn't stack timers.
  let _minimizing = false;
  function minimizeWidget() {
    if (!widget || _minimizing) return;
    // If already minimized/collapsed just ensure the bar shows.
    if (!panel || panel.hidden) {
      widget.dataset.state = 'minimized';
      if (minbar) minbar.hidden = false;
      if (pill) pill.setAttribute('aria-expanded', 'false');
      return;
    }
    _minimizing = true;

    const finish = () => {
      if (!_minimizing) return;        // already finished via the other path
      _minimizing = false;
      panel.removeEventListener('animationend', onEnd);
      widget.dataset.state = 'minimized';
      panel.hidden = true;
      panel.classList.remove('is-minimizing');
      if (minbar) minbar.hidden = false;
      if (pill) pill.setAttribute('aria-expanded', 'false');
    };
    const onEnd = (e) => {
      // Only react to OUR keyframe finishing, not a child's animation.
      if (e.target === panel) finish();
    };

    panel.addEventListener('animationend', onEnd);
    panel.classList.add('is-minimizing');
    // Safety net: if animationend never fires (prefers-reduced-motion
    // disables the keyframe, or the tab is backgrounded), force the
    // handoff slightly after the CSS duration so the control is never
    // stuck half-animated.
    setTimeout(finish, 320);
  }

  // openWidget must also clear the minbar so the three states are
  // mutually exclusive. We patch it via wrapping rather than editing
  // the earlier definition so the existing first-open fetch logic
  // stays intact.
  const _openInner = openWidget;
  openWidget = function () {
    if (minbar) minbar.hidden = true;
    _openInner();
  };

  // ---- localStorage state persistence --------------------------------
  // Saves the widget state ('collapsed' | 'minimized' | 'expanded') so
  // it is restored automatically on every page load.
  const _LS_KEY = 'vapt_notes_state';

  function _saveState(state) {
    try { localStorage.setItem(_LS_KEY, state); } catch (_) {}
  }

  function _restoreState() {
    let saved;
    try { saved = localStorage.getItem(_LS_KEY); } catch (_) { return; }
    if (saved === 'minimized') {
      // Show the slim bottom bar, hide the full panel.
      widget.dataset.state = 'minimized';
      if (panel)  panel.hidden  = true;
      if (minbar) minbar.hidden = false;
      if (pill)   pill.setAttribute('aria-expanded', 'false');
    } else if (saved === 'expanded') {
      // Re-open the panel on next page load so power users who left it
      // open don't have to click the pill every time.
      openWidget();
    }
    // 'collapsed' (default) needs no action — the DOM starts collapsed.
  }

  // Patch each state-change function to also persist the new state.
  const _closeInner2 = closeWidget;
  closeWidget = function () {
    _closeInner2();
    _saveState('collapsed');
  };

  const _openInner2 = openWidget;
  openWidget = function () {
    _openInner2();
    _saveState('expanded');
  };

  const _minimizeInner2 = minimizeWidget;
  minimizeWidget = function () {
    _minimizeInner2();
    // The actual DOM change is async (animation finish). We save
    // immediately because the intent is unambiguous.
    _saveState('minimized');
  };

  // Re-expose updated references on window for inline handlers.
  try {
    window.__vnwCollapse = closeWidget;
    window.__vnwOpen     = openWidget;
    window.__vnwMinimize = minimizeWidget;
  } catch (_) { /* sandboxed contexts — ignore */ }

  // Wire the title-bar controls FIRST (before form/list listeners) so a
  // null-dereference on a missing form/list element later in the script
  // can't silently kill the close/min/Esc/Ctrl-backtick wiring. Every
  // bind is wrapped in try/catch as a final defence — if any single
  // handler fails to install, the others stay live.
  function _safeBind(target, event, handler) {
    if (!target) return;
    try { target.addEventListener(event, handler); }
    catch (err) { /* swallow: we'd rather lose one binding than the lot */ }
  }

  _safeBind(pill,     'click', openWidget);
  // `closeBtn` only exists for legacy DOM that still has the removed
  // × button; on current markup it's null and _safeBind no-ops. Kept
  // so a cached old base.html during a rolling deploy still works.
  _safeBind(closeBtn, 'click', (e) => { e.preventDefault(); closeWidget(); });
  _safeBind(minBtn,   'click', (e) => { e.preventDefault(); minimizeWidget(); });
  // Clicking anywhere on the minimized bottom bar restores the panel.
  _safeBind(minbar,   'click', (e) => { e.preventDefault(); openWidget(); });

  // Belt-and-braces: also bind a delegated click listener on document
  // that matches the controls by ID. Delegation at the document level
  // catches the same click on the bubbling phase, so even if the
  // direct listener never installs OR gets clobbered, this fires.
  // `#vnw-close` is still matched for backward-compat with any cached
  // old markup mid-deploy — it routes to closeWidget() (the pill).
  _safeBind(document, 'click', (e) => {
    if (!e.target || !e.target.closest) return;
    const hit = e.target.closest('#vnw-min, #vnw-close, #vnw-minbar');
    if (!hit) return;
    e.preventDefault();
    if (hit.id === 'vnw-min')         minimizeWidget();
    else if (hit.id === 'vnw-minbar') openWidget();
    else                              closeWidget();
  });

  // Esc handler — attached to `document`, not to `panel`. Previous
  // implementation bound on `panel` so it only fired when focus was
  // inside the widget (e.g. the input). The moment the user clicked
  // anywhere else (a topbar dropdown, the main page) Esc stopped
  // working until they clicked back into the panel. Document-level
  // with an explicit state check is much more forgiving — Esc closes
  // the widget whenever it's open, regardless of where focus is. The
  // existing `document.addEventListener('keydown', ...)` in base.html
  // (which closes topbar dropdowns on Esc) is unaffected; both run.
  _safeBind(document, 'keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (widget.dataset.state !== 'expanded') return;
    e.preventDefault();
    closeWidget();
  });

  // Global Ctrl+` toggles the widget — same shortcut every shell uses
  // for "open / close the terminal", so it should be muscle-memory.
  // `e.code === 'Backquote'` is layout-stable; `e.key === '`'` covers
  // remappers that change e.code.
  _safeBind(document, 'keydown', (e) => {
    if (!(e.ctrlKey || e.metaKey)) return;
    if (e.altKey || e.shiftKey) return;
    if (e.code === 'Backquote' || e.key === '`') {
      e.preventDefault();
      if (widget.dataset.state === 'expanded') closeWidget(); else openWidget();
    }
  });

  // Lightweight badge poll — every 90s while the page is visible —
  // so the unread-pending count on the collapsed pill stays roughly
  // accurate even if the user has the widget closed all session.
  // We don't full-render here, just refresh the cached `notes` array.
  async function pollBadge() {
    try {
      const fresh = await api('GET', '/api/notes');
      notes = fresh;
      updateBadge();
      // If currently open, also re-render so the list stays in sync
      // with edits from other tabs / sessions.
      if (widget.dataset.state === 'expanded') render();
    } catch (_) { /* swallow — pill stays on the cached count */ }
  }
  setInterval(() => {
    if (document.visibilityState === 'visible') pollBadge();
  }, 90000);

  // Run a single badge sync on initial page load so the pill shows the
  // right number before the widget is ever opened.
  pollBadge();

  // Restore the minimized/expanded state the user left the widget in
  // before navigating away. Called LAST so all event listeners, DOM
  // helpers, and function wrappers are already fully initialised.
  _restoreState();
})();
