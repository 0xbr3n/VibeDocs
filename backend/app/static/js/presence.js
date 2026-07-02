/* Live-presence client for the report detail + edit pages.
 *
 * Connects to /ws/reports/{rid}/presence and renders the connected users as
 * coloured avatar pills in any element matching `[data-presence-bar]`
 * (legacy id="presence-bar" also supported). Auto-reconnects with backoff
 * when the socket drops, pings every 25s to keep idle middleboxes from
 * cutting the connection, and gracefully degrades to a single REST snapshot
 * call if WebSockets aren't available at all (e.g. behind a proxy that
 * doesn't upgrade).
 *
 * Usage from a template:
 *   <div id="presence-bar" data-report-id="{{ report.id }}"></div>
 *   <script src="/static/js/presence.js" defer></script>
 *
 * The script auto-initialises on DOMContentLoaded — no extra wiring needed.
 */
(function () {
  'use strict';

  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]);
    });
  }

  function initialsFor(name) {
    const t = String(name || '?').trim();
    if (!t) return '?';
    const parts = t.split(/\s+/);
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  }

  function render(bar, users, myUserId) {
    if (!users || !users.length) {
      bar.hidden = true;
      bar.innerHTML = '';
      return;
    }
    bar.hidden = false;
    const others = users.filter(u => u.user_id !== myUserId).length;
    const label = users.length === 1
      ? 'Only you here'
      : (others + ' other' + (others === 1 ? '' : 's') + ' viewing');
    bar.innerHTML =
      '<span class="presence-label">' + escapeHtml(label) + '</span>' +
      users.map(function (u) {
        const isMe = (u.user_id === myUserId);
        const title = escapeHtml((u.full_name || u.username) + (isMe ? ' (you)' : ''));
        const focus = u.focus ? (' · viewing ' + escapeHtml(u.focus.resource_type) + ' #' + escapeHtml(u.focus.resource_id)) : '';
        return '' +
          '<span class="presence-pill" title="' + title + focus + '" ' +
          'style="background:' + escapeHtml(u.color || '#888') + '">' +
          escapeHtml(initialsFor(u.full_name || u.username)) +
          (isMe ? '<span class="presence-me-dot" aria-hidden="true"></span>' : '') +
          '</span>';
      }).join('');
  }

  // Single REST snapshot when WS isn't reachable. Not live, but lets at
  // least the initial list show up so the UI isn't blank.
  async function restFallback(bar, reportId, myUserId) {
    try {
      const r = await fetch('/api/reports/' + reportId + '/presence', { credentials: 'include' });
      if (!r.ok) return;
      const data = await r.json();
      render(bar, data.users || [], myUserId);
    } catch (_) { /* swallow */ }
  }

  // Fires the explicit "I'm leaving" beacon to the server. `sendBeacon`
  // is the one network primitive browsers actually deliver during page
  // teardown — `fetch()` is cancelled, and the WS close handshake races
  // the next page's WS open.
  function sendLeaveBeacon(reportId) {
    try {
      if (navigator.sendBeacon) {
        // Empty body — endpoint identifies user from the session cookie.
        navigator.sendBeacon('/api/reports/' + reportId + '/presence/leave');
      }
    } catch (_) { /* swallow — unloading anyway */ }
  }

  function connect(bar, reportId, myUserId) {
    const proto = (location.protocol === 'https:') ? 'wss:' : 'ws:';
    const url = proto + '//' + location.host + '/ws/reports/' + reportId + '/presence';
    let ws;
    let backoff = 1000;
    let pingTimer = null;
    let closed = false;
    let beaconSent = false;

    function clearPing() { if (pingTimer) { clearInterval(pingTimer); pingTimer = null; } }

    function open() {
      try { ws = new WebSocket(url); }
      catch (e) { restFallback(bar, reportId, myUserId); return; }

      ws.addEventListener('open', function () {
        backoff = 1000; // reset on success
        clearPing();
        // Keepalive so proxies don't drop the connection AND so the
        // server-side reaper sees regular liveness updates. Ping every
        // 15s — half the reaper's idle window so a single dropped frame
        // doesn't evict an otherwise-active session.
        pingTimer = setInterval(function () {
          try { ws.send(JSON.stringify({ type: 'ping' })); } catch (_) {}
        }, 15000);
      });

      ws.addEventListener('message', function (evt) {
        let msg;
        try { msg = JSON.parse(evt.data); } catch (_) { return; }
        if (msg && msg.type === 'presence') {
          render(bar, msg.users || [], myUserId);
        }
      });

      ws.addEventListener('close', function () {
        clearPing();
        if (closed) return;
        // Fall back to a one-shot REST snapshot so the bar isn't blank
        // while we wait to retry, then back off exponentially up to 30s.
        restFallback(bar, reportId, myUserId);
        setTimeout(open, backoff);
        backoff = Math.min(backoff * 2, 30000);
      });

      ws.addEventListener('error', function () {
        try { ws.close(); } catch (_) {}
      });
    }

    open();

    // Tear down cleanly when the page unloads. We listen to TWO events
    // because `beforeunload` is unreliable: it doesn't fire on bfcache
    // freezes (back/forward navigation), mobile-tab kills, or when the
    // user closes the tab quickly. `pagehide` fires in every one of
    // those cases. Both handlers are idempotent via the `closed` flag,
    // so doubling up is free.
    //
    // The beacon is fire-and-forget — even if the WS close handshake
    // doesn't complete (the new page's WS opening will probably steal
    // attention first), the server gets a definitive "user X left
    // room Y" message and can drop the connection immediately, instead
    // of waiting up to PRESENCE_IDLE_SECONDS for the reaper to notice.
    function teardown() {
      if (closed) return;
      closed = true;
      clearPing();
      if (!beaconSent) {
        beaconSent = true;
        sendLeaveBeacon(reportId);
      }
      try { if (ws) ws.close(); } catch (_) {}
    }
    window.addEventListener('beforeunload', teardown);
    window.addEventListener('pagehide', teardown);
  }

  function init() {
    // Accept either id="presence-bar" (legacy) or [data-presence-bar].
    const bars = $$('[data-presence-bar], #presence-bar');
    bars.forEach(function (bar) {
      // Mark so we don't double-init (e.g. if base.html ever pulls this in twice)
      if (bar.dataset.presenceInit === '1') return;
      bar.dataset.presenceInit = '1';
      const reportId = parseInt(bar.dataset.reportId || bar.getAttribute('data-report-id') || '0', 10);
      if (!reportId) return;
      const myUserId = parseInt(bar.dataset.myUserId || '0', 10) || null;
      bar.classList.add('presence-bar');
      bar.hidden = true; // hidden until the first presence frame arrives
      connect(bar, reportId, myUserId);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
