/* ==========================================================================
   Greenlight component behaviours — vanilla JS, no dependencies.
   Load with: <script src="design-system/components.js" defer></script>
   Everything is opt-in via data attributes; safe to include on any page.

   API (window.GL):
     GL.toast(message)                      — show a toast
     GL.openDialog(el) / GL.closeDialog(el) — show/hide an .overlay
   Auto-wired on DOMContentLoaded:
     [data-theme-toggle]     — flips light/dark, persists to localStorage
     [data-pressed-group]    — exclusive aria-pressed groups (chips, segs)
     [data-dialog-open="id"] — opens overlay #id
     [data-dialog-close]     — closes the containing .overlay
     .search                 — toggles .has-q + wires .search-clear
   ========================================================================== */
(function () {
  "use strict";
  var GL = {};

  /* ---- Theme -------------------------------------------------------------- */
  var root = document.documentElement;
  try {
    var saved = localStorage.getItem('gl-theme');
    if (saved) root.setAttribute('data-theme', saved);
  } catch (err) {}

  function toggleTheme() {
    var isDark = root.getAttribute('data-theme') === 'dark' ||
      (!root.getAttribute('data-theme') && window.matchMedia('(prefers-color-scheme: dark)').matches);
    var next = isDark ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('gl-theme', next); } catch (err) {}
  }

  /* ---- Toast ---------------------------------------------------------------- */
  function toastWrap() {
    var w = document.querySelector('.toast-wrap');
    if (!w) {
      w = document.createElement('div');
      w.className = 'toast-wrap';
      w.setAttribute('aria-live', 'polite');
      document.body.appendChild(w);
    }
    return w;
  }
  GL.toast = function (msg) {
    var t = document.createElement('div');
    t.className = 'toast';
    var dot = document.createElement('span');
    dot.className = 'toast-dot';
    t.appendChild(dot);
    t.appendChild(document.createTextNode(msg));
    toastWrap().appendChild(t);
    var sr = document.querySelector('.overlay.show .toast-sr');
    if (sr) sr.textContent = msg;
    setTimeout(function () {
      t.style.transition = 'opacity .3s, transform .3s';
      t.style.opacity = '0';
      t.style.transform = 'translateY(8px)';
      setTimeout(function () { t.remove(); }, 320);
    }, 2200);
  };

  /* ---- Dialog ---------------------------------------------------------------- */
  var lastFocus = null;
  GL.openDialog = function (el) {
    if (typeof el === 'string') el = document.getElementById(el);
    if (!el) return;
    lastFocus = document.activeElement;
    el.classList.add('show');
    /* aria-modal="true" hides everything outside this dialog from assistive
       tech — including .toast-wrap, which lives on <body>. So an action taken
       inside the dialog confirmed itself into a region screen readers could not
       see. Give the dialog its own live region, created on open so it is already
       in the tree by the time anything is written to it, and mirror toasts into
       it while the dialog is up. */
    if (!el.querySelector('.toast-sr')) {
      var sr = document.createElement('div');
      sr.className = 'toast-sr sr-only';
      sr.setAttribute('aria-live', 'polite');
      (el.querySelector('.panel') || el).appendChild(sr);
    }
    var closer = el.querySelector('[data-dialog-close]');
    if (closer) closer.focus();
  };
  GL.closeDialog = function (el) {
    if (typeof el === 'string') el = document.getElementById(el);
    if (!el) el = document.querySelector('.overlay.show');
    if (!el) return;
    el.classList.remove('show');
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  };

  /* ---- Auto-wiring ---------------------------------------------------------- */
  function wire() {
    document.querySelectorAll('[data-theme-toggle]').forEach(function (b) {
      b.addEventListener('click', toggleTheme);
    });

    /* Exclusive pressed groups: <div data-pressed-group><button aria-pressed>… */
    document.querySelectorAll('[data-pressed-group]').forEach(function (group) {
      group.addEventListener('click', function (e) {
        var btn = e.target.closest('[aria-pressed]');
        if (!btn || !group.contains(btn)) return;
        group.querySelectorAll('[aria-pressed]').forEach(function (b) {
          b.setAttribute('aria-pressed', String(b === btn));
        });
      });
    });

    document.querySelectorAll('[data-dialog-open]').forEach(function (b) {
      b.addEventListener('click', function () { GL.openDialog(b.getAttribute('data-dialog-open')); });
    });
    document.querySelectorAll('.overlay').forEach(function (ov) {
      ov.addEventListener('click', function (e) {
        if (e.target === ov || e.target.closest('[data-dialog-close]')) GL.closeDialog(ov);
      });
    });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') GL.closeDialog();
    });

    /* Search boxes: clear button + has-q class */
    document.querySelectorAll('.search').forEach(function (wrap) {
      var input = wrap.querySelector('input');
      var clr = wrap.querySelector('.search-clear');
      if (!input) return;
      input.addEventListener('input', function () {
        wrap.classList.toggle('has-q', input.value.length > 0);
      });
      if (clr) clr.addEventListener('click', function () {
        input.value = '';
        wrap.classList.remove('has-q');
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.focus();
      });
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire);
  else wire();

  window.GL = GL;
})();
