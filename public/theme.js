// Light / Dark / Follow-system colour mode using Bootstrap 5.3 colour modes.
// Loaded synchronously in <head> so the right theme is applied before first paint.
(() => {
  'use strict';
  const KEY = 'msuser-theme';
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  const icons = { light: 'bi-sun-fill', dark: 'bi-moon-stars-fill', auto: 'bi-circle-half' };
  const labels = { light: 'light', dark: 'dark', auto: 'system' };

  const stored = () => {
    try {
      const v = localStorage.getItem(KEY);
      return v === 'light' || v === 'dark' || v === 'auto' ? v : 'auto';
    } catch {
      return 'auto';
    }
  };
  const save = (v) => {
    try {
      localStorage.setItem(KEY, v);
    } catch {
      /* storage unavailable (private mode etc.) – the choice just won't persist */
    }
  };
  const resolve = (pref) => (pref === 'auto' ? (media.matches ? 'dark' : 'light') : pref);
  const apply = (pref) => document.documentElement.setAttribute('data-bs-theme', resolve(pref));

  const syncMenu = (pref) => {
    const toggle = document.getElementById('themeToggle');
    if (!toggle) return;
    const icon = toggle.querySelector('.theme-icon-active');
    icon.className = `bi ${icons[pref]} theme-icon-active`;
    toggle.setAttribute('aria-label', `Colour theme (${labels[pref]})`);
    document.querySelectorAll('[data-theme-value]').forEach((btn) => {
      const active = btn.dataset.themeValue === pref;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-pressed', String(active));
      btn.querySelector('.bi-check2')?.classList.toggle('d-none', !active);
    });
  };

  apply(stored());

  media.addEventListener('change', () => {
    if (stored() === 'auto') apply('auto');
  });

  window.addEventListener('DOMContentLoaded', () => {
    syncMenu(stored());
    document.querySelectorAll('[data-theme-value]').forEach((btn) =>
      btn.addEventListener('click', () => {
        const pref = btn.dataset.themeValue;
        save(pref);
        apply(pref);
        syncMenu(pref);
      }),
    );
  });
})();
