// Shared app bar + navigation (bottom bar on phones, rail on desktop).
const PAGES = [
    ['vault', 'Vault', './vault.html', '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>'],
    ['lab', 'Lab', './lab.html', '<path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 1.8 3h10.4A2 2 0 0 0 19 18l-5-9V3"/>'],
    ['compare', 'Compare', './compare.html', '<path d="M5 20V10M12 20V4M19 20v-7"/>'],
];
const current = document.body.dataset.page;
const title = document.body.dataset.title || 'Qsytale';

const bar = document.createElement('header');
bar.className = 'appbar';
bar.innerHTML = '<div class="logo">Q</div><div><h1></h1><small>Quantum-safe file vault</small></div>';
bar.querySelector('h1').textContent = title;

const nav = document.createElement('nav');
nav.className = 'nav';
nav.setAttribute('aria-label', 'Primary');
for (const [id, label, href, icon] of PAGES) {
    const a = document.createElement('a');
    a.href = href;
    if (id === current) a.setAttribute('aria-current', 'page');
    a.innerHTML = `<span class="pill"><svg viewBox="0 0 24 24" aria-hidden="true">${icon}</svg></span><span>${label}</span>`;
    nav.appendChild(a);
}
document.body.prepend(bar);
document.body.append(nav);
