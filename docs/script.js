// ── Mobile nav toggle ──
const toggle = document.getElementById('nav-toggle');
const links = document.getElementById('nav-links');
if (toggle && links) {
  toggle.addEventListener('click', () => links.classList.toggle('open'));
  links.addEventListener('click', (e) => {
    if (e.target.tagName === 'A') links.classList.remove('open');
  });
}

// ── Scroll-driven fade-in ──
if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.style.animationPlayState = 'running';
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });

  document.querySelectorAll(
    '.section-number, .section h2, .section-lead, ' +
    '.card, .feature-card, .step, .vector-card, ' +
    '.arch-box, .pipeline, .rules-table-wrap'
  ).forEach((el, i) => {
    el.style.animationPlayState = 'paused';
    el.style.animationDelay = `${(i % 6) * 0.06}s`;
    observer.observe(el);
  });
}

// ── Nav background on scroll ──
const nav = document.getElementById('nav');
if (nav) {
  let ticking = false;
  window.addEventListener('scroll', () => {
    if (!ticking) {
      requestAnimationFrame(() => {
        nav.style.borderBottomColor = window.scrollY > 40
          ? 'var(--border)'
          : 'transparent';
        ticking = false;
      });
      ticking = true;
    }
  });
}

// ── Active nav link highlighting ──
const sections = document.querySelectorAll('.section, .hero');
const navAnchors = document.querySelectorAll('.nav-links a[href^="#"]');
if (sections.length && navAnchors.length) {
  const sectionObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        const id = entry.target.id;
        navAnchors.forEach((a) => {
          a.style.color = a.getAttribute('href') === `#${id}`
            ? 'var(--text)'
            : '';
        });
      }
    });
  }, { threshold: 0.3 });
  sections.forEach((s) => sectionObserver.observe(s));
}
