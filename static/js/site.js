// Interactive pieces of the public site: hero slider, destination map, tabs, trip rail and reveal-on-scroll.
(() => {
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const header = document.getElementById("siteHeader");
  const onScroll = () => header?.classList.toggle("is-scrolled", window.scrollY > 10);
  onScroll();
  window.addEventListener("scroll", onScroll, { passive: true });

  // Hero slider
  const hero = document.querySelector("[data-slider]");
  if (hero) {
    const slides = [...hero.querySelectorAll("[data-slide]")];
    const texts = [...hero.querySelectorAll("[data-slide-text]")];
    const cards = [...hero.querySelectorAll(".ws-hero-card")];
    const dots = [...hero.querySelectorAll(".ws-hero-dots button")];
    const counter = hero.querySelector("[data-current]");
    let index = 0;
    let timer = null;
    const show = (next) => {
      index = (next + slides.length) % slides.length;
      slides.forEach((slide, i) => { slide.classList.toggle("is-active", i === index); slide.setAttribute("aria-hidden", String(i !== index)); });
      texts.forEach((text, i) => { text.hidden = i !== index; text.classList.toggle("is-active", i === index); });
      cards.forEach((card, i) => { card.classList.toggle("is-active", i === index); card.setAttribute("aria-selected", String(i === index)); });
      dots.forEach((dot, i) => dot.classList.toggle("is-active", i === index));
      if (counter) counter.textContent = String(index + 1).padStart(2, "0");
      const active = cards[index];
      if (active && active.parentElement.scrollWidth > active.parentElement.clientWidth) {
        active.parentElement.scrollTo({ left: active.offsetLeft - 8, behavior: reduceMotion ? "auto" : "smooth" });
      }
    };
    const start = () => { if (!reduceMotion) { stop(); timer = setInterval(() => show(index + 1), 6500); } };
    const stop = () => { if (timer) clearInterval(timer); timer = null; };
    hero.querySelectorAll("[data-goto]").forEach((button) => button.addEventListener("click", () => { show(Number(button.dataset.goto)); start(); }));
    hero.addEventListener("mouseenter", stop);
    hero.addEventListener("mouseleave", start);
    hero.addEventListener("focusin", stop);
    let touchX = null;
    hero.addEventListener("touchstart", (event) => { touchX = event.touches[0].clientX; }, { passive: true });
    hero.addEventListener("touchend", (event) => {
      if (touchX === null) return;
      const delta = event.changedTouches[0].clientX - touchX;
      if (Math.abs(delta) > 50 && !event.target.closest(".ws-hero-cards")) { show(index + (delta < 0 ? 1 : -1)); start(); }
      touchX = null;
    });
    document.addEventListener("visibilitychange", () => (document.hidden ? stop() : start()));
    start();
  }

  // Destination map
  const places = document.querySelector("[data-places]");
  if (places) {
    const select = (i) => {
      places.querySelectorAll("[data-place]").forEach((el) => {
        const on = Number(el.dataset.place) === i;
        el.classList.toggle("is-active", on);
        if (el.getAttribute("role") === "tab") el.setAttribute("aria-selected", String(on));
      });
      places.querySelectorAll("[data-place-panel]").forEach((panel) => { panel.hidden = Number(panel.dataset.placePanel) !== i; });
      places.querySelectorAll("[data-place-bg]").forEach((img) => img.classList.toggle("is-active", Number(img.dataset.placeBg) === i));
    };
    places.querySelectorAll("[data-place]").forEach((el) => {
      el.addEventListener("click", () => select(Number(el.dataset.place)));
      el.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select(Number(el.dataset.place)); } });
    });
  }

  // Tabs
  document.querySelectorAll("[data-tabs]").forEach((group) => {
    const buttons = [...group.querySelectorAll("[data-tab]")];
    buttons.forEach((button) => button.addEventListener("click", () => {
      buttons.forEach((b) => { const on = b === button; b.classList.toggle("is-active", on); b.setAttribute("aria-selected", String(on)); });
      group.querySelectorAll("[data-tab-panel]").forEach((panel) => { panel.hidden = panel.dataset.tabPanel !== button.dataset.tab; });
    }));
  });

  // Horizontal trip rail
  document.querySelectorAll("[data-scroll]").forEach((button) => {
    const rail = button.closest("section")?.querySelector("[data-rail]");
    if (!rail) return;
    button.addEventListener("click", () => {
      const card = rail.firstElementChild;
      const step = card ? card.getBoundingClientRect().width + 20 : 320;
      rail.scrollBy({ left: Number(button.dataset.scroll) * step, behavior: reduceMotion ? "auto" : "smooth" });
    });
  });

  // A season tile links to the quote form with ?season=…; note it in the trip details.
  const season = new URLSearchParams(location.search).get("season");
  const brief = document.querySelector("#tripBrief textarea[name='message']");
  if (season && brief && !brief.value) brief.value = `I'd like to travel in ${season}. `;

  // Treks page: filter cards by type and difficulty
  const trekFilters = document.querySelector("[data-trek-filters]");
  const trekGrid = document.querySelector("[data-trek-grid]");
  if (trekFilters && trekGrid) {
    const chosen = { kind: "all", difficulty: "all" };
    const count = trekFilters.querySelector("[data-trek-count]");
    const empty = document.querySelector("[data-trek-empty]");
    trekFilters.querySelectorAll("[data-filter]").forEach((button) => button.addEventListener("click", () => {
      chosen[button.dataset.filter] = button.dataset.value;
      trekFilters.querySelectorAll(`[data-filter="${button.dataset.filter}"]`).forEach((b) => {
        const on = b === button;
        b.classList.toggle("is-active", on);
        b.setAttribute("aria-pressed", String(on));
      });
      let shown = 0;
      trekGrid.querySelectorAll(".ws-trek").forEach((card) => {
        const match = ["kind", "difficulty"].every((key) => chosen[key] === "all" || card.dataset[key] === chosen[key]);
        card.hidden = !match;
        if (match) shown += 1;
      });
      if (count) count.textContent = shown;
      const noun = trekFilters.querySelector("[data-trek-noun]");
      if (noun) noun.textContent = shown === 1 ? "trip" : "trips";
      if (empty) empty.hidden = shown > 0;
    }));
  }

  // Reveal on scroll
  if (!reduceMotion && "IntersectionObserver" in window) {
    const targets = document.querySelectorAll(".ws-section .ws-wrap > *:not(.ws-tiles):not(form), .ws-trips .ws-wrap, .ws-exp, .ws-stay, .ws-tour, .ws-post, .ws-dest-row, .ws-values article, .ws-steps article");
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      });
    }, { rootMargin: "0px 0px -40px" });
    targets.forEach((el) => {
      if (el.getBoundingClientRect().top < window.innerHeight) return;
      el.classList.add("ws-reveal");
      observer.observe(el);
    });
  }
})();
