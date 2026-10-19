const menuToggle = document.getElementById("menuToggle");
const mainNav = document.getElementById("mainNav");
const themeToggle = document.getElementById("themeToggle");
const cookieNotice = document.getElementById("cookieNotice");

// Conversion events activate only after analytics consent has loaded gtag.
document.addEventListener("click", (event) => {
  const link = event.target.closest("a");
  if (!link || typeof window.gtag !== "function") return;
  const href = link.getAttribute("href") || "";
  if (href.startsWith("tel:")) window.gtag("event", "click_to_call", { link_url: href });
  if (href.includes("wa.me/")) window.gtag("event", "whatsapp_click", { link_url: href });
  if (link.classList.contains("premium-google-review-link")) window.gtag("event", "google_reviews_click", { link_url: href });
});

document.addEventListener("submit", (event) => {
  if (typeof window.gtag !== "function") return;
  const form = event.target;
  if (form.matches('.premium-planner-form, .cab-quote-form, [action="/book"]')) {
    window.gtag("event", "generate_lead", { form_location: location.pathname });
  }
});

if (cookieNotice) {
  const cookieChoice = localStorage.getItem("waadi-cookie-choice");
  const loadAnalytics = () => {
    const analyticsId = cookieNotice.dataset.analyticsId;
    if (!analyticsId || document.querySelector('script[data-waadi-analytics]')) return;
    window.dataLayer = window.dataLayer || [];
    window.gtag = function () { window.dataLayer.push(arguments); };
    window.gtag("js", new Date());
    window.gtag("config", analyticsId, { anonymize_ip: true });
    const script = document.createElement("script");
    script.async = true;
    script.dataset.waadiAnalytics = "true";
    script.src = `https://www.googletagmanager.com/gtag/js?id=${encodeURIComponent(analyticsId)}`;
    document.head.appendChild(script);
  };
  if (cookieChoice === "accepted") loadAnalytics();
  cookieNotice.hidden = Boolean(cookieChoice);
  cookieNotice.querySelectorAll("[data-cookie-choice]").forEach((button) => {
    button.addEventListener("click", () => {
      localStorage.setItem("waadi-cookie-choice", button.dataset.cookieChoice);
      if (button.dataset.cookieChoice === "accepted") loadAnalytics();
      cookieNotice.hidden = true;
    });
  });
}

function setTheme(theme, persist = true) {
  const nextTheme = theme === "dark" ? "dark" : "light";
  document.documentElement.dataset.theme = nextTheme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", nextTheme === "dark" ? "#15111b" : "#ffffff");
  if (themeToggle) {
    const dark = nextTheme === "dark";
    themeToggle.setAttribute("aria-pressed", String(dark));
    themeToggle.setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
  }
  if (persist) localStorage.setItem("waadi-theme", nextTheme);
}

setTheme(document.documentElement.dataset.theme, false);
themeToggle?.addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));

// Premium motion: progressive enhancement with reduced-motion support.
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
if (!reduceMotion) {
  document.body.classList.add("motion-ready");

  const revealGroups = document.querySelectorAll(
    ".premium-heading, .section-intro, .nct-package-grid, .nct-destination-grid, .nct-blog-grid, .cab-trust-grid, .hotel-grid, .tour-grid, .reference-guide-grid"
  );
  revealGroups.forEach((element) => element.classList.add("motion-reveal"));

  const staggeredItems = document.querySelectorAll(
    ".nct-package-grid > article, .nct-destination-grid > article, .nct-blog-grid > article, .cab-trust-grid > article, .hotel-grid > article, .tour-grid > article, .reference-guide-grid > article"
  );
  staggeredItems.forEach((item, index) => {
    item.classList.add("motion-item");
    item.style.setProperty("--motion-order", String(index % 6));
  });

  const revealObserver = new IntersectionObserver((entries, observer) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add("motion-visible");
      observer.unobserve(entry.target);
    });
  }, { threshold: 0.02, rootMargin: "0px 0px -32px" });

  document.querySelectorAll(".motion-reveal, .motion-item").forEach((element) => revealObserver.observe(element));
}

// The overlay header needs a solid background once scrolled, whatever the motion preference.
const siteHeader = document.querySelector(".reference-header");
const updateHeader = () => siteHeader?.classList.toggle("is-scrolled", window.scrollY > 16);
updateHeader();
window.addEventListener("scroll", updateHeader, { passive: true });

const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
document.querySelectorAll('form[method="post"], form[method="POST"]').forEach((form) => {
  if (csrfToken && !form.querySelector('input[name="csrf_token"]')) {
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = "csrf_token";
    input.value = csrfToken;
    form.prepend(input);
  }
});

document.querySelectorAll("img:not([loading])").forEach((image, index) => {
  if (index > 1) image.loading = "lazy";
  image.decoding = "async";
});

if (menuToggle && mainNav) {
  menuToggle.addEventListener("click", () => {
    const isOpen = mainNav.classList.toggle("open");
    menuToggle.setAttribute("aria-expanded", String(isOpen));
    menuToggle.setAttribute("aria-label", isOpen ? "Close navigation" : "Open navigation");
  });

  mainNav.addEventListener("click", (event) => {
    if (event.target.closest("a")) {
      mainNav.classList.remove("open");
      menuToggle.setAttribute("aria-expanded", "false");
      menuToggle.setAttribute("aria-label", "Open navigation");
    }
  });

  document.addEventListener("click", (event) => {
    if (!mainNav.contains(event.target) && !menuToggle.contains(event.target)) {
      mainNav.classList.remove("open");
      menuToggle.setAttribute("aria-expanded", "false");
      menuToggle.setAttribute("aria-label", "Open navigation");
    }
  });
}

const blogSearch = document.getElementById("blogSearch");
const blogSearchForm = document.getElementById("blogSearchForm");
const blogNoResults = document.getElementById("blogNoResults");
const blogCards = [...document.querySelectorAll(".reference-blog-card")];

function filterBlogs(term) {
  const query = term.trim().toLowerCase();
  let matches = 0;
  blogCards.forEach((card) => {
    const visible = !query || card.dataset.search.includes(query);
    card.hidden = !visible;
    if (visible) matches += 1;
  });
  if (blogNoResults) blogNoResults.hidden = matches !== 0;
}

if (blogSearch && blogSearchForm) {
  blogSearch.addEventListener("input", () => filterBlogs(blogSearch.value));
  blogSearchForm.addEventListener("submit", (event) => {
    event.preventDefault();
    filterBlogs(blogSearch.value);
  });
  document.querySelectorAll("[data-tag]").forEach((tag) => {
    tag.addEventListener("click", () => {
      blogSearch.value = tag.dataset.tag;
      filterBlogs(tag.dataset.tag);
      blogSearch.focus();
    });
  });
}

// Local package matching: recommendations are computed only from active tours
// rendered by the server, so customer trip preferences never leave the browser.
const advisorForm = document.getElementById("packageAdvisorForm");
const advisorResults = document.getElementById("packageAdvisorResults");
const advisorData = document.getElementById("advisorTourData");
if (advisorForm && advisorResults && advisorData) {
  let packages = [];
  try { packages = JSON.parse(advisorData.textContent || "[]"); } catch (_) { packages = []; }
  const parsePrice = (value) => {
    const digits = String(value || "").replace(/[^0-9]/g, "");
    return digits ? Number(digits) : null;
  };
  const durationDays = (tour) => {
    const match = String(tour.duration || "").match(/(\d+)\s*Days?/i);
    return match ? Number(match[1]) : null;
  };
  const has = (text, words) => words.some((word) => text.includes(word));
  advisorForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const data = new FormData(advisorForm);
    const days = Number(data.get("days"));
    const longTrip = days >= 12;
    const guests = Number(data.get("guests"));
    const style = data.get("style");
    const budget = Number(data.get("budget"));
    const interests = data.getAll("interest");
    const scored = packages.map((tour) => {
      const text = `${tour.title} ${tour.description}`.toLowerCase();
      const price = parsePrice(tour.price);
      const tripDays = durationDays(tour);
      let fit = 0;
      const reasons = [];
      if (tripDays) {
        const gap = longTrip ? Math.abs(tripDays - 12) : Math.abs(tripDays - days);
        fit += longTrip ? (tripDays >= 9 ? Math.max(18, 32 - Math.max(0, tripDays - 12)) : 0) : Math.max(0, 30 - gap * 8);
        reasons.push(longTrip ? (tripDays >= 9 ? "A longer itinerary for an extended holiday" : `${tripDays} days, shorter than your extended trip`) : gap <= 1 ? "Trip length closely matches your plan" : gap <= 3 ? "A little flexibility on trip length" : `${tripDays} days, so allow extra time`);
      } else fit += 8;
      if (has(text, ["group", "family"]) && guests >= 4) { fit += 14; reasons.push("Designed with groups or families in mind"); }
      if (style === "luxury" && has(text, ["luxury", "5-star", "premium", "deluxe"])) { fit += 28; reasons.push("Premium stays and comfort features"); }
      if (style === "romantic" && has(text, ["honeymoon", "romantic", "couple"])) { fit += 32; reasons.push("Romantic experiences for couples"); }
      if (style === "adventure" && has(text, ["adventure", "skiing", "trekking", "rafting"])) { fit += 30; reasons.push("Adventure activities feature in this trip"); }
      if (style === "balanced" && has(text, ["classic", "family", "group"])) { fit += 12; reasons.push("A well-rounded Kashmir route"); }
      if (interests.includes("lake") && has(text, ["lake", "shikara", "houseboat"])) { fit += 10; reasons.push("Includes a Dal Lake or houseboat experience"); }
      if (interests.includes("snow") && has(text, ["gulmarg", "snow", "mountain", "skiing"])) { fit += 10; reasons.push("Good match for mountain or snow experiences"); }
      if (interests.includes("adventure") && has(text, ["adventure", "skiing", "trekking", "rafting"])) { fit += 10; reasons.push("Adventure options match your interests"); }
      if (interests.includes("family") && has(text, ["family", "group"])) { fit += 8; reasons.push("Family-friendly package option"); }
      if (style === "budget" && price) fit += Math.max(0, 18 - Math.round(price / 4000));
      if (style === "luxury" && price) fit += Math.min(15, Math.round(price / 5000));
      if (budget && price) fit += price <= budget ? 20 : -Math.min(32, Math.ceil((price - budget) / 1000));
      return { ...tour, priceValue: price, fit, reasons: [...new Set(reasons)] };
    });
    if (!scored.length) {
      const empty = createElement("div", "advisor-empty");
      empty.append(
        createElement("h3", "", "No active packages are listed yet"),
        createElement("p", "", "Please contact our Srinagar team for a custom quote."),
      );
      advisorResults.replaceChildren(empty);
      return;
    }
    const priced = [...scored].filter((item) => item.priceValue);
    const inBudget = budget ? priced.filter((item) => item.priceValue <= budget) : priced;
    const cheapest = [...(inBudget.length ? inBudget : priced)].sort((a, b) => a.priceValue - b.priceValue)[0] || scored[0];
    const best = [...scored].sort((a, b) => b.fit - a.fit)[0];
    const durationFit = (item) => {
      const tripDays = durationDays(item);
      if (!tripDays) return 0;
      const targetDays = longTrip ? 12 : days;
      return Math.max(0, 18 - Math.abs(tripDays - targetDays) * 5);
    };
    const luxury = [...scored].sort((a, b) => {
      const lux = (item) => (has(`${item.title} ${item.description}`.toLowerCase(), ["luxury", "5-star", "premium", "deluxe"]) ? 40 : 0) + (item.priceValue || 0) / 3500 + durationFit(item) + item.fit / 5;
      return lux(b) - lux(a);
    })[0];
    const distinct = [cheapest, best, luxury].map((item, index, all) => index > 0 && all.slice(0, index).some((previous) => previous.id === item.id)
      ? [...scored].filter((candidate) => !all.slice(0, index).some((previous) => previous.id === candidate.id)).sort((a, b) => index === 2
        ? ((has(`${b.title} ${b.description}`.toLowerCase(), ["luxury", "5-star", "premium", "deluxe"]) ? 40 : 0) + (b.priceValue || 0) / 3500 + durationFit(b) + b.fit / 5) - ((has(`${a.title} ${a.description}`.toLowerCase(), ["luxury", "5-star", "premium", "deluxe"]) ? 40 : 0) + (a.priceValue || 0) / 3500 + durationFit(a) + a.fit / 5)
        : b.fit - a.fit)[0] || item
      : item);
    const cards = [
      { item: distinct[0], label: "LOWEST STARTING PRICE", title: "Spend less", reason: budget && !inBudget.length ? "Every listed package is above your selected budget. Ask our team to build a closer low-cost option." : budget ? "Lowest listed package within your selected budget. Confirm inclusions and price with the team." : "Our lowest listed starting price. Ask the team which inclusions fit your budget." },
      { item: distinct[1], label: "BEST MATCH FOR YOU", title: "Best overall fit", reason: distinct[1].reasons.slice(0, 2).join(" · ") || "Closest match to your trip length and preferences." },
      { item: distinct[2], label: "COMFORT UPGRADE", title: "Go more luxurious", reason: "Our strongest premium option based on listed package details and your trip length." },
    ];
    const money = (value) => value ? `₹${value.toLocaleString("en-IN")}` : "Ask for price";
    advisorResults.replaceChildren(...cards.map(({ item, label, title, reason }) => {
      const card = createElement("article", "advisor-card");
      const top = createElement("div", "advisor-card-top");
      top.append(createElement("span", "", label), createElement("b", "", money(item.priceValue)));
      const link = createElement("a", "", "Explore this package ");
      link.href = `/tour/${encodeURIComponent(item.id)}`;
      const arrow = createElement("span", "", "→");
      arrow.setAttribute("aria-hidden", "true");
      link.append(arrow);
      card.append(
        top,
        createElement("h3", "", title),
        createElement("h4", "", item.title),
        createElement("p", "", reason),
        createElement("small", "", item.duration || "Flexible duration"),
        link,
      );
      return card;
    }));
    const enquiry = document.querySelector(".advisor-enquiry");
    const message = enquiry && enquiry.querySelector('[name="message"]');
    if (message) message.value = `AI trip analysis: ${style} style, ${days} days, ${guests} travellers${budget ? `, budget around ₹${budget.toLocaleString("en-IN")} per person` : ""}. Suggested package: ${best.title}. Interests: ${interests.join(", ") || "open to suggestions"}. Please confirm current dates, availability, inclusions and final price.`;
    const guestsSelect = enquiry && enquiry.querySelector('[name="guests"]');
    if (guestsSelect) guestsSelect.value = String(guests);
    if (style === "luxury" && enquiry) enquiry.querySelector('[name="service"]').value = "Luxury";
  });
}

// Chatbot functionality
function toggleChatbot() {
  const chatbotBody = document.getElementById("chatbot-body");
  const chatbotWidget = document.getElementById("chatbot-widget");
  const isOpen = chatbotBody.style.display !== "none";
  chatbotBody.style.display = isOpen ? "none" : "flex";
  chatbotWidget.classList.toggle("open", !isOpen);
}

function sendChatMessage() {
  const input = document.getElementById("chatbot-input");
  const message = input.value.trim();
  if (message === "") return;

  // Add user message
  const messagesDiv = document.getElementById("chatbot-messages");
  const userMsgDiv = document.createElement("div");
  userMsgDiv.className = "message user-message";
  userMsgDiv.append(createElement("p", "", message));
  messagesDiv.appendChild(userMsgDiv);
  input.value = "";

  // Scroll to bottom
  messagesDiv.scrollTop = messagesDiv.scrollHeight;

  // Simulate bot response
  setTimeout(() => {
    const botMsgDiv = document.createElement("div");
    botMsgDiv.className = "message bot-message";
    const response = getBotResponse(message.toLowerCase());
    botMsgDiv.append(createElement("p", "", response));
    messagesDiv.appendChild(botMsgDiv);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
  }, 500);
}

function handleChatInput(event) {
  if (event.key === "Enter") {
    sendChatMessage();
  }
}

function getBotResponse(message) {
  // Simple chatbot responses
  const responses = {
    greeting: [
      "Hello! How can I help you with your Kashmir or Ladakh tour?",
      "Hi there! 👋 Are you interested in our tour packages?",
      "Welcome! What would you like to know about our destinations?",
    ],
    tour: [
      "We offer amazing tours including Srinagar Paradise, Gulmarg Alpine Adventure, and more! Visit our Tours page to explore.",
      "Our Kashmir & Ladakh tours range from 4 to 12 days. Would you like to know about a specific destination?",
      "Check out our featured packages for unforgettable experiences!",
    ],
    price: [
      "Our tours range from ₹11,000 to ₹55,000 depending on duration and inclusions. Email us for customized packages!",
      "Prices vary by tour. Contact us at waadikashmirtravels@gmail.com for detailed pricing.",
    ],
    booking: [
      "You can book directly on our website! Go to Tours, select a package, and click 'View details' then 'Book this tour'.",
      "To book, visit the Tours page and follow the booking instructions. You can also contact us via WhatsApp!",
    ],
    contact: [
      "📧 Email: waadikashmirtravels@gmail.com\n📱 Phone: +91 84920 83392\n💬 WhatsApp: Click the WhatsApp button!\n📍 Based in Srinagar, Kashmir",
      "You can reach us via email, phone, or WhatsApp. We're here to help!",
    ],
  };

  let response = "I'm here to help! You can ask about tours, destinations, pricing, or how to book. What interests you?";

  if (
    message.includes("hi") ||
    message.includes("hello") ||
    message.includes("hey")
  ) {
    response = responses.greeting[Math.floor(Math.random() * responses.greeting.length)];
  } else if (
    message.includes("tour") ||
    message.includes("package")
  ) {
    response = responses.tour[Math.floor(Math.random() * responses.tour.length)];
  } else if (message.includes("price") || message.includes("cost")) {
    response = responses.price[Math.floor(Math.random() * responses.price.length)];
  } else if (message.includes("book")) {
    response = responses.booking[Math.floor(Math.random() * responses.booking.length)];
  } else if (
    message.includes("contact") ||
    message.includes("number") ||
    message.includes("email")
  ) {
    response = responses.contact[Math.floor(Math.random() * responses.contact.length)];
  }

  return response;
}

function createElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}
