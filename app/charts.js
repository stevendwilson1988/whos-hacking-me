(() => {
  const API = "/whos-hacking-me/api/charts";
  const REFRESH_MS = 60000, MAX_LABEL = 30;
  const $ = id => document.getElementById(id);
  const css = getComputedStyle(document.documentElement);
  const token = name => css.getPropertyValue(name).trim();
  const INK = token("--ink"), MUTED = token("--muted"), PANEL = token("--panel");
  const SLOTS = [1, 2, 3, 4, 5, 6, 7, 8].map(n => token("--series-" + n));
  const OTHER = token("--other");

  // A category keeps its color across windows, whatever its rank.
  const CATEGORY_COLORS = {
    "Secret harvesting": SLOTS[1], "WordPress attack": SLOTS[2],
    "PHP script probing": SLOTS[3], "Device or enterprise exploit": SLOTS[4], "Laravel app probing": SLOTS[5],
    "Admin tool probing": SLOTS[6], "Login page probing": SLOTS[7], "Other": OTHER
  };
  const ROUTE_COLORS = { "SSH": SLOTS[0], "Web (HTTP)": SLOTS[1] };
  // Usernames and countries aren't known in advance, so each keeps its slot while it stays charted.
  function colorKeeper() {
    const slots = new Map();
    return labels => {
      for (const label of [...slots.keys()]) if (!labels.includes(label)) slots.delete(label);
      for (const label of labels) {
        if (label === "Other" || slots.has(label)) continue;
        slots.set(label, SLOTS.findIndex((_, i) => ![...slots.values()].includes(i)));
      }
      return labels.map(label => label === "Other" ? OTHER : SLOTS[slots.get(label)]);
    };
  }
  const nameColors = colorKeeper(), placeColors = colorKeeper();

  const short = s => s.length > MAX_LABEL ? s.slice(0, MAX_LABEL - 1) + "…" : s;
  const num = n => n.toLocaleString();
  const quiet = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Labels only ever reach the canvas, where they are drawn as text and can't become HTML.
  function makeChart(id) {
    return new Chart($(id), {
      type: "doughnut",
      data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderColor: PANEL, borderWidth: 2, hoverOffset: 6 }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        cutout: "60%",
        animation: quiet ? false : { duration: 500 },
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: INK, boxWidth: 12, boxHeight: 12, padding: 10, font: { family: "Nunito, system-ui, sans-serif", size: 13 } }
          },
          tooltip: {
            backgroundColor: token("--bg"), titleColor: INK, bodyColor: INK,
            borderColor: MUTED, borderWidth: 1, padding: 10,
            callbacks: {
              title: items => items[0].chart.fullLabels[items[0].dataIndex],
              label: item => {
                const total = item.dataset.data.reduce((a, b) => a + b, 0);
                return " " + num(item.parsed) + " (" + (item.parsed / total * 100).toFixed(1) + "%)";
              }
            }
          }
        }
      }
    });
  }

  function draw(chart, slices, colors, canvas, summary) {
    chart.fullLabels = slices.map(s => s.label);
    chart.data.labels = slices.map(s => short(s.label));
    chart.data.datasets[0].data = slices.map(s => s.count);
    chart.data.datasets[0].backgroundColor = colors;
    chart.update();
    canvas.setAttribute("aria-label", summary + " " + slices.map(s => s.label + ": " + num(s.count)).join(", "));
  }

  function setCaption(id, lines) {
    $(id).replaceChildren(...lines.map(text => Object.assign(document.createElement("span"), { textContent: text })));
  }

  const share = (count, total) => (count / total * 100).toFixed(1) + "%";

  function show(d) {
    const how = d.how, cats = d.categories, names = d.usernames, places = d.countries;
    draw(howChart, how.slices, how.slices.map(s => ROUTE_COLORS[s.label]), $("chart-how"), "SSH and web attempts.");
    draw(catsChart, cats.slices, cats.slices.map(s => CATEGORY_COLORS[s.label] || OTHER), $("chart-cats"), "Web attempts by category.");
    draw(namesChart, names.slices, nameColors(names.slices.map(s => s.label)), $("chart-names"), "Fake names they use to log into scratchbuild.net.");
    draw(placesChart, places.slices, placeColors(places.slices.map(s => s.label)), $("chart-places"), "Attempts by country.");
    setCaption("how-total", how.total
      ? how.slices.map(s => s.label + ": " + num(s.count) + " (" + share(s.count, how.total) + ")")
      : ["No attempts in this period."]);
    setCaption("cats-total", cats.total ? ["Total: " + num(cats.total) + " web attempts"] : ["No web attempts in this period."]);
    setCaption("names-total", names.shown
      ? ["Top " + names.shown + " of about " + num(names.names_tried) + " usernames tried",
         "Attempts in the last hour aren't included. Other covers every remaining SSH attempt."]
      : ["No usernames to show for this period."]);
    setCaption("places-total", places.total
      ? ["Total: " + num(places.total) + " attempts", "Based on IP address. VPNs and rented servers show the server's country, not the attacker's."]
      : ["No attempts in this period."]);
  }

  async function fetchWindow(w) {
    const res = await fetch(API + "?window=" + encodeURIComponent(w), { cache: "no-store" });
    if (!res.ok) throw new Error(res.status);
    return res.json();
  }

  let current = "7d", request = 0;
  async function load() {
    const mine = ++request;
    try {
      const d = await fetchWindow(current);
      if (mine !== request) return;
      show(d);
    } catch (e) {
      if (mine === request) setCaption("cats-total", ["Couldn't load the charts. They'll try again in a minute."]);
    }
  }

  if (typeof Chart === "undefined") {
    setCaption("cats-total", ["The charts couldn't start. Reload the page to try again."]);
    return;
  }
  const howChart = makeChart("chart-how"), catsChart = makeChart("chart-cats"), namesChart = makeChart("chart-names"), placesChart = makeChart("chart-places");

  for (const btn of document.querySelectorAll("[data-window]")) {
    btn.addEventListener("click", () => {
      current = btn.dataset.window;
      for (const b of document.querySelectorAll("[data-window]")) b.setAttribute("aria-pressed", b === btn);
      load();
    });
  }
  load();
  setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);
})();
