(() => {
  const API = "/whos-hacking-me/api/charts";
  const REFRESH_MS = 60000, MAX_LABEL = 30;
  const $ = id => document.getElementById(id);
  const css = getComputedStyle(document.documentElement);
  const token = name => css.getPropertyValue(name).trim();
  const INK = token("--ink"), MUTED = token("--muted"), PANEL = token("--panel");
  const SLOTS = [1, 2, 3, 4, 5, 6, 7, 8].map(n => token("--series-" + n));
  const OTHER = token("--other"), LINE = token("--line");

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

  const FONT = { family: "Nunito, system-ui, sans-serif", size: 13 };
  const LEGEND = {
    position: "bottom",
    labels: { color: INK, boxWidth: 12, boxHeight: 12, padding: 10, font: FONT }
  };
  const TOOLTIP = {
    backgroundColor: token("--bg"), titleColor: INK, bodyColor: INK,
    borderColor: MUTED, borderWidth: 1, padding: 10
  };

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
          legend: LEGEND,
          tooltip: {
            ...TOOLTIP,
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

  function makeLineChart(id) {
    const line = (label, color) => ({
      label, data: [], borderColor: color, backgroundColor: color,
      borderWidth: 2, pointRadius: 0, pointHoverRadius: 4, cubicInterpolationMode: "monotone"
    });
    const axis = { color: MUTED, font: FONT };
    return new Chart($(id), {
      type: "line",
      data: { labels: [], datasets: [line("SSH", ROUTE_COLORS["SSH"]), line("Web (HTTP)", ROUTE_COLORS["Web (HTTP)"])] },
      options: {
        responsive: true, maintainAspectRatio: false,
        animation: quiet ? false : { duration: 500 },
        interaction: { mode: "index", intersect: false },
        scales: {
          x: { ticks: { ...axis, autoSkip: true, maxTicksLimit: 8, maxRotation: 0 }, grid: { color: LINE } },
          y: { beginAtZero: true, ticks: { ...axis, precision: 0, callback: v => num(v) }, grid: { color: LINE } }
        },
        plugins: {
          legend: LEGEND,
          tooltip: {
            ...TOOLTIP,
            callbacks: {
              title: items => items[0].chart.fullLabels[items[0].dataIndex],
              label: item => " " + item.dataset.label + ": " + num(item.parsed.y)
            }
          }
        }
      }
    });
  }

  // Bucket starts arrive in UTC; they're shown in the visitor's own time zone.
  const TICK = {
    "24h": { hour: "numeric" },
    "7d": { weekday: "short", hour: "numeric" },
    "all": { month: "short", day: "numeric" }
  };
  const FULL = {
    hour: { weekday: "short", month: "short", day: "numeric", hour: "numeric" },
    day: { weekday: "short", month: "short", day: "numeric", year: "numeric" }
  };
  const when = (t, opts) => new Date(t).toLocaleString(undefined, opts);

  function drawTimeline(t) {
    const points = t.points;
    timeChart.fullLabels = points.map(p => when(p.t, FULL[t.step]));
    timeChart.data.labels = points.map(p => when(p.t, TICK[current]));
    timeChart.data.datasets[0].data = points.map(p => p.ssh);
    timeChart.data.datasets[1].data = points.map(p => p.web);
    timeChart.update();
    const unit = t.step === "hour" ? "hour" : "day";
    const ssh = points.reduce((a, p) => a + p.ssh, 0), web = points.reduce((a, p) => a + p.web, 0);
    const busiest = points.reduce((best, p) => p.ssh + p.web > best.ssh + best.web ? p : best, points[0] || { ssh: 0, web: 0 });
    const peak = busiest.ssh + busiest.web;
    const peakText = peak
      ? "Busiest " + unit + ": " + when(busiest.t, FULL[t.step]) + ", " + num(peak) + " attempts"
      : "No attempts in this period.";
    setCaption("time-total", [peakText, "Each point is one " + unit + ". SSH: " + num(ssh) + ", web: " + num(web) + "."]);
    $("chart-time").setAttribute("aria-label", "SSH and web attempts over time, one point per " + unit + ". SSH total " + num(ssh) + ", web total " + num(web) + ". " + peakText);
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
    drawTimeline(d.timeline);
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
  const timeChart = makeLineChart("chart-time");

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
