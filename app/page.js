(() => {
  const VISITS = "/whos-hacking-me/api/visits", FACETS = "/whos-hacking-me/api/facets";
  const POLL_MS = 3000, PAGE_SIZE = 500;
  const $ = id => document.getElementById(id);
  const rows = $("rows"), hideFailed = $("hide-failed"), older = $("older"), statusEl = $("status");

  // { column: { mode: "in" | "not", values: Set } }. "not" with no values means no filter.
  const filters = {};
  let dates = { from: "", to: "" };
  let sort = null;
  let lastId = null, oldest = null, loaded = 0;
  let generation = 0;

  const when = iso => new Date(iso).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit"
  });

  function makeRow(v, fresh) {
    const tr = document.createElement("tr");
    if (fresh) tr.className = "fresh";
    const cells = [
      ["when", when(v.ts)], ["ip", v.ip], ["", v.location], ["hacking " + String(v.hacking_me).toLowerCase(), v.hacking_me], ["category", v.category],
      ["after", v.after_what], ["page", v.path], ["result" + (v.status >= 400 || v.status === 0 ? "" : " ok"), v.result]
    ];
    for (const [cls, text] of cells) {
      const td = document.createElement("td");
      if (cls) td.className = cls;
      td.textContent = text;
      tr.appendChild(td);
    }
    return tr;
  }

  const isActive = f => !(f.mode === "not" && f.values.size === 0);

  // Dates are picked in the viewer's time zone and sent as UTC; the end date is inclusive.
  function dayToUtc(day, addDays) {
    const [y, m, d] = day.split("-").map(Number);
    return new Date(y, m - 1, d + addDays).toISOString().slice(0, 19);
  }

  function criteria(skipColumn) {
    const out = { filters: {}, hide_failed: hideFailed.checked };
    for (const [col, f] of Object.entries(filters)) {
      if (col !== skipColumn) out.filters[col] = { mode: f.mode, values: [...f.values] };
    }
    if (dates.from) out.from = dayToUtc(dates.from, 0);
    if (dates.to) out.to = dayToUtc(dates.to, 1);
    return out;
  }

  async function post(url, body) {
    const res = await fetch(url, {
      method: "POST", cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    if (!res.ok) throw new Error(res.status);
    return res.json();
  }

  function setLive(on) {
    statusEl.textContent = !on ? "Reconnecting" : sort ? "Live counts (new rows show when sorting is cleared)" : "Live";
    statusEl.classList.toggle("off", !on);
  }

  const filtering = () => Object.keys(filters).length > 0 || dates.from || dates.to || hideFailed.checked;

  function showCounts(d) {
    if (d.total === undefined) return;
    $("total").textContent = filtering()
      ? d.matching.toLocaleString() + " of " + d.total.toLocaleString()
      : d.total.toLocaleString();
    $("total-label").textContent = d.total === 1 ? "visit" : "visits";
    $("ips").textContent = d.ips.toLocaleString();
  }

  function paintHeaders() {
    for (const th of document.querySelectorAll("th[data-col]")) {
      const col = th.dataset.col;
      const on = col === "ts" ? Boolean(dates.from || dates.to) : Boolean(filters[col]);
      const btn = th.querySelector(".th-btn");
      btn.classList.toggle("active", on);
      btn.querySelector(".mark").textContent = sort && sort.col === col ? (sort.dir === "asc" ? " ↑" : " ↓") : "";
      btn.setAttribute("aria-label", th.dataset.label + (on ? ", filtered" : "") + ". Open filter and sort menu");
    }
    $("clear-all").hidden = !filtering() && !sort;
  }

  async function reload() {
    const gen = ++generation;
    paintHeaders();
    try {
      const d = await post(VISITS, { ...criteria(), sort, limit: PAGE_SIZE, counts: true });
      if (gen !== generation) return;
      rows.replaceChildren(...d.visits.map(v => makeRow(v, false)));
      lastId = d.max_id;
      loaded = d.visits.length;
      oldest = loaded ? d.visits[loaded - 1].id : null;
      older.hidden = loaded < PAGE_SIZE;
      $("empty").hidden = loaded > 0;
      showCounts(d);
      setLive(true);
    } catch (e) {
      if (gen === generation) setLive(false);
    }
  }

  async function poll() {
    if (lastId === null) return;
    const gen = generation;
    try {
      const d = await post(VISITS, { ...criteria(), sort, after: lastId, limit: PAGE_SIZE });
      if (gen !== generation) return;
      lastId = d.max_id;
      if (!sort && d.visits.length) {
        rows.prepend(...d.visits.map(v => makeRow(v, true)));
        loaded += d.visits.length;
        $("empty").hidden = true;
      }
      showCounts(d);
      setLive(true);
    } catch (e) {
      if (gen === generation) setLive(false);
    }
  }

  older.addEventListener("click", async () => {
    const gen = generation;
    const page = sort ? { offset: loaded } : { before: oldest };
    try {
      const d = await post(VISITS, { ...criteria(), sort, limit: PAGE_SIZE, ...page });
      if (gen !== generation) return;
      rows.append(...d.visits.map(v => makeRow(v, false)));
      loaded += d.visits.length;
      if (d.visits.length) oldest = d.visits[d.visits.length - 1].id;
      older.hidden = d.visits.length < PAGE_SIZE;
    } catch (e) {
      setLive(false);
    }
  });

  /* ---------- Excel-style column menus ---------- */
  let pop = null, popButton = null;

  function closePop() {
    if (!pop) return;
    pop.remove();
    pop = null;
    document.removeEventListener("mousedown", outsideClick);
    if (popButton) popButton.focus();
    popButton = null;
  }

  function outsideClick(e) {
    if (pop && !pop.contains(e.target) && !popButton.contains(e.target)) closePop();
  }

  function el(tag, props, ...kids) {
    const node = Object.assign(document.createElement(tag), props);
    node.append(...kids);
    return node;
  }

  function placePop(button) {
    const r = button.getBoundingClientRect();
    const left = Math.max(16, Math.min(r.left, innerWidth - pop.offsetWidth - 16));
    const top = Math.max(16, Math.min(r.bottom + 4, innerHeight - pop.offsetHeight - 16));
    pop.style.left = left + "px";
    pop.style.top = top + "px";
  }

  function sortButtons(col) {
    const labels = col === "ts" ? ["Oldest first", "Newest first"] : ["Sort A to Z", "Sort Z to A"];
    const apply = dir => () => {
      // Newest first is the default order, and the only one that shows rows live.
      sort = col === "ts" && dir === "desc" ? null : { col, dir };
      closePop();
      reload();
    };
    return el("div", { className: "row" },
      el("button", { type: "button", textContent: labels[0], onclick: apply("asc") }),
      el("button", { type: "button", textContent: labels[1], onclick: apply("desc") }));
  }

  function actionRow(onApply, onClear) {
    const apply = el("button", { type: "button", className: "primary", textContent: "Apply", onclick: onApply });
    const row = el("div", { className: "row" },
      el("button", { type: "button", textContent: "Clear", onclick: onClear }),
      el("button", { type: "button", textContent: "Cancel", onclick: closePop }),
      apply);
    return { row, apply };
  }

  function openDateMenu(col) {
    const from = el("input", { type: "date", id: "pop-from", value: dates.from });
    const to = el("input", { type: "date", id: "pop-to", value: dates.to });
    const { row } = actionRow(
      () => { dates = { from: from.value, to: to.value }; closePop(); reload(); },
      () => { dates = { from: "", to: "" }; closePop(); reload(); }
    );
    pop.append(
      sortButtons(col),
      el("div", { className: "row" },
        el("label", { className: "field", htmlFor: "pop-from" }, "From", from),
        el("label", { className: "field", htmlFor: "pop-to" }, "To", to)),
      row);
  }

  function openValueMenu(col) {
    const saved = filters[col];
    const draft = saved ? { mode: saved.mode, values: new Set(saved.values) } : { mode: "not", values: new Set() };
    const ticked = v => (draft.mode === "not") !== draft.values.has(v);
    const setTick = (v, on) => {
      if ((draft.mode === "not") === on) draft.values.delete(v); else draft.values.add(v);
    };

    const search = el("input", { type: "search", id: "pop-search", placeholder: "Search", autocomplete: "off" });
    const list = el("div", { className: "list" });
    const note = el("p", { className: "note" });
    const { row, apply } = actionRow(
      () => {
        if (isActive(draft)) filters[col] = draft; else delete filters[col];
        closePop();
        reload();
      },
      () => { delete filters[col]; closePop(); reload(); }
    );

    let shown = [], token = 0;
    const refreshApply = () => { apply.disabled = draft.mode === "in" && draft.values.size === 0; };

    function render() {
      list.replaceChildren();
      const allOn = shown.length > 0 && shown.every(v => ticked(v.value));
      const all = el("input", { type: "checkbox", id: "pop-all", checked: allOn });
      all.onchange = () => {
        if (search.value.trim()) {
          shown.forEach(v => setTick(v.value, all.checked));
        } else {
          draft.mode = all.checked ? "not" : "in";
          draft.values.clear();
        }
        render();
      };
      list.append(el("label", { className: "opt", htmlFor: "pop-all" }, all,
        el("span", { textContent: search.value.trim() ? "(Select all results)" : "(Select all)" })));
      shown.forEach((v, i) => {
        const id = "pop-opt-" + i;
        const box = el("input", { type: "checkbox", id, checked: ticked(v.value) });
        box.onchange = () => { setTick(v.value, box.checked); render(); };
        list.append(el("label", { className: "opt", htmlFor: id }, box,
          el("span", { textContent: v.value === null ? "(blank)" : v.value }),
          el("small", { textContent: v.n.toLocaleString() })));
      });
      refreshApply();
    }

    async function load() {
      const mine = ++token;
      try {
        const d = await post(FACETS, { ...criteria(col), col, q: search.value });
        if (mine !== token || !pop) return;
        shown = d.values;
        note.textContent = d.distinct > shown.length
          ? "Showing the " + shown.length + " most common of " + d.distinct.toLocaleString() + ". Search to find others."
          : d.distinct === 0 ? "Nothing matches." : "";
        render();
      } catch (e) {
        if (mine === token && pop) note.textContent = "Couldn't load the list. Close this menu and try again.";
      }
    }

    let timer;
    search.oninput = () => { clearTimeout(timer); timer = setTimeout(load, 200); };
    search.onkeydown = e => { if (e.key === "Enter" && !apply.disabled) { e.preventDefault(); apply.click(); } };
    pop.append(sortButtons(col), search, list, note, row);
    load();
    setTimeout(() => search.focus(), 0);
  }

  function openMenu(col, button) {
    const reopening = popButton === button;
    closePop();
    if (reopening) return;
    pop = el("div", { id: "pop", role: "dialog" });
    pop.setAttribute("aria-label", "Filter and sort");
    pop.onkeydown = e => { if (e.key === "Escape") closePop(); };
    popButton = button;
    document.body.append(pop);
    if (col === "ts") openDateMenu(col); else openValueMenu(col);
    placePop(button);
    document.addEventListener("mousedown", outsideClick);
  }

  for (const th of document.querySelectorAll("th[data-col]")) {
    th.dataset.label = th.textContent;
    const btn = el("button", { type: "button", className: "th-btn" },
      el("span", { textContent: th.textContent }),
      el("span", { className: "mark" }),
      el("span", { className: "caret", textContent: "▾" }));
    btn.setAttribute("aria-haspopup", "dialog");
    btn.onclick = () => openMenu(th.dataset.col, btn);
    th.replaceChildren(btn);
  }

  $("clear-all").addEventListener("click", () => {
    for (const col of Object.keys(filters)) delete filters[col];
    dates = { from: "", to: "" };
    sort = null;
    hideFailed.checked = false;
    reload();
  });
  hideFailed.addEventListener("change", reload);

  reload();
  setInterval(() => { if (!document.hidden) poll(); }, POLL_MS);
})();
