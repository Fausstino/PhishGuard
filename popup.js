// popup.js

const LABELS = {
  safe:       { icon: "✅", text: "Безопасно" },
  suspicious: { icon: "⚠️",  text: "Подозрительно" },
  phishing:   { icon: "🚨", text: "Фишинг!" },
};

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  document.getElementById("urlBar").textContent = tab.url || "—";

  function tryRender() {
    chrome.storage.session?.get?.([`tab_${tab.id}`], (data) => {
      const r = data?.[`tab_${tab.id}`];
      if (r && r.verdict) render(r);
      else setTimeout(tryRender, 800); // ждём результата
    });
  }

  tryRender();
}

function render(result) {
  const card = document.getElementById("card");
  const v    = result.verdict || "suspicious";
  const info = LABELS[v] || LABELS.suspicious;
  const pct  = Math.min(100, result.score || 0);

  card.className = `card ${v}`;
  card.innerHTML = `
    <div class="card-top">
      <div class="card-icon">${info.icon}</div>
      <div>
        <div class="card-label">${info.text}</div>
        <div class="card-sub">${result.category || ""}</div>
      </div>
    </div>

    <div class="risk-bar-wrap">
      <div class="risk-label">
        <span>Риск-балл</span>
        <span>${pct}/100</span>
      </div>
      <div class="risk-bar-bg">
        <div class="risk-bar-fill" style="width:${pct}%"></div>
      </div>
    </div>

    ${result.signs?.length ? `
      <div class="signs">
        ${result.signs.map(s => `<div class="sign">${s}</div>`).join("")}
      </div>` : ""}
  `;
}

init();
