// content.js — собирает данные страницы

(function () {
  const url = window.location.href;

  if (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("about:") ||
    url.startsWith("file://") ||
    url.startsWith("moz-extension://")
  ) return;

  const data = {
    url,
    title: document.title,
    text: (document.body?.innerText || "").slice(0, 4000).toLowerCase(),
    forms: document.querySelectorAll("form").length,
    passwordFields: document.querySelectorAll('input[type="password"]').length,
    hiddenFields: document.querySelectorAll('input[type="hidden"]').length,
    iframes: document.querySelectorAll("iframe").length,
    pageHostname: window.location.hostname,
    protocol: window.location.protocol,
    // Все ссылки на странице
    links: Array.from(document.querySelectorAll("a[href]"))
      .map(a => { try { return new URL(a.href).hostname; } catch { return null; } })
      .filter(Boolean),
    // Внешние скрипты
    scripts: Array.from(document.querySelectorAll("script[src]"))
      .map(s => { try { return new URL(s.src).hostname; } catch { return null; } })
      .filter(Boolean),
    // Есть ли поля для карты
    cardFields: document.querySelectorAll(
      'input[name*="card"], input[name*="cvv"], input[name*="cvc"], ' +
      'input[placeholder*="карт"], input[placeholder*="card"], ' +
      'input[autocomplete*="cc-"]'
    ).length,
  };

  chrome.runtime.sendMessage({ type: "ANALYZE_PAGE", data });
})();
