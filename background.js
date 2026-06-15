
const CACHE_TTL = 20 * 60 * 1000; // 20 минут
const cache = new Map();

// Сообщения

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg.type === "ANALYZE_PAGE") {
    analyzePage(msg.data, sender.tab?.id);
  }
});

// main

function analyzePage(data, tabId) {
  if (!tabId) return;

  const cacheKey = `url:${data.url}`;
  const cached = cache.get(cacheKey);

  if (cached && Date.now() - cached.ts < CACHE_TTL) {
    applyResult(tabId, cached);
    return;
  }

  const result = runRules(data);
  result.ts = Date.now();
  result.url = data.url;

  cache.set(cacheKey, result);
  applyResult(tabId, result);
}

function applyResult(tabId, result) {
  chrome.storage.session?.set?.({ [`tab_${tabId}`]: result });
  updateIcon(tabId, result.verdict);
  if (result.verdict === "phishing") showBanner(tabId, result);
}

// ДВИЖОК ПРАВИЛ 

function runRules(data) {
  let score = 0;
  const signs = [];

  let urlObj, hostname, tld, path;
  try {
    urlObj   = new URL(data.url);
    hostname = urlObj.hostname.toLowerCase();
    tld      = hostname.split(".").slice(-2).join(".");
    path     = urlObj.pathname.toLowerCase();
  } catch {
    return { verdict: "suspicious", score: 30, signs: ["Некорректный URL"], category: "⚠️ Ошибка разбора" };
  }

  // СТРУКТУРА ДОМЕНА 

  // IP-адрес вместо домена
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 45;
    signs.push("Сайт открыт по IP-адресу — легитимные сервисы так не делают");
  }

  // Много дефисов (sber-bank-online-cabinet.ru)
  const dashes = (hostname.match(/-/g) || []).length;
  if (dashes >= 3) { score += 30; signs.push(`Много дефисов в домене (${dashes} шт.) — типичный приём маскировки`); }
  else if (dashes === 2) { score += 10; }

  const parts = hostname.split(".");
  if (parts.length >= 5) { score += 25; signs.push(`Подозрительно много субдоменов (${parts.length} уровней)`); }
  else if (parts.length === 4) { score += 8; }

  if (hostname.length > 40) { score += 15; signs.push(`Очень длинное доменное имя (${hostname.length} символов)`); }

  // ИМИТАЦИЯ ИЗВЕСТНЫХ БРЕНДОВ 

  const BRANDS = {
    // Российские банки и сервисы
    "sberbank":      ["sberbank.ru", "online.sberbank.ru"],
    "tinkoff":       ["tinkoff.ru", "t.me"],
    "vtb":           ["vtb.ru"],
    "alfabank":      ["alfabank.ru"],
    "raiffeisen":    ["raiffeisen.ru"],
    "gosuslugi":     ["gosuslugi.ru", "esia.gosuslugi.ru"],
    "nalog":         ["nalog.gov.ru", "lk.nalog.ru"],
    "mos":           ["mos.ru"],
    "ozon":          ["ozon.ru"],
    "wildberries":   ["wildberries.ru"],
    "avito":         ["avito.ru"],
    "yandex":        ["yandex.ru", "ya.ru", "yandex.com"],
    "mail":          ["mail.ru", "cloud.mail.ru"],
    "vk":            ["vk.com", "vkontakte.ru"],
    // Международные
    "paypal":        ["paypal.com"],
    "google":        ["google.com", "accounts.google.com"],
    "apple":         ["apple.com", "appleid.apple.com"],
    "microsoft":     ["microsoft.com", "login.microsoftonline.com"],
    "amazon":        ["amazon.com", "amazon.co.uk"],
    "facebook":      ["facebook.com", "fb.com"],
    "instagram":     ["instagram.com"],
    "telegram":      ["telegram.org", "t.me"],
    "steam":         ["store.steampowered.com", "steamcommunity.com"],
    "binance":       ["binance.com"],
    "coinbase":      ["coinbase.com"],
  };

  for (const [brand, trustedList] of Object.entries(BRANDS)) {
    const isTrusted = trustedList.some(d => hostname === d || hostname.endsWith("." + d));
    if (!isTrusted && hostname.includes(brand)) {
      score += 50;
      signs.push(`Имитация "${brand}" — домен не является официальным сайтом`);
      break;
    }
  }

  // ПОДОЗРИТЕЛЬНЫЕ СЛОВА

  const urlLower = data.url.toLowerCase();
  const urlSuspiciousWords = [
    ["login", "signin", "sign-in"],
    ["secure", "security", "safe"],
    ["verify", "verification", "подтверди"],
    ["account", "аккаунт", "cabinet", "личный"],
    ["update", "restore", "recovery"],
    ["banking", "online-bank", "bank-online"],
    ["support", "helpdesk"],
    ["blocked", "suspended", "заблокирован"],
  ];

  let urlWordHits = 0;
  for (const group of urlSuspiciousWords) {
    if (group.some(w => urlLower.includes(w))) urlWordHits++;
  }
  if (urlWordHits >= 3) { score += 25; signs.push(`Много тревожных слов в URL (${urlWordHits} групп)`); }
  else if (urlWordHits === 2) { score += 10; }

  // Длина URL
  if (data.url.length > 200) { score += 20; signs.push(`Аномально длинный URL (${data.url.length} символов)`); }
  else if (data.url.length > 120) { score += 8; }

  // Много GET-параметров
  const paramCount = [...urlObj.searchParams.keys()].length;
  if (paramCount > 8) { score += 15; signs.push(`Много параметров в URL (${paramCount} шт.)`); }

  // Проверка на наличие сертификата (HTTPS)

  const isHTTPS = data.protocol === "https:";

  if (!isHTTPS && data.passwordFields > 0) {
    score += 50;
    signs.push("❌ Форма с паролем на HTTP (данные передаются открытым текстом!)");
  } else if (!isHTTPS && data.forms > 0) {
    score += 20;
    signs.push("Форма отправки данных без HTTPS");
  }

  

  if (data.cardFields > 0) {
    score += 35;
    signs.push(`Поля для ввода данных банковской карты (${data.cardFields} шт.)`);
  }

  if (data.passwordFields >= 3) {
    score += 25;
    signs.push(`Необычно много полей для пароля (${data.passwordFields} шт.)`);
  } else if (data.passwordFields === 2 && data.forms >= 2) {
    score += 12;
    signs.push("Несколько форм с полями пароля");
  }

  // 
  if (data.hiddenFields > 15) {
    score += 15;
    signs.push(`Много скрытых полей в формах (${data.hiddenFields} шт.)`);
  }

  // IFRAME

  if (data.iframes > 3) {
    score += 15;
    signs.push(`Много iframe (${data.iframes} шт.) — возможна скрытая загрузка контента`);
  }

  // ТЕКСТ СТРАНИЦЫ 

  const text = data.text;

  // Фишинговые фразы (русские)
  const ruPhrases = [
    ["ваш аккаунт заблокирован", "аккаунт будет заблокирован", "аккаунт приостановлен"],
    ["введите данные карты", "данные вашей карты", "номер карты"],
    ["срочно подтвердите", "необходимо подтвердить", "требуется подтверждение"],
    ["выиграли приз", "вы победитель", "получите приз"],
    ["переведите средства", "пополните счёт", "внесите депозит"],
    ["cvv", "cvc код", "код карты"],
    ["истекает срок", "срок действия карты"],
    ["подозрительная активность", "несанкционированный доступ"],
  ];

  // Фишинговые фразы (английские)
  const enPhrases = [
    ["your account has been", "account suspended", "account blocked"],
    ["enter your password", "confirm your password"],
    ["verify your identity", "identity verification"],
    ["unusual activity", "suspicious activity"],
    ["update your payment", "payment information required"],
    ["you have won", "claim your prize", "you are selected"],
    ["limited time offer", "act now", "expires soon"],
  ];

  let phraseHits = 0;
  for (const group of [...ruPhrases, ...enPhrases]) {
    if (group.some(p => text.includes(p))) phraseHits++;
  }

  if (phraseHits >= 3) { score += 30; signs.push(`Много тревожных фраз в тексте страницы (${phraseHits} совпадений)`); }
  else if (phraseHits >= 2) { score += 15; signs.push(`Подозрительные фразы в тексте страницы`); }
  else if (phraseHits === 1) { score += 5; }

  // Давление срочности
  const urgencyWords = ["срочно", "немедленно", "сейчас", "последний шанс", "urgent", "immediately", "now or never"];
  const urgencyCount = urgencyWords.filter(w => text.includes(w)).length;
  if (urgencyCount >= 3) { score += 15; signs.push("Давление срочности — классический приём социальной инженерии"); }

  // НЕСООТВЕТСТВИЕ КОНТЕНТА И ДОМЕНА

  for (const [brand, trustedList] of Object.entries(BRANDS)) {
    const mentionedInText = text.includes(brand);
    const isTrusted = trustedList.some(d => hostname === d || hostname.endsWith("." + d));
    const inDomain = hostname.includes(brand);

    if (mentionedInText && !isTrusted && !inDomain) {
      score += 20;
      signs.push(`Страница ссылается на "${brand}", но домен не принадлежит им`);
      break;
    }
  }

  // ВНЕШНИЕ ССЫЛКИ

  if (data.links && data.links.length > 0) {
    const foreignLinks = data.links.filter(h =>
      h !== hostname && !h.endsWith("." + tld) && h !== tld
    );
    const uniqueForeign = new Set(foreignLinks).size;
    if (uniqueForeign > 15) {
      score += 10;
      signs.push(`Много ссылок на сторонние домены (${uniqueForeign} уникальных)`);
    }
  }

  // ИТОГ

  let verdict, category;

  if (score >= 60) {
    verdict  = "phishing";
    category = "🚨 Высокий риск фишинга";
  } else if (score >= 25) {
    verdict  = "suspicious";
    category = "⚠️ Подозрительный сайт";
  } else {
    verdict  = "safe";
    category = "✅ Признаков фишинга не найдено";
  }

  return { verdict, score, signs, category };
}


function updateIcon(tabId, verdict) {
  const map = {
    safe:       { color: "#22c55e", text: "✓" },
    suspicious: { color: "#f59e0b", text: "~" },
    phishing:   { color: "#ef4444", text: "!" },
  };
  const { color, text } = map[verdict] || { color: "#6b7280", text: "?" };
  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeText({ text, tabId });
}


function showBanner(tabId, result) {
  const topSign = result.signs?.[0] || "Обнаружены признаки мошенничества";

  chrome.scripting.executeScript({
    target: { tabId },
    func: (sign, score) => {
      if (document.getElementById("phishguard-banner")) return;
      const el = document.createElement("div");
      el.id = "phishguard-banner";
      el.innerHTML = `
        <div style="
          position:fixed; top:0; left:0; right:0; z-index:2147483647;
          background:linear-gradient(135deg,#7f1d1d,#991b1b);
          color:white; padding:12px 20px;
          font-family:system-ui,sans-serif;
          display:flex; align-items:center; justify-content:space-between;
          box-shadow:0 4px 24px rgba(0,0,0,0.5);
          border-bottom:2px solid #ef4444;
        ">
          <div style="display:flex;align-items:center;gap:12px">
            <span style="font-size:22px;flex-shrink:0">🚨</span>
            <div>
              <div style="font-weight:700;font-size:15px">PhishGuard: Возможный фишинг!</div>
              <div style="opacity:0.85;font-size:12px;margin-top:2px">${sign}</div>
              <div style="opacity:0.55;font-size:11px;margin-top:1px">Риск-балл: ${score}/100</div>
            </div>
          </div>
          <button onclick="document.getElementById('phishguard-banner').remove()" style="
            background:rgba(255,255,255,0.15);border:none;color:white;
            font-size:18px;cursor:pointer;padding:4px 10px;border-radius:6px;flex-shrink:0;margin-left:16px
          ">✕</button>
        </div>`;
      document.body.prepend(el);
    },
    args: [topSign, result.score],
  });
}
