(() => {
  const $ = id => document.getElementById(id);
  const setUnavailable = message => {
    $("risk-score").textContent = "—";
    $("risk-label").textContent = "Unavailable";
    $("risk-label").className = "risk-label na";
    $("site-name").textContent = message;
    $("risk-reasons").replaceChildren();
    $("risk-meter").style.width = "0%";
  };

  function rateWebsite(rawUrl) {
    let url;
    try { url = new URL(rawUrl); } catch (_) { return { unavailable: "This page does not have a standard website address." }; }
    if (!["http:", "https:"].includes(url.protocol)) {
      return { unavailable: "Website ratings are available for ordinary HTTP and HTTPS pages." };
    }

    const host = url.hostname.toLowerCase();
    const reasons = [];
    let risk = 0;
    const add = (points, reason) => { risk += points; reasons.push({ points, reason }); };

    if (url.protocol === "http:") add(30, "This connection does not use HTTPS encryption.");
    if (url.username || url.password) add(25, "The address contains embedded username or password text.");
    if (host.startsWith("xn--") || host.split(".").some(part => part.startsWith("xn--"))) {
      add(25, "The domain uses internationalized/punycode characters that can disguise look-alike names.");
    }
    const isIPv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host);
    const isIPv6 = host.startsWith("[") && host.endsWith("]");
    if (isIPv4 || isIPv6) add(20, "The website uses a raw IP address instead of a normal domain name.");
    if (host.split(".").length >= 5) add(10, "The domain has an unusually large number of subdomains.");
    if (host.length > 55) add(10, "The domain name is unusually long.");
    if (/(login|signin|verify|account|secure|update|payment|wallet|password|recover)/i.test(host)) {
      add(12, "The domain includes words commonly used in account or payment lures; check the exact domain carefully.");
    }
    if (/(%[0-9a-f]{2}){4,}/i.test(url.pathname + url.search)) {
      add(8, "The address contains unusually heavy URL encoding.");
    }
    if (url.hostname.includes("..")) add(10, "The domain contains an unusual sequence of dots.");

    const score = Math.max(0, Math.min(100, 100 - risk));
    const level = score >= 80 ? "low" : score >= 50 ? "medium" : "high";
    return { score, level, host, reasons };
  }

  function render(result) {
    if (result.unavailable) return setUnavailable(result.unavailable);
    $("risk-score").textContent = String(result.score);
    $("site-name").textContent = result.host;
    const label = $("risk-label");
    label.className = "risk-label " + result.level;
    label.textContent = result.level === "low" ? "Lower risk signals" : result.level === "medium" ? "Use caution" : "High risk signals";
    $("risk-meter").style.width = result.score + "%";
    $("risk-meter").style.background = result.level === "low" ? "#16a36a" : result.level === "medium" ? "#d99a18" : "#c62828";
    const list = $("risk-reasons");
    list.replaceChildren();
    if (!result.reasons.length) {
      const li = document.createElement("li");
      li.textContent = "No URL warning signs were detected by these basic checks.";
      list.appendChild(li);
    } else {
      result.reasons.forEach(item => {
        const li = document.createElement("li");
        li.textContent = item.reason;
        list.appendChild(li);
      });
    }
  }

  if (!globalThis.chrome?.tabs?.query) {
    setUnavailable("Could not read the active tab.");
    return;
  }
  chrome.tabs.query({ active: true, lastFocusedWindow: true }, tabs => {
    if (chrome.runtime.lastError || !tabs?.[0]?.url) {
      setUnavailable("Open a regular website tab to see its rating.");
      return;
    }
    render(rateWebsite(tabs[0].url));
  });
})();
