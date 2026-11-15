// Run the popup code inside its own function so its variables do not leak into the global scope.
(() => {
  // Short helper for finding an HTML element by its ID.
  // The popup HTML uses these IDs to connect the display with this JavaScript.
  const $ = id => document.getElementById(id);

  // Show a message when the current tab cannot be checked.
  // This resets the score and clears any old warning reasons.
  const setUnavailable = message => {
    $("risk-score").textContent = "—";
    $("risk-label").textContent = "Unavailable";
    $("risk-label").className = "risk-label na";
    $("site-name").textContent = message;
    $("risk-reasons").replaceChildren();
    $("risk-meter").style.width = "0%";
  };

  // Estimate risk from the address only. This is deliberately stricter,
  // but it is not a malware scan or a live reputation lookup.
  function rateWebsite(rawUrl) {
    let url;
    try { url = new URL(rawUrl); }
    catch (_) { return { unavailable: "This page does not have a standard website address." }; }

    if (!["http:", "https:"].includes(url.protocol)) {
      return { unavailable: "Website ratings are available for ordinary HTTP and HTTPS pages." };
    }

    const host = url.hostname.toLowerCase();
    const labels = host.split(".");
    const reasons = [];
    // Start with risk points because a URL-only check cannot prove a site is trustworthy.
    let risk = 15;
    const add = (points, reason) => { risk += points; reasons.push({ points, reason }); };

    if (url.protocol === "http:") add(35, "This connection does not use HTTPS encryption.");
    if (url.username || url.password) add(35, "The address contains embedded username or password text.");

    if (labels.some(part => part.startsWith("xn--"))) {
      add(30, "The domain uses punycode, which can disguise look-alike characters.");
    }

    const isIPv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host);
    const isIPv6 = host.startsWith("[") && host.endsWith("]");
    if (isIPv4 || isIPv6) add(30, "The website uses a raw IP address instead of a normal domain name.");

    if (labels.length >= 4) add(15, "The address uses several nested subdomains.");
    if (host.length > 35) add(10, "The domain name is unusually long.");
    if (host.length > 55) add(10, "The domain is especially long and difficult to inspect.");
    if ((host.match(/-/g) || []).length >= 2) add(12, "The domain contains multiple hyphens, a pattern often used in imitation links.");
    if (/\d/.test(host)) add(8, "The domain contains numbers, which can be used to imitate familiar names.");

    const riskyTlds = ["zip", "mov", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "buzz", "rest"];
    const tld = labels[labels.length - 1];
    if (riskyTlds.includes(tld)) add(25, "This website uses a top-level domain frequently seen in suspicious or disposable links.");

    if (/(login|signin|verify|account|secure|update|payment|wallet|password|recover|support)/i.test(host)) {
      add(18, "The domain includes account, payment, or support wording commonly used in phishing lures.");
    }

    if (/(login|signin|verify|password|wallet|payment|recover|security|account)/i.test(url.pathname)) {
      add(10, "The page address contains account or payment wording often used in credential traps.");
    }

    if (/(%[0-9a-f]{2}){4,}/i.test(url.pathname + url.search)) {
      add(12, "The address contains unusually heavy URL encoding.");
    }

    if (/(^|[?&])(redirect|url|next|return|continue|target)=/i.test(url.search)) {
      add(10, "The address contains a redirect parameter that can hide the final destination.");
    }

    if (url.hostname.includes("..")) add(20, "The domain contains an unusual sequence of dots.");

    // Warn when a well-known brand name appears in a different domain.
    const officialBrandDomains = {
      google: "google.com", microsoft: "microsoft.com", apple: "apple.com",
      amazon: "amazon.com", paypal: "paypal.com", facebook: "facebook.com",
      instagram: "instagram.com", chase: "chase.com", netflix: "netflix.com"
    };
    for (const [brand, officialDomain] of Object.entries(officialBrandDomains)) {
      if (host.includes(brand) && host !== officialDomain && !host.endsWith("." + officialDomain)) {
        add(30, "The domain uses the name of " + brand + " without being its official domain.");
        break;
      }
    }

    // Known link-shortening services hide the destination until the link is opened.
    const shorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy"];
    if (shorteners.some(domain => host === domain || host.endsWith("." + domain))) {
      add(20, "This is a link-shortening domain, so the final destination is hidden.");
    }

    const score = Math.max(0, Math.min(100, 100 - risk));
    // The stricter thresholds make the safer label harder to reach.
    const level = score >= 70 ? "low" : score >= 40 ? "medium" : "high";
    return { score, level, host, reasons };
  }

  // Put the website rating results into the popup's HTML elements.
  function render(result) {
    // If the page could not be rated, show the unavailable message and stop.
    if (result.unavailable) return setUnavailable(result.unavailable);

    // Display the numerical score and the website's domain.
    $("risk-score").textContent = String(result.score);
    $("site-name").textContent = result.host;

    // Update the risk label and its CSS class to match the calculated level.
    const label = $("risk-label");
    label.className = "risk-label " + result.level;
    label.textContent = result.level === "low" ? "Lower risk signals" : result.level === "medium" ? "Use caution" : "High risk signals";

    // Update the meter width and color to visually represent the score.
    $("risk-meter").style.width = result.score + "%";
    $("risk-meter").style.background = result.level === "low" ? "#16a36a" : result.level === "medium" ? "#d99a18" : "#c62828";

    // Find the list where warning explanations should appear and clear old entries.
    const list = $("risk-reasons");
    list.replaceChildren();

    // If no warning patterns were found, explain that to the user.
    if (!result.reasons.length) {
      const li = document.createElement("li");
      li.textContent = "No URL warning signs were detected by these basic checks.";
      list.appendChild(li);
    } else {
      // Otherwise, create one list item for each warning explanation.
      result.reasons.forEach(item => {
        const li = document.createElement("li");
        li.textContent = item.reason;
        list.appendChild(li);
      });
    }
  }

  // Combine the URL checks with findings from the actual page DOM.
  function renderCombinedRating(urlResult, pageAudit) {
    if (urlResult.unavailable) return render(urlResult);

    const reasons = [...urlResult.reasons, ...pageAudit.findings];
    const score = Math.max(0, Math.min(100, urlResult.score - pageAudit.riskPoints));
    const level = score >= 70 ? "low" : score >= 40 ? "medium" : "high";
    render({
      score,
      level,
      host: urlResult.host,
      reasons,
      pageCounts: pageAudit.counts
    });

    const status = $("page-scan-status");
    if (status) {
      status.textContent = "Page checked: " + pageAudit.counts.links + " links, " +
        pageAudit.counts.frames + " embedded frames, and " + pageAudit.counts.scripts +
        " scripts. " + pageAudit.note;
    }
  }

  function scanCurrentPage(tabId, urlResult) {
    const status = $("page-scan-status");
    const button = $("page-scan-button");
    if (status) status.textContent = "Inspecting links, forms, downloads, ads, and embedded content…";
    if (button) { button.disabled = true; button.textContent = "Scanning…"; }

    chrome.tabs.sendMessage(tabId, { type: "PRIVACYGUARD_SCAN_PAGE_RISK" }, audit => {
      if (button) { button.disabled = false; button.textContent = "Rescan page"; }
      if (chrome.runtime.lastError || !audit) {
        if (status) status.textContent = "Page inspection is unavailable on this tab. Refresh the website and try again.";
        render(urlResult);
        return;
      }
      renderCombinedRating(urlResult, audit);
    });
  }

  // Make sure Chrome's tabs API is available before trying to inspect the active tab.
  if (!globalThis.chrome?.tabs?.query) {
    setUnavailable("Could not read the active tab.");
    return;
  }

  // Ask Chrome for the active tab in the currently focused browser window.
  chrome.tabs.query({ active: true, lastFocusedWindow: true }, tabs => {
    // If Chrome reports an error or the tab has no URL, show a helpful message.
    if (chrome.runtime.lastError || !tabs?.[0]?.url) {
      setUnavailable("Open a regular website tab to see its rating.");
      return;
    }

    // Rate the URL, then inspect the actual page before showing the final score.
    const urlResult = rateWebsite(tabs[0].url);
    render(urlResult);
    const pageScanButton = $("page-scan-button");
    if (pageScanButton) pageScanButton.addEventListener("click", () => scanCurrentPage(tabs[0].id, urlResult));
    scanCurrentPage(tabs[0].id, urlResult);

    // Scan visible conversation text only after the user clicks the scam-check button.
    const scamButton = $("scam-check-button");
    const scamStatus = $("scam-check-status");
    const scamFindings = $("scam-check-findings");
    if (scamButton && scamStatus && scamFindings) {
      scamButton.addEventListener("click", () => {
        scamButton.disabled = true;
        scamButton.textContent = "Scanning…";
        scamStatus.textContent = "Checking visible page text on this device.";
        scamFindings.replaceChildren();

        chrome.tabs.sendMessage(tabs[0].id, { type: "PRIVACYGUARD_SCAN_SCAM_CONVERSATION" }, result => {
          scamButton.disabled = false;
          scamButton.textContent = "Scan again";
          if (chrome.runtime.lastError || !result) {
            scamStatus.textContent = "This page cannot be scanned. Try refreshing the tab and opening PrivacyGuard again.";
            return;
          }
          if (!result.findings.length) {
            scamStatus.textContent = "No ranked scam buzzwords were found in the visible page text.";
            return;
          }
          scamStatus.textContent = result.findings.length + " matching words found from " +
            result.buzzwordCount.toLocaleString() + " ranked entries (" +
            result.uniqueBuzzwordCount.toLocaleString() + " unique words). Strongest signal: " +
            result.findings[0].severity + ". Words are clues, not proof.";
          result.findings.forEach(match => {
            const item = document.createElement("li");
            item.textContent = match.severity + " — " + match.word + " (" + match.category + ")";
            scamFindings.appendChild(item);
          });
        });
      });
    }

    // Only offer cookie cleanup on regular HTTP or HTTPS websites.
    const cookieButton = $("cookie-clean-button");
    const cookieStatus = $("cookie-clean-status");
    const pageUrl = new URL(tabs[0].url);
    if (cookieButton && cookieStatus && ["http:", "https:"].includes(pageUrl.protocol)) {
      cookieButton.addEventListener("click", () => {
        // Prevent repeated clicks while Chrome is checking or removing cookies.
        cookieButton.disabled = true;
        cookieButton.textContent = "Checking cookies…";
        cookieStatus.textContent = "Checking this website for common tracking cookies.";

        // These names are commonly used by analytics and advertising tools.
        // A matching name is only a clue; it does not prove a cookie is unnecessary.
        const likelyTrackingCookie = name => [
          /^_ga(?:_|$)/i, /^_gid$/i, /^_gat(?:_|$)/i, /^_gcl_au$/i,
          /^_fbp$/i, /^_ttp$/i, /^ttcsid(?:_|$)/i, /^_clck$/i, /^_clsk$/i,
          /^_hj(?:Session|FirstSeen|IncludedInSessionSample|AbsoluteSessionInProgress)/i,
          /^hubspotutk$/i, /^__hstc$/i, /^_uet(?:_|$)/i, /^amplitude_id_/i, /^mp_.+_mixpanel$/i
        ].some(pattern => pattern.test(name));

        // Ask Chrome for cookies that apply to the current website only.
        chrome.cookies.getAll({ url: tabs[0].url }, cookies => {
          if (chrome.runtime.lastError || !cookies) {
            cookieStatus.textContent = "Could not read cookies. Check the extension permissions in Chrome.";
            cookieButton.disabled = false;
            cookieButton.textContent = "Try again";
            return;
          }

          // Skip partitioned cookies because removing them requires extra partition information.
          const candidates = cookies.filter(cookie => likelyTrackingCookie(cookie.name) && !cookie.partitionKey);
          if (!candidates.length) {
            cookieStatus.textContent = "No cookies from the tracking-cookie list were found on this website.";
            cookieButton.disabled = false;
            cookieButton.textContent = "Check again";
            return;
          }

          cookieButton.textContent = "Removing…";
          let finished = 0;
          let removed = 0;

          // Remove only matched cookies; unrelated login/session cookies are left alone.
          candidates.forEach(cookie => {
            const scheme = cookie.secure ? "https:" : pageUrl.protocol;
            const cookieDomain = cookie.domain.replace(/^\./, "");
            const cookieUrl = scheme + "//" + cookieDomain + (cookie.path || "/");
            chrome.cookies.remove({ url: cookieUrl, name: cookie.name, storeId: cookie.storeId }, result => {
              if (result) removed += 1;
              finished += 1;

              // Report the result after every removal request has completed.
              if (finished === candidates.length) {
                cookieStatus.textContent = "Removed " + removed + " of " + candidates.length + " likely tracking cookies from this website.";
                cookieButton.disabled = false;
                cookieButton.textContent = "Clean again";
              }
            });
          });
        });
      });
    } else if (cookieButton && cookieStatus) {
      cookieButton.disabled = true;
      cookieStatus.textContent = "Cookie cleanup is available on regular HTTP and HTTPS websites.";
    }

    // Helper for updating one of the dashboard's status labels.
    // The optional tone selects a CSS class for the status color.
    const setStatus = (id, value, tone = "") => {
      const el = $(id);
      el.textContent = value;
      el.className = "dashboard-value" + (tone ? " " + tone : "");
    };

    // Translate browser permission states into short labels and visual styles.
    const permissionLabel = state => ({
      granted: ["Allowed", "warn"],
      denied: ["Blocked", "good"],
      prompt: ["Ask first", ""],
      unsupported: ["Not available", ""],
      unknown: ["Unknown", ""]
    }[state] || ["Unknown", ""]);

    // Ask the content script in the active tab for camera activity and permission information.
    chrome.tabs.sendMessage(tabs[0].id, { type: "PRIVACYGUARD_GET_DASHBOARD" }, status => {
      // If the page cannot answer, mark each dashboard value as unavailable.
      if (chrome.runtime.lastError || !status) {
        setStatus("camera-activity", "Not available");
        setStatus("camera-permission", "Not available");
        setStatus("microphone-permission", "Not available");
        setStatus("location-permission", "Not available");
        $("dashboard-note").textContent = "This page does not support dashboard status checks. Try a regular website tab.";
        return;
      }

      // Show whether a camera stream is currently detected in this tab.
      setStatus("camera-activity", status.cameraActive ? "In use" : "Not active", status.cameraActive ? "alert" : "good");

      // Convert each browser permission state into its display label and color.
      const cameraPermission = permissionLabel(status.cameraPermission);
      const mic = permissionLabel(status.microphonePermission);
      const location = permissionLabel(status.locationPermission);
      setStatus("camera-permission", cameraPermission[0], cameraPermission[1]);
      setStatus("microphone-permission", mic[0], mic[1]);
      setStatus("location-permission", location[0], location[1]);

      // Explain when the browser does not expose permission details.
      // Otherwise, remind users that only permission states are checked.
      $("dashboard-note").textContent = status.cameraPermission === "unsupported"
        ? "Chrome does not expose all permission details on this page. Camera activity detection is best-effort."
        : "Permission status only. PrivacyGuard does not access your microphone or location data.";
    });
  });

  // Listen for camera status messages sent by the content script to the extension.
  // This lets the popup update while it remains open.
  chrome.runtime.onMessage.addListener(message => {
    if (message?.type !== "PRIVACYGUARD_CAMERA_STATUS") return;
    setCameraActivity(message.active);
  });

  // Update the camera activity row when a new status message arrives.
  function setCameraActivity(active) {
    const el = $("camera-activity");
    if (!el) return;

    // Show whether the camera is in use and apply the matching status color.
    el.textContent = active ? "In use" : "Not active";
    el.className = "dashboard-value " + (active ? "alert" : "good");
  }
})(); // Run the popup setup immediately.
