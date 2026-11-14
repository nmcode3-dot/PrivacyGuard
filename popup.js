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

  // Estimate website risk using only the address (URL).
  // This is a simple heuristic, not a malware scan or a reputation lookup.
  function rateWebsite(rawUrl) {
    let url;

    // Convert the address string into a URL object.
    // If it is not a valid URL, return a message instead of trying to score it.
    try { url = new URL(rawUrl); } catch (_) { return { unavailable: "This page does not have a standard website address." }; }

    // Only rate ordinary HTTP and HTTPS website pages.
    // Browser pages such as chrome:// settings pages are not supported.
    if (!["http:", "https:"].includes(url.protocol)) {
      return { unavailable: "Website ratings are available for ordinary HTTP and HTTPS pages." };
    }

    // Store the lowercase domain name, a list of reasons, and the total risk points.
    const host = url.hostname.toLowerCase();
    const reasons = [];
    let risk = 0;

    // Add risk points and save the explanation whenever a warning sign is found.
    const add = (points, reason) => { risk += points; reasons.push({ points, reason }); };

    // HTTP does not encrypt the connection in the way HTTPS does.
    if (url.protocol === "http:") add(30, "This connection does not use HTTPS encryption.");

    // A normal website URL should not contain a username or password.
    if (url.username || url.password) add(25, "The address contains embedded username or password text.");

    // Punycode is used to represent certain international characters in domain names.
    // Some look-alike characters can make a domain resemble a different website.
    if (host.startsWith("xn--") || host.split(".").some(part => part.startsWith("xn--"))) {
      add(25, "The domain uses internationalized/punycode characters that can disguise look-alike names.");
    }

    // Check whether the hostname looks like a raw IPv4 or bracketed IPv6 address.
    const isIPv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host);
    const isIPv6 = host.startsWith("[") && host.endsWith("]");
    if (isIPv4 || isIPv6) add(20, "The website uses a raw IP address instead of a normal domain name.");

    // A large number of subdomains can be unusual, so add a small warning.
    if (host.split(".").length >= 5) add(10, "The domain has an unusually large number of subdomains.");

    // Very long domain names can be harder for people to inspect carefully.
    if (host.length > 55) add(10, "The domain name is unusually long.");

    // Check for words often used in fake account, payment, or password pages.
    // These words alone do not prove a site is malicious.
    if (/(login|signin|verify|account|secure|update|payment|wallet|password|recover)/i.test(host)) {
      add(12, "The domain includes words commonly used in account or payment lures; check the exact domain carefully.");
    }

    // Look for repeated percent-encoded characters in the path or query string.
    if (/(%[0-9a-f]{2}){4,}/i.test(url.pathname + url.search)) {
      add(8, "The address contains unusually heavy URL encoding.");
    }

    // Two dots next to each other in a hostname are an unusual pattern.
    if (url.hostname.includes("..")) add(10, "The domain contains an unusual sequence of dots.");

    // Convert the accumulated risk points into a score from 0 to 100.
    // More warning points produce a lower score.
    const score = Math.max(0, Math.min(100, 100 - risk));

    // Group the score into three broad labels.
    const level = score >= 80 ? "low" : score >= 50 ? "medium" : "high";

    // Return the score and the explanations for the popup to display.
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

    // Calculate and display the URL-based risk rating for the active tab.
    render(rateWebsite(tabs[0].url));

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
