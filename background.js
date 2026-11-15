// Keep track of tabs that currently have an active camera stream.
const activeCameraTabs = new Map();

// Handle camera alerts and the user's camera block/unblock requests.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // A content script reports camera activity from the page that requested the camera.
  if (message?.type === "PRIVACYGUARD_CAMERA_STATUS") {
    const tabId = sender.tab?.id;
    const pageUrl = sender.tab?.url;

    // Ignore messages that did not come from a normal website tab.
    if (typeof tabId !== "number" || !pageUrl || !/^https?:\/\//i.test(pageUrl)) return;

    let site = "this website";
    try { site = new URL(pageUrl).hostname; } catch (_) {}

    const notificationId = "privacyguard-camera-" + tabId;

    if (message.active) {
      // Save the site so PrivacyGuard can identify it even from another tab.
      activeCameraTabs.set(tabId, { site, pageUrl });

      // A system notification appears above other websites and browser tabs.
      chrome.notifications.create(notificationId, {
        type: "basic",
        iconUrl: chrome.runtime.getURL("notification-icon.svg"),
        title: "Camera active on " + site,
        message: "PrivacyGuard detected a camera stream from this website.",
        priority: 2
      });
    } else {
      activeCameraTabs.delete(tabId);
      chrome.notifications.clear(notificationId);
    }

    // Save active camera information for when Chrome suspends and restarts this worker.
    chrome.storage.session.set({ activeCameraTabs: [...activeCameraTabs.entries()] });
    return;
  }

  // If the service worker restarts, restore the active camera list from session storage.
  if (message?.type === "PRIVACYGUARD_GET_ACTIVE_CAMERAS") {
    chrome.storage.session.get("activeCameraTabs", data => {
      sendResponse({ cameras: data.activeCameraTabs || [] });
    });
    return true;
  }

  // The remaining supported messages change a site's camera permission.
  if (!["PRIVACYGUARD_BLOCK_CAMERA", "PRIVACYGUARD_UNBLOCK_CAMERA"].includes(message?.type)) return;

  const origin = message.origin;

  // Only accept valid HTTP or HTTPS website origins.
  if (!origin || !/^https?:\/\//i.test(origin)) {
    sendResponse({ ok: false, error: "This page does not have a supported website origin." });
    return;
  }

  // Choose whether Chrome should block or allow camera access for this site.
  const setting = message.type === "PRIVACYGUARD_BLOCK_CAMERA" ? "block" : "allow";

  chrome.contentSettings.camera.set({
    primaryPattern: origin + "/*",
    setting,
    scope: "regular"
  }, () => {
    if (chrome.runtime.lastError) {
      sendResponse({ ok: false, error: chrome.runtime.lastError.message });
      return;
    }
    sendResponse({ ok: true });
  });

  // Keep the message channel open until Chrome finishes changing the permission.
  return true;
});

// Clear the old page's camera status when a tab navigates to a new address.
// The new page will report again if it starts using a camera.
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (!changeInfo.url) return;
  activeCameraTabs.delete(tabId);
  chrome.notifications.clear("privacyguard-camera-" + tabId);
  chrome.storage.session.set({ activeCameraTabs: [...activeCameraTabs.entries()] });
});

// Remove a tab's camera status when that tab is closed.
chrome.tabs.onRemoved.addListener(tabId => {
  activeCameraTabs.delete(tabId);
  chrome.notifications.clear("privacyguard-camera-" + tabId);
  chrome.storage.session.set({ activeCameraTabs: [...activeCameraTabs.entries()] });
});

// If the user clicks a camera notification, take them to the site using the camera.
chrome.notifications.onClicked.addListener(notificationId => {
  const tabId = Number(notificationId.replace("privacyguard-camera-", ""));
  if (!Number.isInteger(tabId)) return;
  chrome.tabs.update(tabId, { active: true }, tab => {
    if (tab?.windowId !== undefined) chrome.windows.update(tab.windowId, { focused: true });
  });
});

// Restore the latest active camera list when the background worker starts.
chrome.storage.session.get("activeCameraTabs", data => {
  for (const [tabId, details] of data.activeCameraTabs || []) {
    activeCameraTabs.set(tabId, details);
  }
});
