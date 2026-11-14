chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "PRIVACYGUARD_BLOCK_CAMERA") return;

  const origin = message.origin;
  if (!origin || !/^https?:\/\//i.test(origin)) {
    sendResponse({ ok: false, error: "This page does not have a supported website origin." });
    return;
  }

  chrome.contentSettings.camera.set(
    { primaryPattern: origin + "/*", setting: "block", scope: "regular" },
    () => {
      if (chrome.runtime.lastError) {
        sendResponse({ ok: false, error: chrome.runtime.lastError.message });
        return;
      }
      sendResponse({ ok: true });
    }
  );
  return true;
});
