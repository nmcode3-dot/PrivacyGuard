// Listen for messages sent from other parts of the PrivacyGuard extension.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  // Only continue if the message is asking PrivacyGuard to block camera access.
  // Ignore any other messages.
  if (message?.type !== "PRIVACYGUARD_BLOCK_CAMERA") return;

  // Get the website address (origin) that the extension wants to block.
  const origin = message.origin;

  // Check that an origin was provided and that it starts with HTTP or HTTPS.
  // This prevents the extension from trying to block an invalid or unsupported address.
  if (!origin || !/^https?:\/\//i.test(origin)) {
    // Tell the part of the extension that sent the message that the request failed.
    sendResponse({
      ok: false,
      error: "This page does not have a supported website origin."
    });
    return; // Stop running the function because the origin is invalid.
  }

  // Use Chrome's content settings API to block camera access for this website.
  chrome.contentSettings.camera.set(
    {
      primaryPattern: origin + "/*", // Apply the rule to every page on this website.
      setting: "block",               // Set the camera permission to blocked.
      scope: "regular"                // Apply the rule to the regular browser profile.
    },
    () => {
      // Check whether Chrome reported an error while applying the permission change.
      if (chrome.runtime.lastError) {
        // Send the error message back to the part of the extension that requested the change.
        sendResponse({
          ok: false,
          error: chrome.runtime.lastError.message
        });
        return; // Stop here because the camera could not be blocked.
      }

      // Tell the requesting part of the extension that the camera was successfully blocked.
      sendResponse({ ok: true });
    }
  );

  // Keep the message channel open because Chrome's permission-setting operation is asynchronous.
  // This allows sendResponse() to send its result after the operation finishes.
  return true;
});
