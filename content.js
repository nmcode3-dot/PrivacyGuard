// Wrap everything in a function that runs immediately.
// This keeps the variables and functions private to this script.
(() => {

  // All sensitive-information checks happen locally in the browser.
  // Password input fields are never read.

  // Remember which forms the user has already approved.
  // WeakSet lets us track forms without permanently keeping references to them.
  const approvedForms = new WeakSet();

  // Remember which Gmail Send buttons the user has approved.
  const approvedSendButtons = new WeakSet();

  // List the patterns PrivacyGuard looks for when checking text.
  // Each pattern has a name and a regular expression that identifies possible sensitive information.
  const patterns = [
    // Detect email addresses.
    { type: "Email address", regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi },

    // Detect common US phone number formats.
    { type: "US phone number", regex: /(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g },

    // Detect possible US Social Security numbers.
    // The expression excludes some invalid number combinations.
    { type: "US Social Security number", regex: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },

    // Look for possible payment card numbers containing 13–19 digits.
    // The card property tells the detector to perform an additional Luhn check.
    { type: "Possible payment card number", regex: /\b(?:\d[ -]*?){13,19}\b/g, card: true },

    // Detect text that appears to contain a password or verification code.
    // It looks for phrases such as "password is" or "verification code:" followed by a value.
    { type: "Password or verification code", regex: /\b(?:password|passcode|passphrase|login code|verification code|2fa code|one[- ]time code)\s*(?:is|:|=)\s*["']?[^\s"'<>]{4,}/gi },

    // Detect several common formats used by API keys and access tokens.
    { type: "API key or access token", regex: /\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b/g },

    // Detect the header that marks the beginning of certain private cryptographic keys.
    { type: "Private cryptographic key", regex: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g },

    // Detect possible bank account or routing numbers when they appear after related phrases.
    { type: "Possible bank account number", regex: /\b(?:bank account|account number|routing number)\s*(?:is|:|=)?\s*\d[\d -]{5,17}\b/gi }
  ];

  // Check whether a possible payment card number passes the Luhn algorithm.
  // This helps filter out some random numbers that are not valid card-number patterns.
  function passesLuhn(value) {

    // Remove spaces, dashes, and any other characters that are not digits.
    const digits = value.replace(/\D/g, "");

    // Most payment card numbers contain between 13 and 19 digits.
    // Reject numbers outside that range.
    if (digits.length < 13 || digits.length > 19) return false;

    // Store the running total used by the Luhn calculation.
    // doubleDigit determines whether the current digit should be doubled.
    let sum = 0, doubleDigit = false;

    // Read the digits from right to left.
    for (let i = digits.length - 1; i >= 0; i--) {

      // Convert the current character into a number.
      let digit = Number(digits[i]);

      // Double every second digit, starting with the second digit from the right.
      if (doubleDigit) {
        digit *= 2;

        // If doubling produces a two-digit number, subtract 9.
        if (digit > 9) digit -= 9;
      }

      // Add the processed digit to the running total.
      sum += digit;

      // Switch between doubling and not doubling the next digit.
      doubleDigit = !doubleDigit;
    }

    // A number passes the Luhn check when the total is divisible by 10.
    return sum % 10 === 0;
  }

  // Search a piece of text for possible sensitive information.
  function detect(value) {

    // Convert the supplied value into a string.
    // If the value is empty or missing, use an empty string instead.
    const text = String(value || "");

    // Store the types of sensitive information found.
    const findings = [];

    // Check the text against every pattern in the patterns list.
    for (const pattern of patterns) {

      // Reset the regular expression's search position before using it again.
      pattern.regex.lastIndex = 0;

      // Find every match for the current pattern.
      for (const match of text.matchAll(pattern.regex)) {

        // For ordinary patterns, accept a match immediately.
        // For possible card numbers, require the additional Luhn check.
        if (!pattern.card || passesLuhn(match[0])) {

          // Save the category of sensitive information that was detected.
          findings.push({ type: pattern.type });

          // Only one finding per category is needed.
          break;
        }
      }
    }

    // Return all the categories that were detected.
    return findings;
  }

  // Check the fields inside a standard HTML form for sensitive information.
  function scanForm(form) {

    // Create a list to store anything suspicious that is found.
    const findings = [];

    // Find text inputs and text areas inside the form.
    // Password fields and hidden fields are deliberately excluded.
    form.querySelectorAll("input:not([type='password']):not([type='hidden']), textarea").forEach(field => {

      // Skip fields that are disabled or marked as read-only.
      // Check the remaining field values for possible sensitive information.
      if (!field.disabled && !field.readOnly) findings.push(...detect(field.value || ""));
    });

    // Return all the findings from the form.
    return findings;
  }

  // Create a warning popup when possible sensitive information is detected.
  // onContinue is the function to run if the user chooses to proceed.
  function showWarning(findings, onContinue) {

    // Remove any previous PrivacyGuard warning so multiple dialogs do not overlap.
    document.getElementById("privacyguard-dialog")?.remove();

    // Create a dark background that covers the webpage.
    const overlay = document.createElement("div");
    overlay.id = "privacyguard-dialog";

    // Style the background to appear above the website.
    overlay.style.cssText = "position:fixed;inset:0;z-index:2147483647;background:rgba(10,16,28,.68);display:flex;align-items:center;justify-content:center;padding:20px;font:14px/1.45 Arial,sans-serif;color:#172033;";

    // Create the white popup panel that contains the warning.
    const panel = document.createElement("div");

    // Identify the panel as a dialog for accessibility tools.
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-modal", "true");

    // Style the warning panel.
    panel.style.cssText = "box-sizing:border-box;width:min(460px,100%);background:#fff;border-radius:16px;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.28);";

    // Create the warning heading.
    const title = document.createElement("h2");
    title.textContent = "PrivacyGuard found a possible privacy risk";
    title.style.cssText = "font-size:19px;margin:0 0 8px;color:#172033;";

    // Create a short explanation below the heading.
    const intro = document.createElement("p");
    intro.textContent = "Check your message before sharing. We detected:";
    intro.style.cssText = "margin:0 0 14px;color:#526071;";

    // Create a list that will display the types of sensitive information found.
    const list = document.createElement("ul");
    list.style.cssText = "margin:0 0 18px;padding-left:20px;color:#172033;";

    // Remove duplicate finding categories so each one appears only once.
    [...new Set(findings.map(item => item.type))].forEach(type => {

      // Create a list item for each category.
      const li = document.createElement("li");
      li.textContent = type;

      // Add the category to the warning list.
      list.appendChild(li);
    });

    // Explain that the check happens locally and is not a guarantee.
    const note = document.createElement("p");
    note.textContent = "This check runs on your device. PrivacyGuard does not upload your message. Detection is a helpful warning, not a guarantee.";
    note.style.cssText = "font-size:12px;color:#667085;margin:0 0 20px;";

    // Create a container for the two buttons.
    const actions = document.createElement("div");
    actions.style.cssText = "display:flex;gap:10px;justify-content:flex-end;flex-wrap:wrap;";

    // Create the button that lets the user return to the form.
    const cancel = document.createElement("button");
    cancel.textContent = "Go back";
    cancel.style.cssText = "border:1px solid #cbd5e1;background:#fff;color:#172033;border-radius:9px;padding:10px 14px;cursor:pointer;font-weight:600;";

    // Create the button that lets the user continue despite the warning.
    const proceed = document.createElement("button");
    proceed.textContent = "Send anyway";
    proceed.style.cssText = "border:0;background:#b42318;color:#fff;border-radius:9px;padding:10px 14px;cursor:pointer;font-weight:600;";

    // When Go back is clicked, close the warning without continuing.
    cancel.addEventListener("click", () => overlay.remove());

    // When Send anyway is clicked, close the warning and run the approved action.
    proceed.addEventListener("click", () => {
      overlay.remove();
      onContinue();
    });

    // Also close the warning if the user clicks the dark background outside the panel.
    overlay.addEventListener("click", event => {
      if (event.target === overlay) overlay.remove();
    });

    // Add both buttons to the button container.
    actions.append(cancel, proceed);

    // Add all the warning content to the white panel.
    panel.append(title, intro, list, note, actions);

    // Place the panel inside the dark background.
    overlay.appendChild(panel);

    // Add the warning to the webpage.
    document.documentElement.appendChild(overlay);

    // Move keyboard focus to the Go back button.
    cancel.focus();
  }

  // --------------------------------------------------
  // STANDARD HTML FORM PROTECTION
  // --------------------------------------------------

  // Listen for attempts to submit forms on the webpage.
  // The true argument makes this a capturing listener, so it runs early.
  document.addEventListener("submit", event => {

    // Get the element that triggered the submission.
    const form = event.target;

    // Ignore the event if it did not come from a standard HTML form.
    if (!(form instanceof HTMLFormElement)) return;

    // If the user already approved this form, allow the submission.
    // Remove the approval so it only applies to this one submission.
    if (approvedForms.has(form)) {
      approvedForms.delete(form);
      return;
    }

    // Scan the form for possible sensitive information.
    const findings = scanForm(form);

    // If nothing suspicious was found, allow the form to submit normally.
    if (!findings.length) return;

    // Stop the form from submitting immediately.
    event.preventDefault();

    // Stop other event listeners from handling this submission.
    event.stopImmediatePropagation();

    // Display a warning and wait for the user's decision.
    showWarning(findings, () => {

      // Remember that the user approved this particular form.
      approvedForms.add(form);

      // Submit the form again using requestSubmit when the browser supports it.
      // This preserves normal form validation and submit-button behavior.
      if (typeof form.requestSubmit === "function") {
        form.requestSubmit(event.submitter || undefined);
      }

      // Use the older submit method as a fallback.
      else {
        form.submit();
      }
    });

  }, true);

  // --------------------------------------------------
  // GMAIL COMPOSE PROTECTION
  // --------------------------------------------------

  // Only activate this section when the current website is Gmail.
  if (location.hostname === "mail.google.com") {

    // Selectors used to find Gmail's subject and message editor fields.
    const editorSelector = '[contenteditable="true"], textarea, input[name="subjectbox"]';

    // Check whether an element is currently visible on the webpage.
    const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));

    // Check whether an element is a visible Gmail Send button.
    function isSendButton(el) {

      // Ignore elements that do not exist or are hidden.
      if (!el || !visible(el)) return false;

      // Collect possible button labels from several accessibility and display attributes.
      const label = [
        el.getAttribute("aria-label"),
        el.getAttribute("data-tooltip"),
        el.getAttribute("title"),
        el.innerText
      ].filter(Boolean).join(" ").trim();

      // Check whether the collected label begins with the word "Send".
      return /^send\b/i.test(label);
    }

    // Find the Gmail compose area that contains a particular element.
    function getComposeRoot(el) {

      // First, check whether the element is inside a Gmail dialog.
      const dialog = el?.closest?.('[role="dialog"]');

      // If the dialog contains a message editor, use it as the compose area.
      if (dialog && dialog.querySelector(editorSelector)) return dialog;

      // Otherwise, move upward through the element's parent elements.
      let current = el?.parentElement;

      while (current && current !== document.body) {

        // Find the first parent that contains a message editor.
        if (current.querySelector(editorSelector)) return current;

        // Continue moving up the webpage.
        current = current.parentElement;
      }

      // If no compose area is found, use the entire document as a fallback.
      return document;
    }

    // Collect the subject and message text from a Gmail compose area.
    function getComposeText(root) {

      // Return an empty string if no compose area exists.
      if (!root) return "";

      // Store the text collected from the message fields.
      const parts = [];

      // Find Gmail's subject input field.
      const subject = root.querySelector('input[name="subjectbox"]');

      // Add the subject if the field exists and is not disabled.
      if (subject && !subject.disabled) parts.push(subject.value || "");

      // Look for Gmail's main message editor.
      let editors = [...root.querySelectorAll('[contenteditable="true"][aria-label*="Message Body"], [contenteditable="true"][role="textbox"]')];

      // If those selectors do not find an editor, use other editable elements as a fallback.
      if (!editors.length) {
        editors = [...root.querySelectorAll('[contenteditable="true"]')].filter(el =>
          !/recipient|to:|cc:|bcc:/i.test(el.getAttribute("aria-label") || "")
        );
      }

      // Add the visible message editor text to the collected text.
      editors.filter(visible).forEach(el => parts.push(el.innerText || el.textContent || ""));

      // Combine the subject and message body into one string.
      return parts.join("\n");
    }

    // Find the Send button inside a Gmail compose area.
    function findSendButton(root) {

      // Search inside the compose area, or the whole document if necessary.
      const scope = root && root !== document ? root : document;

      // Return the first matching Send button, or null if none is found.
      return [...scope.querySelectorAll('button, [role="button"]')].find(isSendButton) || null;
    }

    // Check the Gmail message before allowing it to be sent.
    function checkSend(button, root) {

      // If there is no Send button, there is nothing to check.
      if (!button) return false;

      // If the user has already approved this button, allow this click.
      // Remove the approval so it only applies once.
      if (approvedSendButtons.has(button)) {
        approvedSendButtons.delete(button);
        return false;
      }

      // Scan the Gmail subject and message body for possible sensitive information.
      const findings = detect(getComposeText(root));

      // If no sensitive information was found, allow the message to be sent.
      if (!findings.length) return false;

      // Show a warning before the message is sent.
      showWarning(findings, () => {

        // Remember that the user approved this Send button.
        approvedSendButtons.add(button);

        // Click the Send button again after approval.
        button.click();
      });

      // Return true to indicate that the original Send action was stopped.
      return true;
    }

    // Listen for clicks on the Gmail webpage.
    document.addEventListener("click", event => {

      // Find the actual webpage element that was clicked.
      const target = event.target instanceof Element ? event.target : event.target?.parentElement;

      // Find the nearest button or element acting as a button.
      const button = target?.closest?.('button, [role="button"]');

      // Ignore the click unless it came from a Send button.
      if (!button || !isSendButton(button)) return;

      // Check the message before allowing the Send button to work.
      if (checkSend(button, getComposeRoot(button))) {

        // Stop Gmail's original Send action while the warning is displayed.
        event.preventDefault();
        event.stopImmediatePropagation();
      }

    }, true);

    // Also listen for keyboard shortcuts that can send Gmail messages.
    document.addEventListener("keydown", event => {

      // Only continue when the user presses Command+Enter or Ctrl+Enter.
      if (!(event.metaKey || event.ctrlKey) || event.key !== "Enter") return;

      // Find the element where the keyboard shortcut was used.
      const target = event.target instanceof Element ? event.target : event.target?.parentElement;

      // Ignore the shortcut unless it was used inside a message editor.
      if (!target?.closest?.(editorSelector)) return;

      // Find the compose area containing the editor.
      const root = getComposeRoot(target);

      // Scan the subject and message text.
      const findings = detect(getComposeText(root));

      // If nothing suspicious was found, allow the normal shortcut behavior.
      if (!findings.length) return;

      // Find the Send button for this compose area.
      const button = findSendButton(root);

      // If no Send button can be found, stop here.
      if (!button) return;

      // Stop the keyboard shortcut from sending the message immediately.
      event.preventDefault();
      event.stopImmediatePropagation();

      // Display the warning and let the user decide whether to continue.
      showWarning(findings, () => {
        approvedSendButtons.add(button);
        button.click();
      });

    }, true);
  }

  // --------------------------------------------------
  // CAMERA ACTIVITY ALERTS
  // --------------------------------------------------

  // Store the camera warning element so it can be removed later.
  let cameraNotice = null;

  // Remember whether the user has successfully blocked the camera.
  let cameraBlockedNotice = false;

  // Remove the camera warning from the webpage.
  function removeCameraNotice() {
    cameraNotice?.remove();
    cameraNotice = null;
  }

  // Display a warning when PrivacyGuard detects an active camera stream.
  function showCameraNotice() {

    // Do not show another warning if one already exists
    // or if the user has already blocked the camera.
    if (cameraNotice || cameraBlockedNotice) return;

    // Create the camera warning container.
    const notice = document.createElement("section");
    notice.id = "privacyguard-camera-alert";

    // Identify the warning as an alert for accessibility tools.
    notice.setAttribute("role", "alert");

    // Style the warning so it appears in the top-right corner of the webpage.
    notice.style.cssText = "position:fixed;top:18px;right:18px;z-index:2147483646;width:min(360px,calc(100vw - 36px));box-sizing:border-box;background:#fff;border:1px solid #f0b4ad;border-left:5px solid #c62828;border-radius:12px;padding:16px;box-shadow:0 12px 36px rgba(0,0,0,.24);font:14px/1.45 Arial,sans-serif;color:#172033;";

    // Create the warning heading.
    const heading = document.createElement("strong");
    heading.textContent = "PrivacyGuard: Camera is active";
    heading.style.cssText = "display:block;font-size:16px;margin-bottom:6px;color:#a61b1b;";

    // Explain why the warning appeared and what the user can do.
    const detail = document.createElement("p");
    detail.textContent = "This website has started a camera stream in this tab. If you did not expect this, block camera access for this site.";
    detail.style.cssText = "margin:0 0 12px;color:#475467;";

    // Create a container for the warning buttons.
    const actions = document.createElement("div");
    actions.style.cssText = "display:flex;gap:8px;align-items:center;flex-wrap:wrap;";

    // Create a button that asks Chrome to block camera access for this website.
    const block = document.createElement("button");
    block.textContent = "Block camera on this site";
    block.style.cssText = "border:0;background:#b42318;color:#fff;border-radius:8px;padding:9px 11px;cursor:pointer;font-weight:600;";

    // Create a button that dismisses the warning.
    const dismiss = document.createElement("button");
    dismiss.textContent = "Dismiss";
    dismiss.style.cssText = "border:1px solid #d0d5dd;background:#fff;color:#344054;border-radius:8px;padding:9px 11px;cursor:pointer;";

    // Close the warning when the user clicks Dismiss.
    dismiss.addEventListener("click", removeCameraNotice);

    // Restore camera permission after the user has blocked it.
    function unblockCamera() {
      block.disabled = true;
      block.textContent = "Allowing…";

      try {
        chrome.runtime.sendMessage(
          {
            type: "PRIVACYGUARD_UNBLOCK_CAMERA",
            origin: location.origin
          },
          response => {
            if (chrome.runtime.lastError || !response?.ok) {
              block.disabled = false;
              block.textContent = "Try allowing again";
              detail.textContent = response?.error || chrome.runtime.lastError?.message || "Could not restore this site's camera permission.";
              return;
            }

            // Restoring permission does not automatically restart the camera.
            cameraBlockedNotice = false;
            heading.textContent = "Camera permission restored";
            heading.style.color = "#18794e";
            detail.textContent = "Chrome camera permission is now Allow for this site. The website may ask to use your camera again; it will not restart automatically.";
            block.remove();
            dismiss.textContent = "Close";
          }
        );
      } catch (_) {
        block.disabled = false;
        block.textContent = "Try allowing again";
        detail.textContent = "Could not contact PrivacyGuard. Change this site's camera permission in Chrome site settings.";
      }
    }

    // Handle the user's request to block camera access.
    function blockCamera() {

      // Disable the button while the permission change is being processed.
      block.disabled = true;
      block.textContent = "Blocking…";

      try {

        // Send a message to the extension's background script.
        // The background script uses Chrome's content settings API to block the camera.
        chrome.runtime.sendMessage(
          {
            type: "PRIVACYGUARD_BLOCK_CAMERA",
            origin: location.origin
          },
          response => {

            // Check whether Chrome reported an error or the request failed.
            if (chrome.runtime.lastError || !response?.ok) {

              // Allow the user to try again.
              block.disabled = false;
              block.textContent = "Try blocking again";

              // Display the error message, or provide a general fallback message.
              detail.textContent = response?.error || chrome.runtime.lastError?.message || "Could not change this site's camera permission. Use the camera icon or site settings in Chrome.";

              return;
            }

            // Ask the MAIN-world camera monitor to stop the camera tracks it is tracking.
            window.postMessage({ privacyGuardCameraCommand: "STOP_ACTIVE_CAMERA" }, "*");

            // Remember that the user successfully blocked camera access.
            cameraBlockedNotice = true;

            // Change the heading to confirm that the action succeeded.
            heading.textContent = "Camera blocked for this site";
            heading.style.color = "#18794e";

            // Explain that the active stream was stopped and Chrome's permission was changed.
            detail.textContent = "PrivacyGuard stopped the active camera stream and changed this website's Chrome camera permission to Block. You can change it later in Chrome site settings.";

            // Turn the same button into an option to restore camera permission.
            block.textContent = "Allow camera again";
            block.style.background = "#18794e";
            block.removeEventListener("click", blockCamera);
            block.addEventListener("click", unblockCamera);

            // Change Dismiss into a Close button.
            dismiss.textContent = "Close";
          }
        );

      } catch (_) {

        // If the extension cannot send the message, let the user try again.
        block.disabled = false;
        block.textContent = "Try blocking again";

        // Explain how the user can block camera access manually in Chrome.
        detail.textContent = "Could not contact PrivacyGuard. Open this site's camera permission in Chrome settings and set it to Block.";
      }
    }
    block.addEventListener("click", blockCamera);

    // Add both buttons to the warning.
    actions.append(block, dismiss);

    // Add the heading, explanation, and buttons to the warning container.
    notice.append(heading, detail, actions);

    // Display the warning on the webpage.
    document.documentElement.appendChild(notice);

    // Save a reference to the warning so it can be removed later.
    cameraNotice = notice;
  }

  // Listen for camera activity messages sent by the MAIN-world camera monitor.
  window.addEventListener("message", event => {

    // Ignore messages that did not come from this page
    // or were not marked as PrivacyGuard camera messages.
    if (event.source !== window || event.data?.privacyGuardCamera !== true) return;

    // Show the warning when a camera becomes active.
    if (event.data.type === "CAMERA_ACTIVE") showCameraNotice();

    // Remove the warning when the camera becomes inactive,
    // unless the user has already successfully blocked camera access.
    if (event.data.type === "CAMERA_INACTIVE" && !cameraBlockedNotice) removeCameraNotice();
  });

  // --------------------------------------------------
  // LIVE PRIVACY DASHBOARD
  // --------------------------------------------------

  // The dashboard reports permission states and detected camera activity.
  // It does not collect page content, camera images, audio, or location coordinates.

  // Remember whether the camera monitor currently reports an active camera.
  let privacyGuardCameraActive = false;

  // Listen for camera activity updates from the MAIN-world monitor.
  window.addEventListener("message", event => {

    // Only accept messages sent by this page and marked as PrivacyGuard messages.
    if (event.source !== window || event.data?.privacyGuardCamera !== true) return;

    // Update the camera status when a camera becomes active or inactive.
    if (event.data.type === "CAMERA_ACTIVE") privacyGuardCameraActive = true;
    if (event.data.type === "CAMERA_INACTIVE") privacyGuardCameraActive = false;

    // Only send an update to the extension when the camera status actually changes.
    if (event.data.type === "CAMERA_ACTIVE" || event.data.type === "CAMERA_INACTIVE") {
      try {

        // Send the current camera status to the extension's background script.
        chrome.runtime.sendMessage({
          type: "PRIVACYGUARD_CAMERA_STATUS",
          active: privacyGuardCameraActive
        });

      } catch (_) {
        // Ignore errors if the extension cannot receive the message.
      }
    }
  });

  // Check the browser's permission status for a particular feature.
  async function readPermission(name) {
    try {

      // Check whether the browser supports the Permissions API.
      // If it does not, report that the permission status is unsupported.
      if (!navigator.permissions?.query) return "unsupported";

      // Ask the browser for the current permission state.
      const result = await navigator.permissions.query({ name });

      // Return the permission state, such as "granted", "denied", or "prompt".
      return result.state || "unknown";

    } catch (_) {

      // Some browsers or features may not support permission queries.
      // Return "unsupported" if the request fails.
      return "unsupported";
    }
  }

  // Listen for requests from the extension popup asking for dashboard information.
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

    // Ignore messages that are not requesting dashboard information.
    if (message?.type !== "PRIVACYGUARD_GET_DASHBOARD") return;

    // Check camera, microphone, and location permission states.
    // Promise.all waits until all three permission checks have finished.
    Promise.all([
      readPermission("camera"),
      readPermission("microphone"),
      readPermission("geolocation")
    ]).then(([camera, microphone, location]) => {

      // Send the collected permission states and camera activity status
      // back to the extension popup.
      sendResponse({
        cameraActive: privacyGuardCameraActive,
        cameraPermission: camera,
        microphonePermission: microphone,
        locationPermission: location
      });
    });

    // Keep the message channel open because the permission checks are asynchronous.
    // This allows sendResponse() to run after Promise.all finishes.
    return true;
  });



  // --------------------------------------------------
  // --------------------------------------------------
  // SCAM CONVERSATION CHECKER
  // --------------------------------------------------

  // Each category below creates 500 phrase combinations (25 starters x 20 endings).
  // Matching complete phrases is more useful than flagging isolated words such as
  // "Bitcoin" or "password", which can appear in perfectly harmless conversations.
  function buildPhraseBank(starters, endings) {
    return starters.flatMap(starter => endings.map(ending => starter + " " + ending));
  }

  const scamPhraseBanks = [
    {
      type: "Request for passwords or login details",
      phrases: buildPhraseBank(
        ["please send me your", "please share your", "tell me your", "provide your", "enter your", "type your", "reply with your", "message me your", "confirm your", "verify your", "we need your", "i need your", "support needs your", "our team needs your", "for security give us your", "to continue provide your", "to restore access enter your", "before we proceed share your", "kindly submit your", "can you give me your", "send over your", "forward your", "write down your", "read out your", "upload a copy of your"],
        ["account password", "bank password", "email password", "email login", "bank login", "online banking details", "login credentials", "account credentials", "sign in details", "passphrase", "security answer", "recovery phrase", "wallet recovery phrase", "private key", "card PIN", "debit card PIN", "credit card PIN", "social media password", "work account password", "remote access password"]
      )
    },
    {
      type: "Request for a one-time or verification code",
      phrases: buildPhraseBank(
        ["send me your", "share your", "tell me the", "read me the", "reply with the", "forward the", "copy and send the", "enter the", "type in the", "confirm the", "provide the", "we need the", "support needs the", "our team needs the", "to verify you send the", "to unlock your account send the", "before we continue share the", "please disclose the", "message me the", "give me the", "submit your", "repeat the", "dictate the", "paste the", "upload the"],
        ["one time password", "one-time code", "verification code", "security code", "login code", "sign in code", "two factor code", "2fa code", "authentication code", "authenticator code", "text message code", "SMS code", "email code", "bank confirmation code", "account recovery code", "password reset code", "MFA code", "OTP code", "six digit code", "six-digit verification number"]
      )
    },
    {
      type: "Urgent pressure or threats",
      phrases: buildPhraseBank(
        ["act now or", "respond immediately or", "verify today or", "complete this now or", "pay today or", "reply within one hour or", "you must act now because", "urgent action is required because", "final notice because", "this is your last chance because", "failure to respond means", "if you do not comply", "unless you pay now", "your account is at risk because", "we will close your account if", "we will suspend access if", "legal action will begin if", "the police will be contacted if", "your funds will be frozen unless", "your device will be locked unless", "your service ends today because", "immediate payment is required to avoid", "do not delay or face", "you have minutes before", "this warning expires before"],
        ["your account is closed", "your account is suspended", "your account is permanently disabled", "your bank access is blocked", "your money is frozen", "your funds are seized", "your identity is cancelled", "your device is disabled", "your computer is locked", "your service is disconnected", "a warrant is issued", "police arrive at your home", "you are arrested", "you face prosecution", "you lose your refund", "your payment is forfeited", "your benefits are terminated", "your package is returned", "your account is deleted", "your access is permanently removed"]
      )
    },
    {
      type: "Suspicious payment method",
      phrases: buildPhraseBank(
        ["please pay using", "send the payment through", "make payment with", "settle the balance using", "purchase and send", "pay the fee with", "transfer the money using", "deposit funds into", "send funds by", "complete payment via", "we only accept", "the safest way is", "to release your funds use", "to avoid suspension pay with", "buy and send", "pay your tax using", "pay the delivery fee with", "send the amount in", "make a deposit through", "refund processing requires", "pay our agent with", "send the money to", "load funds onto", "pay the invoice in", "cover the charge using"],
        ["gift cards", "Apple gift cards", "Google Play cards", "Steam gift cards", "Amazon gift cards", "iTunes cards", "prepaid debit cards", "vanilla prepaid cards", "Bitcoin", "cryptocurrency", "Ethereum", "USDT", "crypto wallet", "wire transfer", "Western Union", "MoneyGram", "cash deposit", "peer to peer transfer", "friends and family transfer", "payment app transfer"]
      )
    },
    {
      type: "Impersonation or fake support language",
      phrases: buildPhraseBank(
        ["i am calling from", "i am contacting you from", "this is a message from", "we are representatives of", "i work for", "i represent", "your case has been assigned to", "your account is managed by", "our security department at", "the official support team at", "this is the fraud department of", "i am an agent with", "we are the help desk for", "your government office is", "your bank's security team is", "this notice is from", "we have been sent by", "i am an officer with", "your technical support provider is", "the verification team at", "we are contacting you on behalf of", "your payment provider's team is", "i am a specialist from", "the investigation unit at", "your account recovery agent is from"],
        ["your bank", "the IRS", "Social Security", "Medicare", "the police department", "the FBI", "the tax office", "Microsoft support", "Apple support", "Amazon support", "Google support", "PayPal security", "your credit union", "your card provider", "the post office", "the customs office", "the immigration office", "your internet provider", "the fraud prevention unit", "the government"]
      )
    },
    {
      type: "Prize, refund, or unexpected money offer",
      phrases: buildPhraseBank(
        ["you have won", "you are selected to receive", "you qualify for", "claim your", "collect your", "unlock your", "release your", "we are sending you", "a payment of", "a refund of", "your reward is", "your prize is", "you are entitled to", "an inheritance of", "you have been awarded", "your guaranteed return is", "we found an unclaimed", "your compensation payment is", "your grant payment is", "your lottery payout is", "you can receive", "your cash bonus is", "your settlement payment is", "your surprise gift is", "your winning amount is"],
        ["a cash prize", "a lottery prize", "a free gift", "a guaranteed reward", "a large refund", "an unexpected refund", "an unclaimed payment", "an inheritance", "a government grant", "a tax refund", "a compensation payment", "a settlement payment", "a cash bonus", "a gift voucher", "a prize payout", "a no-risk investment return", "a guaranteed investment profit", "a reward for selected users", "a package of free money", "a special winnings payment"]
      )
    },
    {
      type: "Request to move to a private channel",
      phrases: buildPhraseBank(
        ["let us continue on", "message me privately on", "contact me directly on", "move this conversation to", "switch over to", "we should talk on", "for security use", "for faster support use", "send me a message through", "add me on", "i will explain it on", "continue our chat using", "leave this platform and use", "please download", "install this app and contact me on", "reach my personal account on", "talk to my manager on", "our agent will contact you via", "send your details through", "we can finish the process on", "use my private account on", "do not message here; use", "continue the support session on", "join my private chat on", "switch to an encrypted chat on"],
        ["WhatsApp", "Telegram", "Signal", "Skype", "Google Chat", "Facebook Messenger", "Instagram DM", "Snapchat", "Discord", "Kik", "Line", "Viber", "WeChat", "Threema", "Wire", "Session", "a private chat", "my personal number", "a different messaging app", "an outside messaging service"]
      )
    },
    {
      type: "Suspicious link or account verification request",
      phrases: buildPhraseBank(
        ["click this link to", "open the link below to", "visit this page to", "use this URL to", "tap here to", "follow this link and", "go to this website to", "sign in through this link to", "enter your details here to", "use our portal to", "complete the form to", "confirm your account to", "restore access by", "unlock your profile by", "avoid suspension by", "validate your identity by", "update your payment details to", "secure your account by", "claim your refund by", "track your package by", "release the payment by", "verify your bank account by", "reset your password by", "confirm delivery by", "resolve the issue by"],
        ["verify your account", "confirm your identity", "unlock your account", "restore your access", "avoid account closure", "update your password", "confirm your bank details", "validate your payment method", "claim your refund", "release your package", "prevent account suspension", "remove a security hold", "confirm your card", "update your personal information", "recover your profile", "activate your account", "review a suspicious transaction", "receive your prize", "complete a payment", "download a required security update"]
      )
    }
  ];

  // Check visible page text only when the user requests a scan from the popup.
  // This does not read password fields, hidden content, or send text anywhere.
  function checkScamConversation() {
    const pageText = (document.body?.innerText || "").slice(0, 30000).toLowerCase();
    const findings = scamPhraseBanks
      .filter(category => category.phrases.some(phrase => pageText.includes(phrase.toLowerCase())))
      .map(category => category.type);

    return {
      findings,
      level: findings.length >= 3 ? "high" : findings.length ? "caution" : "none",
      phraseCounts: scamPhraseBanks.map(category => ({ type: category.type, count: category.phrases.length }))
    };
  }

  // Respond only to the popup's explicit scan request.
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type !== "PRIVACYGUARD_SCAN_SCAM_CONVERSATION") return;
    sendResponse(checkScamConversation());
  });

})(); // Immediately run the entire PrivacyGuard content script.
