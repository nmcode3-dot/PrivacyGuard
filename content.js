(() => {
  // All checks run locally. Password input fields are never read.
  const approvedForms = new WeakSet();
  const approvedSendButtons = new WeakSet();
  const patterns = [
    { type: "Email address", regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi },
    { type: "US phone number", regex: /(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g },
    { type: "US Social Security number", regex: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
    { type: "Possible payment card number", regex: /\b(?:\d[ -]*?){13,19}\b/g, card: true },
    { type: "Password or verification code", regex: /\b(?:password|passcode|passphrase|login code|verification code|2fa code|one[- ]time code)\s*(?:is|:|=)\s*["']?[^\s"'<>]{4,}/gi },
    { type: "API key or access token", regex: /\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b/g },
    { type: "Private cryptographic key", regex: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g },
    { type: "Possible bank account number", regex: /\b(?:bank account|account number|routing number)\s*(?:is|:|=)?\s*\d[\d -]{5,17}\b/gi }
  ];

  function passesLuhn(value) {
    const digits = value.replace(/\D/g, "");
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0, doubleDigit = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let digit = Number(digits[i]);
      if (doubleDigit) { digit *= 2; if (digit > 9) digit -= 9; }
      sum += digit;
      doubleDigit = !doubleDigit;
    }
    return sum % 10 === 0;
  }

  function detect(value) {
    const text = String(value || "");
    const findings = [];
    for (const pattern of patterns) {
      pattern.regex.lastIndex = 0;
      for (const match of text.matchAll(pattern.regex)) {
        if (!pattern.card || passesLuhn(match[0])) {
          findings.push({ type: pattern.type });
          break;
        }
      }
    }
    return findings;
  }

  function scanForm(form) {
    const findings = [];
    form.querySelectorAll("input:not([type='password']):not([type='hidden']), textarea").forEach(field => {
      if (!field.disabled && !field.readOnly) findings.push(...detect(field.value || ""));
    });
    return findings;
  }

  function showWarning(findings, onContinue) {
    document.getElementById("privacyguard-dialog")?.remove();
    const overlay = document.createElement("div");
    overlay.id = "privacyguard-dialog";
    overlay.style.cssText = "position:fixed;inset:0;z-index:2147483647;background:rgba(10,16,28,.68);display:flex;align-items:center;justify-content:center;padding:20px;font:14px/1.45 Arial,sans-serif;color:#172033;";
    const panel = document.createElement("div");
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-modal", "true");
    panel.style.cssText = "box-sizing:border-box;width:min(460px,100%);background:#fff;border-radius:16px;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.28);";
    const title = document.createElement("h2");
    title.textContent = "PrivacyGuard found a possible privacy risk";
    title.style.cssText = "font-size:19px;margin:0 0 8px;color:#172033;";
    const intro = document.createElement("p");
    intro.textContent = "Check your message before sharing. We detected:";
    intro.style.cssText = "margin:0 0 14px;color:#526071;";
    const list = document.createElement("ul");
    list.style.cssText = "margin:0 0 18px;padding-left:20px;color:#172033;";
    [...new Set(findings.map(item => item.type))].forEach(type => {
      const li = document.createElement("li");
      li.textContent = type;
      list.appendChild(li);
    });
    const note = document.createElement("p");
    note.textContent = "This check runs on your device. PrivacyGuard does not upload your message. Detection is a helpful warning, not a guarantee.";
    note.style.cssText = "font-size:12px;color:#667085;margin:0 0 20px;";
    const actions = document.createElement("div");
    actions.style.cssText = "display:flex;gap:10px;justify-content:flex-end;flex-wrap:wrap;";
    const cancel = document.createElement("button");
    cancel.textContent = "Go back";
    cancel.style.cssText = "border:1px solid #cbd5e1;background:#fff;color:#172033;border-radius:9px;padding:10px 14px;cursor:pointer;font-weight:600;";
    const proceed = document.createElement("button");
    proceed.textContent = "Send anyway";
    proceed.style.cssText = "border:0;background:#b42318;color:#fff;border-radius:9px;padding:10px 14px;cursor:pointer;font-weight:600;";
    cancel.addEventListener("click", () => overlay.remove());
    proceed.addEventListener("click", () => { overlay.remove(); onContinue(); });
    overlay.addEventListener("click", event => { if (event.target === overlay) overlay.remove(); });
    actions.append(cancel, proceed);
    panel.append(title, intro, list, note, actions);
    overlay.appendChild(panel);
    document.documentElement.appendChild(overlay);
    cancel.focus();
  }

  // Standard HTML forms.
  document.addEventListener("submit", event => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (approvedForms.has(form)) { approvedForms.delete(form); return; }
    const findings = scanForm(form);
    if (!findings.length) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    showWarning(findings, () => {
      approvedForms.add(form);
      if (typeof form.requestSubmit === "function") form.requestSubmit(event.submitter || undefined);
      else form.submit();
    });
  }, true);

  // Gmail custom compose editor and Send button.
  if (location.hostname === "mail.google.com") {
    const editorSelector = '[contenteditable="true"], textarea, input[name="subjectbox"]';
    const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));

    function isSendButton(el) {
      if (!el || !visible(el)) return false;
      const label = [el.getAttribute("aria-label"), el.getAttribute("data-tooltip"), el.getAttribute("title"), el.innerText].filter(Boolean).join(" ").trim();
      return /^send\b/i.test(label);
    }

    function getComposeRoot(el) {
      const dialog = el?.closest?.('[role="dialog"]');
      if (dialog && dialog.querySelector(editorSelector)) return dialog;
      let current = el?.parentElement;
      while (current && current !== document.body) {
        if (current.querySelector(editorSelector)) return current;
        current = current.parentElement;
      }
      return document;
    }

    function getComposeText(root) {
      if (!root) return "";
      const parts = [];
      const subject = root.querySelector('input[name="subjectbox"]');
      if (subject && !subject.disabled) parts.push(subject.value || "");
      let editors = [...root.querySelectorAll('[contenteditable="true"][aria-label*="Message Body"], [contenteditable="true"][role="textbox"]')];
      if (!editors.length) {
        editors = [...root.querySelectorAll('[contenteditable="true"]')].filter(el => !/recipient|to:|cc:|bcc:/i.test(el.getAttribute("aria-label") || ""));
      }
      editors.filter(visible).forEach(el => parts.push(el.innerText || el.textContent || ""));
      return parts.join("\n");
    }

    function findSendButton(root) {
      const scope = root && root !== document ? root : document;
      return [...scope.querySelectorAll('button, [role="button"]')].find(isSendButton) || null;
    }

    function checkSend(button, root) {
      if (!button) return false;
      if (approvedSendButtons.has(button)) { approvedSendButtons.delete(button); return false; }
      const findings = detect(getComposeText(root));
      if (!findings.length) return false;
      showWarning(findings, () => { approvedSendButtons.add(button); button.click(); });
      return true;
    }

    document.addEventListener("click", event => {
      const target = event.target instanceof Element ? event.target : event.target?.parentElement;
      const button = target?.closest?.('button, [role="button"]');
      if (!button || !isSendButton(button)) return;
      if (checkSend(button, getComposeRoot(button))) {
        event.preventDefault();
        event.stopImmediatePropagation();
      }
    }, true);

    document.addEventListener("keydown", event => {
      if (!(event.metaKey || event.ctrlKey) || event.key !== "Enter") return;
      const target = event.target instanceof Element ? event.target : event.target?.parentElement;
      if (!target?.closest?.(editorSelector)) return;
      const root = getComposeRoot(target);
      const findings = detect(getComposeText(root));
      if (!findings.length) return;
      const button = findSendButton(root);
      if (!button) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      showWarning(findings, () => { approvedSendButtons.add(button); button.click(); });
    }, true);
  }
})();