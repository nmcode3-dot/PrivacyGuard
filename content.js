(() => {
  // PrivacyGuard v0.1: all scanning happens locally in this browser tab.
  // Password fields are deliberately excluded.
  const approvedForms = new WeakSet();
  const patterns = [
    { type: "Email address", regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi },
    { type: "US phone number", regex: /(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g },
    { type: "US Social Security number", regex: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
    { type: "Possible payment card number", regex: /\b(?:\d[ -]*?){13,19}\b/g, card: true }
  ];

  function passesLuhn(value) {
    const digits = value.replace(/\D/g, "");
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0;
    let doubleDigit = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let digit = Number(digits[i]);
      if (doubleDigit) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      doubleDigit = !doubleDigit;
    }
    return sum % 10 === 0;
  }

  function detect(text) {
    const findings = [];
    for (const pattern of patterns) {
      pattern.regex.lastIndex = 0;
      for (const match of text.matchAll(pattern.regex)) {
        if (!pattern.card || passesLuhn(match[0])) {
          findings.push({ type: pattern.type, value: match[0] });
        }
      }
    }
    return findings;
  }

  function scanForm(form) {
    const fields = form.querySelectorAll("input:not([type='password']):not([type='hidden']), textarea");
    const findings = [];
    fields.forEach((field) => {
      if (field.disabled || field.readOnly) return;
      findings.push(...detect(field.value || ""));
    });
    return findings;
  }

  function showWarning(form, findings, submitter) {
    const existing = document.getElementById("privacyguard-dialog");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "privacyguard-dialog";
    overlay.style.cssText = "position:fixed;inset:0;z-index:2147483647;background:rgba(10,16,28,.62);display:flex;align-items:center;justify-content:center;padding:20px;font:14px/1.45 Arial,sans-serif;color:#172033;";

    const panel = document.createElement("div");
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-modal", "true");
    panel.setAttribute("aria-labelledby", "pg-title");
    panel.style.cssText = "box-sizing:border-box;width:min(440px,100%);background:#fff;border-radius:16px;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.28);";

    const title = document.createElement("h2");
    title.id = "pg-title";
    title.textContent = "PrivacyGuard found sensitive information";
    title.style.cssText = "font-size:19px;margin:0 0 8px;color:#172033;";

    const intro = document.createElement("p");
    intro.textContent = "This form appears to contain information you may not want to share:";
    intro.style.cssText = "margin:0 0 14px;color:#526071;";

    const list = document.createElement("ul");
    list.style.cssText = "margin:0 0 18px;padding-left:20px;color:#172033;";
    const uniqueTypes = [...new Set(findings.map((item) => item.type))];
    uniqueTypes.forEach((type) => {
      const li = document.createElement("li");
      li.textContent = type;
      list.appendChild(li);
    });

    const note = document.createElement("p");
    note.textContent = "Your text is scanned locally by this extension; PrivacyGuard does not send it to a server. The website may still receive it if you choose to continue.";
    note.style.cssText = "font-size:12px;color:#667085;margin:0 0 20px;";

    const actions = document.createElement("div");
    actions.style.cssText = "display:flex;gap:10px;justify-content:flex-end;flex-wrap:wrap;";
    const cancel = document.createElement("button");
    cancel.textContent = "Go back";
    cancel.style.cssText = "border:1px solid #cbd5e1;background:#fff;color:#172033;border-radius:9px;padding:10px 14px;cursor:pointer;font-weight:600;";
    const proceed = document.createElement("button");
    proceed.textContent = "Submit anyway";
    proceed.style.cssText = "border:0;background:#b42318;color:#fff;border-radius:9px;padding:10px 14px;cursor:pointer;font-weight:600;";

    cancel.addEventListener("click", () => overlay.remove());
    proceed.addEventListener("click", () => {
      overlay.remove();
      approvedForms.add(form);
      if (typeof form.requestSubmit === "function") form.requestSubmit(submitter || undefined);
      else form.submit();
    });
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) overlay.remove();
    });
    panel.append(title, intro, list, note, actions);
    actions.append(cancel, proceed);
    overlay.appendChild(panel);
    document.documentElement.appendChild(overlay);
    cancel.focus();
  }

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (approvedForms.has(form)) {
      approvedForms.delete(form);
      return;
    }
    const findings = scanForm(form);
    if (findings.length === 0) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    showWarning(form, findings, event.submitter);
  }, true);
})();
