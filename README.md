# PrivacyGuard 🛡️

A lightweight Chrome extension prototype that detects some potentially sensitive information in regular HTML forms before submission.

## What it currently detects

- Email addresses
- US-style phone numbers
- US Social Security number patterns
- Possible payment card numbers (with a Luhn checksum check)

When a matching value is found in a regular HTML form, PrivacyGuard pauses submission and lets the user go back or submit anyway.

## Privacy approach

- Detection runs locally in the browser content script.
- This prototype does not send scanned text to a server.
- Password input fields are intentionally excluded.
- The extension does not store detected values.

## Install locally

1. Download or clone this repository.
2. Open `chrome://extensions` in Google Chrome.
3. Turn on **Developer mode**.
4. Select **Load unpacked**.
5. Choose the `privacyguard` project folder.

## Project files

- `manifest.json` — Chrome Extension Manifest V3 configuration.
- `content.js` — local detection and pre-submit warning.
- `popup.html` and `popup.css` — extension popup interface.

## Current limitations

This is an early prototype, not a complete privacy or security product.

- It currently checks regular HTML form submissions. Many modern websites, including some chat apps, send messages through JavaScript handlers without a normal form submit event.
- It does not yet inspect `contenteditable` editors, file uploads, screenshots, or clipboard contents.
- Pattern matching can produce false positives and false negatives.
- A Luhn-valid number is not proof that a number is an active payment card.
- The phone and SSN checks are tailored to common US formats.
- It does not automatically redact information.

Always review what you are sharing. PrivacyGuard is a warning aid, not a guarantee that sensitive data will be blocked.

## Roadmap

- [ ] Live scanning while typing
- [ ] Support for contenteditable editors and selected AI chat interfaces
- [ ] User-configurable detection categories
- [ ] Optional redaction with user confirmation
- [ ] Unit tests for detection patterns
- [ ] Accessibility and browser compatibility testing

## Development

No build step or external dependencies are required for this prototype.

## License

MIT — see `LICENSE`.
