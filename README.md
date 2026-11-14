# PrivacyGuard - Nishil Mehta, OCSEF Hacks

A Chrome extension that helps people spot privacy risks before they share information or interact with websites. Made for OCSEF Hacks Hackathon.

## Features

### Website risk rating

- Shows a 0–100 indicator on the site safety for the current tab when the extension popup is opened. Notifies the user if its <50.
- Checks URL-only warning signs locally, including missing HTTPS, embedded credentials, punycode domains, raw IP addresses, unusually long domains, and suspicious account/payment wording in the hostname. User is notified instantly upon entrance to site.
- Explains which signals affected the rating, and possible signs of scams, malware, and dangerous bots.
- Does not send browsing history or page URLs to a server.

The score is a simple estimation, not a instant determinant of a site's genuine safety. It does not verify site ownership, inspect a site's full behavior, or guarantee that a website is safe. A site with a high score may still be malicious, and a legitimate site may receive a warning.

### Sensitive-information detection

- Email addresses
- Common US phone number formats
- US Social Security number patterns
- Possible payment card numbers (validated with the Luhn checksum)
- Password, passcode, and verification-code phrases when followed by a value
- Common API keys and access tokens (recognizable GitHub, Slack, AWS, and `sk-` formats)
- Private cryptographic key headers
- Possible bank account or routing numbers when introduced by a matching phrase

### Gmail support

PrivacyGuard includes best-effort support for Gmail's custom compose editor and Send button, including the Ctrl/Cmd+Enter shortcut. It reads the subject and message body when it can identify them. Gmail's interface changes over time, so this integration must be tested against current Gmail behavior and is not guaranteed to intercept every send path.

### Camera protection

- A page-world monitor observes calls to `navigator.mediaDevices.getUserMedia()` that request video and reports when a live video track starts or ends.
- The extension displays an alert while a camera stream is active in that tab.
- The alert offers **Block camera on this site**. This sets Chrome's camera content setting for that website to Block and asks the page monitor to stop the active video tracks.
- This does not take pictures, record video, or upload camera data.
- Coverage is best-effort: a page may bypass the hook, and this does not detect camera use by native apps, other browsers, operating-system services, or every browser/worker context. Chrome's own camera indicator and site permission controls remain important.

## Privacy

- Detection and website URL checks run locally in the browser.
- No API key, account, paid service, external AI model, or backend is required.
- Message text and browsing URLs are not uploaded by PrivacyGuard.
- Password input fields are deliberately excluded from sensitive-text scanning.
- The extension does not store detected values.

## Install locally

1. Download or clone this repository.
2. Open `chrome://extensions` in Google Chrome.
3. Turn on **Developer mode** at the top right of the page
4. Select **Load unpacked**.
5. Choose the unzipped project folder.
6. Refresh any open Gmail tabs after reloading the extension.

## Development

No build step or external dependencies are required.

