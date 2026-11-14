# PrivacyGuard 🛡️

A free Chrome extension prototype that warns users about potentially sensitive information before they share text.

## What it detects

- Email addresses
- Common US phone number formats
- US Social Security number patterns
- Possible payment card numbers (validated with the Luhn checksum)
- Password, passcode, and verification-code phrases when followed by a value
- Common API keys and access tokens (recognizable GitHub, Slack, AWS, and `sk-` formats)
- Private cryptographic key headers
- Possible bank account or routing numbers when introduced by a matching phrase

## Gmail support

PrivacyGuard includes best-effort support for Gmail's custom compose editor and Send button, including the Ctrl/Cmd+Enter shortcut. It reads the subject and message body when it can identify them. Gmail's interface changes over time, so this integration must be tested against current Gmail behavior and is not guaranteed to intercept every send path.

## Privacy

- Detection runs locally in the browser.
- No API key, account, paid service, external AI model, or backend is required.
- Message text is not uploaded by PrivacyGuard.
- Password input fields are deliberately excluded.
- The extension does not store detected values.

## Install locally

1. Download or clone this repository.
2. Open `chrome://extensions` in Google Chrome.
3. Turn on **Developer mode**.
4. Select **Load unpacked**.
5. Choose the unzipped project folder.
6. Refresh any open Gmail tabs after reloading the extension.

## Current limitations

This is a hackathon prototype and a warning aid, not a complete security product.

- Pattern matching can produce false positives and false negatives.
- Contextual patterns recognize common wording and formats; they do not understand every meaning or privacy risk.
- A Luhn-valid number is not proof that a number is an active payment card.
- Gmail's DOM and event handling can change, and some send paths may bypass the extension.
- Some websites use custom JavaScript submission flows that are not covered by ordinary form interception.
- The extension does not automatically redact information.

Always review what you are sharing. A clean scan does not prove that a message is safe.

## Development

No build step or external dependencies are required.

## License

MIT — see `LICENSE`.
