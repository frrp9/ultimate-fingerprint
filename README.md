# Ultimate Fingerprint

Deep client-side browser fingerprint analysis suite.

**Live:** https://frrp9.github.io/ultimate-fingerprint/

## What it does

Runs an aggregated battery of high-entropy fingerprint tests entirely in the browser and produces a readable report:

- Visitor ID (SHA-256 of stable signal set)
- Entropy-weighted uniqueness score
- Trust / tamper / automation flags
- Per-category signal dump with source attribution

Nothing is sent to a server. Export JSON locally.

## Sources (open techniques)

| Project | License | Role in this suite |
|---------|---------|-------------------|
| [CreepJS](https://github.com/abrahamjuliot/creepjs) | MIT | Deepest suite: canvas/WebGL/audio/fonts/DOMRect/CSS system/lie patterns/workers |
| [FingerprintJS](https://github.com/fingerprintjs/fingerprintjs) (OSS) | MIT | Stable visitor-id style signals, audio, canvas, math, UA |
| [ClientJS](https://github.com/jackspirou/clientjs) | Apache-2.0 | Screen, plugins, fonts, storage baselines |
| AmIUnique-class techniques | academic public | Font probe list, locale/Intl depth |
| BrowserLeaks-class techniques | public demos | WebRTC ICE, media devices, WebGL params |
| Bot-surface heuristics | public | `webdriver`, CDP leftovers, prototype native checks |

This is **not** a fork of CreepJS (trademark restricted for public mirrors). It reimplements public fingerprinting techniques for defensive research.

## Categories collected

Navigator, Client Hints (high-entropy), Screen, Locale/Timezone, Canvas + TextMetrics, WebGL/GPU, AudioContext, Fonts, Storage, JS Engine (Math), DOMRect, CSS system colors, Speech voices, Media devices, Permissions, WebRTC, Battery, Feature surface, Tamper/automation, Intl, Performance, Worker consistency.

## Local use

Open `index.html` in a browser, or:

```bash
npx serve .
```

## Deploy (GitHub Pages)

Repo is configured for Pages from `main` / root.

## Disclaimer

Educational and defensive research only. Fingerprinting can be privacy-invasive; use responsibly.
