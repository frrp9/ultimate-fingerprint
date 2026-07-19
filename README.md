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

**Base:** Navigator, Client Hints, Screen, Locale/Timezone, Canvas + TextMetrics, WebGL/GPU, AudioContext, Fonts, Storage, JS Engine (Math), DOMRect, CSS system colors, Speech, Media, Permissions, WebRTC, Battery, Features, Tamper, Intl, Performance, Workers.

**Hard suite v1 (detection / anti-spoof):** Prototype lies, JS engine error stacks, Headless/CDP markers, Canvas stability (noise), WebGL hard, Cross-signal consistency, SVG/Emoji, Audio hard, Font metrics + `fonts.check`, Timing/RFP, WebGPU, CSS media, Keyboard, Storage quota, Intl hard, Speech hash, Worker hard, Plugins, Window/realm, Permissions.

**Hard suite v2 (stronger):** Multi-realm (top/iframe/srcdoc/worker), Identity matrix UA↔UA-CH↔GPU, WebGL shader compiler fingerprint, Geometry/ClientRects stability, CSS.supports entropy, WebRTC SDP codecs, Audio analyser stack, Intl.supportedValuesOf, Prototype/toString integrity, Feature↔UA coherence (FF/Chrome/Safari lies), OffscreenCanvas vs main, Side channels, Speech integrity, Math hard + worker, Automation deep leftovers.

Trust score aggregates **danger/warn** flags. Bottom **Diagnostics** panel explains each alert with measured vs expected values.

## Local use

Open `index.html` in a browser, or:

```bash
npx serve .
```

## Deploy (GitHub Pages)

Repo is configured for Pages from `main` / root.

## Disclaimer

Educational and defensive research only. Fingerprinting can be privacy-invasive; use responsibly.
