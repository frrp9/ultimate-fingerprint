# Research notes — open-source fingerprint projects

## Tier 1 (depth + recognition)

### CreepJS — https://github.com/abrahamjuliot/creepjs
- **Stars:** ~2.5k · **License:** MIT (+ trademark on name)
- **Activity:** maintained (pushed 2026)
- **Detects:** contentWindow, CSS system/computed, HTMLElement, Math, console errors, emoji DomRect, SVG, audio, mimeTypes, canvas (image/blob/paint/text/emoji), TextMetrics, WebGL + GPU params/model, fonts, voices, screen, resistance/lie patterns, timezone/device
- **Why kept:** strongest public *research* suite for anti-spoof and privacy-extension detection

### FingerprintJS (open source) — https://github.com/fingerprintjs/fingerprintjs
- **Stars:** ~28k · **License:** MIT
- **Activity:** highly maintained (v5.x)
- **Detects:** canvas, audio, fonts, screen, plugins, timezone, languages, hardware, WebGL, math, fonts, etc. → hashed `visitorId`
- **Why kept:** industry standard client-side library; stable hashing approach

### ClientJS — https://github.com/jackspirou/clientjs
- **Stars:** ~2.2k · **License:** Apache-2.0
- **Detects:** UA, screen, plugins, fonts, storage, timezone, language, canvas
- **Why kept:** classic pure-JS baseline; still useful for device/OS taxonomy

## Tier 2 (reference / class of techniques)

### AmIUnique (amiunique.org)
- Academic uniqueness study; public font/locale/plugin methodology
- Used as reference for font probe lists and uniqueness framing

### BrowserLeaks (browserleaks.com)
- Not fully open-source as one monorepo, but techniques are public
- WebRTC local IP, canvas/WebGL demos, JS features

### Cover Your Tracks (EFF)
- Privacy test framing; less deep than CreepJS

### niespodd/browser-fingerprinting
- Knowledge base of bot protection + test page index
- Points to CreepJS as “the strongest of all”

## Intentionally not copied as products
- Fingerprint **Pro** / commercial server-side ID (closed)
- CreepJS **name/trademark** for public site branding
- Supercookie (favicon) — needs backend
- TLS JA3/JA4 — needs server

## Aggregation policy
Prefer **deep** high-entropy signals that are hard to fake consistently (canvas geometry, WebGL unmasked renderer + params + render hash, audio compressor sum, font presence set, worker/main navigator consistency, native-code checks) over shallow UA-only checks.
