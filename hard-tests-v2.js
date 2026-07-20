/**
 * HARD TESTS v2 — deeper anti-detect / multi-realm / GPU / network-surface
 * Designed to catch incomplete spoof layers (window-only patches, noise, UA lies).
 */

function sSafe(fn, fallback = null) {
  try {
    return fn();
  } catch (e) {
    return fallback ?? { error: String(e?.message || e) };
  }
}

async function sSafeAsync(fn, fallback = null) {
  try {
    return await fn();
  } catch (e) {
    return fallback ?? { error: String(e?.message || e) };
  }
}

async function sSha(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(str)));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function isNative(fn) {
  if (typeof fn !== "function") return false;
  try {
    return /\[native code\]/.test(Function.prototype.toString.call(fn));
  } catch {
    return false;
  }
}

// ─── 21. Multi-realm deep (top / iframe / srcdoc / worker) ────
export async function collectMultiRealm() {
  const flags = [];
  const snap = (nav, label) => {
    if (!nav) return { label, error: "no navigator" };
    return {
      label,
      ua: nav.userAgent,
      platform: nav.platform,
      language: nav.language,
      languages: nav.languages ? [...nav.languages] : null,
      hw: nav.hardwareConcurrency,
      mem: nav.deviceMemory ?? null,
      webdriver: nav.webdriver,
      vendor: nav.vendor,
      maxTouch: nav.maxTouchPoints,
      pdf: nav.pdfViewerEnabled ?? null,
    };
  };

  const top = snap(navigator, "top");

  const iframeBlank = sSafe(() => {
    const iframe = document.createElement("iframe");
    iframe.style.cssText = "position:absolute;left:-9999px;width:0;height:0;border:0";
    document.body.appendChild(iframe);
    try {
      return snap(iframe.contentWindow?.navigator, "iframe-blank");
    } finally {
      iframe.remove();
    }
  });

  const iframeSrcdoc = sSafe(() => {
    const iframe = document.createElement("iframe");
    iframe.srcdoc = "<!doctype html><title>x</title>";
    iframe.style.cssText = "position:absolute;left:-9999px;width:0;height:0;border:0";
    document.body.appendChild(iframe);
    // srcdoc may need a tick
    return new Promise((resolve) => {
      const done = () => {
        try {
          resolve(snap(iframe.contentWindow?.navigator, "iframe-srcdoc"));
        } catch (e) {
          resolve({ label: "iframe-srcdoc", error: String(e.message || e) });
        } finally {
          iframe.remove();
        }
      };
      iframe.onload = done;
      setTimeout(done, 50);
    });
  });

  const srcdocNav = iframeSrcdoc instanceof Promise ? await iframeSrcdoc : iframeSrcdoc;

  let workerNav = null;
  if (window.Worker) {
    workerNav = await sSafeAsync(
      () =>
        new Promise((resolve) => {
          const code = `self.onmessage=()=>self.postMessage({
            ua:navigator.userAgent,platform:navigator.platform,language:navigator.language,
            languages:navigator.languages?[...navigator.languages]:null,
            hw:navigator.hardwareConcurrency,mem:navigator.deviceMemory||null,
            webdriver:navigator.webdriver,vendor:navigator.vendor,maxTouch:navigator.maxTouchPoints
          })`;
          const url = URL.createObjectURL(new Blob([code], { type: "application/javascript" }));
          const w = new Worker(url);
          const t = setTimeout(() => {
            w.terminate();
            URL.revokeObjectURL(url);
            resolve({ error: "timeout" });
          }, 1500);
          w.onmessage = (e) => {
            clearTimeout(t);
            w.terminate();
            URL.revokeObjectURL(url);
            resolve({ label: "worker", ...e.data });
          };
          w.postMessage(1);
        })
    );
  }

  const realms = [top, iframeBlank, srcdocNav, workerNav].filter(Boolean);

  // Normalize values that legitimately differ in representation across realms
  const normField = (f, v) => {
    if (f === "webdriver") return v === true; // false/undefined/null → false
    if (f === "maxTouch") return v == null ? 0 : Number(v) || 0;
    if (f === "vendor") return v == null || v === "" ? "" : String(v);
    if (f === "mem") return v == null ? null : v;
    return v;
  };

  // vendor often empty in workers on Gecko — only compare when both sides non-empty
  // maxTouch / webdriver use normalized equality
  const fields = ["ua", "platform", "language", "hw", "webdriver", "vendor", "maxTouch"];
  const diffs = [];
  for (const f of fields) {
    const vals = realms
      .filter((r) => r && !r.error && f in r)
      .map((r) => ({ label: r.label, raw: r[f], value: normField(f, r[f]) }));

    if (f === "vendor") {
      const nonempty = vals.filter((v) => v.value !== "");
      if (nonempty.length >= 2) {
        const uniq = new Set(nonempty.map((v) => v.value));
        if (uniq.size > 1) {
          diffs.push({ field: f, values: vals });
          flags.push({
            type: "danger",
            id: `realm_${f}`,
            text: `multi-realm ${f} mismatch`,
            why: `Non-empty navigator.vendor differs across realms (empty worker vendor is ignored — normal on some engines).`,
            measured: vals,
            expected: `identical non-empty vendor strings`,
          });
        }
      }
      continue;
    }

    const uniq = new Set(vals.map((v) => JSON.stringify(v.value)));
    if (uniq.size > 1) {
      diffs.push({ field: f, values: vals });
      flags.push({
        type: "danger",
        id: `realm_${f}`,
        text: `multi-realm ${f} mismatch`,
        why: `Property navigator.${f} differs across top/iframe/srcdoc/worker after normalization. Antidetect often patches only the page window.`,
        measured: vals,
        expected: `identical ${f} in every realm (webdriver: true vs not-true; maxTouch: null≡0)`,
      });
    }
  }

  // languages array deep compare
  const langSets = realms
    .filter((r) => r?.languages)
    .map((r) => ({ label: r.label, languages: r.languages }));
  if (langSets.length >= 2) {
    const sig = langSets.map((x) => x.languages.join(","));
    if (new Set(sig).size > 1) {
      flags.push({
        type: "danger",
        id: "realm_languages",
        text: "multi-realm languages mismatch",
        why: "navigator.languages array differs across realms — incomplete locale spoof.",
        measured: langSets,
        expected: "identical languages arrays",
      });
    }
  }

  if (!flags.length) flags.push({ type: "ok", text: "multi-realm consistent" });

  return {
    category: "multiRealm",
    label: "Multi-Realm Deep",
    entropy: 16,
    source: "CreepJS contentWindow / worker isolation",
    items: { realms, diffs, flags },
  };
}

// ─── 22. UA / UA-CH / Platform / GPU matrix ──────────────────
export async function collectIdentityMatrix() {
  const flags = [];
  const ua = navigator.userAgent;
  const platform = navigator.platform || "";
  const uad = navigator.userAgentData;
  let he = null;
  if (uad?.getHighEntropyValues) {
    he = await sSafeAsync(() =>
      uad.getHighEntropyValues([
        "architecture",
        "bitness",
        "model",
        "platformVersion",
        "uaFullVersion",
        "fullVersionList",
        "wow64",
        "formFactors",
      ])
    );
  }

  // WebGL GPU
  let gpu = null;
  sSafe(() => {
    const c = document.createElement("canvas");
    const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
    if (!gl) return;
    const dbg = gl.getExtension("WEBGL_debug_renderer_info");
    gpu = {
      vendor: gl.getParameter(gl.VENDOR),
      renderer: gl.getParameter(gl.RENDERER),
      unmaskedVendor: dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : null,
      unmaskedRenderer: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : null,
    };
  });

  const matrix = {
    ua,
    platform,
    uaDataBrands: uad?.brands ?? null,
    uaDataPlatform: uad?.platform ?? null,
    uaDataMobile: uad?.mobile ?? null,
    highEntropy: he,
    gpu,
    maxTouchPoints: navigator.maxTouchPoints,
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory ?? null,
  };

  const osFromUa = (() => {
    if (/Windows NT 10/.test(ua)) return "win10+";
    if (/Windows NT 11|Windows NT 10\.0.*Windows/.test(ua)) return "win";
    if (/Windows/.test(ua)) return "win";
    if (/Android/.test(ua)) return "android";
    if (/iPhone|iPad|iPod/.test(ua)) return "ios";
    if (/Mac OS X|Macintosh/.test(ua)) return "mac";
    if (/Linux|X11/.test(ua)) return "linux";
    if (/CrOS/.test(ua)) return "cros";
    return "other";
  })();

  const osFromPlatform = (() => {
    const p = platform.toLowerCase();
    if (p.includes("win")) return "win";
    if (p.includes("mac")) return "mac";
    if (p.includes("linux")) return "linux";
    if (p.includes("iphone") || p.includes("ipad")) return "ios";
    return "other";
  })();

  const osFromCh = (() => {
    const p = String(he?.platform || uad?.platform || "").toLowerCase();
    if (p.includes("windows")) return "win";
    if (p.includes("android")) return "android";
    if (p.includes("mac") || p.includes("ios")) return p.includes("ios") ? "ios" : "mac";
    if (p.includes("linux") || p.includes("chrome os") || p.includes("cros")) return "linux";
    return null;
  })();

  // OS triangle
  if (osFromUa === "win" && osFromPlatform !== "win" && osFromPlatform !== "other") {
    flags.push({
      type: "danger",
      id: "os_ua_platform",
      text: "UA OS ≠ navigator.platform OS",
      why: "User-Agent claims a different OS family than navigator.platform — classic antidetect profile mismatch.",
      measured: { osFromUa, osFromPlatform, ua, platform },
      expected: "same OS family",
    });
  }
  if (osFromCh && osFromUa !== "other" && osFromCh !== osFromUa && !(osFromUa === "win10+" && osFromCh === "win")) {
    flags.push({
      type: "danger",
      id: "os_ua_ch",
      text: "UA OS ≠ Client Hints platform",
      why: "Sec-CH-UA platform disagrees with User-Agent OS. Hard to keep consistent under spoof.",
      measured: { osFromUa, osFromCh, uaDataPlatform: uad?.platform, hePlatform: he?.platform },
      expected: "UA and UA-CH same OS",
    });
  }

  // mobile flag vs touch / UA
  const mobileUa = /Mobile|Android|iPhone|iPad/.test(ua);
  if (uad && uad.mobile === true && !mobileUa) {
    flags.push({
      type: "danger",
      id: "ch_mobile_ua",
      text: "UA-CH mobile=true but desktop UA",
      why: "Client Hints mobile bit set while UA looks desktop.",
      measured: { mobile: uad.mobile, ua },
      expected: "mobile CH matches UA form factor",
    });
  }
  if (uad && uad.mobile === false && mobileUa && !/iPad/.test(ua)) {
    flags.push({
      type: "warn",
      id: "ch_mobile_false",
      text: "UA-CH mobile=false but mobile UA",
      why: "Opposite form-factor lie between CH and UA.",
      measured: { mobile: uad.mobile, ua },
      expected: "consistent form factor",
    });
  }

  // Chrome version brands vs UA version
  if (uad?.brands && /Chrome\/(\d+)/.test(ua)) {
    const ver = RegExp.$1;
    const brands = uad.brands.map((b) => `${b.brand}/${b.version}`).join(", ");
    const has = uad.brands.some((b) => String(b.version) === ver || String(b.version).startsWith(ver));
    // Chromium brands often use shortened versions; check major
    const brandMajors = uad.brands.map((b) => String(b.version).split(".")[0]);
    if (!brandMajors.includes(ver) && !/Not.?A.?Brand/i.test(brands)) {
      // Not always exact — only flag if no brand major matches and chrome in UA
      const anyChrome = uad.brands.some((b) => /Chromium|Google Chrome|Chrome/i.test(b.brand));
      if (anyChrome && !brandMajors.includes(ver)) {
        flags.push({
          type: "warn",
          id: "ch_version",
          text: "Chrome major version UA ≠ brands",
          why: "UA Chrome/N major not present in navigator.userAgentData.brands majors.",
          measured: { uaMajor: ver, brandMajors, brands: uad.brands },
          expected: "matching major versions",
        });
      }
    }
  }

  // GPU vs OS
  const gpuStr = `${gpu?.unmaskedRenderer || gpu?.renderer || ""} ${gpu?.unmaskedVendor || ""}`;
  if (osFromUa === "win" || osFromPlatform === "win") {
    if (/Apple M[0-9]|Apple GPU|Metal/i.test(gpuStr) && !/Parallels|VMware|VirtualBox/i.test(gpuStr)) {
      flags.push({
        type: "danger",
        id: "gpu_apple_on_win",
        text: "Windows identity + Apple GPU",
        why: "Profile claims Windows but WebGL unmasked renderer looks Apple Silicon/Metal.",
        measured: { osFromUa, osFromPlatform, gpu },
        expected: "GPU vendor matches claimed OS",
      });
    }
  }
  if (osFromUa === "mac" || osFromPlatform === "mac") {
    if (/Direct3D|D3D11|D3D12/i.test(gpuStr) && !/Apple/i.test(gpuStr)) {
      flags.push({
        type: "danger",
        id: "gpu_d3d_on_mac",
        text: "macOS identity + Direct3D GPU",
        why: "ANGLE/Direct3D renderer on a macOS UA/platform is a strong spoof signal.",
        measured: { osFromUa, osFromPlatform, gpu },
        expected: "Metal/Apple or valid Mac GPU string",
      });
    }
  }

  // architecture wow64 vs bitness
  if (he?.bitness && he?.architecture) {
    matrix.archBits = { architecture: he.architecture, bitness: he.bitness, wow64: he.wow64 };
  }

  // touch vs desktop
  if (!mobileUa && navigator.maxTouchPoints === 0 && /Tablet|Touch/i.test(ua)) {
    flags.push({
      type: "warn",
      id: "touch_ua",
      text: "Touch token in UA but maxTouchPoints=0",
      why: "UA advertises touch capability the navigator API denies.",
      measured: { maxTouchPoints: navigator.maxTouchPoints, ua },
      expected: "aligned touch capability",
    });
  }

  if (!flags.length) flags.push({ type: "ok", text: "identity matrix consistent" });

  return {
    category: "identityMatrix",
    label: "Identity Matrix (UA/CH/GPU)",
    entropy: 18,
    source: "pixelscan / bot.incolumitas cross-check",
    items: { ...matrix, osFromUa, osFromPlatform, osFromCh, flags },
  };
}

// ─── 23. WebGL shader compile fingerprint ────────────────────
export async function collectShaderFingerprint() {
  const flags = [];
  const canvas = document.createElement("canvas");
  const gl =
    canvas.getContext("webgl2") ||
    canvas.getContext("webgl") ||
    canvas.getContext("experimental-webgl");
  if (!gl) {
    return {
      category: "shaderFp",
      label: "WebGL Shader Fingerprint",
      entropy: 10,
      source: "GPU compiler surface",
      items: { supported: false },
    };
  }

  const vsSrc = `
    attribute vec2 p;
    void main(){
      gl_Position = vec4(p, 0.0, 1.0);
    }
  `;
  // Intentional mediump math stress — compiler/driver differences leak
  const fsSrc = `
    precision mediump float;
    uniform float t;
    void main(){
      float x = sin(t * 1.2345) * cos(t * 0.9876);
      float y = pow(abs(x) + 0.0001, 1.5);
      float z = exp(y * 0.25) * log(1.0 + abs(x));
      vec3 col = vec3(fract(z * 12.9898), fract(z * 78.233), fract(z * 37.719));
      gl_FragColor = vec4(col, 1.0);
    }
  `;

  function compile(type, src) {
    const sh = gl.createShader(type);
    gl.shaderSource(sh, src);
    gl.compileShader(sh);
    const ok = gl.getShaderParameter(sh, gl.COMPILE_STATUS);
    const log = gl.getShaderInfoLog(sh) || "";
    return { ok, log: log.slice(0, 300), sourceLen: src.length };
  }

  const vs = compile(gl.VERTEX_SHADER, vsSrc);
  const fs = compile(gl.FRAGMENT_SHADER, fsSrc);
  const prog = gl.createProgram();
  // need actual shaders attached - recompile cleanly
  const vsh = gl.createShader(gl.VERTEX_SHADER);
  gl.shaderSource(vsh, vsSrc);
  gl.compileShader(vsh);
  const fsh = gl.createShader(gl.FRAGMENT_SHADER);
  gl.shaderSource(fsh, fsSrc);
  gl.compileShader(fsh);
  gl.attachShader(prog, vsh);
  gl.attachShader(prog, fsh);
  gl.linkProgram(prog);
  const linked = gl.getProgramParameter(prog, gl.LINK_STATUS);
  const progLog = gl.getProgramInfoLog(prog) || "";

  // draw + readPixels entropy
  let pixelHash = null;
  if (linked) {
    gl.useProgram(prog);
    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, "p");
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    const uloc = gl.getUniformLocation(prog, "t");
    gl.uniform1f(uloc, 1.6180339887);
    gl.viewport(0, 0, canvas.width || 300, canvas.height || 150);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    const w = 32;
    const h = 32;
    const pixels = new Uint8Array(w * h * 4);
    gl.readPixels(0, 0, w, h, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
    // sample checksum
    let acc = 0;
    for (let i = 0; i < pixels.length; i += 17) acc = (acc + pixels[i] * (i + 3)) >>> 0;
    pixelHash = {
      checksum: acc.toString(16),
      head: Array.from(pixels.slice(0, 32)),
      sha: (await sSha(Array.from(pixels).join(","))).slice(0, 24),
    };
  } else {
    flags.push({
      type: "warn",
      id: "shader_link_fail",
      text: "shader program link failed",
      why: "Unexpected WebGL program link failure — broken GL, blocked GPU, or hostile context.",
      measured: { progLog, vs, fs },
      expected: "successful link of simple stress shader",
    });
  }

  // precision formats
  const precision = {};
  for (const t of ["LOW_FLOAT", "MEDIUM_FLOAT", "HIGH_FLOAT", "LOW_INT", "MEDIUM_INT", "HIGH_INT"]) {
    const p = gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl[t]);
    precision[t] = p
      ? { rangeMin: p.rangeMin, rangeMax: p.rangeMax, precision: p.precision }
      : null;
  }

  if (!flags.length) flags.push({ type: "ok", text: "shader fingerprint ok" });

  return {
    category: "shaderFp",
    label: "WebGL Shader Fingerprint",
    entropy: 16,
    source: "GPU compiler / readPixels",
    items: {
      supported: true,
      vs,
      fs,
      linked,
      progLog: progLog.slice(0, 200),
      precision,
      pixelHash,
      flags,
    },
  };
}

// ─── 24. Geometry hard (ClientRects / Range / transforms) ────
export async function collectGeometryHard() {
  const flags = [];
  const host = document.createElement("div");
  host.style.cssText =
    "position:absolute;left:-9999px;top:0;width:320px;font-family:Arial,sans-serif;";
  host.innerHTML = `
    <div id="g1" style="width:100.125px;height:33.333px;transform:rotate(0.15deg) scale(1.03);font-size:16.5px;letter-spacing:0.2px;">mmmmmmmmmmlli φ 中 😀</div>
    <span id="g2" style="font:italic 22px Georgia;">W@م永</span>
    <svg id="g3" width="120" height="40" xmlns="http://www.w3.org/2000/svg"><text x="2" y="28" font-size="18" font-family="Times New Roman">SVG-φ-😀</text></svg>
  `;
  document.body.appendChild(host);

  const g1 = host.querySelector("#g1");
  const g2 = host.querySelector("#g2");
  const g3 = host.querySelector("#g3 text");

  const rects = {
    g1: g1.getBoundingClientRect(),
    g1Client: g1.getClientRects()[0] || null,
    g2: g2.getBoundingClientRect(),
    g2Clients: [...g2.getClientRects()].map((r) => ({
      w: r.width,
      h: r.height,
      x: r.x,
      y: r.y,
    })),
  };

  const range = document.createRange();
  range.selectNodeContents(g1);
  const rr = range.getBoundingClientRect();
  const rangeRects = [...range.getClientRects()].map((r) => ({
    w: r.width,
    h: r.height,
  }));

  let svgBBox = null;
  try {
    svgBBox = g3.getBBox();
  } catch {
    svgBBox = null;
  }

  document.body.removeChild(host);

  const payload = {
    g1: { w: rects.g1.width, h: rects.g1.height, x: rects.g1.x, top: rects.g1.top },
    g2: { w: rects.g2.width, h: rects.g2.height },
    g2Clients: rects.g2Clients,
    range: { w: rr.width, h: rr.height },
    rangeRects,
    svgBBox: svgBBox
      ? { w: svgBBox.width, h: svgBBox.height, x: svgBBox.x, y: svgBBox.y }
      : null,
  };

  // stability: remeasure once
  const host2 = document.createElement("div");
  host2.style.cssText = host.style.cssText;
  host2.innerHTML = host.innerHTML;
  document.body.appendChild(host2);
  const g1b = host2.querySelector("#g1").getBoundingClientRect();
  document.body.removeChild(host2);
  const drift = Math.abs(g1b.width - rects.g1.width) + Math.abs(g1b.height - rects.g1.height);
  if (drift > 0.02) {
    flags.push({
      type: "danger",
      id: "geometry_drift",
      text: "geometry unstable between measures",
      why: "DOMRect values drift without layout change — noise injection or non-deterministic layout spoof.",
      measured: { first: payload.g1, second: { w: g1b.width, h: g1b.height }, drift },
      expected: "stable sub-pixel geometry",
    });
  }

  const hash = (await sSha(JSON.stringify(payload))).slice(0, 24);
  if (!flags.length) flags.push({ type: "ok", text: "geometry stable" });

  return {
    category: "geometryHard",
    label: "Geometry Hard (ClientRects)",
    entropy: 14,
    source: "CreepJS DomRect / Range",
    items: { ...payload, drift, hash, flags },
  };
}

// ─── 25. CSS.supports + media + computed entropy ─────────────
export function collectCssHard() {
  const flags = [];
  const supports = {};
  const queries = [
    "display:grid",
    "display:flex",
    "display:contents",
    "gap:1px",
    "aspect-ratio:1/1",
    "backdrop-filter:blur(1px)",
    "filter:blur(1px)",
    "position:sticky",
    "scroll-snap-type:x mandatory",
    "color:color(display-p3 1 0 0)",
    "color:oklch(0.5 0.2 180)",
    "container-type:inline-size",
    "view-transition-name:none",
    "offset-path:path('M0 0')",
    "accent-color:red",
    "appearance:none",
    "-webkit-line-clamp:2",
    "text-wrap:balance",
    "font-palette:normal",
    "hyphenate-character:'-'",
  ];
  for (const q of queries) {
    const idx = q.indexOf(":");
    const prop = idx >= 0 ? q.slice(0, idx) : q;
    const val = idx >= 0 ? q.slice(idx + 1) : "";
    supports[q] = sSafe(() => (val ? CSS.supports(prop, val) : CSS.supports(q)));
    supports[`raw:${q}`] = sSafe(() => CSS.supports(q));
  }

  // system colors sample
  const el = document.createElement("div");
  el.style.cssText = "position:absolute;left:-9999px";
  document.body.appendChild(el);
  const sys = {};
  for (const c of ["Canvas", "CanvasText", "Highlight", "HighlightText", "ButtonFace", "Field", "Mark", "LinkText"]) {
    el.style.color = c;
    sys[c] = getComputedStyle(el).color;
  }
  // font family default
  const font = getComputedStyle(el).fontFamily;
  document.body.removeChild(el);

  // prefers-* already elsewhere — add forced-colors vs system
  const media = {
    prefersColorScheme: matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light",
    prefersContrast: matchMedia("(prefers-contrast: more)").matches
      ? "more"
      : matchMedia("(prefers-contrast: less)").matches
        ? "less"
        : "no-preference",
    colorGamut: matchMedia("(color-gamut: rec2020)").matches
      ? "rec2020"
      : matchMedia("(color-gamut: p3)").matches
        ? "p3"
        : "srgb",
    dynamicRange: matchMedia("(dynamic-range: high)").matches ? "high" : "standard",
    scripting: matchMedia("(scripting: enabled)").matches,
  };

  if (!CSS?.supports) {
    flags.push({
      type: "warn",
      id: "css_supports_missing",
      text: "CSS.supports missing",
      why: "Unexpected on modern browsers — restricted environment.",
      measured: { CSS: typeof CSS },
      expected: "CSS.supports available",
    });
  }

  return {
    category: "cssHard",
    label: "CSS Hard (supports)",
    entropy: 10,
    source: "CreepJS css / cssmedia",
    items: {
      supports,
      systemColors: sys,
      defaultFontFamily: font,
      media,
      flags: flags.length ? flags : [{ type: "ok", text: "css hard ok" }],
    },
  };
}

// ─── 26. WebRTC SDP / codec fingerprint ──────────────────────
export async function collectWebRtcHard() {
  const flags = [];
  if (!window.RTCPeerConnection) {
    return {
      category: "webrtcHard",
      label: "WebRTC Hard (SDP)",
      entropy: 8,
      source: "BrowserLeaks WebRTC",
      items: { supported: false },
    };
  }

  const pc = new RTCPeerConnection({ iceServers: [] });
  try {
    pc.addTransceiver("audio", { direction: "recvonly" });
    pc.addTransceiver("video", { direction: "recvonly" });
  } catch {
    /* older */
    try {
      pc.createDataChannel("ufp");
    } catch {}
  }

  let offer = null;
  try {
    offer = await pc.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: true });
    await pc.setLocalDescription(offer);
  } catch (e) {
    pc.close();
    return {
      category: "webrtcHard",
      label: "WebRTC Hard (SDP)",
      entropy: 8,
      source: "BrowserLeaks WebRTC",
      items: { supported: true, error: String(e.message || e) },
    };
  }

  const sdp = pc.localDescription?.sdp || offer?.sdp || "";
  const lines = sdp.split(/\r?\n/);
  const codecs = lines.filter((l) => /a=rtpmap:/i.test(l)).map((l) => l.trim());
  const exts = lines.filter((l) => /a=extmap:/i.test(l)).map((l) => l.trim());
  const fingerprint = lines.find((l) => /a=fingerprint:/i.test(l)) || null;
  const iceUfrag = lines.find((l) => /a=ice-ufrag:/i.test(l)) || null;
  const icePwd = lines.find((l) => /a=ice-pwd:/i.test(l)) || null;
  const msid = lines.some((l) => /a=msid/i.test(l));

  // codec set hash (stable-ish)
  const codecHash = (await sSha(codecs.sort().join("|"))).slice(0, 24);
  const extHash = (await sSha(exts.sort().join("|"))).slice(0, 24);

  // ICE gather a bit without STUN for host candidates only
  const hostCandidates = [];
  await new Promise((resolve) => {
    const t = setTimeout(resolve, 800);
    pc.onicecandidate = (e) => {
      if (!e.candidate) {
        clearTimeout(t);
        resolve();
        return;
      }
      const c = e.candidate.candidate;
      if (/ typ host /.test(c) || /typ host/.test(c)) hostCandidates.push(c);
    };
  });

  pc.close();

  if (!codecs.length) {
    flags.push({
      type: "warn",
      id: "webrtc_no_codecs",
      text: "WebRTC SDP has no rtpmap codecs",
      why: "Empty codec list is abnormal for a working RTC stack — blocked WebRTC or broken spoof.",
      measured: { sdpHead: sdp.slice(0, 200) },
      expected: "audio/video rtpmap lines present",
    });
  }

  if (!flags.length) flags.push({ type: "ok", text: "webrtc sdp ok" });

  return {
    category: "webrtcHard",
    label: "WebRTC Hard (SDP)",
    entropy: 14,
    source: "BrowserLeaks WebRTC",
    items: {
      supported: true,
      codecs,
      codecHash,
      extensionsCount: exts.length,
      extHash,
      hasFingerprint: !!fingerprint,
      hasIceUfrag: !!iceUfrag,
      hasIcePwd: !!icePwd,
      msid,
      hostCandidateCount: hostCandidates.length,
      hostCandidatesSample: hostCandidates.slice(0, 4),
      sdpLength: sdp.length,
      flags,
    },
  };
}

// ─── 27. Audio analyser frequency fingerprint ────────────────
export async function collectAudioAnalyser() {
  const flags = [];
  const AC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
  if (!AC) {
    return {
      category: "audioAnalyser",
      label: "Audio Analyser",
      entropy: 8,
      source: "FingerprintJS audio depth",
      items: { supported: false },
    };
  }

  // Offline path with dynamics + oscillator stack
  const ctx = new AC(1, 44100, 44100);
  const osc1 = ctx.createOscillator();
  osc1.type = "sawtooth";
  osc1.frequency.value = 440;
  const osc2 = ctx.createOscillator();
  osc2.type = "sine";
  osc2.frequency.value = 1000;
  const gain = ctx.createGain();
  gain.gain.value = 0.5;
  const comp = ctx.createDynamicsCompressor();
  osc1.connect(gain);
  osc2.connect(gain);
  gain.connect(comp);
  comp.connect(ctx.destination);
  osc1.start(0);
  osc2.start(0);

  const buf = await ctx.startRendering();
  const data = buf.getChannelData(0);

  // simple DFT-ish bins on a window
  const bins = [];
  const N = 1024;
  const start = 2000;
  for (let k = 1; k <= 16; k++) {
    let re = 0;
    let im = 0;
    for (let n = 0; n < N; n++) {
      const v = data[start + n] || 0;
      const ang = (2 * Math.PI * k * n) / N;
      re += v * Math.cos(ang);
      im -= v * Math.sin(ang);
    }
    bins.push(Math.sqrt(re * re + im * im));
  }

  let sum = 0;
  let max = 0;
  for (let i = 0; i < data.length; i += 64) {
    const v = Math.abs(data[i]);
    sum += v;
    if (v > max) max = v;
  }

  // second render for stability
  const ctx2 = new AC(1, 44100, 44100);
  const o = ctx2.createOscillator();
  o.type = "sawtooth";
  o.frequency.value = 440;
  const g = ctx2.createGain();
  g.gain.value = 0.5;
  o.connect(g);
  g.connect(ctx2.destination);
  o.start(0);
  const buf2 = await ctx2.startRendering();
  const d2 = buf2.getChannelData(0);
  let sum2 = 0;
  for (let i = 0; i < d2.length; i += 64) sum2 += Math.abs(d2[i]);
  const stable = Math.abs(sum - sum2) < 1e-4 || Math.abs(sum - sum2) / (sum + 1e-12) < 1e-6;
  // note: different graph → don't compare sum to sum2 for stability of same graph
  // redo identical graph for stability
  const ctx3 = new AC(1, 44100, 44100);
  const o3a = ctx3.createOscillator();
  o3a.type = "sawtooth";
  o3a.frequency.value = 440;
  const o3b = ctx3.createOscillator();
  o3b.type = "sine";
  o3b.frequency.value = 1000;
  const g3 = ctx3.createGain();
  g3.gain.value = 0.5;
  const c3 = ctx3.createDynamicsCompressor();
  o3a.connect(g3);
  o3b.connect(g3);
  g3.connect(c3);
  c3.connect(ctx3.destination);
  o3a.start(0);
  o3b.start(0);
  const buf3 = await ctx3.startRendering();
  const d3 = buf3.getChannelData(0);
  let sum3 = 0;
  for (let i = 0; i < d3.length; i += 64) sum3 += Math.abs(d3[i]);
  const sameGraphStable = Math.abs(sum - sum3) < 1e-5;

  if (!sameGraphStable) {
    flags.push({
      type: "danger",
      id: "audio_analyser_unstable",
      text: "audio analyser stack unstable",
      why: "Identical OfflineAudio graphs produced different energy — audio noise / spoof layer.",
      measured: { sum, sum3, delta: Math.abs(sum - sum3) },
      expected: "identical sums",
    });
  }

  const hash = (await sSha(bins.map((b) => b.toFixed(6)).join(","))).slice(0, 24);
  if (!flags.length) flags.push({ type: "ok", text: "audio analyser ok" });

  return {
    category: "audioAnalyser",
    label: "Audio Analyser",
    entropy: 12,
    source: "FingerprintJS / CreepJS audio",
    items: {
      supported: true,
      bins: bins.map((b) => Math.round(b * 1e6) / 1e6),
      energySum: sum,
      energyMax: max,
      sameGraphStable,
      hash,
      flags,
    },
  };
}

// ─── 28. Intl.supportedValuesOf + locale deep ────────────────
export function collectIntlDeep() {
  const flags = [];
  const items = {
    supportedValuesOf: null,
    locale: Intl.DateTimeFormat().resolvedOptions(),
  };

  if (typeof Intl.supportedValuesOf === "function") {
    items.supportedValuesOf = sSafe(() => ({
      timeZoneCount: Intl.supportedValuesOf("timeZone").length,
      calendarCount: Intl.supportedValuesOf("calendar").length,
      currencyCount: Intl.supportedValuesOf("currency").length,
      numberingSystemCount: Intl.supportedValuesOf("numberingSystem").length,
      unitCount: Intl.supportedValuesOf("unit").length,
      // samples
      calendarsHead: Intl.supportedValuesOf("calendar").slice(0, 12),
      numberingHead: Intl.supportedValuesOf("numberingSystem").slice(0, 12),
    }));
  }

  // timezone exists in supported list
  const tz = items.locale.timeZone;
  if (items.supportedValuesOf?.timeZoneCount && tz) {
    const all = sSafe(() => Intl.supportedValuesOf("timeZone"));
    if (Array.isArray(all) && !all.includes(tz)) {
      flags.push({
        type: "danger",
        id: "tz_not_supported",
        text: "resolved timeZone not in supportedValuesOf",
        why: "Spoofed timezone string that the engine does not actually support.",
        measured: { timeZone: tz },
        expected: "timeZone ∈ Intl.supportedValuesOf('timeZone')",
      });
    }
  }

  // offset vs zone rough check using formatToParts
  const offsetMin = new Date().getTimezoneOffset();
  const parts = sSafe(() =>
    new Intl.DateTimeFormat("en-US", {
      timeZone: tz,
      timeZoneName: "shortOffset",
    }).formatToParts(new Date())
  );
  const offPart = Array.isArray(parts)
    ? parts.find((p) => p.type === "timeZoneName")?.value
    : null;
  items.offsetMinutes = offsetMin;
  items.offsetLabel = offPart;

  // hour cycle mismatch
  items.hourCycle = items.locale.hourCycle;
  items.hour12 = sSafe(
    () =>
      new Intl.DateTimeFormat(undefined, { hour: "numeric" }).resolvedOptions().hour12
  );

  if (!flags.length) flags.push({ type: "ok", text: "intl deep ok" });

  return {
    category: "intlDeep",
    label: "Intl Deep",
    entropy: 10,
    source: "AmIUnique / CreepJS intl",
    items: { ...items, flags },
  };
}

// ─── 29. Prototype integrity / Proxy / toString chain ────────
export function collectPrototypeIntegrity() {
  const flags = [];
  const checks = {};

  // Function.prototype.toString call on itself
  checks.toStringNative = isNative(Function.prototype.toString);
  checks.toStringCallNative = sSafe(() =>
    /\[native code\]/.test(Function.prototype.toString.call(Function.prototype.toString))
  );
  if (!checks.toStringNative || checks.toStringCallNative === false) {
    flags.push({
      type: "danger",
      id: "tostring_hook",
      text: "Function.prototype.toString hooked",
      why: "toString is the primary way to detect native code; antidetect often hooks it to hide patches.",
      measured: checks,
      expected: "native Function.prototype.toString",
    });
  }

  // Object.getOwnPropertyDescriptor native
  checks.getOwnPropertyDescriptorNative = isNative(Object.getOwnPropertyDescriptor);
  checks.definePropertyNative = isNative(Object.defineProperty);
  checks.applyNative = isNative(Reflect.apply);
  if (!checks.getOwnPropertyDescriptorNative) {
    flags.push({
      type: "danger",
      id: "gopd_hook",
      text: "Object.getOwnPropertyDescriptor hooked",
      why: "Descriptor inspection hooked — classic to hide non-native getters on Navigator.",
      measured: { native: false },
      expected: "native getOwnPropertyDescriptor",
    });
  }

  // navigator brand
  checks.navigatorTag = Object.prototype.toString.call(navigator);
  checks.navigatorCtor = sSafe(() => navigator.constructor?.name);
  if (checks.navigatorTag !== "[object Navigator]") {
    flags.push({
      type: "danger",
      id: "navigator_tag",
      text: `navigator toStringTag = ${checks.navigatorTag}`,
      why: "Symbol.toStringTag / proxy brand mismatch on navigator.",
      measured: checks.navigatorTag,
      expected: "[object Navigator]",
    });
  }

  // iframe fresh Function.prototype.toString vs top
  const iframeTs = sSafe(() => {
    const iframe = document.createElement("iframe");
    iframe.style.display = "none";
    document.body.appendChild(iframe);
    try {
      const its = iframe.contentWindow.Function.prototype.toString;
      const sameRef = its === Function.prototype.toString;
      const topOnIframeFn = Function.prototype.toString.call(iframe.contentWindow.fetch || its);
      const iframeOnTopFn = its.call(Function.prototype.toString);
      return {
        sameRef,
        iframeToStringNative: isNative(its),
        topDescribesIframeFetch: String(topOnIframeFn).slice(0, 80),
        iframeDescribesTopToString: String(iframeOnTopFn).slice(0, 80),
      };
    } finally {
      iframe.remove();
    }
  });
  checks.iframeToString = iframeTs;
  if (iframeTs && iframeTs.sameRef === true) {
    flags.push({
      type: "warn",
      id: "tostring_same_ref",
      text: "iframe Function.toString === top (same ref)",
      why: "Different windows normally have different function objects; same reference can indicate a patched environment.",
      measured: iframeTs,
      expected: "different Function.prototype.toString per realm",
    });
  }

  // Permissions.query / canvas methods already checked — add OfflineAudio
  checks.offlineAudioNative = sSafe(() => {
    const C = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!C) return null;
    return isNative(C.prototype.startRendering);
  });

  // Error stack getter
  checks.errorStack = sSafe(() => {
    const e = new Error("ufp");
    return {
      hasStack: typeof e.stack === "string",
      stackHead: String(e.stack || "").split("\n").slice(0, 2).join(" | ").slice(0, 160),
    };
  });

  if (!flags.length) flags.push({ type: "ok", text: "prototype integrity ok" });

  return {
    category: "protoIntegrity",
    label: "Prototype Integrity",
    entropy: 14,
    source: "CreepJS lies / toString",
    items: { ...checks, flags },
  };
}

// ─── 30. Feature vs UA / engine coherence ────────────────────
export function collectFeatureCoherence() {
  const flags = [];
  const ua = navigator.userAgent;
  const isFF = /Firefox\//.test(ua) && !/Seamonkey/i.test(ua);
  const isChrome = /Chrome\//.test(ua) && !/Edg\//.test(ua) && !/OPR\//.test(ua);
  const isSafari = /Safari\//.test(ua) && !/Chrome\//.test(ua) && !/Chromium\//.test(ua);
  const isEdge = /Edg\//.test(ua);

  const feats = {
    chromeObject: !!window.chrome,
    InstallTrigger: typeof window.InstallTrigger !== "undefined",
    safariPush: !!(window.safari && window.safari.pushNotification),
    buildID: navigator.buildID ?? null,
    productSub: navigator.productSub,
    vendor: navigator.vendor,
    webkitPersistentStorage: !!navigator.webkitPersistentStorage,
    brave: !!(navigator.brave && navigator.brave.isBrave),
    userAgentData: !!navigator.userAgentData,
    deviceMemory: navigator.deviceMemory ?? null,
  };

  if (isFF) {
    if (feats.chromeObject)
      flags.push({
        type: "danger",
        id: "ff_chrome_obj",
        text: "Firefox UA + window.chrome",
        why: "Stock Firefox has no window.chrome; presence indicates spoof or Chromium mislabeled as Firefox.",
        measured: feats,
        expected: "no window.chrome on Firefox",
      });
    if (feats.userAgentData)
      flags.push({
        type: "danger",
        id: "ff_uach",
        text: "Firefox UA + userAgentData",
        why: "Client Hints API is Chromium; Firefox UA with UA-CH is a strong antidetect signal.",
        measured: { userAgentData: true, ua },
        expected: "no userAgentData on Firefox",
      });
    if (feats.deviceMemory != null)
      flags.push({
        type: "warn",
        id: "ff_device_memory",
        text: "Firefox UA + deviceMemory",
        why: "deviceMemory is primarily Chromium; unusual on real Firefox.",
        measured: { deviceMemory: feats.deviceMemory },
        expected: "deviceMemory undefined on Firefox",
      });
    if (feats.productSub && feats.productSub !== "20100101")
      flags.push({
        type: "warn",
        id: "ff_product_sub",
        text: "Firefox productSub atypical",
        why: "Firefox typically uses productSub 20100101.",
        measured: { productSub: feats.productSub },
        expected: "20100101",
      });
  }

  if (isChrome || isEdge) {
    if (!feats.chromeObject && !/Android|Mobile/.test(ua))
      flags.push({
        type: "danger",
        id: "chrome_no_chrome",
        text: "Chrome/Edge UA without window.chrome",
        why: "Desktop Chromium exposes window.chrome; missing object is headless/spoof residue.",
        measured: feats,
        expected: "window.chrome present",
      });
    if (feats.InstallTrigger)
      flags.push({
        type: "danger",
        id: "chrome_installtrigger",
        text: "Chromium UA + InstallTrigger",
        why: "InstallTrigger is a Firefox legacy API.",
        measured: feats,
        expected: "no InstallTrigger on Chromium",
      });
  }

  if (isSafari) {
    if (feats.chromeObject)
      flags.push({
        type: "danger",
        id: "safari_chrome",
        text: "Safari UA + window.chrome",
        why: "Safari should not expose window.chrome.",
        measured: feats,
        expected: "no chrome object",
      });
    if (feats.userAgentData)
      flags.push({
        type: "danger",
        id: "safari_uach",
        text: "Safari UA + userAgentData",
        why: "UA-CH on Safari UA is inconsistent.",
        measured: feats,
        expected: "no userAgentData",
      });
  }

  // vendor checks
  if (isChrome && feats.vendor && feats.vendor !== "Google Inc." && !isEdge) {
    flags.push({
      type: "warn",
      id: "chrome_vendor",
      text: `Chrome UA vendor="${feats.vendor}"`,
      why: "Unexpected navigator.vendor for Chrome UA.",
      measured: { vendor: feats.vendor },
      expected: "Google Inc.",
    });
  }

  if (!flags.length) flags.push({ type: "ok", text: "feature/UA coherent" });

  return {
    category: "featureCoherence",
    label: "Feature / UA Coherence",
    entropy: 12,
    source: "CreepJS resistance / engine tells",
    items: { uaClass: { isFF, isChrome, isSafari, isEdge }, feats, flags },
  };
}

// ─── 31. OffscreenCanvas vs main canvas ──────────────────────
export async function collectOffscreenVsMain() {
  const flags = [];
  if (typeof OffscreenCanvas === "undefined") {
    return {
      category: "offscreenCanvas",
      label: "OffscreenCanvas vs Main",
      entropy: 6,
      source: "multi-context canvas",
      items: { supported: false },
    };
  }

  function paint(ctx) {
    ctx.fillStyle = "#204080";
    ctx.fillRect(0, 0, 120, 40);
    ctx.fillStyle = "#ffcc00";
    ctx.font = "16px Arial";
    ctx.fillText("Offscreenφ中", 4, 24);
    ctx.strokeStyle = "#0f0";
    ctx.beginPath();
    ctx.arc(90, 20, 12, 0, Math.PI * 2);
    ctx.stroke();
  }

  const main = document.createElement("canvas");
  main.width = 120;
  main.height = 40;
  const mctx = main.getContext("2d");
  paint(mctx);
  const mainUrl = main.toDataURL();
  const mainHash = (await sSha(mainUrl)).slice(0, 24);

  const off = new OffscreenCanvas(120, 40);
  const octx = off.getContext("2d");
  paint(octx);
  let offHash = null;
  let offUrl = null;
  try {
    const blob = await off.convertToBlob({ type: "image/png" });
    offUrl = await new Promise((resolve) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.readAsDataURL(blob);
    });
    offHash = (await sSha(offUrl)).slice(0, 24);
  } catch (e) {
    offHash = `err:${e.message || e}`;
  }

  // Worker offscreen if transferable
  let workerHash = null;
  if (window.Worker) {
    workerHash = await sSafeAsync(
      () =>
        new Promise((resolve) => {
          const code = `
            self.onmessage = async () => {
              try {
                const c = new OffscreenCanvas(120, 40);
                const x = c.getContext('2d');
                x.fillStyle = '#204080'; x.fillRect(0,0,120,40);
                x.fillStyle = '#ffcc00'; x.font = '16px Arial';
                x.fillText('Offscreenφ中', 4, 24);
                x.strokeStyle = '#0f0'; x.beginPath(); x.arc(90,20,12,0,Math.PI*2); x.stroke();
                const b = await c.convertToBlob({type:'image/png'});
                const ab = await b.arrayBuffer();
                const u = new Uint8Array(ab);
                let s = 0; for (let i=0;i<u.length;i++) s = (s + u[i]*(i+1))>>>0;
                self.postMessage({ sum: s.toString(16), len: u.length });
              } catch (e) { self.postMessage({ error: e.message }); }
            };
          `;
          const url = URL.createObjectURL(new Blob([code], { type: "application/javascript" }));
          const w = new Worker(url);
          const t = setTimeout(() => {
            w.terminate();
            resolve({ error: "timeout" });
          }, 2000);
          w.onmessage = (e) => {
            clearTimeout(t);
            w.terminate();
            URL.revokeObjectURL(url);
            resolve(e.data);
          };
          w.postMessage(1);
        })
    );
  }

  if (offHash && mainHash && offHash !== mainHash && !String(offHash).startsWith("err:")) {
    // PNG encoding from Offscreen convertToBlob vs toDataURL can differ legitimately in some engines —
    // only flag if both are data URLs and differ a lot in length AND hash (still useful signal)
    const lenDiff = Math.abs((offUrl?.length || 0) - mainUrl.length);
    if (lenDiff > 50) {
      flags.push({
        type: "warn",
        id: "offscreen_main_diff",
        text: "OffscreenCanvas PNG ≠ main canvas",
        why: "Main 2D canvas and OffscreenCanvas encodings diverge significantly — can be multi-context spoof or engine quirk; high interest for antidetect.",
        measured: { mainHash, offHash, mainLen: mainUrl.length, offLen: offUrl?.length },
        expected: "similar rasterization fingerprint",
      });
    }
  }

  if (!flags.length) flags.push({ type: "ok", text: "offscreen/main ok" });

  return {
    category: "offscreenCanvas",
    label: "OffscreenCanvas vs Main",
    entropy: 10,
    source: "multi-context canvas",
    items: { supported: true, mainHash, offHash, workerHash, flags },
  };
}

// ─── 32. Storage / network / privacy side channels ───────────
export async function collectSideChannels() {
  const flags = [];
  const items = {};

  // storage estimate + persisted
  if (navigator.storage?.estimate) {
    const est = await sSafeAsync(() => navigator.storage.estimate());
    items.quota = est?.quota ?? null;
    items.usage = est?.usage ?? null;
    items.usageDetails = est?.usageDetails ?? null;
  }
  if (navigator.storage?.persisted) {
    items.persisted = await sSafeAsync(() => navigator.storage.persisted());
  }

  // cookie store
  items.cookieEnabled = navigator.cookieEnabled;
  items.cookieStore = !!window.cookieStore;

  // connection
  const c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
  items.connection = c
    ? {
        effectiveType: c.effectiveType,
        downlink: c.downlink,
        rtt: c.rtt,
        saveData: c.saveData,
        type: c.type,
      }
    : null;

  // temporary vs persistent storage type (legacy)
  items.webkitTemporaryStorage = !!navigator.webkitTemporaryStorage;
  items.webkitPersistentStorage = !!navigator.webkitPersistentStorage;

  // IndexedDB in private often works; quota small in Chromium
  if (items.quota != null && items.quota > 0 && items.quota < 200 * 1024 * 1024) {
    flags.push({
      type: "warn",
      id: "small_quota",
      text: "small storage quota",
      why: "Quota under ~200MB often indicates incognito/private or restricted profile — antidetect profiles sometimes inherit this.",
      measured: { quota: items.quota, usage: items.usage },
      expected: "multi-GB quota on normal desktop profiles",
    });
  }

  // hardwareConcurrency vs deviceMemory coherence again
  if (navigator.deviceMemory != null && navigator.hardwareConcurrency != null) {
    if (navigator.deviceMemory <= 0.5 && navigator.hardwareConcurrency >= 8) {
      flags.push({
        type: "danger",
        id: "mem_cpu_lie",
        text: "deviceMemory≤0.5 with high concurrency",
        why: "Implausible hardware pairing — spoofed deviceMemory or concurrency.",
        measured: {
          deviceMemory: navigator.deviceMemory,
          hardwareConcurrency: navigator.hardwareConcurrency,
        },
        expected: "plausible RAM/CPU pairing",
      });
    }
  }

  if (!flags.length) flags.push({ type: "ok", text: "side channels ok" });

  return {
    category: "sideChannels",
    label: "Side Channels",
    entropy: 8,
    source: "storage / network info",
    items: { ...items, flags },
  };
}

// ─── 33. Speech + voices integrity ───────────────────────────
export async function collectSpeechIntegrity() {
  if (!window.speechSynthesis) {
    return {
      category: "speechIntegrity",
      label: "Speech Integrity",
      entropy: 4,
      source: "CreepJS speech",
      items: { supported: false },
    };
  }
  const flags = [];
  const voices = await new Promise((resolve) => {
    let v = speechSynthesis.getVoices();
    if (v.length) return resolve(v);
    const t = setTimeout(() => resolve(speechSynthesis.getVoices() || []), 700);
    speechSynthesis.onvoiceschanged = () => {
      clearTimeout(t);
      resolve(speechSynthesis.getVoices() || []);
    };
  });

  const langs = [...new Set(voices.map((v) => v.lang.split("-")[0]))].sort();
  const local = voices.filter((v) => v.localService);
  const remote = voices.filter((v) => !v.localService);
  const defaults = voices.filter((v) => v.default);

  // language vs voices
  const navLang = (navigator.language || "").split("-")[0];
  if (voices.length && navLang && !langs.includes(navLang) && !langs.includes("en")) {
    flags.push({
      type: "warn",
      id: "speech_lang",
      text: "no speech voice for navigator.language",
      why: "Locale spoof without matching TTS voices is a common incomplete profile.",
      measured: { navigatorLanguage: navigator.language, voiceLangs: langs },
      expected: "at least one voice matching UI language (or en)",
    });
  }

  // empty voices on desktop chrome is suspicious
  if (
    /Chrome\//.test(navigator.userAgent) &&
    !/Mobile|Android/.test(navigator.userAgent) &&
    voices.length === 0
  ) {
    flags.push({
      type: "warn",
      id: "speech_empty",
      text: "Chrome desktop with 0 voices",
      why: "Stock desktop Chrome usually exposes local voices; empty list can be headless/container/antidetect.",
      measured: { count: 0 },
      expected: "non-zero speechSynthesis voices",
    });
  }

  const hash = (await sSha(voices.map((v) => `${v.name}|${v.lang}|${v.localService}`).join(";"))).slice(
    0,
    24
  );

  if (!flags.length) flags.push({ type: "ok", text: "speech integrity ok" });

  return {
    category: "speechIntegrity",
    label: "Speech Integrity",
    entropy: 8,
    source: "CreepJS speech",
    items: {
      supported: true,
      count: voices.length,
      localCount: local.length,
      remoteCount: remote.length,
      defaults: defaults.map((v) => v.name),
      langs,
      hash,
      flags,
    },
  };
}

// ─── 34. Math / typed array engine hard ──────────────────────
export async function collectMathHard() {
  const flags = [];
  const vals = {
    tan_neg1e300: Math.tan(-1e300),
    sin_1e300: Math.sin(1e300),
    cos_10: Math.cos(10.000000000123),
    log2e: Math.LOG2E,
    ln2: Math.LN2,
    sinh1: Math.sinh?.(1),
    asinh1: Math.asinh?.(1),
    acosh2: Math.acosh?.(2),
    atanh05: Math.atanh?.(0.5),
    hypot: Math.hypot?.(1e300, 1e300),
    fround_pi: Math.fround?.(Math.PI),
    imul: Math.imul?.(0xffffffff, 5),
    clz32: Math.clz32?.(1),
  };

  // Float32Array vs number path
  const f32 = new Float32Array([Math.PI, Math.E, 0.1 + 0.2]);
  vals.f32 = Array.from(f32);

  // BigInt mix
  vals.bigint = sSafe(() => String(2n ** 53n + 1n));

  // Intl number vs math
  vals.polyfillLie = sSafe(() => 0.1 + 0.2 === 0.3);

  const hash = (await sSha(JSON.stringify(vals))).slice(0, 24);

  // worker math compare
  let workerMath = null;
  if (window.Worker) {
    workerMath = await sSafeAsync(
      () =>
        new Promise((resolve) => {
          const code = `self.onmessage=()=>self.postMessage({
            tan:Math.tan(-1e300), sin:Math.sin(1e300), fround:Math.fround?Math.fround(Math.PI):null
          })`;
          const url = URL.createObjectURL(new Blob([code], { type: "application/javascript" }));
          const w = new Worker(url);
          const t = setTimeout(() => {
            w.terminate();
            resolve({ error: "timeout" });
          }, 1000);
          w.onmessage = (e) => {
            clearTimeout(t);
            w.terminate();
            URL.revokeObjectURL(url);
            resolve(e.data);
          };
          w.postMessage(1);
        })
    );
    if (workerMath && !workerMath.error) {
      if (workerMath.tan !== vals.tan_neg1e300) {
        flags.push({
          type: "danger",
          id: "math_worker",
          text: "Math.tan differs in worker",
          why: "JS engine math must match across realms; divergence suggests polyfill/spoof.",
          measured: { worker: workerMath.tan, main: vals.tan_neg1e300 },
          expected: "identical",
        });
      }
    }
  }

  if (!flags.length) flags.push({ type: "ok", text: "math hard ok" });

  return {
    category: "mathHard",
    label: "Math / Engine Hard",
    entropy: 10,
    source: "CreepJS math / engine",
    items: { vals, hash, workerMath, flags },
  };
}

// ─── 35. DOM automation / CDP deep leftovers ─────────────────
export function collectAutomationDeep() {
  const flags = [];
  const measured = {
    documentKeys: Object.getOwnPropertyNames(document).filter((k) =>
      /cdc_|\$chrome_|__selenium|__webdriver|__driver|__playwright|__pw/i.test(k)
    ),
    windowKeys: Object.getOwnPropertyNames(window).filter((k) =>
      /^(cdc_|\$cdc_|\$chrome_|__webdriver|__driver|__selenium|__fxdriver|__playwright|__pw_|callPhantom|_phantom|domAutomation)/i.test(
        k
      )
    ),
    htmlAttrs: {
      webdriver: document.documentElement.getAttribute("webdriver"),
      selenium: document.documentElement.getAttribute("selenium"),
      driver: document.documentElement.getAttribute("driver"),
    },
    navigatorWebdriver: navigator.webdriver,
    // Playwright binding
    playwrightBinding: !!(window.__playwright && window.__playwright__binding__),
    // puppeteer
    puppeteer: !!(window.__puppeteer_evaluation_script__ || window.__pptr__),
  };

  if (measured.documentKeys.length) {
    flags.push({
      type: "danger",
      id: "doc_auto_keys",
      text: `document automation keys: ${measured.documentKeys.slice(0, 6).join(",")}`,
      why: "CDP/Selenium leaves enumerable leftovers on document.",
      measured: measured.documentKeys,
      expected: "none",
    });
  }
  if (measured.windowKeys.length) {
    flags.push({
      type: "danger",
      id: "win_auto_keys",
      text: `window automation keys: ${measured.windowKeys.slice(0, 6).join(",")}`,
      why: "Automation globals on window.",
      measured: measured.windowKeys,
      expected: "none",
    });
  }
  if (measured.htmlAttrs.webdriver || measured.htmlAttrs.selenium || measured.htmlAttrs.driver) {
    flags.push({
      type: "danger",
      id: "html_auto_attr",
      text: "html automation attributes present",
      why: "documentElement carries webdriver/selenium/driver attributes.",
      measured: measured.htmlAttrs,
      expected: "null attributes",
    });
  }
  if (measured.playwrightBinding || measured.puppeteer) {
    flags.push({
      type: "danger",
      id: "pw_pptr",
      text: "Playwright/Puppeteer bindings detected",
      why: "Framework evaluation bindings exposed to page JS.",
      measured: {
        playwrightBinding: measured.playwrightBinding,
        puppeteer: measured.puppeteer,
      },
      expected: "no framework bindings",
    });
  }

  // Runtime.enable heuristic: console methods sometimes wrapped
  measured.console = {
    logNative: isNative(console.log),
    debugNative: isNative(console.debug),
    dirNative: isNative(console.dir),
  };

  if (!flags.length) flags.push({ type: "ok", text: "no automation leftovers" });

  return {
    category: "automationDeep",
    label: "Automation Deep",
    entropy: 12,
    source: "CDP / Selenium / Playwright surface",
    items: { ...measured, flags },
  };
}

// ─── runner ──────────────────────────────────────────────────
export async function runHardSuiteV2(onProgress) {
  const steps = [
    ["Multi-realm", () => collectMultiRealm()],
    ["Identity matrix", () => collectIdentityMatrix()],
    ["Shader FP", () => collectShaderFingerprint()],
    ["Geometry hard", () => collectGeometryHard()],
    ["CSS hard", () => collectCssHard()],
    ["WebRTC SDP", () => collectWebRtcHard()],
    ["Audio analyser", () => collectAudioAnalyser()],
    ["Intl deep", () => collectIntlDeep()],
    ["Proto integrity", () => collectPrototypeIntegrity()],
    ["Feature coherence", () => collectFeatureCoherence()],
    ["Offscreen canvas", () => collectOffscreenVsMain()],
    ["Side channels", () => collectSideChannels()],
    ["Speech integrity", () => collectSpeechIntegrity()],
    ["Math hard", () => collectMathHard()],
    ["Automation deep", () => collectAutomationDeep()],
  ];

  const out = [];
  for (let i = 0; i < steps.length; i++) {
    const [name, fn] = steps[i];
    onProgress?.(i / steps.length, name);
    try {
      const block = await fn();
      if (block) out.push(block);
    } catch (e) {
      out.push({
        category: `v2_error_${i}`,
        label: `${name} (failed)`,
        entropy: 0,
        source: "runner-v2",
        items: {
          error: String(e?.message || e),
          stack: String(e?.stack || "").slice(0, 400),
          flags: [
            {
              type: "warn",
              text: `${name} threw`,
              why: "Collector crashed; environment may block the API.",
              measured: String(e?.message || e),
              expected: "collector completes",
            },
          ],
        },
      });
    }
  }
  return out;
}
