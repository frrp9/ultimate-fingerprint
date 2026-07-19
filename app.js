/**
 * ULTIMATE FINGERPRINT — client-side deep analysis suite
 * Aggregates techniques inspired by:
 * - CreepJS (abrahamjuliot/creepjs) MIT — deepest anti-spoof / lie detection
 * - FingerprintJS open-source core MIT — stable visitorId signals
 * - ClientJS Apache-2.0 — device/screen/plugin/font baselines
 * - AmIUnique / BrowserLeaks-class public techniques
 * - Bot / automation surface checks (webdriver, CDP, chrome runtime)
 *
 * Fully client-side. No backend required.
 */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const state = {
  report: null,
  activeTab: "all",
};

// ─── crypto / hash ───────────────────────────────────────────
async function sha256(str) {
  const data = new TextEncoder().encode(String(str));
  const buf = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function stableStringify(v) {
  if (v === null || v === undefined) return String(v);
  if (typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  return `{${Object.keys(v)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${stableStringify(v[k])}`)
    .join(",")}}`;
}

async function hashObj(obj) {
  return (await sha256(stableStringify(obj))).slice(0, 16);
}

function safe(fn, fallback = null) {
  try {
    return fn();
  } catch (e) {
    return fallback ?? { error: String(e?.message || e) };
  }
}

async function safeAsync(fn, fallback = null) {
  try {
    return await fn();
  } catch (e) {
    return fallback ?? { error: String(e?.message || e) };
  }
}

// ─── FONT LIST (high-entropy subset used by AmIUnique / FPJS-class) ───
const FONT_PROBE = [
  "Arial", "Arial Black", "Arial Narrow", "Calibri", "Cambria", "Candara",
  "Comic Sans MS", "Consolas", "Constantia", "Corbel", "Courier", "Courier New",
  "Georgia", "Helvetica", "Impact", "Lucida Console", "Lucida Sans Unicode",
  "Microsoft Sans Serif", "Palatino Linotype", "Segoe UI", "Tahoma", "Times",
  "Times New Roman", "Trebuchet MS", "Verdana", "Wingdings", "Webdings",
  "MS Gothic", "MS Mincho", "Yu Gothic", "Meiryo", "Malgun Gothic", "Gulim",
  "Dotum", "SimSun", "SimHei", "Microsoft YaHei", "NSimSun", "FangSong",
  "KaiTi", "STHeiti", "STSong", "PingFang SC", "Hiragino Sans", "Apple SD Gothic Neo",
  "Menlo", "Monaco", "SF Pro Text", "Helvetica Neue", "Gill Sans", "Optima",
  "Futura", "Avenir", "Didot", "American Typewriter", "Copperplate",
  "DejaVu Sans", "DejaVu Serif", "Liberation Sans", "Ubuntu", "Noto Sans",
  "Roboto", "Open Sans", "Lato", "Source Code Pro", "Fira Code",
  "Garamond", "Bookman Old Style", "Century Gothic", "Franklin Gothic Medium",
  "Brush Script MT", "Papyrus", "Rockwell", "Symbol", "Zapf Dingbats",
];

// ─── collectors ──────────────────────────────────────────────

function collectNavigator() {
  const n = navigator;
  const uaData = n.userAgentData;
  return {
    category: "navigator",
    label: "Navigator & Identity",
    entropy: 18,
    source: "FingerprintJS / ClientJS / CreepJS",
    items: {
      userAgent: n.userAgent,
      appVersion: n.appVersion,
      platform: n.platform,
      vendor: n.vendor,
      product: n.product,
      productSub: n.productSub,
      language: n.language,
      languages: n.languages ? [...n.languages] : null,
      cookieEnabled: n.cookieEnabled,
      doNotTrack: n.doNotTrack,
      globalPrivacyControl: n.globalPrivacyControl ?? null,
      hardwareConcurrency: n.hardwareConcurrency,
      deviceMemory: n.deviceMemory ?? null,
      maxTouchPoints: n.maxTouchPoints,
      pdfViewerEnabled: n.pdfViewerEnabled ?? null,
      webdriver: n.webdriver,
      onLine: n.onLine,
      javaEnabled: safe(() => n.javaEnabled?.() ?? null),
      pluginsCount: n.plugins?.length ?? 0,
      mimeTypesCount: n.mimeTypes?.length ?? 0,
      plugins: safe(() =>
        [...(n.plugins || [])].map((p) => ({
          name: p.name,
          filename: p.filename,
          description: p.description,
        }))
      ),
      mimeTypes: safe(() =>
        [...(n.mimeTypes || [])].slice(0, 40).map((m) => ({
          type: m.type,
          suffixes: m.suffixes,
          description: m.description,
        }))
      ),
      connection: safe(() => {
        const c = n.connection || n.mozConnection || n.webkitConnection;
        if (!c) return null;
        return {
          effectiveType: c.effectiveType,
          downlink: c.downlink,
          rtt: c.rtt,
          saveData: c.saveData,
          type: c.type,
        };
      }),
      userAgentData: safe(() => {
        if (!uaData) return null;
        return {
          brands: uaData.brands,
          mobile: uaData.mobile,
          platform: uaData.platform,
        };
      }),
    },
  };
}

async function collectHighEntropyUA() {
  const uaData = navigator.userAgentData;
  if (!uaData?.getHighEntropyValues) {
    return {
      category: "clientHints",
      label: "Client Hints (high entropy)",
      entropy: 12,
      source: "CreepJS / modern Chromium",
      items: { available: false },
    };
  }
  const he = await safeAsync(() =>
    uaData.getHighEntropyValues([
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
  return {
    category: "clientHints",
    label: "Client Hints (high entropy)",
    entropy: 14,
    source: "CreepJS / Chromium Client Hints",
    items: he || { available: false },
  };
}

function collectScreen() {
  const s = screen;
  return {
    category: "screen",
    label: "Screen & Window",
    entropy: 10,
    source: "FingerprintJS / ClientJS / BrowserLeaks-class",
    items: {
      width: s.width,
      height: s.height,
      availWidth: s.availWidth,
      availHeight: s.availHeight,
      colorDepth: s.colorDepth,
      pixelDepth: s.pixelDepth,
      orientation: s.orientation?.type ?? null,
      angle: s.orientation?.angle ?? null,
      devicePixelRatio: window.devicePixelRatio,
      outerWidth: window.outerWidth,
      outerHeight: window.outerHeight,
      innerWidth: window.innerWidth,
      innerHeight: window.innerHeight,
      screenX: window.screenX,
      screenY: window.screenY,
      isSecureContext: window.isSecureContext,
      matchMediaColor: window.matchMedia?.("(color-gamut: p3)").matches
        ? "p3"
        : window.matchMedia?.("(color-gamut: srgb)").matches
          ? "srgb"
          : "unknown",
      prefersColorScheme: window.matchMedia?.("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light",
      prefersReducedMotion: window.matchMedia?.("(prefers-reduced-motion: reduce)").matches,
      forcedColors: window.matchMedia?.("(forced-colors: active)").matches,
      hover: window.matchMedia?.("(hover: hover)").matches,
      pointer: window.matchMedia?.("(pointer: fine)").matches
        ? "fine"
        : window.matchMedia?.("(pointer: coarse)").matches
          ? "coarse"
          : "none",
    },
  };
}

function collectTimezone() {
  const d = new Date();
  let resolved = null;
  try {
    resolved = Intl.DateTimeFormat().resolvedOptions();
  } catch {}
  return {
    category: "locale",
    label: "Timezone & Locale",
    entropy: 8,
    source: "AmIUnique / FingerprintJS / CreepJS",
    items: {
      timezoneOffset: d.getTimezoneOffset(),
      timezone: resolved?.timeZone ?? null,
      locale: resolved?.locale ?? null,
      calendar: resolved?.calendar ?? null,
      numberingSystem: resolved?.numberingSystem ?? null,
      hourCycle: resolved?.hourCycle ?? null,
      dateString: d.toString(),
      localeDateString: d.toLocaleString(),
      intlDate: safe(() =>
        new Intl.DateTimeFormat(undefined, {
          timeZoneName: "long",
          year: "numeric",
          month: "long",
          day: "numeric",
          hour: "numeric",
          minute: "numeric",
          second: "numeric",
        }).format(d)
      ),
      numberFormat: safe(() =>
        new Intl.NumberFormat(undefined, { style: "currency", currency: "USD" }).format(123456.78)
      ),
      collation: safe(() => ["a", "ä", "z", "å"].sort(new Intl.Collator().compare).join(",")),
    },
  };
}

async function collectCanvas() {
  const canvas = document.createElement("canvas");
  canvas.width = 280;
  canvas.height = 80;
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    return {
      category: "canvas",
      label: "Canvas",
      entropy: 16,
      source: "CreepJS / FingerprintJS / BrowserLeaks",
      items: { supported: false },
    };
  }

  ctx.textBaseline = "alphabetic";
  ctx.fillStyle = "#f60";
  ctx.fillRect(10, 8, 120, 40);
  ctx.fillStyle = "#069";
  ctx.font = "16px Arial";
  ctx.fillText("Cwm fjord bank 😃glyphs", 4, 28);
  ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
  ctx.font = "18px Times New Roman";
  ctx.fillText("mmmmmmmmmmlli", 4, 52);
  ctx.strokeStyle = "#ff00aa";
  ctx.beginPath();
  ctx.arc(200, 40, 28, 0, Math.PI * 2);
  ctx.stroke();
  ctx.globalCompositeOperation = "multiply";
  ctx.fillStyle = "rgb(255,0,255)";
  ctx.beginPath();
  ctx.arc(180, 30, 22, 0, Math.PI * 2);
  ctx.fill();
  ctx.fillStyle = "rgb(0,255,255)";
  ctx.beginPath();
  ctx.arc(210, 30, 22, 0, Math.PI * 2);
  ctx.fill();
  ctx.fillStyle = "rgb(255,255,0)";
  ctx.beginPath();
  ctx.arc(195, 50, 22, 0, Math.PI * 2);
  ctx.fill();

  const dataUrl = canvas.toDataURL();
  const hash = await sha256(dataUrl);

  // TextMetrics (CreepJS-class)
  const metrics = safe(() => {
    ctx.font = "72px Arial";
    const m = ctx.measureText("mmmmmmmmmmlli|W|@|م|中|😀");
    return {
      width: m.width,
      actualBoundingBoxAscent: m.actualBoundingBoxAscent,
      actualBoundingBoxDescent: m.actualBoundingBoxDescent,
      actualBoundingBoxLeft: m.actualBoundingBoxLeft,
      actualBoundingBoxRight: m.actualBoundingBoxRight,
      fontBoundingBoxAscent: m.fontBoundingBoxAscent,
      fontBoundingBoxDescent: m.fontBoundingBoxDescent,
    };
  });

  // Paint / emoji geometry
  const emojiCanvas = document.createElement("canvas");
  emojiCanvas.width = 64;
  emojiCanvas.height = 64;
  const ectx = emojiCanvas.getContext("2d");
  ectx.font = "48px serif";
  ectx.fillText("👾", 4, 48);
  const emojiHash = await sha256(emojiCanvas.toDataURL());

  return {
    category: "canvas",
    label: "Canvas & TextMetrics",
    entropy: 20,
    source: "CreepJS / FingerprintJS / BrowserLeaks",
    items: {
      supported: true,
      winding: safe(() => {
        ctx.rect(0, 0, 10, 10);
        ctx.rect(2, 2, 6, 6);
        return ctx.isPointInPath(5, 5, "evenodd") === false;
      }),
      dataUrlHash: hash.slice(0, 32),
      dataUrlLen: dataUrl.length,
      emojiHash: emojiHash.slice(0, 24),
      textMetrics: metrics,
      preview: dataUrl,
    },
  };
}

async function collectWebGL() {
  const canvas = document.createElement("canvas");
  const gl =
    canvas.getContext("webgl2") ||
    canvas.getContext("webgl") ||
    canvas.getContext("experimental-webgl");
  if (!gl) {
    return {
      category: "webgl",
      label: "WebGL / GPU",
      entropy: 18,
      source: "CreepJS / FingerprintJS / BrowserLeaks",
      items: { supported: false },
    };
  }

  const dbg = gl.getExtension("WEBGL_debug_renderer_info");
  const params = {};
  const names = [
    "VERSION",
    "SHADING_LANGUAGE_VERSION",
    "VENDOR",
    "RENDERER",
    "MAX_TEXTURE_SIZE",
    "MAX_CUBE_MAP_TEXTURE_SIZE",
    "MAX_RENDERBUFFER_SIZE",
    "MAX_VIEWPORT_DIMS",
    "MAX_VERTEX_ATTRIBS",
    "MAX_VERTEX_UNIFORM_VECTORS",
    "MAX_FRAGMENT_UNIFORM_VECTORS",
    "MAX_VARYING_VECTORS",
    "MAX_COMBINED_TEXTURE_IMAGE_UNITS",
    "MAX_TEXTURE_IMAGE_UNITS",
    "MAX_VERTEX_TEXTURE_IMAGE_UNITS",
    "ALIASED_LINE_WIDTH_RANGE",
    "ALIASED_POINT_SIZE_RANGE",
    "DEPTH_BITS",
    "STENCIL_BITS",
    "MAX_DRAW_BUFFERS",
    "MAX_COLOR_ATTACHMENTS",
  ];
  for (const name of names) {
    const key = gl[name];
    if (key === undefined) continue;
    params[name] = safe(() => {
      const v = gl.getParameter(key);
      if (v && typeof v === "object" && "length" in v) return Array.from(v);
      return v;
    });
  }

  const unmaskedVendor = dbg
    ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)
    : null;
  const unmaskedRenderer = dbg
    ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)
    : null;

  const extensions = gl.getSupportedExtensions() || [];
  const aniso = gl.getExtension("EXT_texture_filter_anisotropic") ||
    gl.getExtension("WEBKIT_EXT_texture_filter_anisotropic") ||
    gl.getExtension("MOZ_EXT_texture_filter_anisotropic");
  const maxAniso = aniso
    ? gl.getParameter(aniso.MAX_TEXTURE_MAX_ANISOTROPY_EXT)
    : null;

  // Shader precision (CreepJS-class)
  const precision = safe(() => {
    const types = ["LOW_FLOAT", "MEDIUM_FLOAT", "HIGH_FLOAT", "LOW_INT", "MEDIUM_INT", "HIGH_INT"];
    const out = {};
    for (const t of types) {
      const shaderType = gl.FRAGMENT_SHADER;
      const p = gl.getShaderPrecisionFormat(shaderType, gl[t]);
      out[`frag_${t}`] = p ? { rangeMin: p.rangeMin, rangeMax: p.rangeMax, precision: p.precision } : null;
    }
    return out;
  });

  // WebGL render hash (simple triangle)
  const renderHash = safe(() => {
    const vs = gl.createShader(gl.VERTEX_SHADER);
    gl.shaderSource(
      vs,
      "attribute vec2 p;void main(){gl_Position=vec4(p,0.,1.);}"
    );
    gl.compileShader(vs);
    const fs = gl.createShader(gl.FRAGMENT_SHADER);
    gl.shaderSource(
      fs,
      "precision mediump float;void main(){gl_FragColor=vec4(.2,.5,.8,1.);}"
    );
    gl.compileShader(fs);
    const prog = gl.createProgram();
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    gl.useProgram(prog);
    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-0.5, -0.5, 0.5, -0.5, 0, 0.5]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, "p");
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    gl.clearColor(0.1, 0.1, 0.1, 1);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    const pixels = new Uint8Array(16 * 16 * 4);
    gl.readPixels(0, 0, 16, 16, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
    return Array.from(pixels.slice(0, 64)).join(",");
  });

  const renderHashDigest = renderHash ? (await sha256(renderHash)).slice(0, 24) : null;

  return {
    category: "webgl",
    label: "WebGL / GPU",
    entropy: 22,
    source: "CreepJS / FingerprintJS / BrowserLeaks",
    items: {
      supported: true,
      contextType: canvas.getContext("webgl2") ? "webgl2" : "webgl",
      vendor: params.VENDOR,
      renderer: params.RENDERER,
      unmaskedVendor,
      unmaskedRenderer,
      version: params.VERSION,
      shadingLanguage: params.SHADING_LANGUAGE_VERSION,
      maxTextureSize: params.MAX_TEXTURE_SIZE,
      maxViewport: params.MAX_VIEWPORT_DIMS,
      maxAnisotropy: maxAniso,
      extensionsCount: extensions.length,
      extensions: extensions.slice().sort(),
      parameters: params,
      shaderPrecision: precision,
      renderHash: renderHashDigest,
    },
  };
}

async function collectAudio() {
  const OfflineCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
  if (!OfflineCtx) {
    return {
      category: "audio",
      label: "AudioContext",
      entropy: 14,
      source: "FingerprintJS / CreepJS",
      items: { supported: false },
    };
  }

  const sampleRate = safe(() => {
    const ac = new (window.AudioContext || window.webkitAudioContext)();
    const r = ac.sampleRate;
    ac.close?.();
    return r;
  });

  const fp = await safeAsync(async () => {
    const ctx = new OfflineCtx(1, 44100, 44100);
    const osc = ctx.createOscillator();
    osc.type = "triangle";
    osc.frequency.value = 10000;
    const comp = ctx.createDynamicsCompressor();
    comp.threshold.value = -50;
    comp.knee.value = 40;
    comp.ratio.value = 12;
    comp.attack.value = 0;
    comp.release.value = 0.25;
    osc.connect(comp);
    comp.connect(ctx.destination);
    osc.start(0);
    const buf = await ctx.startRendering();
    const data = buf.getChannelData(0);
    let sum = 0;
    for (let i = 4500; i < 5000; i++) sum += Math.abs(data[i]);
    const sample = Array.from(data.slice(4500, 4520));
    return { sum, sample, length: data.length };
  });

  const hash = fp ? (await sha256(stableStringify(fp))).slice(0, 24) : null;

  return {
    category: "audio",
    label: "AudioContext",
    entropy: 14,
    source: "FingerprintJS / CreepJS",
    items: {
      supported: true,
      sampleRate,
      compressorSum: fp?.sum ?? null,
      fingerprintHash: hash,
      sampleSnippet: fp?.sample ?? null,
    },
  };
}

function collectFonts() {
  const baseFonts = ["monospace", "sans-serif", "serif"];
  const testString = "mmmmmmmmmmlli";
  const testSize = "72px";
  const body = document.body;
  const span = document.createElement("span");
  span.style.position = "absolute";
  span.style.left = "-9999px";
  span.style.fontSize = testSize;
  span.style.lineHeight = "normal";
  span.style.fontVariant = "normal";
  span.style.fontStyle = "normal";
  span.style.fontWeight = "normal";
  span.style.letterSpacing = "normal";
  span.style.textTransform = "none";
  span.innerHTML = testString;
  body.appendChild(span);

  const defaults = {};
  for (const base of baseFonts) {
    span.style.fontFamily = base;
    defaults[base] = { w: span.offsetWidth, h: span.offsetHeight };
  }

  const detected = [];
  for (const font of FONT_PROBE) {
    let found = false;
    for (const base of baseFonts) {
      span.style.fontFamily = `'${font}',${base}`;
      const w = span.offsetWidth;
      const h = span.offsetHeight;
      if (w !== defaults[base].w || h !== defaults[base].h) {
        found = true;
        break;
      }
    }
    if (found) detected.push(font);
  }
  body.removeChild(span);

  return {
    category: "fonts",
    label: "Fonts",
    entropy: 16,
    source: "AmIUnique / ClientJS / FingerprintJS-class",
    items: {
      probed: FONT_PROBE.length,
      detectedCount: detected.length,
      fonts: detected,
    },
  };
}

function collectStorage() {
  return {
    category: "storage",
    label: "Storage & APIs",
    entropy: 6,
    source: "ClientJS / FingerprintJS",
    items: {
      localStorage: safe(() => {
        try {
          localStorage.setItem("__fp_t", "1");
          localStorage.removeItem("__fp_t");
          return true;
        } catch {
          return false;
        }
      }),
      sessionStorage: safe(() => {
        try {
          sessionStorage.setItem("__fp_t", "1");
          sessionStorage.removeItem("__fp_t");
          return true;
        } catch {
          return false;
        }
      }),
      indexedDB: !!window.indexedDB,
      openDatabase: !!window.openDatabase,
      caches: !!window.caches,
      serviceWorker: !!navigator.serviceWorker,
      cookieEnabled: navigator.cookieEnabled,
      sharedArrayBuffer: typeof SharedArrayBuffer !== "undefined",
      crossOriginIsolated: window.crossOriginIsolated ?? null,
      storageEstimate: null,
    },
  };
}

async function collectStorageEstimate(block) {
  if (navigator.storage?.estimate) {
    const est = await safeAsync(() => navigator.storage.estimate());
    block.items.storageEstimate = est
      ? { quota: est.quota, usage: est.usage }
      : null;
  }
  if (navigator.storage?.persisted) {
    block.items.persisted = await safeAsync(() => navigator.storage.persisted());
  }
  return block;
}

function collectMath() {
  // JS engine fingerprint (CreepJS / FingerprintJS-class)
  const values = {
    acos: Math.acos(0.1231231231234567),
    acosh: Math.acosh?.(1e308),
    asin: Math.asin(0.1231231231234567),
    asinh: Math.asinh?.(1),
    atanh: Math.atanh?.(0.5),
    atan: Math.atan(0.5),
    sin: Math.sin(-1e300),
    cos: Math.cos(10.000000000123),
    tan: Math.tan(-1e300),
    exp: Math.exp(1),
    expm1: Math.expm1?.(1),
    log1p: Math.log1p?.(10),
    powPI: Math.pow(Math.PI, -100),
  };
  return {
    category: "jsEngine",
    label: "JS Engine (Math)",
    entropy: 8,
    source: "CreepJS / FingerprintJS",
    items: values,
  };
}

function collectDomRect() {
  const div = document.createElement("div");
  div.style.cssText =
    "position:absolute;left:-9999px;width:100.125px;height:33.333px;font:16px Arial;transform:rotate(0.1deg);";
  div.textContent = "mmmmmmmmmmlli 😀 م中";
  document.body.appendChild(div);
  const r = div.getBoundingClientRect();
  const range = document.createRange();
  range.selectNode(div);
  const rr = range.getBoundingClientRect();
  document.body.removeChild(div);
  return {
    category: "domrect",
    label: "DOMRect / Geometry",
    entropy: 10,
    source: "CreepJS",
    items: {
      width: r.width,
      height: r.height,
      x: r.x,
      y: r.y,
      rangeWidth: rr.width,
      rangeHeight: rr.height,
      clientWidth: div.clientWidth,
      offsetWidth: 0,
    },
  };
}

function collectCssSystem() {
  const el = document.createElement("div");
  el.style.cssText = "position:absolute;left:-9999px;";
  document.body.appendChild(el);
  const props = [
    "font-family",
    "font-size",
    "color",
    "background-color",
    "border-top-color",
    "line-height",
    "letter-spacing",
    "word-spacing",
    "text-transform",
  ];
  const computed = getComputedStyle(el);
  const system = {};
  for (const p of props) system[p] = computed.getPropertyValue(p);
  // system colors
  const colors = [
    "Canvas",
    "CanvasText",
    "LinkText",
    "VisitedText",
    "ActiveText",
    "ButtonFace",
    "ButtonText",
    "Field",
    "FieldText",
    "Highlight",
    "HighlightText",
    "GrayText",
  ];
  const sysColors = {};
  for (const c of colors) {
    el.style.color = c;
    sysColors[c] = getComputedStyle(el).color;
  }
  document.body.removeChild(el);
  return {
    category: "css",
    label: "CSS System Styles",
    entropy: 8,
    source: "CreepJS",
    items: { computed: system, systemColors: sysColors },
  };
}

function collectVoices() {
  return new Promise((resolve) => {
    const done = (list) => {
      resolve({
        category: "voices",
        label: "Speech Voices",
        entropy: 8,
        source: "CreepJS / FingerprintJS",
        items: {
          count: list.length,
          voices: list.map((v) => ({
            name: v.name,
            lang: v.lang,
            localService: v.localService,
            default: v.default,
            voiceURI: v.voiceURI,
          })),
        },
      });
    };
    if (!window.speechSynthesis) {
      done([]);
      return;
    }
    let voices = speechSynthesis.getVoices();
    if (voices.length) {
      done(voices);
      return;
    }
    const t = setTimeout(() => done(speechSynthesis.getVoices() || []), 800);
    speechSynthesis.onvoiceschanged = () => {
      clearTimeout(t);
      done(speechSynthesis.getVoices() || []);
    };
  });
}

function collectMediaDevices() {
  return safeAsync(async () => {
    if (!navigator.mediaDevices?.enumerateDevices) {
      return {
        category: "media",
        label: "Media Devices",
        entropy: 6,
        source: "BrowserLeaks-class",
        items: { supported: false },
      };
    }
    const devices = await navigator.mediaDevices.enumerateDevices();
    return {
      category: "media",
      label: "Media Devices",
      entropy: 8,
      source: "BrowserLeaks-class",
      items: {
        supported: true,
        count: devices.length,
        devices: devices.map((d) => ({
          kind: d.kind,
          label: d.label || "(permission required)",
          deviceId: d.deviceId ? d.deviceId.slice(0, 12) + "…" : "",
          groupId: d.groupId ? d.groupId.slice(0, 12) + "…" : "",
        })),
      },
    };
  });
}

function collectPermissions() {
  const names = [
    "geolocation",
    "notifications",
    "camera",
    "microphone",
    "midi",
    "clipboard-read",
    "clipboard-write",
    "persistent-storage",
    "push",
    "accelerometer",
    "gyroscope",
    "magnetometer",
  ];
  return safeAsync(async () => {
    if (!navigator.permissions?.query) {
      return {
        category: "permissions",
        label: "Permissions",
        entropy: 4,
        source: "FingerprintJS-class",
        items: { supported: false },
      };
    }
    const out = {};
    await Promise.all(
      names.map(async (name) => {
        try {
          const r = await navigator.permissions.query({ name });
          out[name] = r.state;
        } catch {
          out[name] = "unsupported";
        }
      })
    );
    return {
      category: "permissions",
      label: "Permissions",
      entropy: 5,
      source: "FingerprintJS-class",
      items: out,
    };
  });
}

function collectWebRTC() {
  return safeAsync(async () => {
    if (!window.RTCPeerConnection) {
      return {
        category: "webrtc",
        label: "WebRTC",
        entropy: 10,
        source: "BrowserLeaks-class",
        items: { supported: false },
      };
    }
    const pc = new RTCPeerConnection({
      iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
    });
    pc.createDataChannel("fp");
    const ips = new Set();
    const candidates = [];
    const done = new Promise((resolve) => {
      const timer = setTimeout(() => resolve(), 1500);
      pc.onicecandidate = (e) => {
        if (!e.candidate) {
          clearTimeout(timer);
          resolve();
          return;
        }
        const c = e.candidate.candidate;
        candidates.push(c);
        const m = /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9:]{8,})/i.exec(c);
        if (m) ips.add(m[1]);
      };
    });
    await pc.createOffer().then((o) => pc.setLocalDescription(o));
    await done;
    pc.close();
    return {
      category: "webrtc",
      label: "WebRTC",
      entropy: 12,
      source: "BrowserLeaks-class",
      items: {
        supported: true,
        localIPs: [...ips],
        candidateCount: candidates.length,
        candidatesSample: candidates.slice(0, 8),
      },
    };
  });
}

function collectBattery() {
  return safeAsync(async () => {
    if (!navigator.getBattery) {
      return {
        category: "battery",
        label: "Battery",
        entropy: 3,
        source: "legacy API",
        items: { supported: false },
      };
    }
    const b = await navigator.getBattery();
    return {
      category: "battery",
      label: "Battery",
      entropy: 3,
      source: "legacy API",
      items: {
        supported: true,
        charging: b.charging,
        level: b.level,
        chargingTime: b.chargingTime,
        dischargingTime: b.dischargingTime,
      },
    };
  });
}

function collectFeatures() {
  const features = {
    bluetooth: !!navigator.bluetooth,
    usb: !!navigator.usb,
    hid: !!navigator.hid,
    serial: !!navigator.serial,
    xr: !!navigator.xr,
    gpu: !!navigator.gpu,
    wakeLock: !!navigator.wakeLock,
    credentials: !!navigator.credentials,
    keyboard: !!navigator.keyboard,
    locks: !!navigator.locks,
    scheduling: !!navigator.scheduling,
    ink: !!navigator.ink,
    virtualKeyboard: !!navigator.virtualKeyboard,
    windowControlsOverlay: !!navigator.windowControlsOverlay,
    cookieStore: !!window.cookieStore,
    showOpenFilePicker: !!window.showOpenFilePicker,
    EyeDropper: !!window.EyeDropper,
    BarcodeDetector: !!window.BarcodeDetector,
    OffscreenCanvas: !!window.OffscreenCanvas,
    WebAssembly: !!window.WebAssembly,
    BigInt: typeof BigInt !== "undefined",
    Atomics: typeof Atomics !== "undefined",
    Notification: !!window.Notification,
    PaymentRequest: !!window.PaymentRequest,
    BluetoothUUID: !!window.BluetoothUUID,
  };
  return {
    category: "features",
    label: "Feature Detection",
    entropy: 10,
    source: "CreepJS new-API surface",
    items: features,
  };
}

function collectTamper() {
  // CreepJS-class lie / automation detection
  const flags = [];
  const details = {};

  // webdriver
  details.webdriver = navigator.webdriver === true;
  if (details.webdriver) flags.push({ type: "danger", text: "navigator.webdriver" });

  // chrome runtime (headless / automation)
  details.chromeRuntime = !!(window.chrome && window.chrome.runtime);
  details.chromeApp = !!(window.chrome && window.chrome.app);

  // phantom / nightmare / selenium leftovers
  details.phantom = !!(window.callPhantom || window._phantom);
  details.nightmare = !!window.__nightmare;
  details.selenium = !!(
    document.documentElement.getAttribute("webdriver") ||
    window.domAutomation ||
    window.domAutomationController ||
    window._Selenium_IDE_Recorder
  );
  if (details.phantom) flags.push({ type: "danger", text: "phantom" });
  if (details.nightmare) flags.push({ type: "danger", text: "nightmare" });
  if (details.selenium) flags.push({ type: "danger", text: "selenium" });

  // permissions lie pattern
  details.notificationPermission = typeof Notification !== "undefined" ? Notification.permission : null;

  // plugins empty on chrome desktop is suspicious
  const isChromium = /Chrome|Chromium|Edg/.test(navigator.userAgent);
  details.pluginsEmpty = (navigator.plugins?.length || 0) === 0;
  if (isChromium && details.pluginsEmpty && !/Mobile|Android/.test(navigator.userAgent)) {
    flags.push({ type: "warn", text: "empty plugins (Chromium desktop)" });
  }

  // languages empty
  details.languagesEmpty = !navigator.languages || navigator.languages.length === 0;
  if (details.languagesEmpty) flags.push({ type: "warn", text: "empty languages" });

  // outer dimensions 0 (headless-ish)
  details.outerZero = window.outerWidth === 0 && window.outerHeight === 0;
  if (details.outerZero) flags.push({ type: "warn", text: "outer dimensions 0" });

  // Function.prototype.toString native check
  details.toStringNative = safe(() => {
    const s = Function.prototype.toString.call(navigator.permissions?.query || (() => {}));
    return /\[native code\]/.test(s) || s.length < 100;
  });

  // iframe chrome
  details.hasChrome = !!window.chrome;

  // CDP / DevTools protocol heuristics
  details.cdcProps = Object.keys(window).filter((k) => /^cdc_|\$cdc_|__webdriver|__driver|__selenium|__fxdriver/i.test(k));
  if (details.cdcProps.length) flags.push({ type: "danger", text: "automation cdc props" });

  // prototype lie samples
  details.navigatorProto = safe(() => Object.getPrototypeOf(navigator).constructor.name);
  details.screenProto = safe(() => Object.getPrototypeOf(screen).constructor.name);

  // inconsistent platform vs UA
  const ua = navigator.userAgent;
  const plat = navigator.platform || "";
  details.platformUAMismatch = safe(() => {
    if (/Win/.test(plat) && !/Windows/.test(ua)) return true;
    if (/Mac/.test(plat) && !/Mac|iPhone|iPad/.test(ua)) return true;
    if (/Linux/.test(plat) && /Windows|Mac OS/.test(ua) && !/Android/.test(ua)) return true;
    return false;
  });
  if (details.platformUAMismatch) flags.push({ type: "warn", text: "platform/UA mismatch" });

  // hardwareConcurrency extremes
  if (navigator.hardwareConcurrency === 1) flags.push({ type: "warn", text: "concurrency=1" });
  if (navigator.deviceMemory === 0.25 || navigator.deviceMemory === 0.5)
    flags.push({ type: "warn", text: "low deviceMemory" });

  // canvas toDataURL overridden?
  details.canvasToDataURLNative = safe(() => {
    const s = HTMLCanvasElement.prototype.toDataURL.toString();
    return /\[native code\]/.test(s);
  });
  if (details.canvasToDataURLNative === false)
    flags.push({ type: "danger", text: "canvas.toDataURL patched" });

  // webgl getParameter overridden?
  details.webglGetParameterNative = safe(() => {
    const c = document.createElement("canvas");
    const gl = c.getContext("webgl");
    if (!gl) return null;
    return /\[native code\]/.test(gl.getParameter.toString());
  });
  if (details.webglGetParameterNative === false)
    flags.push({ type: "danger", text: "webgl.getParameter patched" });

  if (!flags.length) flags.push({ type: "ok", text: "no obvious lies" });

  return {
    category: "tamper",
    label: "Tamper / Automation",
    entropy: 12,
    source: "CreepJS resistance / bot surface",
    items: { ...details, flags },
  };
}

function collectIntl() {
  return {
    category: "intl",
    label: "Intl & I18n depth",
    entropy: 6,
    source: "AmIUnique-class",
    items: {
      locales: safe(() => Intl.DateTimeFormat.supportedLocalesOf(["en", "fr", "de", "ja", "zh", "ar", "ru", "es", "pt", "hi"])),
      relativeTime: safe(() => new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }).format(-1, "day")),
      listFormat: safe(() => new Intl.ListFormat(undefined, { style: "long", type: "conjunction" }).format(["a", "b", "c"])),
      pluralRules: safe(() => new Intl.PluralRules().select(1) + "/" + new Intl.PluralRules().select(2)),
      displayNames: safe(() => {
        if (!Intl.DisplayNames) return null;
        return new Intl.DisplayNames(undefined, { type: "region" }).of("US");
      }),
    },
  };
}

function collectPerformance() {
  return {
    category: "performance",
    label: "Performance / Timing",
    entropy: 4,
    source: "CreepJS-class",
    items: {
      timeOrigin: performance.timeOrigin,
      nowPrecision: safe(() => {
        const a = performance.now();
        const b = performance.now();
        return b - a;
      }),
      memory: safe(() => {
        const m = performance.memory;
        if (!m) return null;
        return {
          jsHeapSizeLimit: m.jsHeapSizeLimit,
          totalJSHeapSize: m.totalJSHeapSize,
          usedJSHeapSize: m.usedJSHeapSize,
        };
      }),
      hardwareConcurrency: navigator.hardwareConcurrency,
    },
  };
}

function collectWorkerProbe() {
  return safeAsync(async () => {
    if (!window.Worker) {
      return {
        category: "workers",
        label: "Workers",
        entropy: 4,
        source: "CreepJS / core-estimator class",
        items: { supported: false },
      };
    }
    const code = `
      self.onmessage = () => {
        const nav = {
          userAgent: navigator.userAgent,
          language: navigator.language,
          languages: navigator.languages ? [...navigator.languages] : null,
          platform: navigator.platform,
          hardwareConcurrency: navigator.hardwareConcurrency,
          deviceMemory: navigator.deviceMemory || null,
          webdriver: navigator.webdriver,
        };
        self.postMessage(nav);
      };
    `;
    const blob = new Blob([code], { type: "application/javascript" });
    const url = URL.createObjectURL(blob);
    const data = await new Promise((resolve) => {
      const w = new Worker(url);
      const t = setTimeout(() => {
        w.terminate();
        resolve({ error: "timeout" });
      }, 1000);
      w.onmessage = (e) => {
        clearTimeout(t);
        w.terminate();
        resolve(e.data);
      };
      w.postMessage(1);
    });
    URL.revokeObjectURL(url);
    const main = {
      userAgent: navigator.userAgent,
      language: navigator.language,
      platform: navigator.platform,
      hardwareConcurrency: navigator.hardwareConcurrency,
      webdriver: navigator.webdriver,
    };
    const mismatch =
      data && !data.error
        ? {
            ua: data.userAgent !== main.userAgent,
            language: data.language !== main.language,
            platform: data.platform !== main.platform,
            concurrency: data.hardwareConcurrency !== main.hardwareConcurrency,
            webdriver: data.webdriver !== main.webdriver,
          }
        : null;
    return {
      category: "workers",
      label: "Workers (consistency)",
      entropy: 6,
      source: "CreepJS / core-estimator class",
      items: {
        supported: true,
        workerNavigator: data,
        mainNavigator: main,
        mismatch,
      },
    };
  });
}

// ─── scoring ─────────────────────────────────────────────────
function computeUniqueness(categories) {
  // Entropy-weighted heuristic (client-side only; no population DB)
  let totalEntropy = 0;
  let collected = 0;
  for (const c of categories) {
    const keys = Object.keys(c.items || {}).filter((k) => c.items[k] !== null && c.items[k] !== undefined);
    if (!keys.length) continue;
    collected++;
    // discount if errors / unsupported
    const unsupported =
      c.items.supported === false ||
      c.items.available === false ||
      c.items.error;
    totalEntropy += unsupported ? c.entropy * 0.15 : c.entropy;
  }
  // map entropy ~30–140 → uniqueness 5–99
  const score = Math.max(5, Math.min(99, Math.round((totalEntropy / 140) * 100)));
  return { score, totalEntropy: Math.round(totalEntropy * 10) / 10, collected };
}

function computeTrust(tamperBlock) {
  const flags = tamperBlock?.items?.flags || [];
  let score = 100;
  for (const f of flags) {
    if (f.type === "danger") score -= 25;
    if (f.type === "warn") score -= 10;
  }
  score = Math.max(0, Math.min(100, score));
  let label = "Clean";
  if (score < 40) label = "Highly suspicious";
  else if (score < 70) label = "Anomalies detected";
  else if (score < 90) label = "Minor anomalies";
  return { score, label, flags };
}

// ─── orchestrator ────────────────────────────────────────────
async function runSuite(onProgress) {
  const steps = [
    ["Navigator", () => collectNavigator()],
    ["Client Hints", () => collectHighEntropyUA()],
    ["Screen", () => collectScreen()],
    ["Locale", () => collectTimezone()],
    ["Canvas", () => collectCanvas()],
    ["WebGL", () => collectWebGL()],
    ["Audio", () => collectAudio()],
    ["Fonts", () => collectFonts()],
    ["Storage", async () => collectStorageEstimate(collectStorage())],
    ["JS Engine", () => collectMath()],
    ["DOMRect", () => collectDomRect()],
    ["CSS", () => collectCssSystem()],
    ["Voices", () => collectVoices()],
    ["Media", () => collectMediaDevices()],
    ["Permissions", () => collectPermissions()],
    ["WebRTC", () => collectWebRTC()],
    ["Battery", () => collectBattery()],
    ["Features", () => collectFeatures()],
    ["Tamper", () => collectTamper()],
    ["Intl", () => collectIntl()],
    ["Performance", () => collectPerformance()],
    ["Workers", () => collectWorkerProbe()],
  ];

  const categories = [];
  for (let i = 0; i < steps.length; i++) {
    const [name, fn] = steps[i];
    onProgress?.((i / steps.length) * 100, name);
    const block = await fn();
    if (block) categories.push(block);
  }
  onProgress?.(100, "Hashing");

  // visitor id from high-entropy stable-ish subset
  const idPayload = {};
  for (const c of categories) {
    if (["webrtc", "battery", "permissions", "performance"].includes(c.category)) continue;
    idPayload[c.category] = c.items;
  }
  // strip previews / volatile
  if (idPayload.canvas?.preview) {
    const { preview, ...rest } = idPayload.canvas;
    idPayload.canvas = rest;
  }
  if (idPayload.webrtc) delete idPayload.webrtc;

  const visitorId = (await sha256(stableStringify(idPayload))).slice(0, 32);
  const uniqueness = computeUniqueness(categories);
  const tamper = categories.find((c) => c.category === "tamper");
  const trust = computeTrust(tamper);

  let signalCount = 0;
  for (const c of categories) signalCount += Object.keys(c.items || {}).length;

  return {
    visitorId,
    uniqueness,
    trust,
    signalCount,
    categories,
    generatedAt: new Date().toISOString(),
    userAgent: navigator.userAgent,
  };
}

// ─── UI ──────────────────────────────────────────────────────
function setProgress(pct) {
  let bar = $("#progress-bar");
  if (!bar) {
    bar = document.createElement("div");
    bar.className = "progress show";
    bar.id = "progress-bar";
    bar.innerHTML = "<i></i>";
    $(".top").after(bar);
  }
  bar.classList.add("show");
  bar.querySelector("i").style.width = `${pct}%`;
  if (pct >= 100) setTimeout(() => bar.classList.remove("show"), 400);
}

function formatValue(v) {
  if (v === null || v === undefined) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return String(v);
  if (typeof v === "string") return v;
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

function render(report) {
  state.report = report;
  $("#visitor-id").textContent = report.visitorId;
  $("#run-meta").textContent = `Generated ${new Date(report.generatedAt).toLocaleString()} · ${report.signalCount} signals`;
  $("#uniq-score").textContent = report.uniqueness.score;
  $("#uniq-label").textContent = `~${report.uniqueness.totalEntropy} bits weighted · ${report.uniqueness.collected} categories`;
  const ring = $("#score-ring");
  const offset = 327 - (327 * report.uniqueness.score) / 100;
  ring.style.strokeDashoffset = String(offset);
  ring.style.stroke =
    report.uniqueness.score > 75 ? "var(--danger)" : report.uniqueness.score > 50 ? "var(--warn)" : "var(--ok)";

  $("#trust-score").textContent = `${report.trust.score}/100`;
  $("#trust-label").textContent = report.trust.label;
  const flagsEl = $("#trust-flags");
  flagsEl.innerHTML = "";
  for (const f of report.trust.flags) {
    const li = document.createElement("li");
    li.className = f.type;
    li.textContent = f.text;
    flagsEl.appendChild(li);
  }

  $("#signal-count").textContent = String(report.signalCount);
  $("#category-count").textContent = `${report.categories.length} categories`;

  // tabs
  const tabs = $("#tabs");
  tabs.innerHTML = "";
  const allBtn = document.createElement("button");
  allBtn.className = "tab active";
  allBtn.dataset.tab = "all";
  allBtn.innerHTML = `All <span class="count">${report.categories.length}</span>`;
  tabs.appendChild(allBtn);
  for (const c of report.categories) {
    const b = document.createElement("button");
    b.className = "tab";
    b.dataset.tab = c.category;
    const n = Object.keys(c.items || {}).length;
    b.innerHTML = `${c.label} <span class="count">${n}</span>`;
    tabs.appendChild(b);
  }
  tabs.onclick = (e) => {
    const t = e.target.closest(".tab");
    if (!t) return;
    state.activeTab = t.dataset.tab;
    $$(".tab").forEach((x) => x.classList.toggle("active", x === t));
    renderCategories(report);
  };

  renderCategories(report);
  $("#btn-export").disabled = false;
  $("#btn-copy").disabled = false;
}

function renderCategories(report) {
  const root = $("#report");
  root.innerHTML = "";
  const list =
    state.activeTab === "all"
      ? report.categories
      : report.categories.filter((c) => c.category === state.activeTab);

  for (const c of list) {
    const cat = document.createElement("section");
    cat.className = "cat";
    cat.innerHTML = `
      <div class="cat-head">
        <h2>${escapeHtml(c.label)}</h2>
        <div>
          <span class="entropy">~${c.entropy} bits</span>
          <span class="badge"> · ${escapeHtml(c.source)}</span>
        </div>
      </div>
      <div class="grid"></div>
    `;
    const grid = cat.querySelector(".grid");
    for (const [k, v] of Object.entries(c.items || {})) {
      if (k === "flags") continue;
      const item = document.createElement("div");
      item.className = "item";
      const isLong =
        (typeof v === "string" && v.length > 80) ||
        (typeof v === "object" && v !== null);
      const isPreview = k === "preview" && typeof v === "string" && v.startsWith("data:image");
      item.innerHTML = `
        <div class="k"><span>${escapeHtml(k)}</span><span class="src">${escapeHtml(c.category)}</span></div>
        <div class="v ${isLong ? "long" : ""}"></div>
      `;
      const val = item.querySelector(".v");
      if (isPreview) {
        const img = document.createElement("img");
        img.className = "canvas-preview";
        img.src = v;
        img.alt = "canvas preview";
        val.appendChild(img);
      } else {
        val.textContent = formatValue(v);
      }
      grid.appendChild(item);
    }
    root.appendChild(cat);
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ─── events ──────────────────────────────────────────────────
$("#btn-run").addEventListener("click", async () => {
  const btn = $("#btn-run");
  btn.disabled = true;
  btn.textContent = "Running…";
  document.body.classList.add("running");
  try {
    const report = await runSuite((pct, name) => {
      setProgress(pct);
      $("#run-meta").textContent = `Collecting: ${name}…`;
    });
    render(report);
    window.__ULTIMATE_FP__ = report;
  } catch (e) {
    $("#run-meta").textContent = `Error: ${e.message || e}`;
    console.error(e);
  } finally {
    btn.disabled = false;
    btn.textContent = "Run full suite";
    document.body.classList.remove("running");
  }
});

$("#btn-export").addEventListener("click", () => {
  if (!state.report) return;
  const blob = new Blob([JSON.stringify(state.report, null, 2)], {
    type: "application/json",
  });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `fingerprint-${state.report.visitorId.slice(0, 8)}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
});

$("#btn-copy").addEventListener("click", async () => {
  if (!state.report) return;
  await navigator.clipboard.writeText(state.report.visitorId);
  const b = $("#btn-copy");
  const t = b.textContent;
  b.textContent = "Copied";
  setTimeout(() => (b.textContent = t), 1200);
});

// auto-run
setTimeout(() => $("#btn-run").click(), 200);
