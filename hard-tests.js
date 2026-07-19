/**
 * HARD TESTS — high-signal detection (not noise)
 * Techniques inspired by CreepJS lies/resistance/engine/headless,
 * bot.incolumitas, sannysoft, pixelscan-class inconsistency checks.
 * Pure client-side. Each test targets a real spoof/automation leak.
 */

function hSafe(fn, fallback = null) {
  try {
    return fn();
  } catch (e) {
    return fallback ?? { error: String(e?.message || e) };
  }
}

async function hSafeAsync(fn, fallback = null) {
  try {
    return await fn();
  } catch (e) {
    return fallback ?? { error: String(e?.message || e) };
  }
}

async function hSha(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(str)));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function isNative(fn) {
  if (typeof fn !== "function") return false;
  try {
    const s = Function.prototype.toString.call(fn);
    return /\[native code\]/.test(s);
  } catch {
    return false;
  }
}

/** Never invoke prototype getters (Firefox throws TypeError on Navigator.prototype.userAgent). */
function descriptorLie(obj, prop) {
  try {
    const d = Object.getOwnPropertyDescriptor(obj, prop);
    if (!d) return { exists: false };
    const out = {
      exists: true,
      configurable: d.configurable,
      enumerable: d.enumerable,
      writable: d.writable ?? null,
      hasGetter: typeof d.get === "function",
      hasSetter: typeof d.set === "function",
      getterNative: typeof d.get === "function" ? isNative(d.get) : null,
      valueNative: typeof d.value === "function" ? isNative(d.value) : null,
      valueType: d.value !== undefined ? typeof d.value : null,
    };
    return out;
  } catch (e) {
    return { error: String(e.message || e) };
  }
}

function methodNativeOn(instance, prop) {
  try {
    const fn = instance?.[prop];
    if (typeof fn !== "function") return null;
    return isNative(fn);
  } catch {
    return null;
  }
}

// ─── 1. Prototype / API lies (CreepJS-class) ─────────────────
export function collectPrototypeLies() {
  const flags = [];
  // Only inspect descriptors on prototypes — never call getters on the prototype itself.
  const apis = [
    ["Navigator", Navigator?.prototype, ["userAgent", "platform", "languages", "hardwareConcurrency", "deviceMemory", "webdriver", "plugins", "mimeTypes", "maxTouchPoints", "vendor", "language"]],
    ["Screen", Screen?.prototype, ["width", "height", "availWidth", "availHeight", "colorDepth", "pixelDepth"]],
    ["HTMLCanvasElement", HTMLCanvasElement?.prototype, ["toDataURL", "toBlob", "getContext"]],
    ["CanvasRenderingContext2D", CanvasRenderingContext2D?.prototype, ["getImageData", "fillText", "measureText"]],
    ["WebGLRenderingContext", window.WebGLRenderingContext?.prototype, ["getParameter", "getExtension", "getSupportedExtensions"]],
    ["OfflineAudioContext", (window.OfflineAudioContext || window.webkitOfflineAudioContext)?.prototype, ["startRendering"]],
    ["Permissions", window.Permissions?.prototype, ["query"]],
    ["PluginArray", window.PluginArray?.prototype, ["item", "namedItem", "refresh"]],
    ["Function", Function.prototype, ["toString", "toLocaleString"]],
  ];

  const report = {};
  let patched = 0;
  for (const [name, proto, props] of apis) {
    if (!proto) {
      report[name] = { available: false };
      continue;
    }
    const detail = {};
    for (const p of props) {
      const d = descriptorLie(proto, p);
      detail[p] = d;
      if (d.valueNative === false) {
        patched++;
        flags.push({ type: "danger", text: `${name}.${p} not native` });
      }
      if (d.hasGetter && d.getterNative === false) {
        patched++;
        flags.push({ type: "danger", text: `${name}.${p} getter patched` });
      }
    }
    report[name] = detail;
  }

  // Instance-bound method native checks (safe: real instances, not prototypes)
  report.instanceMethods = hSafe(() => {
    const c = document.createElement("canvas");
    const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
    return {
      canvasToDataURL: methodNativeOn(c, "toDataURL"),
      canvasGetContext: methodNativeOn(c, "getContext"),
      webglGetParameter: gl ? methodNativeOn(gl, "getParameter") : null,
      functionToString: isNative(Function.prototype.toString),
      permissionsQuery: navigator.permissions
        ? methodNativeOn(navigator.permissions, "query")
        : null,
    };
  });
  if (report.instanceMethods?.canvasToDataURL === false) {
    patched++;
    flags.push({ type: "danger", text: "canvas.toDataURL not native" });
  }
  if (report.instanceMethods?.webglGetParameter === false) {
    patched++;
    flags.push({ type: "danger", text: "webgl.getParameter not native" });
  }
  if (report.instanceMethods?.functionToString === false) {
    patched++;
    flags.push({ type: "danger", text: "Function.toString not native" });
  }

  // navigator.webdriver own vs proto
  report.webdriverOwn = Object.prototype.hasOwnProperty.call(navigator, "webdriver");
  report.webdriverValue = navigator.webdriver;
  if (navigator.webdriver === true) {
    flags.push({
      type: "danger",
      id: "webdriver_true",
      text: "webdriver=true",
      why: "navigator.webdriver is true — automation (Selenium/WebDriver) or failed antidetect hide.",
      measured: { webdriver: true, ownProperty: report.webdriverOwn },
      expected: false,
    });
  }

  // iframe contentWindow navigator vs top (isolation spoof often fails)
  report.iframeNav = hSafe(() => {
    const iframe = document.createElement("iframe");
    iframe.style.cssText = "position:absolute;width:0;height:0;border:0;left:-9999px";
    document.body.appendChild(iframe);
    try {
      const win = iframe.contentWindow;
      const nav = win?.navigator;
      if (!nav) return { error: "no iframe navigator" };
      return {
        sameUA: nav.userAgent === navigator.userAgent,
        samePlatform: nav.platform === navigator.platform,
        sameHW: nav.hardwareConcurrency === navigator.hardwareConcurrency,
        sameWebdriver: nav.webdriver === navigator.webdriver,
        iframeUA: String(nav.userAgent || "").slice(0, 80),
        iframeWebdriver: nav.webdriver,
        topUA: String(navigator.userAgent || "").slice(0, 80),
        topWebdriver: navigator.webdriver,
      };
    } finally {
      iframe.remove();
    }
  });
  if (report.iframeNav && report.iframeNav.sameUA === false) {
    flags.push({
      type: "danger",
      id: "iframe_ua",
      text: "iframe UA ≠ top UA",
      why: "User-Agent differs between top window and about:blank iframe — incomplete multi-realm spoof (common antidetect leak).",
      measured: report.iframeNav,
      expected: "identical userAgent in iframe and top",
    });
  }
  if (report.iframeNav && report.iframeNav.sameWebdriver === false) {
    flags.push({
      type: "danger",
      id: "iframe_webdriver",
      text: "iframe webdriver ≠ top",
      why: "webdriver flag differs across iframe vs top — spoof applied only to one realm.",
      measured: {
        iframe: report.iframeNav.iframeWebdriver,
        top: report.iframeNav.topWebdriver,
      },
      expected: "identical webdriver in both realms",
    });
  }

  // Proxy detection via instanceof / Reflect
  report.navigatorProxy = hSafe(() => {
    const keys = Reflect.ownKeys(navigator);
    return {
      ownKeysCount: keys.length,
      hasProxySymbol: keys.some((k) => String(k).includes("Proxy")),
    };
  });

  if (!flags.length) flags.push({ type: "ok", text: "no prototype lies detected" });

  return {
    category: "prototypeLies",
    label: "Prototype Lies",
    entropy: 14,
    source: "CreepJS lies engine",
    items: { patchedCount: patched, ...report, flags },
  };
}

// ─── 2. JS engine via error stacks + typeof quirks ───────────
export function collectEngineFingerprint() {
  const flags = [];
  const errors = {};
  const probes = [
    () => null.x,
    () => undefined.x,
    () => (1).x(),
    () => new Array(-1),
    () => decodeURIComponent("%"),
    () => new Function("}{"),
    () => Object.create(null).x.y,
    () => { "use strict"; return arguments.callee; },
  ];
  for (let i = 0; i < probes.length; i++) {
    try {
      probes[i]();
      errors[`p${i}`] = "no-throw";
    } catch (e) {
      errors[`p${i}`] = {
        name: e.name,
        message: String(e.message || "").slice(0, 120),
        stackHead: String(e.stack || "")
          .split("\n")
          .slice(0, 3)
          .map((l) => l.trim())
          .join(" | ")
          .slice(0, 200),
      };
    }
  }

  // Engine tells from error format
  const sample = errors.p0?.stackHead || "";
  let engineGuess = "unknown";
  if (/@|\[native code\]|webkit/i.test(sample) || /safari/i.test(navigator.userAgent)) {
    /* continue */
  }
  if (/\.js:\d+:\d+/.test(sample) && !/eval/.test(sample)) engineGuess = "v8-or-sm";
  if (/@http|@file|@blob/.test(sample)) engineGuess = "spidermonkey-like";
  if (/global code|eval code/.test(sample)) engineGuess = "jsc-like";
  if (/TypeError: Cannot read prop/i.test(errors.p0?.message || "")) engineGuess = "v8";
  if (/TypeError: null is not an object/i.test(errors.p0?.message || "")) engineGuess = "jsc";
  if (/TypeError: .* is null/i.test(errors.p0?.message || "") && /@/.test(sample))
    engineGuess = "spidermonkey";

  // installTrigger / chrome / safari tells
  const runtime = {
    chrome: !!window.chrome,
    chromeLoadTimes: typeof window.chrome?.loadTimes === "function",
    chromeCsi: typeof window.chrome?.csi === "function",
    chromeApp: !!window.chrome?.app,
    chromeRuntime: !!window.chrome?.runtime,
    InstallTrigger: typeof window.InstallTrigger !== "undefined",
    safari: !!(window.safari && window.safari.pushNotification),
    opera: !!(window.opr && window.opr.addons) || !!window.opera,
    brave: !!(navigator.brave && typeof navigator.brave.isBrave === "function"),
  };

  // UA vs engine mismatch
  const ua = navigator.userAgent;
  const claimsChrome = /Chrome\//.test(ua) && !/Edg\//.test(ua);
  const claimsFirefox = /Firefox\//.test(ua);
  const claimsSafari = /Safari\//.test(ua) && !/Chrome\//.test(ua);
  if (claimsFirefox && runtime.chrome) flags.push({ type: "danger", text: "FF UA + chrome object" });
  if (claimsSafari && runtime.chrome) flags.push({ type: "danger", text: "Safari UA + chrome object" });
  if (claimsChrome && runtime.InstallTrigger) flags.push({ type: "danger", text: "Chrome UA + InstallTrigger" });
  if (claimsChrome && !runtime.chrome && !/Android|Mobile/.test(ua))
    flags.push({ type: "warn", text: "Chrome UA without chrome object" });

  // eval.toString length (engine)
  const evalLen = hSafe(() => eval.toString().length);
  const functionLen = hSafe(() => Function.prototype.toString.call(Function.prototype.toString).length);

  return {
    category: "engine",
    label: "JS Engine / Errors",
    entropy: 10,
    source: "CreepJS engine + console errors",
    items: {
      engineGuess,
      errorProbes: errors,
      runtime,
      evalToStringLength: evalLen,
      functionToStringLength: functionLen,
      flags,
    },
  };
}

// ─── 3. Headless / automation deep ───────────────────────────
export function collectHeadless() {
  const flags = [];
  const items = {};

  items.webdriver = navigator.webdriver;
  items.userAgentHeadless = /HeadlessChrome|PhantomJS|Electron/i.test(navigator.userAgent);
  if (items.userAgentHeadless) flags.push({ type: "danger", text: "headless UA token" });

  // window dimensions (classic headless)
  items.outerInner = {
    outerWidth: window.outerWidth,
    outerHeight: window.outerHeight,
    innerWidth: window.innerWidth,
    innerHeight: window.innerHeight,
    screenX: window.screenX,
    screenY: window.screenY,
  };
  if (window.outerWidth === 0 && window.outerHeight === 0)
    flags.push({ type: "danger", text: "outer 0×0" });
  if (window.outerHeight - window.innerHeight < 0)
    flags.push({ type: "warn", text: "outer < inner height" });

  // missing chrome APIs on chrome-like
  const isChromeUA = /Chrome\//.test(navigator.userAgent) && !/Edg\//.test(navigator.userAgent);
  items.chromePayload = {
    chrome: !!window.chrome,
    runtime: !!window.chrome?.runtime,
    app: !!window.chrome?.app,
    csi: typeof window.chrome?.csi,
    loadTimes: typeof window.chrome?.loadTimes,
  };
  if (isChromeUA && !window.chrome) flags.push({ type: "danger", text: "Chrome UA, no window.chrome" });

  // plugins: headless often empty
  items.pluginsLength = navigator.plugins?.length ?? 0;
  items.mimeTypesLength = navigator.mimeTypes?.length ?? 0;
  if (isChromeUA && items.pluginsLength === 0 && !/Mobile|Android|iPhone/.test(navigator.userAgent))
    flags.push({ type: "warn", text: "desktop Chrome empty plugins" });

  // Notification + permissions inconsistency (puppeteer classic)
  items.notificationPermission =
    typeof Notification !== "undefined" ? Notification.permission : "n/a";
  items.permissionQuery = null; // filled async below via separate call

  // connection.rtt 0 sometimes in automation
  const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
  items.connectionRtt = conn?.rtt ?? null;
  items.connectionDownlink = conn?.downlink ?? null;

  // document element attributes
  items.htmlWebdriver = document.documentElement.getAttribute("webdriver");
  items.htmlSelenium = document.documentElement.getAttribute("selenium");
  items.htmlDriver = document.documentElement.getAttribute("driver");
  if (items.htmlWebdriver) flags.push({ type: "danger", text: "html[webdriver]" });

  // CDP leftovers
  const cdc = Object.getOwnPropertyNames(window).filter((k) =>
    /^(cdc_|\$cdc_|\$chrome_|__webdriver|__driver_evaluate|__selenium|__fxdriver|__lastWatir|domAutomation)/i.test(
      k
    )
  );
  items.cdcKeys = cdc;
  if (cdc.length) flags.push({ type: "danger", text: `CDP keys: ${cdc.slice(0, 3).join(",")}` });

  // document.$cdc_asdjflasutopfhvcZLmcfl_
  items.documentCdc = Object.getOwnPropertyNames(document).filter((k) =>
    /cdc_|\$chrome_|__selenium|__webdriver/i.test(k)
  );
  if (items.documentCdc.length) flags.push({ type: "danger", text: "document automation props" });

  // Playwright/Puppeteer init scripts sometimes leave Error.stackTraceLimit oddities
  items.stackTraceLimit = Error.stackTraceLimit ?? null;

  // SharedArrayBuffer / crossOriginIsolated (env signal)
  items.sharedArrayBuffer = typeof SharedArrayBuffer !== "undefined";
  items.crossOriginIsolated = window.crossOriginIsolated ?? null;

  // devtools protocol Runtime.enable side-effect: often creates strong references — hard to detect pure JS
  // Use console.debug toString
  items.consoleDebugNative = isNative(console.debug);
  items.consoleLogNative = isNative(console.log);

  // No mouse movement ever — can't know; skip behavioral

  // Permissions API vs Notification (async helper used later)
  items._needsAsyncPermissions = true;

  if (!flags.length) flags.push({ type: "ok", text: "no headless markers" });
  items.flags = flags;

  return {
    category: "headless",
    label: "Headless / Automation",
    entropy: 16,
    source: "CreepJS headless + sannysoft-class",
    items,
  };
}

export async function enrichHeadlessPermissions(block) {
  if (!block?.items) return block;
  const flags = block.items.flags.filter((f) => f.type !== "ok");
  if (navigator.permissions?.query && typeof Notification !== "undefined") {
    try {
      const st = await navigator.permissions.query({ name: "notifications" });
      block.items.permissionQueryNotifications = st.state;
      // Classic bot: Notification.permission "denied" but permissions.query "prompt" (or reverse)
      if (
        Notification.permission === "denied" &&
        st.state === "prompt"
      ) {
        flags.push({ type: "danger", text: "Notification/permissions mismatch" });
      }
      if (
        Notification.permission === "default" &&
        st.state === "denied"
      ) {
        flags.push({ type: "warn", text: "permissions denied vs default Notification" });
      }
    } catch (e) {
      block.items.permissionQueryNotifications = String(e.message || e);
    }
  }
  // WebDriver BiDi / selenium atom
  block.items.callPhantom = !!(window.callPhantom || window._phantom);
  if (block.items.callPhantom) flags.push({ type: "danger", text: "phantom" });
  block.items.domAutomation = !!(window.domAutomation || window.domAutomationController);
  if (block.items.domAutomation) flags.push({ type: "danger", text: "domAutomation" });

  if (!flags.length) flags.push({ type: "ok", text: "no headless markers" });
  block.items.flags = flags;
  return block;
}

// ─── 4. Canvas stability (noise spoof detection) ─────────────
export async function collectCanvasHard() {
  const flags = [];
  const canvas = document.createElement("canvas");
  canvas.width = 240;
  canvas.height = 60;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) {
    return {
      category: "canvasHard",
      label: "Canvas Hard (stability)",
      entropy: 12,
      source: "noise-detection / Morellian-class",
      items: { supported: false },
    };
  }

  function paint(c) {
    c.fillStyle = "#f0f";
    c.fillRect(0, 0, 240, 60);
    c.fillStyle = "#0ff";
    c.font = "18px Arial";
    c.fillText("Stabilityφ中😀", 8, 28);
    c.strokeStyle = "rgba(0,0,0,0.4)";
    c.beginPath();
    c.arc(180, 30, 20, 0, Math.PI * 2);
    c.stroke();
    c.globalCompositeOperation = "multiply";
    c.fillStyle = "#ff0";
    c.fillRect(100, 10, 40, 40);
  }

  paint(ctx);
  const a = canvas.toDataURL();
  const imgA = ctx.getImageData(0, 0, 240, 60);

  // second paint same canvas
  ctx.clearRect(0, 0, 240, 60);
  ctx.globalCompositeOperation = "source-over";
  paint(ctx);
  const b = canvas.toDataURL();
  const imgB = ctx.getImageData(0, 0, 240, 60);

  let pixelDiff = 0;
  for (let i = 0; i < imgA.data.length; i++) {
    if (imgA.data[i] !== imgB.data[i]) pixelDiff++;
  }

  // third: OffscreenCanvas if available
  let offscreenHash = null;
  let offscreenMatch = null;
  if (typeof OffscreenCanvas !== "undefined") {
    try {
      const oc = new OffscreenCanvas(240, 60);
      const octx = oc.getContext("2d");
      paint(octx);
      const blob = await oc.convertToBlob();
      const ab = await blob.arrayBuffer();
      offscreenHash = (await hSha(String([...new Uint8Array(ab).slice(0, 256)]))).slice(0, 24);
      // compare to main via draw
      const c2 = document.createElement("canvas");
      c2.width = 240;
      c2.height = 60;
      const c2x = c2.getContext("2d");
      paint(c2x);
      offscreenMatch = c2.toDataURL() === a || c2.toDataURL() === b;
    } catch (e) {
      offscreenHash = { error: String(e.message || e) };
    }
  }

  const stable = a === b && pixelDiff === 0;
  if (!stable) flags.push({ type: "danger", text: "canvas unstable (noise injected?)" });
  if (pixelDiff > 0 && pixelDiff < 50)
    flags.push({ type: "warn", text: `canvas micro-noise diffs=${pixelDiff}` });

  // toBlob vs toDataURL consistency
  const blobUrl = await hSafeAsync(
    () =>
      new Promise((resolve) => {
        canvas.toBlob((blob) => {
          if (!blob) return resolve(null);
          const r = new FileReader();
          r.onload = () => resolve(r.result);
          r.readAsDataURL(blob);
        }, "image/png");
      })
  );

  const hashA = (await hSha(a)).slice(0, 24);
  const hashB = (await hSha(b)).slice(0, 24);

  if (!flags.length) flags.push({ type: "ok", text: "canvas stable" });

  return {
    category: "canvasHard",
    label: "Canvas Hard (stability)",
    entropy: 14,
    source: "noise-detection / Morellian-class",
    items: {
      supported: true,
      stable,
      pixelDiff,
      hashA,
      hashB,
      sameDataURL: a === b,
      offscreenHash,
      offscreenMatch,
      toBlobLen: typeof blobUrl === "string" ? blobUrl.length : null,
      flags,
    },
  };
}

// ─── 5. WebGL hard: consistency + extension profile ──────────
export async function collectWebGLHard() {
  const flags = [];
  const canvas = document.createElement("canvas");
  const gl =
    canvas.getContext("webgl2", { failIfMajorPerformanceCaveat: true }) ||
    canvas.getContext("webgl", { failIfMajorPerformanceCaveat: true }) ||
    canvas.getContext("webgl");
  if (!gl) {
    return {
      category: "webglHard",
      label: "WebGL Hard",
      entropy: 12,
      source: "CreepJS GPU / pixelscan-class",
      items: { supported: false, flags: [{ type: "warn", text: "WebGL unavailable" }] },
    };
  }

  const dbg = hSafe(() => gl.getExtension("WEBGL_debug_renderer_info"));
  const vendor = hSafe(() => gl.getParameter(gl.VENDOR));
  const renderer = hSafe(() => gl.getParameter(gl.RENDERER));
  const unmaskedVendor = dbg
    ? hSafe(() => gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL))
    : null;
  const unmaskedRenderer = dbg
    ? hSafe(() => gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL))
    : renderer;

  // Software renderer detection
  const soft =
    /SwiftShader|llvmpipe|Software|Microsoft Basic Render|SoftGL|Google SwiftShader/i.test(
      String(unmaskedRenderer || renderer)
    );
  if (soft) flags.push({ type: "danger", text: "software WebGL renderer" });

  // UA OS vs GPU string
  const ua = navigator.userAgent;
  const plat = navigator.platform || "";
  const gpu = `${unmaskedVendor || ""} ${unmaskedRenderer || ""}`;
  if (/Win/.test(plat) && /Apple M[0-9]|Intel Iris|Apple GPU/i.test(gpu) && !/Parallels|VMware/i.test(gpu))
    flags.push({ type: "warn", text: "Windows host + Apple/Mac GPU string" });
  if (/Mac/.test(plat) && /Direct3D|ANGLE \(NVIDIA|ANGLE \(AMD/i.test(gpu) && !/Apple/i.test(gpu))
    flags.push({ type: "warn", text: "Mac platform + ANGLE/D3D GPU" });
  if (/Linux/.test(plat) && /Direct3D/i.test(gpu))
    flags.push({ type: "warn", text: "Linux + Direct3D" });

  // failIfMajorPerformanceCaveat context vs normal
  const glSoft = document.createElement("canvas").getContext("webgl", {
    failIfMajorPerformanceCaveat: false,
  });
  const softRenderer = glSoft
    ? (() => {
        const d = glSoft.getExtension("WEBGL_debug_renderer_info");
        return d ? glSoft.getParameter(d.UNMASKED_RENDERER_WEBGL) : glSoft.getParameter(glSoft.RENDERER);
      })()
    : null;

  // Extension set hash (high entropy, hard to fake consistently with noise)
  const exts = (gl.getSupportedExtensions() || []).slice().sort();
  const extHash = (await hSha(exts.join(","))).slice(0, 24);

  // Draw buffer + readPixels fingerprint (harder than params alone)
  const pixels = hSafe(() => {
    gl.clearColor(0.12, 0.34, 0.56, 1);
    gl.clear(gl.COLOR_BUFFER_BIT);
    const p = new Uint8Array(4);
    gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, p);
    return Array.from(p);
  });

  // WebGL2 specific
  const is2 = typeof WebGL2RenderingContext !== "undefined" && gl instanceof WebGL2RenderingContext;
  let webgl2Params = null;
  if (is2) {
    webgl2Params = hSafe(() => ({
      MAX_3D_TEXTURE_SIZE: gl.getParameter(gl.MAX_3D_TEXTURE_SIZE),
      MAX_ARRAY_TEXTURE_LAYERS: gl.getParameter(gl.MAX_ARRAY_TEXTURE_LAYERS),
      MAX_SAMPLES: gl.getParameter(gl.MAX_SAMPLES),
      MAX_UNIFORM_BUFFER_BINDINGS: gl.getParameter(gl.MAX_UNIFORM_BUFFER_BINDINGS),
    }));
  }

  // getParameter override double-check via iframe
  const iframeParamNative = hSafe(() => {
    const iframe = document.createElement("iframe");
    iframe.style.cssText = "display:none";
    document.body.appendChild(iframe);
    const igl = iframe.contentWindow.document.createElement("canvas").getContext("webgl");
    const native = igl ? isNative(igl.getParameter) : null;
    const sameRenderer = (() => {
      if (!igl || !dbg) return null;
      const id = igl.getExtension("WEBGL_debug_renderer_info");
      if (!id) return null;
      return igl.getParameter(id.UNMASKED_RENDERER_WEBGL) === unmaskedRenderer;
    })();
    document.body.removeChild(iframe);
    return { native, sameRenderer };
  });
  if (iframeParamNative?.sameRenderer === false)
    flags.push({ type: "danger", text: "iframe WebGL renderer ≠ top" });

  if (!flags.length) flags.push({ type: "ok", text: "WebGL consistent" });

  return {
    category: "webglHard",
    label: "WebGL Hard",
    entropy: 16,
    source: "CreepJS GPU / pixelscan-class",
    items: {
      supported: true,
      isWebGL2: is2,
      vendor,
      renderer,
      unmaskedVendor,
      unmaskedRenderer,
      softwareRenderer: soft,
      softContextRenderer: softRenderer,
      extensionsCount: exts.length,
      extensionsHash: extHash,
      clearPixel: pixels,
      webgl2Params,
      iframeCheck: iframeParamNative,
      ua,
      platform: plat,
      flags,
    },
  };
}

// ─── 6. Screen / hardware consistency ────────────────────────
export function collectConsistency() {
  const flags = [];
  const s = screen;
  const items = {
    screen: { w: s.width, h: s.height, aw: s.availWidth, ah: s.availHeight },
    window: {
      iw: window.innerWidth,
      ih: window.innerHeight,
      ow: window.outerWidth,
      oh: window.outerHeight,
      dpr: devicePixelRatio,
    },
    hw: {
      concurrency: navigator.hardwareConcurrency,
      memory: navigator.deviceMemory ?? null,
      touch: navigator.maxTouchPoints,
      platform: navigator.platform,
      ua: navigator.userAgent,
    },
  };

  // avail > full is impossible
  if (s.availWidth > s.width || s.availHeight > s.height)
    flags.push({ type: "danger", text: "avail > screen size" });
  // width/height 0
  if (!s.width || !s.height) flags.push({ type: "danger", text: "screen 0 size" });
  // mobile UA with no touch
  if (/Android|iPhone|iPad/.test(navigator.userAgent) && navigator.maxTouchPoints === 0)
    flags.push({ type: "danger", text: "mobile UA, maxTouchPoints=0" });
  // desktop UA with many touch points only warn if extreme
  if (!/Android|iPhone|iPad|Mobile/.test(navigator.userAgent) && navigator.maxTouchPoints > 10)
    flags.push({ type: "warn", text: "desktop UA, touchPoints>10" });

  // deviceMemory vs concurrency rough sanity (very rough)
  const mem = navigator.deviceMemory;
  const hc = navigator.hardwareConcurrency;
  if (mem != null && hc != null) {
    if (mem <= 1 && hc >= 16) flags.push({ type: "warn", text: "1GB RAM claim + 16+ cores" });
    if (mem >= 8 && hc === 1) flags.push({ type: "warn", text: "8GB+ RAM + 1 core" });
  }

  // timezone vs language rough (not definitive)
  const tz = hSafe(() => Intl.DateTimeFormat().resolvedOptions().timeZone);
  const lang = navigator.language || "";
  items.timezone = tz;
  items.language = lang;
  // offset vs timezone name
  items.tzOffset = new Date().getTimezoneOffset();

  // client hints platform vs navigator.platform
  const uad = navigator.userAgentData;
  if (uad?.platform) {
    items.uaDataPlatform = uad.platform;
    const p = (uad.platform || "").toLowerCase();
    const np = (navigator.platform || "").toLowerCase();
    if (p.includes("windows") && !np.includes("win"))
      flags.push({ type: "danger", text: "UA-CH Windows ≠ navigator.platform" });
    if (p.includes("mac") && !np.includes("mac"))
      flags.push({ type: "danger", text: "UA-CH macOS ≠ navigator.platform" });
    if (p.includes("linux") && np.includes("win"))
      flags.push({ type: "danger", text: "UA-CH Linux + Win platform" });
  }

  // color depth sanity
  if (![1, 4, 8, 15, 16, 24, 30, 32, 48].includes(s.colorDepth))
    flags.push({ type: "warn", text: `unusual colorDepth=${s.colorDepth}` });

  if (!flags.length) flags.push({ type: "ok", text: "hardware/screen consistent" });
  items.flags = flags;

  return {
    category: "consistency",
    label: "Cross-Signal Consistency",
    entropy: 12,
    source: "pixelscan / bot.incolumitas-class",
    items,
  };
}

// ─── 7. SVG + emoji geometry (CreepJS) ───────────────────────
export async function collectSvgEmoji() {
  const flags = [];
  // SVG rect
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("width", "200");
  svg.setAttribute("height", "50");
  svg.style.cssText = "position:absolute;left:-9999px";
  const text = document.createElementNS(ns, "text");
  text.setAttribute("x", "10");
  text.setAttribute("y", "30");
  text.setAttribute("font-size", "20");
  text.setAttribute("font-family", "Arial");
  text.textContent = "mmmmmmmmmmlli φ 😀";
  svg.appendChild(text);
  document.body.appendChild(svg);
  const bbox = text.getBBox?.() || { width: 0, height: 0, x: 0, y: 0 };
  const svgRect = svg.getBoundingClientRect();
  document.body.removeChild(svg);

  // Emoji DomRect
  const span = document.createElement("span");
  span.style.cssText =
    "position:absolute;left:-9999px;font-size:48px;font-family:serif;line-height:normal";
  span.textContent = "👾👨‍💻🇺🇸";
  document.body.appendChild(span);
  const er = span.getBoundingClientRect();
  document.body.removeChild(span);

  // Canvas emoji pixels
  const c = document.createElement("canvas");
  c.width = 64;
  c.height = 64;
  const cx = c.getContext("2d");
  cx.font = "48px serif";
  cx.fillText("😀", 4, 48);
  const emojiData = c.toDataURL();
  const emojiHash = (await hSha(emojiData)).slice(0, 24);

  // CJK measure
  cx.clearRect(0, 0, 64, 64);
  cx.font = "32px Arial";
  const cjk = cx.measureText("永骨中文測試");
  const arabic = cx.measureText("مرحبا بالعالم");

  return {
    category: "svgEmoji",
    label: "SVG / Emoji Geometry",
    entropy: 12,
    source: "CreepJS DomRect / emoji",
    items: {
      svgBBox: { w: bbox.width, h: bbox.height, x: bbox.x, y: bbox.y },
      svgRect: { w: svgRect.width, h: svgRect.height },
      emojiRect: { w: er.width, h: er.height },
      emojiHash,
      cjkWidth: cjk.width,
      arabicWidth: arabic.width,
      flags,
    },
  };
}

// ─── 8. Audio hard (dual stack) ──────────────────────────────
export async function collectAudioHard() {
  const flags = [];
  const OfflineCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
  if (!OfflineCtx) {
    return {
      category: "audioHard",
      label: "Audio Hard",
      entropy: 10,
      source: "FingerprintJS / CreepJS audio",
      items: { supported: false },
    };
  }

  async function render(seedFreq) {
    const ctx = new OfflineCtx(1, 5000, 44100);
    const osc = ctx.createOscillator();
    osc.type = "triangle";
    osc.frequency.value = seedFreq;
    const comp = ctx.createDynamicsCompressor();
    comp.threshold.setValueAtTime(-50, ctx.currentTime);
    comp.knee.setValueAtTime(40, ctx.currentTime);
    comp.ratio.setValueAtTime(12, ctx.currentTime);
    comp.attack.setValueAtTime(0, ctx.currentTime);
    comp.release.setValueAtTime(0.25, ctx.currentTime);
    const gain = ctx.createGain();
    gain.gain.value = 1;
    osc.connect(comp);
    comp.connect(gain);
    gain.connect(ctx.destination);
    osc.start(0);
    const buf = await ctx.startRendering();
    const data = buf.getChannelData(0);
    let sum = 0;
    let max = 0;
    for (let i = 0; i < data.length; i++) {
      const v = Math.abs(data[i]);
      sum += v;
      if (v > max) max = v;
    }
    return { sum, max, sample: Array.from(data.slice(1000, 1016)) };
  }

  const r1 = await hSafeAsync(() => render(10000));
  const r2 = await hSafeAsync(() => render(10000));
  const r3 = await hSafeAsync(() => render(20000));

  const stable =
    r1 && r2 && Math.abs(r1.sum - r2.sum) < 1e-6;
  if (!stable && r1 && r2) flags.push({ type: "danger", text: "audio unstable (noise?)" });

  // Online AudioContext baseLatency / outputLatency
  const online = hSafe(() => {
    const ac = new (window.AudioContext || window.webkitAudioContext)();
    const info = {
      sampleRate: ac.sampleRate,
      baseLatency: ac.baseLatency ?? null,
      outputLatency: ac.outputLatency ?? null,
      state: ac.state,
      destinationChannels: ac.destination.maxChannelCount,
    };
    ac.close?.();
    return info;
  });

  const hash = r1
    ? (await hSha(JSON.stringify({ sum: r1.sum, max: r1.max, sample: r1.sample }))).slice(0, 24)
    : null;

  if (!flags.length) flags.push({ type: "ok", text: "audio stable" });

  return {
    category: "audioHard",
    label: "Audio Hard",
    entropy: 12,
    source: "FingerprintJS / CreepJS audio",
    items: {
      supported: true,
      stable,
      sum1: r1?.sum,
      sum2: r2?.sum,
      sum3: r3?.sum,
      max1: r1?.max,
      fingerprintHash: hash,
      online,
      flags,
    },
  };
}

// ─── 9. Fonts hard: metrics + emoji fonts ────────────────────
export function collectFontsHard() {
  const flags = [];
  // measure width differences for CJK / emoji base fonts
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  const samples = ["mmmmmmmmmmlli", "永", "م", "😀", "W", "@"];
  const families = [
    "monospace",
    "sans-serif",
    "serif",
    "Arial",
    "Courier New",
    "Georgia",
    "Times New Roman",
    "Segoe UI Emoji",
    "Apple Color Emoji",
    "Noto Color Emoji",
    "Segoe UI Symbol",
  ];
  const metrics = {};
  for (const f of families) {
    metrics[f] = {};
    for (const s of samples) {
      ctx.font = `48px '${f}', monospace`;
      metrics[f][s] = Math.round(ctx.measureText(s).width * 100) / 100;
    }
  }

  // document.fonts.check — antidetect/spoof often returns true for every family
  const fontsReady = !!document.fonts;
  let statusCheck = null;
  if (document.fonts?.check) {
    const fakeName = "DefinitelyNotAFont_XYZ_987_ufp";
    statusCheck = {
      arial: document.fonts.check("12px Arial"),
      fake: document.fonts.check(`12px "${fakeName}"`),
      fakeBare: document.fonts.check(`12px ${fakeName}`),
    };
    if (statusCheck.fake === true || statusCheck.fakeBare === true) {
      flags.push({
        type: "danger",
        id: "fonts_check_fake",
        text: "fonts.check accepts fake font",
        why: "FontFaceSet.check() returned true for a nonsense family. Stock browsers should return false (or only match real installed fonts). Common in antidetect font spoof layers that whitelist/always-true check().",
        measured: statusCheck,
        expected: { fake: false, fakeBare: false },
      });
    }
  }

  if (!flags.length) flags.push({ type: "ok", text: "font metrics ok" });

  return {
    category: "fontsHard",
    label: "Fonts Hard (metrics)",
    entropy: 12,
    source: "AmIUnique / CreepJS fonts",
    items: {
      metrics,
      fontsAPI: fontsReady,
      fontsCheck: statusCheck,
      flags,
    },
  };
}

// ─── 10. Timing / RFP (resistance) ───────────────────────────
export function collectTimingResistance() {
  const flags = [];
  // performance.now resolution (RFP rounds to 1ms or 16.67ms)
  const samples = [];
  let last = performance.now();
  for (let i = 0; i < 500; i++) {
    const n = performance.now();
    if (n !== last) {
      samples.push(n - last);
      last = n;
    }
  }
  const minStep = samples.length ? Math.min(...samples) : null;
  // Date.now resolution
  const dSamples = [];
  let dlast = Date.now();
  for (let i = 0; i < 200; i++) {
    const n = Date.now();
    if (n !== dlast) {
      dSamples.push(n - dlast);
      dlast = n;
    }
  }
  const dateStep = dSamples.length ? Math.min(...dSamples) : null;

  // event.timeStamp coarseness not measured here

  if (minStep != null && minStep >= 1) flags.push({ type: "warn", text: `perf.now step≥${minStep}ms (RFP?)` });
  if (minStep != null && minStep >= 16) flags.push({ type: "warn", text: "perf.now heavily rounded" });

  // worker performance.now comparison done elsewhere

  // privacy.resistFingerprinting-ish: reduced screen, etc. already elsewhere

  return {
    category: "timing",
    label: "Timing / Resistance",
    entropy: 6,
    source: "CreepJS resistance / Tor RFP-class",
    items: {
      performanceNowMinStep: minStep,
      performanceDistinctDeltas: samples.length,
      dateNowMinStep: dateStep,
      timeOrigin: performance.timeOrigin,
      flags: flags.length ? flags : [{ type: "ok", text: "fine timers" }],
    },
  };
}

// ─── 11. WebGPU ──────────────────────────────────────────────
export async function collectWebGPU() {
  const flags = [];
  if (!navigator.gpu) {
    return {
      category: "webgpu",
      label: "WebGPU",
      entropy: 8,
      source: "modern GPU surface",
      items: { supported: false },
    };
  }
  const adapter = await hSafeAsync(() => navigator.gpu.requestAdapter());
  if (!adapter) {
    return {
      category: "webgpu",
      label: "WebGPU",
      entropy: 8,
      source: "modern GPU surface",
      items: {
        supported: true,
        adapter: null,
        gpuPresent: true,
        flags: [
          {
            type: "warn",
            id: "webgpu_no_adapter",
            text: "no GPU adapter",
            why: "navigator.gpu exists but requestAdapter() returned null. Can be blocked GPU, disabled WebGPU, remote/VM, or antidetect stripping the adapter while leaving the API stub.",
            measured: { navigatorGpu: true, adapter: null },
            expected: "non-null GPUAdapter on devices with working WebGPU",
          },
        ],
      },
    };
  }
  let info = null;
  try {
    // requestAdapterInfo deprecated → info property
    info = adapter.info
      ? {
          vendor: adapter.info.vendor,
          architecture: adapter.info.architecture,
          device: adapter.info.device,
          description: adapter.info.description,
        }
      : await adapter.requestAdapterInfo?.();
  } catch {
    info = null;
  }
  const features = adapter.features ? [...adapter.features].sort() : [];
  const limits = adapter.limits
    ? {
        maxTextureDimension2D: adapter.limits.maxTextureDimension2D,
        maxBindGroups: adapter.limits.maxBindGroups,
        maxBufferSize: adapter.limits.maxBufferSize,
      }
    : null;

  if (info?.description && /software|swiftshader|llvmpipe/i.test(info.description))
    flags.push({ type: "danger", text: "WebGPU software adapter" });

  if (!flags.length) flags.push({ type: "ok", text: "WebGPU ok" });

  return {
    category: "webgpu",
    label: "WebGPU",
    entropy: 12,
    source: "modern GPU surface",
    items: {
      supported: true,
      info,
      featuresCount: features.length,
      features: features.slice(0, 40),
      limits,
      flags,
    },
  };
}

// ─── 12. CSS media deep ──────────────────────────────────────
export function collectCssMediaHard() {
  const q = (s) => !!window.matchMedia?.(s).matches;
  const items = {
    colorGamut: q("(color-gamut: rec2020)")
      ? "rec2020"
      : q("(color-gamut: p3)")
        ? "p3"
        : q("(color-gamut: srgb)")
          ? "srgb"
          : "unknown",
    prefersColorScheme: q("(prefers-color-scheme: dark)") ? "dark" : "light",
    prefersContrast: q("(prefers-contrast: more)")
      ? "more"
      : q("(prefers-contrast: less)")
        ? "less"
        : "no-preference",
    prefersReducedMotion: q("(prefers-reduced-motion: reduce)"),
    prefersReducedTransparency: q("(prefers-reduced-transparency: reduce)"),
    invertedColors: q("(inverted-colors: inverted)"),
    forcedColors: q("(forced-colors: active)"),
    hover: q("(hover: hover)") ? "hover" : q("(hover: none)") ? "none" : "?",
    anyHover: q("(any-hover: hover)") ? "hover" : "none",
    pointer: q("(pointer: fine)") ? "fine" : q("(pointer: coarse)") ? "coarse" : "none",
    anyPointer: q("(any-pointer: fine)") ? "fine" : q("(any-pointer: coarse)") ? "coarse" : "none",
    dynamicRange: q("(dynamic-range: high)") ? "high" : "standard",
    update: q("(update: fast)") ? "fast" : q("(update: slow)") ? "slow" : "?",
    monochrome: q("(monochrome)"),
    grid: q("(grid: 1)"),
  };

  const flags = [];
  // mobile UA + fine pointer only → mild
  if (/Mobile|Android|iPhone/.test(navigator.userAgent) && items.pointer === "fine" && items.hover === "hover")
    flags.push({ type: "warn", text: "mobile UA + fine pointer/hover" });

  return {
    category: "cssMedia",
    label: "CSS Media Features",
    entropy: 8,
    source: "CreepJS cssmedia",
    items: { ...items, flags: flags.length ? flags : [{ type: "ok", text: "css media ok" }] },
  };
}

// ─── 13. Keyboard layout (high entropy when available) ───────
export async function collectKeyboard() {
  if (!navigator.keyboard?.getLayoutMap) {
    return {
      category: "keyboard",
      label: "Keyboard Layout",
      entropy: 4,
      source: "Keyboard API",
      items: { supported: false },
    };
  }
  const map = await hSafeAsync(() => navigator.keyboard.getLayoutMap());
  if (!map) {
    return {
      category: "keyboard",
      label: "Keyboard Layout",
      entropy: 4,
      source: "Keyboard API",
      items: { supported: true, map: null },
    };
  }
  const keys = ["KeyQ", "KeyW", "KeyE", "KeyA", "KeyZ", "Digit1", "Digit2", "Minus", "Equal", "BracketLeft"];
  const layout = {};
  for (const k of keys) layout[k] = map.get(k);
  const hash = (await hSha(JSON.stringify(layout))).slice(0, 16);
  // AZERTY vs QWERTY
  let guess = "unknown";
  if (layout.KeyQ === "a" || layout.KeyA === "q") guess = "azerty-like";
  else if (layout.KeyQ === "q" && layout.KeyW === "w") guess = "qwerty-like";
  else if (layout.KeyY === "z" || layout.KeyZ === "y") guess = "qwertz-like";

  return {
    category: "keyboard",
    label: "Keyboard Layout",
    entropy: 8,
    source: "Keyboard API",
    items: { supported: true, layout, layoutHash: hash, guess },
  };
}

// ─── 14. Storage / quota side-channels ───────────────────────
export async function collectStorageHard() {
  const flags = [];
  const items = {
    localStorage: hSafe(() => {
      const k = "__ufp_" + Math.random();
      localStorage.setItem(k, "1");
      const ok = localStorage.getItem(k) === "1";
      localStorage.removeItem(k);
      return ok;
    }),
    sessionStorage: hSafe(() => {
      const k = "__ufp_" + Math.random();
      sessionStorage.setItem(k, "1");
      const ok = sessionStorage.getItem(k) === "1";
      sessionStorage.removeItem(k);
      return ok;
    }),
    indexedDB: !!window.indexedDB,
    caches: !!window.caches,
    cookieEnabled: navigator.cookieEnabled,
  };

  if (navigator.storage?.estimate) {
    const est = await hSafeAsync(() => navigator.storage.estimate());
    items.quota = est?.quota ?? null;
    items.usage = est?.usage ?? null;
    // Incognito often has tiny quota in Chromium (~120MB)
    if (est?.quota && est.quota < 120 * 1024 * 1024)
      flags.push({ type: "warn", text: "tiny storage quota (incognito?)" });
  }

  // open database probe
  items.idbOpen = await hSafeAsync(
    () =>
      new Promise((resolve) => {
        const req = indexedDB.open("__ufp_probe__");
        req.onerror = () => resolve(false);
        req.onsuccess = () => {
          req.result.close();
          indexedDB.deleteDatabase("__ufp_probe__");
          resolve(true);
        };
      })
  );

  return {
    category: "storageHard",
    label: "Storage Hard",
    entropy: 5,
    source: "incognito / storage side-channel",
    items: { ...items, flags: flags.length ? flags : [{ type: "ok", text: "storage ok" }] },
  };
}

// ─── 15. Intl / timezone hard ────────────────────────────────
export function collectIntlHard() {
  const flags = [];
  const resolved = Intl.DateTimeFormat().resolvedOptions();
  const offset = new Date().getTimezoneOffset();
  // sample format across locales
  const d = new Date(Date.UTC(2020, 11, 31, 23, 59, 59));
  const formats = {};
  for (const loc of ["en-US", "fr-FR", "de-DE", "ja-JP", "zh-CN", "ar-EG", "ru-RU"]) {
    formats[loc] = hSafe(() =>
      new Intl.DateTimeFormat(loc, {
        timeZone: resolved.timeZone,
        dateStyle: "full",
        timeStyle: "long",
      }).format(d)
    );
  }

  // NumberFormat currency set
  const currencies = {};
  for (const c of ["USD", "EUR", "JPY", "GBP", "CNY"]) {
    currencies[c] = hSafe(() =>
      new Intl.NumberFormat(undefined, { style: "currency", currency: c }).format(1234.5)
    );
  }

  // Collator for special chars
  const collator = hSafe(() =>
    ["ä", "a", "z", "å", "ø", "ö"].sort(new Intl.Collator(resolved.locale).compare)
  );

  // timezone validity
  if (!resolved.timeZone) flags.push({ type: "warn", text: "missing timeZone" });

  // offset must match zone roughly — use formatToParts
  const parts = hSafe(() =>
    new Intl.DateTimeFormat("en-US", {
      timeZone: resolved.timeZone,
      timeZoneName: "longOffset",
    }).formatToParts(new Date())
  );

  return {
    category: "intlHard",
    label: "Intl / Timezone Hard",
    entropy: 8,
    source: "AmIUnique / CreepJS timezone",
    items: {
      resolved,
      offsetMinutes: offset,
      formats,
      currencies,
      collator,
      offsetParts: parts,
      flags: flags.length ? flags : [{ type: "ok", text: "intl ok" }],
    },
  };
}

// ─── 16. Speech hard hash ────────────────────────────────────
export async function collectSpeechHard() {
  if (!window.speechSynthesis) {
    return {
      category: "speechHard",
      label: "Speech Hard",
      entropy: 6,
      source: "CreepJS speech",
      items: { supported: false },
    };
  }
  const voices = await new Promise((resolve) => {
    let v = speechSynthesis.getVoices();
    if (v.length) return resolve(v);
    const t = setTimeout(() => resolve(speechSynthesis.getVoices() || []), 600);
    speechSynthesis.onvoiceschanged = () => {
      clearTimeout(t);
      resolve(speechSynthesis.getVoices() || []);
    };
  });
  const slim = voices.map((x) => `${x.name}|${x.lang}|${x.localService}|${x.default}`);
  const hash = (await hSha(slim.join(";"))).slice(0, 24);
  const langs = [...new Set(voices.map((v) => v.lang))].sort();
  return {
    category: "speechHard",
    label: "Speech Hard",
    entropy: 8,
    source: "CreepJS speech",
    items: {
      supported: true,
      count: voices.length,
      langs,
      hash,
      defaults: voices.filter((v) => v.default).map((v) => v.name),
      localCount: voices.filter((v) => v.localService).length,
    },
  };
}

// ─── 17. Worker deep consistency + Math in worker ────────────
export async function collectWorkerHard() {
  if (!window.Worker) {
    return {
      category: "workerHard",
      label: "Worker Hard",
      entropy: 8,
      source: "CreepJS worker / core-estimator",
      items: { supported: false },
    };
  }
  const code = `
    self.onmessage = async () => {
      const math = {
        tan: Math.tan(-1e300),
        sin: Math.sin(1e300),
        cos: Math.cos(10.000000000123),
        expm1: Math.expm1 ? Math.expm1(1) : null,
      };
      let canvasHash = null;
      try {
        const c = new OffscreenCanvas(50, 20);
        const x = c.getContext('2d');
        x.fillStyle = '#f60';
        x.fillRect(0,0,50,20);
        x.fillStyle = '#069';
        x.font = '12px Arial';
        x.fillText('W', 2, 14);
        const b = await c.convertToBlob();
        const ab = await b.arrayBuffer();
        const u = new Uint8Array(ab);
        let s = 0;
        for (let i = 0; i < u.length; i++) s = (s + u[i] * (i+1)) >>> 0;
        canvasHash = s.toString(16);
      } catch (e) {
        canvasHash = 'err:' + e.message;
      }
      self.postMessage({
        ua: navigator.userAgent,
        platform: navigator.platform,
        lang: navigator.language,
        hw: navigator.hardwareConcurrency,
        mem: navigator.deviceMemory || null,
        webdriver: navigator.webdriver,
        math,
        canvasHash,
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      });
    };
  `;
  const url = URL.createObjectURL(new Blob([code], { type: "application/javascript" }));
  const data = await new Promise((resolve) => {
    const w = new Worker(url);
    const t = setTimeout(() => {
      w.terminate();
      resolve({ error: "timeout" });
    }, 2000);
    w.onmessage = (e) => {
      clearTimeout(t);
      w.terminate();
      resolve(e.data);
    };
    w.postMessage(1);
  });
  URL.revokeObjectURL(url);

  const flags = [];
  // Strict cross-realm compare — antidetect often patches window but not worker
  if (data && !data.error) {
    if (data.ua !== navigator.userAgent) {
      flags.push({
        type: "danger",
        id: "worker_ua",
        text: "worker UA ≠ main",
        why: "Antidetect / spoof layers often patch only the main-world navigator, not DedicatedWorkerGlobalScope.",
        measured: { worker: data.ua, main: navigator.userAgent },
        expected: "identical userAgent in worker and main",
      });
    }
    if (data.platform !== navigator.platform) {
      flags.push({
        type: "danger",
        id: "worker_platform",
        text: "worker platform ≠ main",
        why: "Platform spoof incomplete across realms (main vs worker).",
        measured: { worker: data.platform, main: navigator.platform },
        expected: "identical platform",
      });
    }
    if (data.hw !== navigator.hardwareConcurrency) {
      flags.push({
        type: "danger",
        id: "worker_hw",
        text: "worker HW concurrency ≠ main",
        why: "hardwareConcurrency spoof often misses workers.",
        measured: { worker: data.hw, main: navigator.hardwareConcurrency },
        expected: "identical hardwareConcurrency",
      });
    }
    // Strict: true vs false, and true vs undefined (incomplete hide)
    if (data.webdriver !== navigator.webdriver) {
      flags.push({
        type: "danger",
        id: "worker_webdriver",
        text: "worker webdriver ≠ main",
        why: "webdriver is inconsistent between main thread and worker. Antidetect often forces navigator.webdriver=false in page JS only; the worker still leaks the real/automation value (or the inverse).",
        measured: { worker: data.webdriver, main: navigator.webdriver },
        expected: "strictly equal in both realms (both false, both true, or both undefined)",
      });
    }
    if (data.tz !== Intl.DateTimeFormat().resolvedOptions().timeZone) {
      flags.push({
        type: "warn",
        id: "worker_tz",
        text: "worker timezone ≠ main",
        why: "Timezone spoof may only apply in the window realm.",
        measured: {
          worker: data.tz,
          main: Intl.DateTimeFormat().resolvedOptions().timeZone,
        },
        expected: "identical IANA timezone",
      });
    }
    if (data.math && data.math.tan !== Math.tan(-1e300)) {
      flags.push({
        type: "danger",
        id: "worker_math",
        text: "worker Math ≠ main engine",
        why: "Different JS engine Math results between worker and main is abnormal (or realm isolation bug).",
        measured: { workerTan: data.math.tan, mainTan: Math.tan(-1e300) },
        expected: "identical Math.tan(-1e300)",
      });
    }
  } else {
    flags.push({
      type: "warn",
      id: "worker_fail",
      text: "worker probe failed",
      why: "Worker could not run or timed out (blocked workers / CSP / broken environment).",
      measured: data,
      expected: "worker response payload",
    });
  }
  if (!flags.length) flags.push({ type: "ok", text: "worker consistent" });

  return {
    category: "workerHard",
    label: "Worker Hard",
    entropy: 10,
    source: "CreepJS worker / core-estimator",
    items: {
      supported: true,
      worker: data,
      mainMathTan: Math.tan(-1e300),
      flags,
    },
  };
}

// ─── 18. Plugin / mime deep structure ────────────────────────
export function collectPluginsHard() {
  const flags = [];
  const plugins = [...(navigator.plugins || [])].map((p) => ({
    name: p.name,
    filename: p.filename,
    description: p.description,
    length: p.length,
  }));
  const mimes = [...(navigator.mimeTypes || [])].map((m) => ({
    type: m.type,
    suffixes: m.suffixes,
    description: m.description,
  }));

  // PluginArray should be array-like; spoof often breaks
  const protoOk = hSafe(() => navigator.plugins instanceof PluginArray);
  const mimeOk = hSafe(() => navigator.mimeTypes instanceof MimeTypeArray);
  if (navigator.plugins && protoOk === false)
    flags.push({ type: "danger", text: "plugins not PluginArray" });
  if (navigator.mimeTypes && mimeOk === false)
    flags.push({ type: "danger", text: "mimeTypes not MimeTypeArray" });

  // refresh should be native
  if (navigator.plugins?.refresh && !isNative(navigator.plugins.refresh))
    flags.push({ type: "danger", text: "plugins.refresh patched" });

  // item(0) === [0]
  if (plugins.length) {
    const same = navigator.plugins[0] === navigator.plugins.item(0);
    if (same === false) flags.push({ type: "danger", text: "plugins[0] ≠ item(0)" });
  }

  // Chrome PDF plugin expected on desktop chrome
  const isChrome = /Chrome\//.test(navigator.userAgent) && !/Mobile|Android/.test(navigator.userAgent);
  const hasPdf = plugins.some((p) => /PDF|Chrome PDF|Chromium PDF/i.test(p.name));
  if (isChrome && plugins.length > 0 && !hasPdf)
    flags.push({ type: "warn", text: "Chrome without PDF plugin" });

  if (!flags.length) flags.push({ type: "ok", text: "plugins structure ok" });

  return {
    category: "pluginsHard",
    label: "Plugins Hard",
    entropy: 8,
    source: "CreepJS navigator plugins",
    items: {
      pluginsCount: plugins.length,
      mimeCount: mimes.length,
      plugins,
      mimes: mimes.slice(0, 30),
      instanceofPluginArray: protoOk,
      instanceofMimeTypeArray: mimeOk,
      flags,
    },
  };
}

// ─── 19. Window chrome / iframe chrome props ─────────────────
export function collectWindowChrome() {
  const flags = [];
  // Automation leftovers — anchored names only (avoid matching WebGLRenderbuffer / GPUBuffer)
  const keys = Object.getOwnPropertyNames(window);
  const autoRe =
    /^(cdc_|\$cdc_|\$chrome_|__webdriver|__driver|__selenium|__fxdriver|__lastWatir|__playwright|__pw_|callPhantom|_phantom|domAutomation|domAutomationController|_Selenium)/i;
  const suspicious = keys.filter((k) => autoRe.test(k));
  if (suspicious.length) {
    flags.push({
      type: "danger",
      id: "window_automation_keys",
      text: `window automation keys: ${suspicious.slice(0, 8).join(",")}`,
      why: "Globals injected by Selenium/CDP/Playwright/Phantom. Legitimate WebGL/WebGPU constructors (WebGLRenderbuffer, GPUBuffer, …) are ignored.",
      measured: suspicious,
      expected: "no automation global names on window",
    });
  }

  // toString tags
  const tags = {
    window: Object.prototype.toString.call(window),
    document: Object.prototype.toString.call(document),
    navigator: Object.prototype.toString.call(navigator),
    screen: Object.prototype.toString.call(screen),
    history: Object.prototype.toString.call(history),
  };
  if (tags.navigator !== "[object Navigator]")
    flags.push({ type: "danger", text: `navigator tag ${tags.navigator}` });

  // Array / Object constructor from iframe must be different realm
  const realm = hSafe(() => {
    const iframe = document.createElement("iframe");
    iframe.style.display = "none";
    document.body.appendChild(iframe);
    const iArray = iframe.contentWindow.Array;
    const different = iArray !== Array;
    const instance = [] instanceof iArray; // false across realms
    document.body.removeChild(iframe);
    return { differentArrayCtor: different, mainArrayInstanceofIframe: instance };
  });
  if (realm && realm.differentArrayCtor === false)
    flags.push({ type: "warn", text: "iframe Array === top Array (unexpected)" });

  if (!flags.length) flags.push({ type: "ok", text: "window chrome ok" });

  return {
    category: "windowChrome",
    label: "Window / Realm",
    entropy: 8,
    source: "CreepJS window / contentWindow",
    items: {
      windowKeysCount: keys.length,
      suspicious,
      tags,
      realm,
      flags,
    },
  };
}

// ─── 20. Permissions matrix ──────────────────────────────────
export async function collectPermissionsHard() {
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
    "background-sync",
    "payment-handler",
    "idle-detection",
    "nfc",
    "display-capture",
    "bluetooth",
  ];
  const states = {};
  if (!navigator.permissions?.query) {
    return {
      category: "permissionsHard",
      label: "Permissions Hard",
      entropy: 4,
      source: "Permissions API",
      items: { supported: false },
    };
  }
  await Promise.all(
    names.map(async (name) => {
      try {
        const r = await navigator.permissions.query({ name });
        states[name] = r.state;
      } catch {
        states[name] = "err";
      }
    })
  );
  const flags = [];
  // all same "denied" can be privacy mode — not necessarily bot
  const unique = new Set(Object.values(states));
  if (unique.size === 1 && unique.has("denied"))
    flags.push({ type: "warn", text: "all permissions denied" });

  return {
    category: "permissionsHard",
    label: "Permissions Hard",
    entropy: 6,
    source: "Permissions API",
    items: { supported: true, states, flags: flags.length ? flags : [{ type: "ok", text: "permissions ok" }] },
  };
}

// ─── aggregate runner ────────────────────────────────────────
export async function runHardSuite(onProgress) {
  const steps = [
    ["Prototype lies", () => collectPrototypeLies()],
    ["JS engine", () => collectEngineFingerprint()],
    ["Headless", async () => enrichHeadlessPermissions(collectHeadless())],
    ["Canvas hard", () => collectCanvasHard()],
    ["WebGL hard", () => collectWebGLHard()],
    ["Consistency", () => collectConsistency()],
    ["SVG/Emoji", () => collectSvgEmoji()],
    ["Audio hard", () => collectAudioHard()],
    ["Fonts hard", () => collectFontsHard()],
    ["Timing", () => collectTimingResistance()],
    ["WebGPU", () => collectWebGPU()],
    ["CSS media", () => collectCssMediaHard()],
    ["Keyboard", () => collectKeyboard()],
    ["Storage hard", () => collectStorageHard()],
    ["Intl hard", () => collectIntlHard()],
    ["Speech hard", () => collectSpeechHard()],
    ["Worker hard", () => collectWorkerHard()],
    ["Plugins hard", () => collectPluginsHard()],
    ["Window realm", () => collectWindowChrome()],
    ["Permissions hard", () => collectPermissionsHard()],
  ];

  const out = [];
  const n = steps.length;
  // leave headroom: v1 is first 55% of hard phase when called alone;
  // app.js will call v2 separately. Here progress is 0..1 for v1 only.
  for (let i = 0; i < n; i++) {
    const [name, fn] = steps[i];
    onProgress?.(i / n, name);
    try {
      const block = await fn();
      if (block) out.push(block);
    } catch (e) {
      out.push({
        category: `error_${i}`,
        label: `${name} (failed)`,
        entropy: 0,
        source: "runner",
        items: {
          error: String(e?.message || e),
          stack: String(e?.stack || "").slice(0, 400),
          flags: [{ type: "warn", text: `${name} threw` }],
        },
      });
    }
  }
  return out;
}

export function collectAllHardFlags(categories) {
  const flags = [];
  for (const c of categories) {
    const f = c.items?.flags;
    if (Array.isArray(f)) {
      for (const x of f) {
        if (x.type === "ok") continue;
        flags.push({
          ...x,
          category: c.category,
          label: c.label,
          source: c.source,
        });
      }
    }
  }
  return flags;
}

/**
 * Build diagnostic rows for UI: alert + why + measured + expected
 */
export function buildDiagnostics(categories) {
  const rows = [];
  for (const c of categories) {
    const flags = c.items?.flags;
    if (!Array.isArray(flags)) continue;
    for (const f of flags) {
      if (f.type === "ok") continue;
      rows.push({
        id: f.id || `${c.category}:${f.text}`,
        severity: f.type || "warn",
        alert: f.text,
        category: c.category,
        categoryLabel: c.label,
        source: c.source,
        why:
          f.why ||
          defaultWhy(c.category, f.text),
        measured:
          f.measured !== undefined
            ? f.measured
            : pickMeasured(c, f),
        expected: f.expected !== undefined ? f.expected : defaultExpected(f.text),
      });
    }
  }
  // danger first
  rows.sort((a, b) => {
    const rank = { danger: 0, warn: 1, info: 2 };
    return (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9);
  });
  return rows;
}

function defaultWhy(category, text) {
  const t = String(text || "").toLowerCase();
  if (t.includes("webdriver"))
    return "navigator.webdriver (or realm mismatch) indicates automation or an incomplete antidetect hide.";
  if (t.includes("fonts.check") || t.includes("fake font"))
    return "FontFaceSet.check() accepted a font family that does not exist — typical of spoofed font APIs in antidetect browsers.";
  if (t.includes("gpu adapter") || t.includes("webgpu"))
    return "WebGPU API is exposed but no adapter was returned — blocked GPU, VM, or stubbed WebGPU surface.";
  if (t.includes("worker"))
    return "Main thread and DedicatedWorker disagree — spoof often only patches the page window.";
  if (t.includes("canvas") && t.includes("unstable"))
    return "Two identical paints produced different pixels — canvas noise / anti-fingerprint injection.";
  if (t.includes("audio") && t.includes("unstable"))
    return "Two identical OfflineAudio renders disagree — audio noise injection.";
  if (t.includes("software") && t.includes("webgl"))
    return "WebGL reports a software rasterizer (SwiftShader/llvmpipe) — headless, VM, or forced software GL.";
  if (t.includes("prototype") || t.includes("not native") || t.includes("patched"))
    return "Native browser function/getter was replaced — JS-level spoof or extension hook.";
  if (t.includes("cdc") || t.includes("automation") || t.includes("selenium") || t.includes("phantom"))
    return "Automation framework leftovers detected on the global object.";
  if (t.includes("iframe"))
    return "Isolated iframe realm does not match top window — incomplete multi-realm spoof.";
  if (t.includes("platform") || t.includes("ua-ch") || t.includes("mismatch"))
    return "Cross-signal identity fields disagree (UA / platform / client hints / GPU).";
  return `Signal from category “${category}” failed a consistency or anti-spoof check used against antidetect and automation.`;
}

function defaultExpected(text) {
  const t = String(text || "").toLowerCase();
  if (t.includes("fake font")) return "document.fonts.check('12px Nonsense') === false";
  if (t.includes("webdriver") && t.includes("worker"))
    return "worker.webdriver === main.webdriver (strict)";
  if (t.includes("webdriver")) return "navigator.webdriver === false (or undefined on some engines)";
  if (t.includes("gpu adapter")) return "await navigator.gpu.requestAdapter() → GPUAdapter";
  if (t.includes("stable")) return "identical hash / samples on repeated measurement";
  if (t.includes("native") || t.includes("patched")) return "function toString contains [native code]";
  return "values consistent with a stock browser (no spoof layer)";
}

function pickMeasured(categoryBlock, flag) {
  const items = categoryBlock?.items || {};
  // Prefer structured fields related to the alert
  const t = String(flag.text || "").toLowerCase();
  if (t.includes("fake font") && items.fontsCheck) return items.fontsCheck;
  if (t.includes("webdriver") && items.worker) {
    return {
      worker: items.worker?.webdriver,
      main: items.mainMathTan !== undefined ? navigator.webdriver : items.worker?.webdriver,
      workerPayload: {
        webdriver: items.worker?.webdriver,
        ua: items.worker?.ua,
        platform: items.worker?.platform,
      },
    };
  }
  if (categoryBlock.category === "workerHard" && items.worker) {
    return {
      worker: {
        webdriver: items.worker.webdriver,
        ua: items.worker.ua,
        platform: items.worker.platform,
        hw: items.worker.hw,
        tz: items.worker.tz,
      },
      main: {
        webdriver: navigator.webdriver,
        ua: navigator.userAgent,
        platform: navigator.platform,
        hw: navigator.hardwareConcurrency,
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      },
    };
  }
  if (categoryBlock.category === "webgpu") {
    return { supported: items.supported, adapter: items.adapter ?? null, info: items.info ?? null };
  }
  if (categoryBlock.category === "windowChrome" && items.suspicious) {
    return { suspicious: items.suspicious, windowKeysCount: items.windowKeysCount };
  }
  if (categoryBlock.category === "fontsHard" && items.fontsCheck) return items.fontsCheck;
  if (items.flags) {
    const { flags, preview, ...rest } = items;
    // compact snapshot
    const keys = Object.keys(rest).slice(0, 12);
    const snap = {};
    for (const k of keys) snap[k] = rest[k];
    return snap;
  }
  return null;
}
