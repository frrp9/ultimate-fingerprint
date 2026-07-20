/**
 * HARD TESTS v3 — aggressive multi-surface antidetect detection
 * Focus: incomplete spoof layers, API capability lies, codec/media, sensors, WASM, SW.
 */

function tSafe(fn, fallback = null) {
  try {
    return fn();
  } catch (e) {
    return fallback ?? { error: String(e?.message || e) };
  }
}

async function tSafeAsync(fn, fallback = null) {
  try {
    return await fn();
  } catch (e) {
    return fallback ?? { error: String(e?.message || e) };
  }
}

async function tSha(str) {
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

// ─── 36. Media capabilities + MSE / EME surface ──────────────
export async function collectMediaCapabilities() {
  const flags = [];
  const types = [
    'video/mp4; codecs="avc1.42E01E"',
    'video/mp4; codecs="avc1.4D401E"',
    'video/mp4; codecs="avc1.640028"',
    'video/mp4; codecs="hev1.1.6.L93.B0"',
    'video/mp4; codecs="hvc1.1.6.L93.B0"',
    'video/mp4; codecs="av01.0.05M.08"',
    'video/webm; codecs="vp8"',
    'video/webm; codecs="vp9"',
    'video/webm; codecs="vp09.00.10.08"',
    'video/webm; codecs="av01.0.04M.08"',
    'audio/mp4; codecs="mp4a.40.2"',
    'audio/webm; codecs="opus"',
    'audio/ogg; codecs="vorbis"',
    'audio/mpeg',
    'audio/wav',
    'audio/flac',
  ];

  const video = document.createElement("video");
  const canPlay = {};
  for (const t of types) canPlay[t] = video.canPlayType(t);

  const mse = {};
  if (window.MediaSource?.isTypeSupported) {
    for (const t of types) mse[t] = MediaSource.isTypeSupported(t);
  }

  // MediaCapabilities decodingInfo sample
  let decoding = null;
  if (navigator.mediaCapabilities?.decodingInfo) {
    decoding = await tSafeAsync(async () => {
      const configs = [
        {
          type: "file",
          video: {
            contentType: 'video/mp4; codecs="avc1.42E01E"',
            width: 1920,
            height: 1080,
            bitrate: 2_000_000,
            framerate: 30,
          },
        },
        {
          type: "file",
          video: {
            contentType: 'video/webm; codecs="vp9"',
            width: 1280,
            height: 720,
            bitrate: 1_500_000,
            framerate: 30,
          },
        },
        {
          type: "file",
          audio: {
            contentType: 'audio/webm; codecs="opus"',
            channels: 2,
            bitrate: 128000,
            samplerate: 48000,
          },
        },
      ];
      const out = [];
      for (const c of configs) {
        try {
          const r = await navigator.mediaCapabilities.decodingInfo(c);
          out.push({
            contentType: c.video?.contentType || c.audio?.contentType,
            supported: r.supported,
            smooth: r.smooth,
            powerEfficient: r.powerEfficient,
          });
        } catch (e) {
          out.push({ error: String(e.message || e), contentType: c.video?.contentType || c.audio?.contentType });
        }
      }
      return out;
    });
  }

  // EME / requestMediaKeySystemAccess probe (no keys, just support)
  let eme = null;
  if (navigator.requestMediaKeySystemAccess) {
    eme = await tSafeAsync(async () => {
      const systems = [
        "com.widevine.alpha",
        "com.microsoft.playready",
        "com.apple.fps.1_0",
        "org.w3.clearkey",
      ];
      const conf = [
        {
          initDataTypes: ["cenc"],
          videoCapabilities: [{ contentType: 'video/mp4; codecs="avc1.42E01E"' }],
        },
      ];
      const res = {};
      for (const s of systems) {
        try {
          const access = await navigator.requestMediaKeySystemAccess(s, conf);
          res[s] = { supported: true, keySystem: access.keySystem };
        } catch {
          res[s] = { supported: false };
        }
      }
      return res;
    });
  }

  // Chrome desktop without any canPlayType support is broken/spoofed
  const anyPlay = Object.values(canPlay).some((v) => v && v !== "");
  if (!anyPlay) {
    flags.push({
      type: "danger",
      id: "media_no_canplay",
      text: "video.canPlayType all empty",
      why: "No media MIME support reported — broken media stack, heavily stripped browser, or hostile spoof.",
      measured: { sample: Object.entries(canPlay).slice(0, 5) },
      expected: "at least some probably/maybe for common codecs",
    });
  }

  // UA claims Safari but Widevine-only etc.
  const ua = navigator.userAgent;
  if (/Safari\//.test(ua) && !/Chrome\//.test(ua) && eme?.["com.widevine.alpha"]?.supported && !eme?.["com.apple.fps.1_0"]?.supported) {
    flags.push({
      type: "danger",
      id: "eme_safari_widevine",
      text: "Safari UA + Widevine without FairPlay",
      why: "Real Safari uses FairPlay; Widevine without FPS on Safari UA is Chromium spoofed as Safari.",
      measured: eme,
      expected: "FairPlay on Safari, not Widevine-only",
    });
  }

  const hash = (await tSha(JSON.stringify({ canPlay, mse, decoding, eme }))).slice(0, 24);
  if (!flags.length) flags.push({ type: "ok", text: "media capabilities ok" });

  return {
    category: "mediaCapabilities",
    label: "Media Capabilities / EME",
    entropy: 14,
    source: "codec surface / DRM support",
    items: { canPlay, mse, decoding, eme, hash, flags },
  };
}

// ─── 37. RTCRtp capabilities (sender/receiver) ───────────────
export async function collectRtcCapabilities() {
  const flags = [];
  if (!window.RTCRtpSender?.getCapabilities && !window.RTCRtpReceiver?.getCapabilities) {
    return {
      category: "rtcCapabilities",
      label: "WebRTC RTP Capabilities",
      entropy: 6,
      source: "WebRTC codec caps",
      items: { supported: false },
    };
  }

  const audioSend = tSafe(() => RTCRtpSender.getCapabilities?.("audio"));
  const videoSend = tSafe(() => RTCRtpSender.getCapabilities?.("video"));
  const audioRecv = tSafe(() => RTCRtpReceiver.getCapabilities?.("audio"));
  const videoRecv = tSafe(() => RTCRtpReceiver.getCapabilities?.("video"));

  const slim = (caps) =>
    caps
      ? {
          codecs: (caps.codecs || []).map((c) => ({
            mimeType: c.mimeType,
            clockRate: c.clockRate,
            channels: c.channels,
            sdpFmtpLine: c.sdpFmtpLine,
          })),
          headerExtensions: (caps.headerExtensions || []).map((h) => h.uri),
        }
      : null;

  const items = {
    audioSend: slim(audioSend),
    videoSend: slim(videoSend),
    audioRecv: slim(audioRecv),
    videoRecv: slim(videoRecv),
  };

  const aCount = items.audioSend?.codecs?.length || 0;
  const vCount = items.videoSend?.codecs?.length || 0;
  if (window.RTCPeerConnection && aCount === 0 && vCount === 0) {
    flags.push({
      type: "warn",
      id: "rtc_caps_empty",
      text: "RTCRtpSender capabilities empty",
      why: "WebRTC present but codec capability lists empty — blocked WebRTC or incomplete environment.",
      measured: { aCount, vCount },
      expected: "non-empty audio/video codec lists",
    });
  }

  // sender vs receiver codec set mismatch (unusual if large)
  if (items.audioSend && items.audioRecv) {
    const s = new Set(items.audioSend.codecs.map((c) => c.mimeType));
    const r = new Set(items.audioRecv.codecs.map((c) => c.mimeType));
    const onlyS = [...s].filter((x) => !r.has(x));
    const onlyR = [...r].filter((x) => !s.has(x));
    items.audioSendRecvDiff = { onlySender: onlyS, onlyReceiver: onlyR };
  }

  const hash = (
    await tSha(
      JSON.stringify({
        a: items.audioSend?.codecs,
        v: items.videoSend?.codecs,
        he: items.videoSend?.headerExtensions,
      })
    )
  ).slice(0, 24);

  if (!flags.length) flags.push({ type: "ok", text: "rtc capabilities ok" });

  return {
    category: "rtcCapabilities",
    label: "WebRTC RTP Capabilities",
    entropy: 12,
    source: "WebRTC getCapabilities",
    items: { supported: true, ...items, hash, flags },
  };
}

// ─── 38. Font dual-measure (DOM width vs canvas vs fonts.check) ─
export function collectFontDualMeasure() {
  const flags = [];
  const fonts = [
    "Arial",
    "Courier New",
    "Georgia",
    "Times New Roman",
    "Verdana",
    "Comic Sans MS",
    "Impact",
    "Segoe UI",
    "Tahoma",
    "Lucida Console",
    "MS Gothic",
    "SimSun",
    "Microsoft YaHei",
    "Menlo",
    "Monaco",
    "Roboto",
    "Ubuntu",
    "Noto Sans",
    "DefinitelyFakeFont_UFP_999",
  ];

  const base = ["monospace", "sans-serif", "serif"];
  const span = document.createElement("span");
  span.style.cssText =
    "position:absolute;left:-9999px;font-size:72px;line-height:normal;font-style:normal;font-weight:normal;letter-spacing:normal;white-space:nowrap";
  span.textContent = "mmmmmmmmmmlli";
  document.body.appendChild(span);

  const baseW = {};
  for (const b of base) {
    span.style.fontFamily = b;
    baseW[b] = span.offsetWidth;
  }

  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  const results = {};

  for (const font of fonts) {
    const domHits = [];
    for (const b of base) {
      span.style.fontFamily = `'${font}',${b}`;
      const w = span.offsetWidth;
      if (w !== baseW[b]) domHits.push(b);
    }
    ctx.font = `72px '${font}', monospace`;
    const cw = ctx.measureText("mmmmmmmmmmlli").width;
    ctx.font = "72px monospace";
    const monoW = ctx.measureText("mmmmmmmmmmlli").width;
    const canvasHit = Math.abs(cw - monoW) > 0.5;
    const check = document.fonts?.check ? document.fonts.check(`72px "${font}"`) : null;
    results[font] = {
      domDetected: domHits.length > 0,
      domBases: domHits,
      canvasWidth: Math.round(cw * 100) / 100,
      canvasDiffFromMono: Math.round((cw - monoW) * 100) / 100,
      canvasDetected: canvasHit,
      fontsCheck: check,
    };

    // fake font must not be "detected" by geometry
    if (font.startsWith("DefinitelyFake") && (results[font].domDetected || results[font].canvasDetected)) {
      flags.push({
        type: "danger",
        id: "font_fake_geometry",
        text: "fake font detected by geometry",
        why: "A nonsense font family changed text metrics — font spoof layer invents metrics for any name.",
        measured: results[font],
        expected: "no geometry change for missing fonts",
      });
    }
    // check true but geometry false for common fonts can be lie; inverse for fake already handled in v1
    if (
      !font.startsWith("DefinitelyFake") &&
      check === true &&
      !results[font].domDetected &&
      !results[font].canvasDetected &&
      font !== "Roboto" &&
      font !== "Ubuntu" &&
      font !== "Noto Sans"
    ) {
      // weak signal only for fonts almost always present
      if (["Arial", "Times New Roman", "Courier New"].includes(font)) {
        flags.push({
          type: "warn",
          id: `font_check_geom_${font}`,
          text: `fonts.check true but no geometry for ${font}`,
          why: "API claims font is available but neither DOM nor canvas metrics change — possible FontFaceSet spoof.",
          measured: results[font],
          expected: "geometry change when fonts.check is true for installed fonts",
        });
      }
    }
  }

  document.body.removeChild(span);

  const detected = Object.entries(results)
    .filter(([, v]) => v.domDetected || v.canvasDetected)
    .map(([k]) => k);

  if (!flags.length) flags.push({ type: "ok", text: "font dual-measure ok" });

  return {
    category: "fontDual",
    label: "Font Dual Measure",
    entropy: 14,
    source: "AmIUnique / canvas+DOM cross-check",
    items: {
      probed: fonts.length,
      detectedCount: detected.length,
      detected,
      results,
      flags,
    },
  };
}

// ─── 39. VisualViewport / screen / device-width coherence ────
export function collectViewportHard() {
  const flags = [];
  const vv = window.visualViewport;
  const items = {
    screen: {
      w: screen.width,
      h: screen.height,
      aw: screen.availWidth,
      ah: screen.availHeight,
      dpr: devicePixelRatio,
    },
    window: {
      innerW: innerWidth,
      innerH: innerHeight,
      outerW: outerWidth,
      outerH: outerHeight,
    },
    visualViewport: vv
      ? {
          width: vv.width,
          height: vv.height,
          scale: vv.scale,
          offsetLeft: vv.offsetLeft,
          offsetTop: vv.offsetTop,
          pageLeft: vv.pageLeft,
          pageTop: vv.pageTop,
        }
      : null,
    matchMedia: {
      deviceWidth: matchMedia(`(device-width: ${screen.width}px)`).matches,
      deviceHeight: matchMedia(`(device-height: ${screen.height}px)`).matches,
      widthScreen: matchMedia(`(width: ${screen.width}px)`).matches,
      resolution: matchMedia(`(resolution: ${devicePixelRatio}dppx)`).matches,
      minRes: matchMedia(`(min-resolution: ${Math.max(0.5, devicePixelRatio - 0.01)}dppx)`).matches,
    },
  };

  if (!items.matchMedia.deviceWidth && screen.width > 0) {
    flags.push({
      type: "danger",
      id: "mq_device_width",
      text: "matchMedia device-width ≠ screen.width",
      why: "CSS media device-width does not match screen.width — screen spoof often misses matchMedia.",
      measured: {
        screenWidth: screen.width,
        deviceWidthMatch: items.matchMedia.deviceWidth,
      },
      expected: "matchMedia(`(device-width: ${screen.width}px)`) === true",
    });
  }

  if (devicePixelRatio > 0 && !items.matchMedia.minRes) {
    flags.push({
      type: "warn",
      id: "mq_resolution",
      text: "matchMedia resolution vs devicePixelRatio mismatch",
      why: "DPR spoof may not update CSS resolution media queries.",
      measured: {
        dpr: devicePixelRatio,
        resolutionMatch: items.matchMedia.resolution,
        minRes: items.matchMedia.minRes,
      },
      expected: "CSS resolution aligned with devicePixelRatio",
    });
  }

  // outer < inner impossible (except rare mobile browser chrome quirks)
  if (outerWidth > 0 && outerWidth + 10 < innerWidth) {
    flags.push({
      type: "danger",
      id: "outer_lt_inner",
      text: "outerWidth << innerWidth",
      why: "Window outer dimensions smaller than inner — classic headless/automation or broken spoof.",
      measured: { outerWidth, innerWidth, outerHeight, innerHeight },
      expected: "outer ≥ inner (browser chrome)",
    });
  }

  // avail > full
  if (screen.availWidth > screen.width + 1 || screen.availHeight > screen.height + 1) {
    flags.push({
      type: "danger",
      id: "avail_gt_screen",
      text: "avail dimensions > screen",
      why: "Impossible screen geometry — spoofed screen object.",
      measured: items.screen,
      expected: "avail ≤ screen",
    });
  }

  if (!flags.length) flags.push({ type: "ok", text: "viewport coherent" });

  return {
    category: "viewportHard",
    label: "Viewport / Screen Hard",
    entropy: 10,
    source: "matchMedia vs screen cross-check",
    items: { ...items, flags },
  };
}

// ─── 40. Sensors / orientation / device motion surface ───────
export async function collectSensors() {
  const flags = [];
  const items = {
    DeviceOrientationEvent: typeof DeviceOrientationEvent !== "undefined",
    DeviceMotionEvent: typeof DeviceMotionEvent !== "undefined",
    Accelerometer: typeof Accelerometer !== "undefined",
    Gyroscope: typeof Gyroscope !== "undefined",
    LinearAccelerationSensor: typeof LinearAccelerationSensor !== "undefined",
    AbsoluteOrientationSensor: typeof AbsoluteOrientationSensor !== "undefined",
    RelativeOrientationSensor: typeof RelativeOrientationSensor !== "undefined",
    AmbientLightSensor: typeof AmbientLightSensor !== "undefined",
    Magnetometer: typeof Magnetometer !== "undefined",
    ondeviceorientation: "ondeviceorientation" in window,
    ondevicemotion: "ondevicemotion" in window,
  };

  // Generic Sensor API probe (may throw security errors — still informative)
  async function probeSensor(Ctor, name) {
    if (typeof Ctor === "undefined") return { name, available: false };
    try {
      const s = new Ctor({ frequency: 1 });
      return await new Promise((resolve) => {
        const t = setTimeout(() => {
          try {
            s.stop();
          } catch {}
          resolve({ name, available: true, reading: null, timeout: true });
        }, 400);
        s.onreading = () => {
          clearTimeout(t);
          const reading = {};
          for (const k of ["x", "y", "z", "quaternion", "illuminance"]) {
            if (k in s) reading[k] = s[k];
          }
          try {
            s.stop();
          } catch {}
          resolve({ name, available: true, reading, timeout: false });
        };
        s.onerror = (e) => {
          clearTimeout(t);
          resolve({
            name,
            available: true,
            error: e.error?.name || "error",
            message: e.error?.message || "",
          });
        };
        try {
          s.start();
        } catch (e) {
          clearTimeout(t);
          resolve({ name, available: true, startError: String(e.message || e) });
        }
      });
    } catch (e) {
      return { name, available: true, constructError: String(e.message || e) };
    }
  }

  items.probes = {
    accelerometer: await probeSensor(window.Accelerometer, "Accelerometer"),
    gyroscope: await probeSensor(window.Gyroscope, "Gyroscope"),
  };

  // Mobile UA without orientation events is mild signal
  if (/Android|iPhone|iPad/.test(navigator.userAgent) && !items.DeviceOrientationEvent) {
    flags.push({
      type: "warn",
      id: "mobile_no_orientation",
      text: "mobile UA without DeviceOrientationEvent",
      why: "Mobile profiles usually expose orientation APIs; missing API may mean desktop spoofed as mobile.",
      measured: items,
      expected: "DeviceOrientationEvent on mobile",
    });
  }

  // Desktop with Generic Sensor constructors can be chrome; no flag alone

  if (!flags.length) flags.push({ type: "ok", text: "sensors surface ok" });

  return {
    category: "sensors",
    label: "Sensors Surface",
    entropy: 8,
    source: "Generic Sensor / deviceorientation",
    items: { ...items, flags },
  };
}

// ─── 41. WebAssembly feature fingerprint ─────────────────────
export async function collectWasmHard() {
  const flags = [];
  if (typeof WebAssembly === "undefined") {
    return {
      category: "wasmHard",
      label: "WebAssembly Hard",
      entropy: 4,
      source: "WASM feature detect",
      items: { supported: false },
    };
  }

  // Minimal valid module (empty)
  const empty = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  const validateEmpty = tSafe(() => WebAssembly.validate(empty));

  // Feature probes via validate of small modules / known patterns
  const features = {
    validateEmpty,
    instantiate: null,
    simd: tSafe(() => WebAssembly.validate(new Uint8Array([
      // wasm magic + version + type/func/export with v128 — simplified: use known SIMD byte pattern probe
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7b, 0x03,
      0x02, 0x01, 0x00, 0x0a, 0x0a, 0x01, 0x08, 0x00, 0x41, 0x00, 0xfd, 0x0f, 0x0b,
    ]))),
    // big int?
    jsBigIntIntegration: typeof WebAssembly.Global === "function",
    exceptionHandling: typeof WebAssembly.Exception === "function" || typeof WebAssembly.Tag === "function",
    threads: typeof SharedArrayBuffer !== "undefined" && typeof WebAssembly.Memory === "function",
    streaming: typeof WebAssembly.instantiateStreaming === "function",
    compileStreaming: typeof WebAssembly.compileStreaming === "function",
    memory64: false,
  };

  features.instantiate = await tSafeAsync(async () => {
    const m = await WebAssembly.instantiate(empty);
    return !!m?.module;
  });

  // Memory max
  features.memory = tSafe(() => {
    const mem = new WebAssembly.Memory({ initial: 1, maximum: 2 });
    return { bufferBytes: mem.buffer.byteLength, max: 2 };
  });

  if (validateEmpty !== true) {
    flags.push({
      type: "danger",
      id: "wasm_broken",
      text: "WebAssembly.validate(empty) failed",
      why: "Broken or mocked WASM pipeline.",
      measured: { validateEmpty },
      expected: true,
    });
  }

  // UA chrome without WASM is almost impossible today
  if (/Chrome\/|Firefox\/|Safari\//.test(navigator.userAgent) && !features.instantiate) {
    flags.push({
      type: "warn",
      id: "wasm_no_instantiate",
      text: "modern UA but WASM instantiate failed",
      why: "Unexpected WASM failure on a mainstream browser UA.",
      measured: features,
      expected: "successful empty module instantiate",
    });
  }

  const hash = (await tSha(JSON.stringify(features))).slice(0, 24);
  if (!flags.length) flags.push({ type: "ok", text: "wasm ok" });

  return {
    category: "wasmHard",
    label: "WebAssembly Hard",
    entropy: 10,
    source: "WASM feature surface",
    items: { supported: true, features, hash, flags },
  };
}

// ─── 42. Stack / Error engine deep ───────────────────────────
export function collectStackHard() {
  const flags = [];
  const samples = {};

  // prepare stack from different call shapes
  function deep(n) {
    if (n <= 0) {
      try {
        null.x();
      } catch (e) {
        return String(e.stack || e.message || "");
      }
    }
    return deep(n - 1);
  }

  samples.deep = deep(5).split("\n").slice(0, 8);
  samples.eval = tSafe(() => {
    try {
      // eslint-disable-next-line no-eval
      eval("throw new Error('ufp-eval')");
    } catch (e) {
      return String(e.stack || "").split("\n").slice(0, 6);
    }
  });
  samples.newFunction = tSafe(() => {
    try {
      Function("throw new Error('ufp-fn')")();
    } catch (e) {
      return String(e.stack || "").split("\n").slice(0, 6);
    }
  });
  samples.async = null; // filled below sync portion

  // engine markers
  const joined = samples.deep.join("\n");
  let engine = "unknown";
  if (/^\s*at\s+/m.test(joined) && /:\d+:\d+/.test(joined)) engine = "v8-like";
  if (/@/.test(joined) && /:\d+:\d+/.test(joined) && !/^\s*at\s+/m.test(joined)) engine = "spidermonkey-like";
  if (/global code|eval code|module code/.test(joined)) engine = "jsc-like";

  const ua = navigator.userAgent;
  if (engine === "v8-like" && /Firefox\//.test(ua)) {
    flags.push({
      type: "danger",
      id: "stack_v8_ff",
      text: "V8-like stacks with Firefox UA",
      why: "Error.stack format looks Chromium/V8 but UA claims Firefox — engine spoof incomplete.",
      measured: { engine, stackHead: samples.deep.slice(0, 3) },
      expected: "SpiderMonkey-style stacks on Firefox",
    });
  }
  if (engine === "spidermonkey-like" && /Chrome\//.test(ua) && !/Firefox\//.test(ua)) {
    flags.push({
      type: "danger",
      id: "stack_sm_chrome",
      text: "SpiderMonkey-like stacks with Chrome UA",
      why: "Stack format disagrees with claimed Chromium engine.",
      measured: { engine, stackHead: samples.deep.slice(0, 3) },
      expected: "V8-style 'at ...' stacks on Chrome",
    });
  }

  // Error.captureStackTrace (V8)
  samples.captureStackTrace = typeof Error.captureStackTrace === "function";
  if (samples.captureStackTrace && /Firefox\//.test(ua)) {
    flags.push({
      type: "danger",
      id: "capture_stack_ff",
      text: "Error.captureStackTrace on Firefox UA",
      why: "V8-only API present under Firefox identity.",
      measured: { captureStackTrace: true },
      expected: "undefined on Firefox",
    });
  }

  samples.stackTraceLimit = Error.stackTraceLimit ?? null;

  if (!flags.length) flags.push({ type: "ok", text: "stack engine ok" });

  return {
    category: "stackHard",
    label: "Stack / Engine Hard",
    entropy: 10,
    source: "Error.stack engine fingerprint",
    items: { engine, samples, flags },
  };
}

// ─── 43. Timezone triple lock (Date / Intl / offset) ──────────
export function collectTimezoneLock() {
  const flags = [];
  const resolved = Intl.DateTimeFormat().resolvedOptions();
  const tz = resolved.timeZone;
  const offset = new Date().getTimezoneOffset();

  // parse shortOffset
  const label = tSafe(() =>
    new Intl.DateTimeFormat("en-US", { timeZone: tz, timeZoneName: "longOffset" }).formatToParts(
      new Date()
    )
  );
  const tzName = Array.isArray(label)
    ? label.find((p) => p.type === "timeZoneName")?.value
    : null;

  // independent: format in UTC vs local
  const now = Date.now();
  const localHour = new Date(now).getHours();
  const utcHour = new Date(now).getUTCHours();
  const hourDelta = (localHour - utcHour + 24) % 24;
  // offset minutes: positive means behind UTC in ES
  const offsetHours = -offset / 60;
  // rough: hourDelta should be close to floor(offsetHours) accounting DST — allow 1h slack via minutes
  const expectedHourFromOffset = ((Math.floor((-offset) / 60) % 24) + 24) % 24;
  // Better: use same instant parts
  const localParts = tSafe(() =>
    new Intl.DateTimeFormat("en-GB", {
      timeZone: tz,
      hour: "numeric",
      hourCycle: "h23",
      minute: "numeric",
    }).formatToParts(new Date(now))
  );
  const utcParts = tSafe(() =>
    new Intl.DateTimeFormat("en-GB", {
      timeZone: "UTC",
      hour: "numeric",
      hourCycle: "h23",
      minute: "numeric",
    }).formatToParts(new Date(now))
  );

  const get = (parts, type) =>
    Array.isArray(parts) ? Number(parts.find((p) => p.type === type)?.value) : NaN;
  const lh = get(localParts, "hour");
  const lm = get(localParts, "minute");
  const uh = get(utcParts, "hour");
  const um = get(utcParts, "minute");
  const intlDeltaMin =
    Number.isFinite(lh) && Number.isFinite(uh)
      ? ((lh * 60 + lm) - (uh * 60 + um) + 24 * 60) % (24 * 60)
      : null;
  // ES offset: local = UTC - offset → delta local-utc minutes = -offset
  const esDeltaMin = -offset;
  // normalize intl delta to signed -12h..12h style matching -offset
  let intlSigned = intlDeltaMin;
  if (intlSigned != null && intlSigned > 12 * 60) intlSigned -= 24 * 60;

  const items = {
    timeZone: tz,
    locale: resolved.locale,
    offsetMinutes: offset,
    tzName,
    hourDeltaLocalUtc: hourDelta,
    intlDeltaMin: intlSigned,
    esDeltaMin,
    dateString: new Date().toString(),
    iso: new Date().toISOString(),
  };

  if (intlSigned != null && Math.abs(intlSigned - esDeltaMin) > 1) {
    flags.push({
      type: "danger",
      id: "tz_offset_lie",
      text: "Date offset ≠ Intl timezone offset",
      why: "getTimezoneOffset() disagrees with the offset implied by Intl in the resolved timeZone — classic incomplete timezone spoof.",
      measured: {
        offsetMinutes: offset,
        esDeltaMin,
        intlSigned,
        timeZone: tz,
        tzName,
      },
      expected: "Date and Intl describe the same UTC offset",
    });
  }

  // resolvedOptions timeZone vs Date string parenthesis often contains name — soft
  if (!tz) {
    flags.push({
      type: "warn",
      id: "tz_missing",
      text: "missing resolved timeZone",
      why: "Intl.DateTimeFormat().resolvedOptions().timeZone empty.",
      measured: resolved,
      expected: "IANA timezone string",
    });
  }

  if (!flags.length) flags.push({ type: "ok", text: "timezone lock ok" });

  return {
    category: "timezoneLock",
    label: "Timezone Triple Lock",
    entropy: 10,
    source: "Date vs Intl offset consistency",
    items: { ...items, flags },
  };
}

// ─── 44. iframe sandbox / srcdoc / null origin isolation ─────
export async function collectIframeIsolation() {
  const flags = [];
  const results = {};

  // about:blank
  results.blank = tSafe(() => {
    const iframe = document.createElement("iframe");
    iframe.style.cssText = "position:absolute;left:-9999px;width:0;height:0;border:0";
    document.body.appendChild(iframe);
    try {
      const w = iframe.contentWindow;
      return {
        sameUA: w.navigator.userAgent === navigator.userAgent,
        sameHW: w.navigator.hardwareConcurrency === navigator.hardwareConcurrency,
        parentIsTop: w.parent === window,
        selfIsTop: w.self === w.top,
        chrome: !!w.chrome,
        devicePixelRatio: w.devicePixelRatio,
        topDpr: devicePixelRatio,
      };
    } finally {
      iframe.remove();
    }
  });

  // sandboxed srcdoc
  results.sandboxed = await tSafeAsync(
    () =>
      new Promise((resolve) => {
        const iframe = document.createElement("iframe");
        iframe.setAttribute("sandbox", "allow-scripts");
        iframe.srcdoc =
          "<!doctype html><script>parent.postMessage({t:'ufp-sb',ua:navigator.userAgent,hw:navigator.hardwareConcurrency,wd:navigator.webdriver,dpr:devicePixelRatio,platform:navigator.platform},'*')</script>";
        iframe.style.cssText = "position:absolute;left:-9999px;width:0;height:0;border:0";
        const t = setTimeout(() => {
          window.removeEventListener("message", onMsg);
          iframe.remove();
          resolve({ error: "timeout" });
        }, 1000);
        function onMsg(e) {
          if (!e.data || e.data.t !== "ufp-sb") return;
          clearTimeout(t);
          window.removeEventListener("message", onMsg);
          iframe.remove();
          resolve(e.data);
        }
        window.addEventListener("message", onMsg);
        document.body.appendChild(iframe);
      })
  );

  if (results.blank && results.blank.sameUA === false) {
    flags.push({
      type: "danger",
      id: "iframe_blank_ua",
      text: "about:blank iframe UA ≠ top",
      why: "Navigator spoof not applied to about:blank child realm.",
      measured: results.blank,
      expected: "identical UA",
    });
  }
  if (results.blank && results.blank.devicePixelRatio !== results.blank.topDpr) {
    flags.push({
      type: "danger",
      id: "iframe_dpr",
      text: "iframe devicePixelRatio ≠ top",
      why: "DPR spoof often only on top window.",
      measured: {
        iframe: results.blank.devicePixelRatio,
        top: results.blank.topDpr,
      },
      expected: "identical DPR",
    });
  }

  if (results.sandboxed && !results.sandboxed.error) {
    if (results.sandboxed.ua !== navigator.userAgent) {
      flags.push({
        type: "danger",
        id: "sandbox_ua",
        text: "sandboxed iframe UA ≠ top",
        why: "Sandboxed srcdoc realm escaped the spoof — strong antidetect leak.",
        measured: {
          sandboxUA: results.sandboxed.ua,
          topUA: navigator.userAgent,
          sandboxHW: results.sandboxed.hw,
          topHW: navigator.hardwareConcurrency,
          sandboxWD: results.sandboxed.wd,
          topWD: navigator.webdriver,
        },
        expected: "identical navigator in sandboxed iframe",
      });
    }
    if (results.sandboxed.hw !== navigator.hardwareConcurrency) {
      flags.push({
        type: "danger",
        id: "sandbox_hw",
        text: "sandboxed iframe HW ≠ top",
        why: "hardwareConcurrency spoof incomplete in sandboxed realm.",
        measured: {
          sandbox: results.sandboxed.hw,
          top: navigator.hardwareConcurrency,
        },
        expected: "identical hardwareConcurrency",
      });
    }
    if (results.sandboxed.wd !== navigator.webdriver) {
      flags.push({
        type: "danger",
        id: "sandbox_wd",
        text: "sandboxed iframe webdriver ≠ top",
        why: "webdriver hide not applied inside sandbox.",
        measured: { sandbox: results.sandboxed.wd, top: navigator.webdriver },
        expected: "identical webdriver",
      });
    }
  }

  if (!flags.length) flags.push({ type: "ok", text: "iframe isolation ok" });

  return {
    category: "iframeIsolation",
    label: "Iframe Isolation",
    entropy: 14,
    source: "sandbox/srcdoc multi-realm",
    items: { ...results, flags },
  };
}

// ─── 45. Canvas emoji / text path entropy ────────────────────
export async function collectCanvasEmojiHard() {
  const flags = [];
  const canvas = document.createElement("canvas");
  canvas.width = 200;
  canvas.height = 80;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) {
    return {
      category: "canvasEmojiHard",
      label: "Canvas Emoji / Path",
      entropy: 8,
      source: "emoji raster fingerprint",
      items: { supported: false },
    };
  }

  const emojis = ["😀", "👾", "🏳️‍🌈", "👨‍💻", "🇺🇸", "中", "م", "Ω"];
  const hashes = {};
  for (const e of emojis) {
    ctx.clearRect(0, 0, 200, 80);
    ctx.fillStyle = "#fff";
    ctx.fillRect(0, 0, 200, 80);
    ctx.font = "48px serif";
    ctx.textBaseline = "top";
    ctx.fillStyle = "#000";
    ctx.fillText(e, 10, 10);
    const data = ctx.getImageData(0, 0, 200, 80).data;
    let acc = 0;
    let nonzero = 0;
    for (let i = 0; i < data.length; i += 4) {
      const v = data[i] + data[i + 1] + data[i + 2];
      if (v < 765) {
        nonzero++;
        acc = (acc + v * (i + 1)) >>> 0;
      }
    }
    hashes[e] = {
      checksum: acc.toString(16),
      inkPixels: nonzero,
      sha: (await tSha(Array.from(data.subarray(0, 800)).join(","))).slice(0, 16),
    };
  }

  // path winding / isPointInPath fingerprint
  ctx.clearRect(0, 0, 200, 80);
  ctx.beginPath();
  ctx.rect(20, 20, 60, 40);
  ctx.rect(40, 30, 20, 20);
  const evenodd = ctx.isPointInPath(50, 40, "evenodd");
  const nonzeroW = ctx.isPointInPath(50, 40, "nonzero");

  // stability
  ctx.clearRect(0, 0, 200, 80);
  ctx.font = "48px serif";
  ctx.fillText("😀", 10, 10);
  const a = canvas.toDataURL();
  ctx.clearRect(0, 0, 200, 80);
  ctx.font = "48px serif";
  ctx.fillText("😀", 10, 10);
  const b = canvas.toDataURL();
  if (a !== b) {
    flags.push({
      type: "danger",
      id: "emoji_unstable",
      text: "emoji canvas unstable",
      why: "Identical emoji paints differ — canvas noise injection.",
      measured: {
        hashA: (await tSha(a)).slice(0, 16),
        hashB: (await tSha(b)).slice(0, 16),
      },
      expected: "stable toDataURL",
    });
  }

  if (!flags.length) flags.push({ type: "ok", text: "canvas emoji ok" });

  return {
    category: "canvasEmojiHard",
    label: "Canvas Emoji / Path",
    entropy: 12,
    source: "emoji raster + winding",
    items: {
      hashes,
      winding: { evenodd, nonzero: nonzeroW },
      flags,
    },
  };
}

// ─── 46. Plugin / mime internal structure hard ───────────────
export function collectPluginStructure() {
  const flags = [];
  const plugins = navigator.plugins;
  const mimes = navigator.mimeTypes;
  const items = {
    pluginsLength: plugins?.length ?? 0,
    mimesLength: mimes?.length ?? 0,
    details: [],
  };

  if (plugins && plugins.length) {
    for (let i = 0; i < plugins.length; i++) {
      const p = plugins[i];
      const entry = {
        i,
        name: p.name,
        filename: p.filename,
        description: p.description,
        length: p.length,
        item0EqualsBracket: tSafe(() => p[0] === p.item(0)),
        namedItem: tSafe(() => (p.name ? p.namedItem?.(p[0]?.type) : null)),
        mimes: [],
      };
      for (let j = 0; j < p.length; j++) {
        const m = p[j];
        entry.mimes.push({
          type: m?.type,
          suffixes: m?.suffixes,
          enabledPluginName: m?.enabledPlugin?.name ?? null,
          enabledPluginIsSelf: tSafe(() => m?.enabledPlugin === p),
        });
        if (m?.enabledPlugin && m.enabledPlugin !== p) {
          flags.push({
            type: "danger",
            id: "mime_enabled_plugin",
            text: "mime.enabledPlugin !== parent plugin",
            why: "Plugin/MimeType graph inconsistent — handmade spoof arrays often break enabledPlugin links.",
            measured: {
              plugin: p.name,
              mime: m.type,
              enabled: m.enabledPlugin?.name,
            },
            expected: "enabledPlugin points back to parent Plugin",
          });
        }
      }
      items.details.push(entry);
      if (entry.item0EqualsBracket === false) {
        flags.push({
          type: "danger",
          id: "plugin_item_bracket",
          text: "plugin[0] !== plugin.item(0)",
          why: "PluginArray-like spoof incomplete.",
          measured: { plugin: p.name },
          expected: "bracket access equals item()",
        });
      }
    }
  }

  // mimeTypes refresh / namedItem
  if (mimes && mimes.length) {
    items.mime0 = {
      type: mimes[0]?.type,
      itemEq: tSafe(() => mimes[0] === mimes.item(0)),
      named: tSafe(() => mimes.namedItem(mimes[0]?.type)?.type),
    };
    if (items.mime0.itemEq === false) {
      flags.push({
        type: "danger",
        id: "mime_item_eq",
        text: "mimeTypes[0] !== item(0)",
        why: "MimeTypeArray spoof structure broken.",
        measured: items.mime0,
        expected: "equal references",
      });
    }
  }

  // refresh native
  if (plugins?.refresh && !isNative(plugins.refresh)) {
    flags.push({
      type: "danger",
      id: "plugins_refresh",
      text: "plugins.refresh not native",
      why: "PluginArray.refresh replaced — spoof layer.",
      measured: { native: false },
      expected: "[native code]",
    });
  }

  if (!flags.length) flags.push({ type: "ok", text: "plugin structure ok" });

  return {
    category: "pluginStructure",
    label: "Plugin Structure Hard",
    entropy: 10,
    source: "Plugin/MimeType graph integrity",
    items: { ...items, flags },
  };
}

// ─── 47. Performance / memory coherence ──────────────────────
export function collectPerfHard() {
  const flags = [];
  const navEntry = performance.getEntriesByType?.("navigation")?.[0];
  const items = {
    timeOrigin: performance.timeOrigin,
    now: performance.now(),
    timing: performance.timing
      ? {
          navigationStart: performance.timing.navigationStart,
          domComplete: performance.timing.domComplete,
        }
      : null,
    navigation: navEntry
      ? {
          type: navEntry.type,
          transferSize: navEntry.transferSize,
          decodedBodySize: navEntry.decodedBodySize,
        }
      : null,
    memory: performance.memory
      ? {
          jsHeapSizeLimit: performance.memory.jsHeapSizeLimit,
          totalJSHeapSize: performance.memory.totalJSHeapSize,
          usedJSHeapSize: performance.memory.usedJSHeapSize,
        }
      : null,
  };

  // timeOrigin vs Date.now coherence (rough)
  const wall = Date.now();
  const approx = performance.timeOrigin + performance.now();
  const drift = Math.abs(wall - approx);
  items.wallClockDriftMs = drift;
  if (drift > 5000) {
    flags.push({
      type: "warn",
      id: "perf_wall_drift",
      text: "performance.timeOrigin+now far from Date.now",
      why: "Clock sources disagree by >5s — timer spoof / RFP / broken timeOrigin.",
      measured: { wall, approx, drift },
      expected: "drift typically < few hundred ms",
    });
  }

  if (items.memory) {
    const { jsHeapSizeLimit, totalJSHeapSize, usedJSHeapSize } = items.memory;
    if (usedJSHeapSize > totalJSHeapSize + 1024) {
      flags.push({
        type: "danger",
        id: "heap_used_gt_total",
        text: "usedJSHeapSize > totalJSHeapSize",
        why: "Impossible heap accounting — spoofed performance.memory.",
        measured: items.memory,
        expected: "used ≤ total ≤ limit",
      });
    }
    if (totalJSHeapSize > jsHeapSizeLimit + 1024) {
      flags.push({
        type: "danger",
        id: "heap_total_gt_limit",
        text: "totalJSHeapSize > jsHeapSizeLimit",
        why: "Impossible heap limit relationship.",
        measured: items.memory,
        expected: "total ≤ limit",
      });
    }
  }

  // performance.now monotonic sample
  const samples = [];
  let last = performance.now();
  for (let i = 0; i < 200; i++) {
    const n = performance.now();
    if (n < last) samples.push({ i, last, n });
    last = n;
  }
  items.nonMonotonic = samples.length;
  if (samples.length) {
    flags.push({
      type: "danger",
      id: "perf_now_non_monotonic",
      text: "performance.now went backwards",
      why: "Timer should be monotonic; regressions indicate hostile timer hooks.",
      measured: samples.slice(0, 5),
      expected: "non-decreasing performance.now",
    });
  }

  if (!flags.length) flags.push({ type: "ok", text: "perf hard ok" });

  return {
    category: "perfHard",
    label: "Performance Hard",
    entropy: 8,
    source: "timeOrigin / heap / monotonic now",
    items: { ...items, flags },
  };
}

// ─── 48. ServiceWorker / Cache / Push surface ────────────────
export async function collectServiceWorkerSurface() {
  const flags = [];
  const items = {
    serviceWorker: !!navigator.serviceWorker,
    controller: !!navigator.serviceWorker?.controller,
    caches: !!window.caches,
    PushManager: !!window.PushManager,
    Notification: !!window.Notification,
    notificationPermission:
      typeof Notification !== "undefined" ? Notification.permission : null,
  };

  if (navigator.serviceWorker) {
    items.ready = await tSafeAsync(async () => {
      // don't hang — race timeout
      return await Promise.race([
        navigator.serviceWorker.ready.then((r) => ({
          active: !!r.active,
          scope: r.scope,
        })),
        new Promise((resolve) => setTimeout(() => resolve({ timeout: true }), 400)),
      ]);
    });
    items.regs = await tSafeAsync(async () => {
      const list = await navigator.serviceWorker.getRegistrations();
      return list.map((r) => ({
        scope: r.scope,
        active: !!r.active,
        installing: !!r.installing,
        waiting: !!r.waiting,
      }));
    });
  }

  if (window.caches) {
    items.cacheKeys = await tSafeAsync(async () => {
      const keys = await caches.keys();
      return keys.slice(0, 20);
    });
  }

  // secure context required for SW
  items.isSecureContext = window.isSecureContext;
  if (!window.isSecureContext && items.serviceWorker) {
    flags.push({
      type: "warn",
      id: "sw_insecure",
      text: "serviceWorker present outside secure context",
      why: "Unusual — SW APIs normally limited to secure contexts.",
      measured: items,
      expected: "SW only in secure contexts",
    });
  }

  if (!flags.length) flags.push({ type: "ok", text: "SW surface ok" });

  return {
    category: "serviceWorker",
    label: "ServiceWorker / Cache",
    entropy: 6,
    source: "SW / Cache API surface",
    items: { ...items, flags },
  };
}

// ─── 49. Locale / language matrix hard ───────────────────────
export function collectLocaleMatrix() {
  const flags = [];
  const navLang = navigator.language;
  const navLangs = navigator.languages ? [...navigator.languages] : [];
  const intlLocale = Intl.DateTimeFormat().resolvedOptions().locale;
  const collator = tSafe(() => new Intl.Collator().resolvedOptions().locale);
  const number = tSafe(() => new Intl.NumberFormat().resolvedOptions().locale);
  const plural = tSafe(() => new Intl.PluralRules().resolvedOptions().locale);

  const items = {
    navigatorLanguage: navLang,
    navigatorLanguages: navLangs,
    dateLocale: intlLocale,
    collatorLocale: collator,
    numberLocale: number,
    pluralLocale: plural,
  };

  if (navLangs.length && navLangs[0] && navLang && navLangs[0] !== navLang) {
    flags.push({
      type: "danger",
      id: "lang0_ne_language",
      text: "languages[0] ≠ navigator.language",
      why: "Spec expects languages[0] to match language; mismatch is a spoof smell.",
      measured: { language: navLang, languages0: navLangs[0], languages: navLangs },
      expected: "languages[0] === language",
    });
  }

  // Intl locales should share primary language with navigator (soft for region)
  const primary = (s) => String(s || "").split("-")[0].toLowerCase();
  if (navLang && intlLocale && primary(navLang) !== primary(intlLocale)) {
    // can be legitimate if user overrides — warn not danger
    flags.push({
      type: "warn",
      id: "intl_lang_nav",
      text: "Intl locale primary ≠ navigator.language primary",
      why: "UI language and Intl default locale disagree — possible incomplete locale spoof.",
      measured: { navLang, intlLocale },
      expected: "same primary language subtag (often)",
    });
  }

  // empty languages
  if (!navLangs.length) {
    flags.push({
      type: "danger",
      id: "langs_empty",
      text: "navigator.languages empty",
      why: "Empty languages array is abnormal for real browsers.",
      measured: { languages: navLangs },
      expected: "non-empty languages",
    });
  }

  if (!flags.length) flags.push({ type: "ok", text: "locale matrix ok" });

  return {
    category: "localeMatrix",
    label: "Locale Matrix",
    entropy: 8,
    source: "navigator vs Intl locales",
    items: { ...items, flags },
  };
}

// ─── 50. WebGL context attributes + drawing buffer ───────────
export async function collectWebGLContextHard() {
  const flags = [];
  const canvas = document.createElement("canvas");
  canvas.width = 64;
  canvas.height = 64;
  const attrsList = [
    { antialias: true, depth: true, stencil: false, alpha: true, premultipliedAlpha: true },
    { antialias: false, depth: true, stencil: true, alpha: false },
    { failIfMajorPerformanceCaveat: true },
    { failIfMajorPerformanceCaveat: false, powerPreference: "high-performance" },
    { powerPreference: "low-power" },
  ];

  const contexts = [];
  for (const attrs of attrsList) {
    const c = document.createElement("canvas");
    c.width = 32;
    c.height = 32;
    const gl =
      c.getContext("webgl2", attrs) ||
      c.getContext("webgl", attrs) ||
      c.getContext("experimental-webgl", attrs);
    if (!gl) {
      contexts.push({ attrs, ok: false });
      continue;
    }
    const got = gl.getContextAttributes?.() || null;
    const dbg = gl.getExtension("WEBGL_debug_renderer_info");
    const renderer = dbg
      ? tSafe(() => gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL))
      : tSafe(() => gl.getParameter(gl.RENDERER));
    gl.clearColor(0.25, 0.5, 0.75, 1);
    gl.clear(gl.COLOR_BUFFER_BIT);
    const px = new Uint8Array(4);
    gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, px);
    contexts.push({
      attrs,
      ok: true,
      contextType: typeof WebGL2RenderingContext !== "undefined" && gl instanceof WebGL2RenderingContext ? "webgl2" : "webgl",
      got,
      renderer,
      pixel: Array.from(px),
      drawingBufferWidth: gl.drawingBufferWidth,
      drawingBufferHeight: gl.drawingBufferHeight,
    });
  }

  // high-performance vs low-power renderer swap detection
  const hi = contexts.find((c) => c.attrs?.powerPreference === "high-performance" && c.ok);
  const lo = contexts.find((c) => c.attrs?.powerPreference === "low-power" && c.ok);
  if (hi?.renderer && lo?.renderer && hi.renderer !== lo.renderer) {
    // legitimate dual-GPU machines differ — record only, mild
    // no flag: dual GPU is real. Store signal only.
  }

  // failIfMajorPerformanceCaveat true failed but false worked with software
  const strict = contexts.find((c) => c.attrs?.failIfMajorPerformanceCaveat === true);
  const loose = contexts.find((c) => c.attrs?.failIfMajorPerformanceCaveat === false);
  if (strict && loose && !strict.ok && loose.ok) {
    const soft = /SwiftShader|llvmpipe|Software|Basic Render/i.test(String(loose.renderer || ""));
    if (soft) {
      flags.push({
        type: "danger",
        id: "webgl_software_only",
        text: "WebGL only without failIfMajorPerformanceCaveat (software GL)",
        why: "Hardware GL unavailable; only software rasterizer works — headless/VM/antidetect software WebGL.",
        measured: { strictOk: strict.ok, looseRenderer: loose.renderer },
        expected: "hardware WebGL with failIfMajorPerformanceCaveat:true",
      });
    }
  }

  const hash = (await tSha(JSON.stringify(contexts.map((c) => ({ a: c.attrs, r: c.renderer, p: c.pixel }))))).slice(0, 24);
  if (!flags.length) flags.push({ type: "ok", text: "webgl context hard ok" });

  return {
    category: "webglContextHard",
    label: "WebGL Context Attributes",
    entropy: 12,
    source: "context attrs / software GL",
    items: { contexts, hash, flags },
  };
}

// ─── 51. SharedWorker / BroadcastChannel realm ───────────────
export async function collectSharedChannels() {
  const flags = [];
  const items = {
    SharedWorker: typeof SharedWorker !== "undefined",
    BroadcastChannel: typeof BroadcastChannel !== "undefined",
    MessageChannel: typeof MessageChannel !== "undefined",
  };

  // BroadcastChannel self echo
  if (window.BroadcastChannel) {
    items.broadcast = await tSafeAsync(
      () =>
        new Promise((resolve) => {
          const name = "ufp-bc-" + Math.random().toString(36).slice(2);
          const a = new BroadcastChannel(name);
          const b = new BroadcastChannel(name);
          const t = setTimeout(() => {
            a.close();
            b.close();
            resolve({ ok: false, timeout: true });
          }, 500);
          b.onmessage = (e) => {
            clearTimeout(t);
            a.close();
            b.close();
            resolve({ ok: true, data: e.data });
          };
          a.postMessage({ ping: 1, ua: navigator.userAgent.slice(0, 40) });
        })
    );
  }

  // MessageChannel
  if (window.MessageChannel) {
    items.messageChannel = await tSafeAsync(
      () =>
        new Promise((resolve) => {
          const mc = new MessageChannel();
          const t = setTimeout(() => resolve({ ok: false, timeout: true }), 300);
          mc.port2.onmessage = (e) => {
            clearTimeout(t);
            resolve({ ok: true, data: e.data });
          };
          mc.port1.postMessage({ hw: navigator.hardwareConcurrency });
        })
    );
  }

  // SharedWorker probe if available
  if (typeof SharedWorker !== "undefined") {
    items.sharedWorker = await tSafeAsync(
      () =>
        new Promise((resolve) => {
          try {
            const code = `onconnect=e=>{const p=e.ports[0];p.onmessage=()=>p.postMessage({ua:navigator.userAgent,hw:navigator.hardwareConcurrency,wd:navigator.webdriver})}`;
            const url = URL.createObjectURL(new Blob([code], { type: "application/javascript" }));
            const sw = new SharedWorker(url);
            const t = setTimeout(() => {
              URL.revokeObjectURL(url);
              resolve({ error: "timeout" });
            }, 1500);
            sw.port.onmessage = (e) => {
              clearTimeout(t);
              URL.revokeObjectURL(url);
              resolve(e.data);
            };
            sw.port.start();
            sw.port.postMessage(1);
          } catch (e) {
            resolve({ error: String(e.message || e) });
          }
        })
    );
    if (items.sharedWorker && !items.sharedWorker.error) {
      if (items.sharedWorker.ua !== navigator.userAgent) {
        flags.push({
          type: "danger",
          id: "sharedworker_ua",
          text: "SharedWorker UA ≠ main",
          why: "SharedWorker realm not covered by navigator spoof.",
          measured: { worker: items.sharedWorker.ua, main: navigator.userAgent },
          expected: "identical UA",
        });
      }
      if (items.sharedWorker.wd !== navigator.webdriver) {
        flags.push({
          type: "danger",
          id: "sharedworker_wd",
          text: "SharedWorker webdriver ≠ main",
          why: "webdriver hide incomplete in SharedWorker.",
          measured: { worker: items.sharedWorker.wd, main: navigator.webdriver },
          expected: "identical webdriver",
        });
      }
    }
  }

  if (!flags.length) flags.push({ type: "ok", text: "shared channels ok" });

  return {
    category: "sharedChannels",
    label: "SharedWorker / Channels",
    entropy: 10,
    source: "SharedWorker multi-realm",
    items: { ...items, flags },
  };
}

// ─── 52. CSS computed system UI fonts ────────────────────────
export function collectSystemFontsCss() {
  const flags = [];
  const families = [
    "system-ui",
    "-apple-system",
    "BlinkMacSystemFont",
    "Segoe UI",
    "Roboto",
    "Helvetica Neue",
    "Arial",
    "ui-sans-serif",
    "ui-serif",
    "ui-monospace",
    "ui-rounded",
    "emoji",
    "math",
    "fangsong",
  ];
  const el = document.createElement("div");
  el.style.cssText = "position:absolute;left:-9999px;font-size:16px";
  document.body.appendChild(el);
  const computed = {};
  for (const f of families) {
    el.style.fontFamily = f;
    const cs = getComputedStyle(el);
    computed[f] = {
      fontFamily: cs.fontFamily,
      fontSize: cs.fontSize,
      fontWeight: cs.fontWeight,
    };
  }
  // generic default
  el.style.fontFamily = "";
  computed.default = {
    fontFamily: getComputedStyle(el).fontFamily,
    fontSize: getComputedStyle(el).fontSize,
  };
  document.body.removeChild(el);

  // system-ui resolving to something impossible for claimed OS — soft checks
  const ua = navigator.userAgent;
  const sys = computed["system-ui"]?.fontFamily || "";
  if (/Windows/.test(ua) && /San Francisco|Helvetica Neue|BlinkMacSystemFont/i.test(sys) && !/Segoe/i.test(sys)) {
    flags.push({
      type: "warn",
      id: "system_ui_mac_on_win",
      text: "system-ui computes to Mac-like family on Windows UA",
      why: "CSS system font stack disagrees with claimed OS.",
      measured: { systemUi: sys, ua: ua.slice(0, 80) },
      expected: "Segoe UI-ish stack on Windows",
    });
  }
  if (/Mac OS X|Macintosh/.test(ua) && /Segoe UI|Tahoma|Roboto/i.test(sys) && !/system-ui|San Francisco|Helvetica/i.test(sys)) {
    flags.push({
      type: "warn",
      id: "system_ui_win_on_mac",
      text: "system-ui computes to Windows-like family on Mac UA",
      why: "CSS system font stack disagrees with claimed OS.",
      measured: { systemUi: sys },
      expected: "Apple system font stack on macOS",
    });
  }

  if (!flags.length) flags.push({ type: "ok", text: "system fonts css ok" });

  return {
    category: "systemFontsCss",
    label: "System Fonts CSS",
    entropy: 8,
    source: "system-ui computed fonts",
    items: { computed, flags },
  };
}

// ─── runner v3 ───────────────────────────────────────────────
export async function runHardSuiteV3(onProgress) {
  const steps = [
    ["Media capabilities", () => collectMediaCapabilities()],
    ["RTC capabilities", () => collectRtcCapabilities()],
    ["Font dual-measure", () => collectFontDualMeasure()],
    ["Viewport hard", () => collectViewportHard()],
    ["Sensors", () => collectSensors()],
    ["WASM hard", () => collectWasmHard()],
    ["Stack hard", () => collectStackHard()],
    ["Timezone lock", () => collectTimezoneLock()],
    ["Iframe isolation", () => collectIframeIsolation()],
    ["Canvas emoji", () => collectCanvasEmojiHard()],
    ["Plugin structure", () => collectPluginStructure()],
    ["Perf hard", () => collectPerfHard()],
    ["ServiceWorker", () => collectServiceWorkerSurface()],
    ["Locale matrix", () => collectLocaleMatrix()],
    ["WebGL contexts", () => collectWebGLContextHard()],
    ["Shared channels", () => collectSharedChannels()],
    ["System fonts CSS", () => collectSystemFontsCss()],
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
        category: `v3_error_${i}`,
        label: `${name} (failed)`,
        entropy: 0,
        source: "runner-v3",
        items: {
          error: String(e?.message || e),
          stack: String(e?.stack || "").slice(0, 400),
          flags: [
            {
              type: "warn",
              text: `${name} threw`,
              why: "Collector crashed; API blocked or environment hostile.",
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

