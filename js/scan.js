/*
 * Totals POS - Barcode scanning
 * ---------------------------------------------------------------------------
 * Two input paths, both offline:
 *   1. Camera (tablet/phone rear camera) — uses the native BarcodeDetector API
 *      when present (Android Chrome/Edge) and falls back to the vendored ZXing
 *      decoder (iOS Safari and older browsers).
 *   2. Hardware USB/Bluetooth scanners — these emulate a keyboard; app.js
 *      captures their rapid keystrokes on the Sell screen (see wire()).
 *
 * A scanned code is matched against a variation's barcode OR SKU for the
 * active shop, so either identifier works.
 */
window.Scan = (function () {
  'use strict';

  const FORMATS = ['ean_13', 'ean_8', 'upc_a', 'upc_e', 'code_128', 'code_39', 'itf', 'codabar', 'qr_code', 'data_matrix'];

  function lookup(code) {
    const tid = Config.activeTenantId();
    const norm = String(code == null ? '' : code).trim();
    if (!norm) return null;
    return DB.get(
      `SELECT v.*, p.name AS product_name, p.id AS pid, p.image, p.category
       FROM variations v JOIN products p ON p.id = v.product_id
       WHERE v.tenant_id = ? AND v.active = 1 AND (v.barcode = ? OR v.sku = ?)
       LIMIT 1`, [tid, norm, norm]);
  }

  function cameraSupported() {
    return !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);
  }

  /* ---- Native BarcodeDetector engine ---- */
  async function runNative(video, onCode, stopRef) {
    const stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: 'environment' } }, audio: false
    });
    video.srcObject = stream;
    await video.play().catch(() => {});
    let supported = FORMATS;
    try { supported = (await window.BarcodeDetector.getSupportedFormats()) || FORMATS; } catch (e) {}
    const detector = new window.BarcodeDetector({
      formats: FORMATS.filter((f) => supported.includes(f))
    });
    let raf = null;
    async function tick() {
      if (stopRef.stopped) return;
      try {
        const codes = await detector.detect(video);
        if (codes && codes.length) onCode(codes[0].rawValue);
      } catch (e) {}
      raf = requestAnimationFrame(tick);
    }
    tick();
    return () => {
      stopRef.stopped = true;
      if (raf) cancelAnimationFrame(raf);
      stream.getTracks().forEach((t) => t.stop());
      video.srcObject = null;
    };
  }

  /* ---- ZXing fallback engine ---- */
  async function runZXing(video, onCode, stopRef) {
    if (!window.ZXing) throw new Error('Scanner library unavailable');
    const reader = new ZXing.BrowserMultiFormatReader();
    await reader.decodeFromVideoDevice(null, video, (result) => {
      if (result && !stopRef.stopped) onCode(result.getText());
    });
    return () => { stopRef.stopped = true; try { reader.reset(); } catch (e) {} };
  }

  // Starts the camera into `video`, calling onCode(text) for each read.
  // Returns a promise resolving to a stop() function.
  async function startCamera(video, onCode) {
    if (!cameraSupported()) throw new Error('This device has no accessible camera.');
    const stopRef = { stopped: false };
    if ('BarcodeDetector' in window) {
      try { return await runNative(video, onCode, stopRef); }
      catch (e) { /* fall through to ZXing */ }
    }
    return runZXing(video, onCode, stopRef);
  }

  return { lookup, startCamera, cameraSupported, FORMATS };
})();
