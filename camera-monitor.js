(() => {
  // MAIN-world hook: observes camera streams created by this page.
  // It does not capture, store, or transmit camera images/audio.
  const mediaDevices = navigator.mediaDevices;
  if (!mediaDevices || typeof mediaDevices.getUserMedia !== "function") return;

  const originalGetUserMedia = mediaDevices.getUserMedia.bind(mediaDevices);
  const activeVideoTracks = new Set();
  let lastCount = 0;

  function report() {
    const count = [...activeVideoTracks].filter(track => track.readyState === "live").length;
    if (count === lastCount) return;
    lastCount = count;
    window.postMessage({
      privacyGuardCamera: true,
      type: count > 0 ? "CAMERA_ACTIVE" : "CAMERA_INACTIVE",
      count
    }, "*");
  }

  function trackEnded(track) {
    activeVideoTracks.delete(track);
    report();
  }

  function watchStream(stream) {
    for (const track of stream.getVideoTracks()) {
      if (track.readyState !== "live" || activeVideoTracks.has(track)) continue;
      activeVideoTracks.add(track);

      const originalStop = track.stop.bind(track);
      try {
        track.stop = function (...args) {
          const result = originalStop(...args);
          trackEnded(track);
          return result;
        };
      } catch (_) {
        // The ended event below remains a fallback if stop cannot be wrapped.
      }
      track.addEventListener("ended", () => trackEnded(track), { once: true });
    }
    report();
  }

  try {
    Object.defineProperty(mediaDevices, "getUserMedia", {
      configurable: true,
      writable: true,
      value: async function (constraints) {
        const stream = await originalGetUserMedia(constraints);
        if (constraints?.video) watchStream(stream);
        return stream;
      }
    });
  } catch (_) {
    // Some pages may prevent API wrapping; Chrome's own camera indicator remains available.
  }

  window.addEventListener("message", event => {
    if (event.source !== window || event.data?.privacyGuardCameraCommand !== "STOP_ACTIVE_CAMERA") return;
    for (const track of [...activeVideoTracks]) {
      try { track.stop(); } catch (_) {}
      trackEnded(track);
    }
  });
})();
