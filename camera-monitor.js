// Wrap the code in a function that runs immediately.
// This keeps the variables inside private to this script.
(() => {

  // This script runs in the MAIN world, meaning it can observe
  // camera streams created by the actual website.
  // It does not capture, store, or send camera images or audio.

  // Get the browser's mediaDevices API, which websites use to access cameras and microphones.
  const mediaDevices = navigator.mediaDevices;

  // Check whether the browser supports getUserMedia.
  // If it doesn't, stop running this script.
  if (!mediaDevices || typeof mediaDevices.getUserMedia !== "function") return;

  // Save the original getUserMedia function so we can still use it later.
  // bind() makes sure it continues to run with the correct browser context.
  const originalGetUserMedia = mediaDevices.getUserMedia.bind(mediaDevices);

  // Create a Set to keep track of camera video tracks that are currently active.
  // A Set prevents the same track from being added more than once.
  const activeVideoTracks = new Set();

  // Remember the last number of active camera tracks we reported.
  // This helps prevent sending unnecessary repeated messages.
  let lastCount = 0;

  // Count active camera tracks and report changes to the extension.
  function report() {

    // Count only tracks that are still marked as live by the browser.
    const count = [...activeVideoTracks].filter(track => track.readyState === "live").length;

    // If the number hasn't changed, there is no need to send another message.
    if (count === lastCount) return;

    // Save the new count so we can compare it next time.
    lastCount = count;

    // Send a message to other scripts on the same page.
    // PrivacyGuard uses this message to update its camera activity status.
    window.postMessage({
      privacyGuardCamera: true, // Identifies this message as coming from PrivacyGuard.
      type: count > 0 ? "CAMERA_ACTIVE" : "CAMERA_INACTIVE", // Report whether a camera is active.
      count // Include the number of active camera tracks.
    }, "*"); // Allow the message to be sent regardless of the page's origin.
  }

  // Remove a camera track from our tracking Set when it stops.
  function trackEnded(track) {
    activeVideoTracks.delete(track);
    report(); // Update the reported camera activity.
  }

  // Start watching a camera stream returned by getUserMedia.
  function watchStream(stream) {

    // Get every video track in the stream.
    // A stream can contain more than one video track.
    for (const track of stream.getVideoTracks()) {

      // Ignore tracks that have already stopped or are already being tracked.
      if (track.readyState !== "live" || activeVideoTracks.has(track)) continue;

      // Add this active camera track to our Set.
      activeVideoTracks.add(track);

      // Save the track's original stop() function.
      // This lets us detect when the website stops its camera track.
      const originalStop = track.stop.bind(track);

      try {
        // Wrap the stop() function so PrivacyGuard can detect when it is called.
        track.stop = function (...args) {

          // Run the browser's original stop() function.
          const result = originalStop(...args);

          // Remove the track from our active tracking list.
          trackEnded(track);

          // Return the original function's result.
          return result;
        };
      } catch (_) {
        // If the browser prevents us from replacing stop(),
        // the ended event below can still detect when the track stops.
      }

      // Listen for the browser's ended event.
      // This is another way to detect when a camera track has stopped.
      // once: true means this listener only needs to run one time.
      track.addEventListener("ended", () => trackEnded(track), { once: true });
    }

    // Report the current number of active camera tracks.
    report();
  }

  try {
    // Replace getUserMedia with our own wrapper.
    // This allows PrivacyGuard to observe camera requests made by the website.
    Object.defineProperty(mediaDevices, "getUserMedia", {
      configurable: true, // Allows this property to be changed again.
      writable: true,     // Allows the function to be replaced.
      value: async function (constraints) {

        // Call the original browser function to request camera or microphone access.
        const stream = await originalGetUserMedia(constraints);

        // Only monitor the stream if the website requested video.
        // Audio-only requests are not treated as camera activity.
        if (constraints?.video) watchStream(stream);

        // Return the original stream so the website continues working normally.
        return stream;
      }
    });

  } catch (_) {
    // Some websites may prevent this API from being replaced.
    // In that case, the browser's own camera indicator remains available.
  }

  // Listen for messages asking PrivacyGuard to stop active camera tracks.
  window.addEventListener("message", event => {

    // Only accept messages coming from this same page window
    // and containing the correct PrivacyGuard stop command.
    if (event.source !== window || event.data?.privacyGuardCameraCommand !== "STOP_ACTIVE_CAMERA") return;

    // Go through every camera track that PrivacyGuard is currently tracking.
    for (const track of [...activeVideoTracks]) {
      try {
        // Stop the camera track.
        track.stop();
      } catch (_) {
        // Ignore errors if the browser cannot stop a particular track.
      }

      // Remove the track from our tracking Set and update the status.
      trackEnded(track);
    }
  });

})(); // Immediately run the function.
