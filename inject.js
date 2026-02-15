(function(){
  if (window.__MH_SPONSORBLOCK_LOADED) { return; }
  window.__MH_SPONSORBLOCK_LOADED = true;

  // ── Toast helper (unchanged) ──────────────────────────────────────
  function showToast(title, subtitle) {
    try {
      var popupAction = {
        openPopupAction: {
          popupType: 'TOAST',
          popup: {
            overlayToastRenderer: {
              title: { simpleText: title },
              subtitle: { simpleText: subtitle }
            }
          }
        }
      };
      for (var key in window._yttv) {
        if (window._yttv[key] && window._yttv[key].instance && window._yttv[key].instance.resolveCommand) {
          window._yttv[key].instance.resolveCommand(popupAction);
          break;
        }
      }
    } catch(e) {}
  }

  // ── 1. JSON.parse monkey-patch (from TizenTube) ──────────────────
  // Intercept YouTube API responses and strip ad data before rendering.
  // Uses delete (not empty array) so downstream truthiness checks work.
  var origParse = JSON.parse;
  JSON.parse = function() {
    var r = origParse.apply(this, arguments);
    if (r && typeof r === 'object' && !Array.isArray(r)) {
      if (r.adPlacements) { delete r.adPlacements; }
      if (r.playerAds)    { delete r.playerAds; }
      if (r.adSlots)      { delete r.adSlots; }
    }
    return r;
  };

  // Patch across all YouTube TV internal contexts (once, like TizenTube)
  window.JSON.parse = JSON.parse;
  try {
    for (var key in window._yttv) {
      if (window._yttv[key] && window._yttv[key].JSON && window._yttv[key].JSON.parse) {
        window._yttv[key].JSON.parse = JSON.parse;
      }
    }
  } catch(e) {}

  // ── 2. SponsorBlock — event-driven segment skipping ──────────────
  var sponsorSegments = [];
  var currentVideoId = null;
  var currentVideo = null;
  var skipTimeout = null;
  var skippedMap = {};  // UUID -> { count, firstSkipped, lastSkipped }

  function getVideoId() {
    try {
      var match = window.location.hash.match(/[?&]v=([^&]+)/);
      return match ? match[1] : null;
    } catch(e) {
      return null;
    }
  }

  function loadSponsorBlock(videoId) {
    if (!videoId) return;
    var tryPort = function(port) {
      try {
        var xhr = new XMLHttpRequest();
        var url = 'http://127.0.0.1:' + port + '/' + encodeURIComponent(videoId);
        xhr.timeout = 2000;
        xhr.onload = function() {
          if (xhr.status === 200) {
            try {
              var data = origParse(xhr.responseText);
              if (Array.isArray(data) && data.length > 0) {
                sponsorSegments = data;
                showToast('SponsorBlock', data.length + ' segment(s) found');
                // Kick off event-driven skipping now that segments are loaded
                scheduleSkip();
              } else {
                sponsorSegments = [];
              }
            } catch(e) {}
          }
        };
        xhr.onerror = function() { if (port < 4050) tryPort(port + 1); };
        xhr.ontimeout = function() { if (port < 4050) tryPort(port + 1); };
        xhr.open('GET', url, true);
        xhr.send();
      } catch(e) {
        if (port < 4050) tryPort(port + 1);
      }
    };
    tryPort(4040);
  }

  // Event-driven skip scheduling (adapted from TizenTube)
  function scheduleSkip() {
    if (skipTimeout) {
      clearTimeout(skipTimeout);
      skipTimeout = null;
    }

    if (!currentVideo || currentVideo.paused || sponsorSegments.length === 0) return;

    var now = currentVideo.currentTime;

    // Find the next segment that hasn't been fully passed yet
    var nextSegments = [];
    for (var i = 0; i < sponsorSegments.length; i++) {
      var seg = sponsorSegments[i].segment;
      if (seg[0] > now - 0.3 && seg[1] > now - 0.3) {
        nextSegments.push(sponsorSegments[i]);
      }
    }
    nextSegments.sort(function(a, b) { return a.segment[0] - b.segment[0]; });

    if (nextSegments.length === 0) return;

    var segment = nextSegments[0];
    var start = segment.segment[0];
    var end = segment.segment[1];
    var delay = (start - now) * 1000;

    skipTimeout = setTimeout(function() {
      if (!currentVideo || currentVideo.paused) return;

      // Infinite-loop protection (from TizenTube): if we've skipped
      // the same segment multiple times within 1 second, stop.
      var uuid = segment.UUID || (segment.category + '_' + start + '_' + end);
      var prev = skippedMap[uuid];
      if (prev) {
        prev.count++;
        prev.lastSkipped = Date.now();
        if (prev.lastSkipped - prev.firstSkipped < 1000) {
          return; // likely an infinite skip loop, bail out
        }
      } else {
        skippedMap[uuid] = { count: 1, firstSkipped: Date.now(), lastSkipped: Date.now() };
      }

      var skipName = segment.category;
      showToast('Segment Skipped', skipName + ' (' + Math.floor(end - start) + 's)');

      // Avoid seeking to the very end of the video
      if (currentVideo.duration - end < 1) {
        currentVideo.currentTime = end - 1;
      } else {
        currentVideo.currentTime = end;
      }

      // Schedule the next segment
      scheduleSkip();
    }, Math.max(delay, 0));
  }

  function onScheduleSkip() {
    scheduleSkip();
  }

  // ── 3. Video attachment & cleanup ─────────────────────────────────
  function detachVideo() {
    if (currentVideo) {
      currentVideo.removeEventListener('play', onScheduleSkip);
      currentVideo.removeEventListener('pause', onScheduleSkip);
      currentVideo.removeEventListener('timeupdate', onScheduleSkip);
      currentVideo = null;
    }
    if (skipTimeout) {
      clearTimeout(skipTimeout);
      skipTimeout = null;
    }
  }

  function attachVideo() {
    detachVideo();
    var video = document.querySelector('video');
    if (!video) {
      setTimeout(attachVideo, 200);
      return;
    }
    currentVideo = video;
    currentVideo.addEventListener('play', onScheduleSkip);
    currentVideo.addEventListener('pause', onScheduleSkip);
    currentVideo.addEventListener('timeupdate', onScheduleSkip);
  }

  // ── 4. Video change detection via hashchange event ────────────────
  function onVideoChange() {
    var videoId = getVideoId();
    if (videoId && videoId !== currentVideoId) {
      currentVideoId = videoId;
      sponsorSegments = [];
      skippedMap = {};
      attachVideo();
      loadSponsorBlock(videoId);
    }
  }

  window.addEventListener('hashchange', onVideoChange, false);

  // Initial check
  onVideoChange();

  setTimeout(function() {
    showToast('Ad Block + SponsorBlock Enabled!', 'by earthonion');
  }, 2000);
})();
