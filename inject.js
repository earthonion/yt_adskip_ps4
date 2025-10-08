(function(){
  if (window.__MH_SPONSORBLOCK_LOADED) { return; }
  window.__MH_SPONSORBLOCK_LOADED = true;

  var sponsorSegments = [];
  var currentVideoId = null;
  var segmentsSkipped = 0;

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

  setTimeout(function() {
    showToast('SponsorBlock Enabled', 'Sponsored segments will be automatically skipped');
  }, 2000);

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
              var data = JSON.parse(xhr.responseText);
              if (Array.isArray(data) && data.length > 0) {
                sponsorSegments = data;
                showToast('SponsorBlock', data.length + ' segment(s) found');
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

  function skipAds() {
    try {
      var video = document.querySelector('video');
      if (!video) return;
      var skipBtn = document.querySelector('.ytp-ad-skip-button-modern, .ytp-ad-skip-button');
      if (skipBtn) skipBtn.click();
      var adContainer = document.querySelector('.ad-showing');
      if (adContainer && video.duration && isFinite(video.duration)) {
        video.currentTime = video.duration;
      }
    } catch(e) {}
  }

  function skipSponsorSegments() {
    try {
      var video = document.querySelector('video');
      if (!video || video.paused || sponsorSegments.length === 0) return;
      var currentTime = video.currentTime;
      for (var i = 0; i < sponsorSegments.length; i++) {
        var seg = sponsorSegments[i].segment;
        if (currentTime >= seg[0] && currentTime < seg[1]) {
          video.currentTime = seg[1] + 0.1;
          segmentsSkipped++;
          showToast('Segment Skipped', sponsorSegments[i].category + ' (' + Math.floor(seg[1] - seg[0]) + 's)');
          break;
        }
      }
    } catch(e) {}
  }

  function checkVideoChange() {
    var videoId = getVideoId();
    if (videoId && videoId !== currentVideoId) {
      currentVideoId = videoId;
      sponsorSegments = [];
      segmentsSkipped = 0;
      loadSponsorBlock(videoId);
    }
  }

  setInterval(skipAds, 50);
  setInterval(skipSponsorSegments, 500);
  setInterval(checkVideoChange, 1000);
  checkVideoChange();
})();
