(function(){
  if (window.__MH_ADSKIP_READY) { return; }
  window.__MH_ADSKIP_READY = true;

  try {
    var bannerId = '__MH_ADSKIP_BANNER';
    if (!document.getElementById(bannerId)) {
      var banner = document.createElement('div');
      banner.id = bannerId;
      banner.textContent = 'Ad skip enabled';
      banner.style.position = 'fixed';
      banner.style.left = '10px';
      banner.style.bottom = '10px';
      banner.style.zIndex = '2147483647';
      banner.style.background = 'rgba(0,0,0,0.8)';
      banner.style.color = '#00FF99';
      banner.style.padding = '8px 14px';
      banner.style.font = '16px/1.2 sans-serif';
      banner.style.borderRadius = '4px';
      banner.style.boxShadow = '0 3px 10px rgba(0,0,0,0.4)';
      document.documentElement.appendChild(banner);
      setTimeout(function(){
        try {
          var b = document.getElementById(bannerId);
          if (b) b.remove();
        } catch (_) {}
      }, 4000);
    }
  } catch (_) {}

  setInterval(function(){
    try {
      var videos = document.getElementsByClassName('html5-main-video');
      if (document.getElementsByClassName('ad-showing').length > 0 && videos.length > 0) {
        var vid = videos[0];
        if (vid && typeof vid.duration === 'number' && isFinite(vid.duration) && vid.duration > 0) {
          vid.currentTime = vid.duration;
        }
      }
    } catch (_) {}
  }, 50);
})();
