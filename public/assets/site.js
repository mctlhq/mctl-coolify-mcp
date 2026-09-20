(function () {
  var root = document.documentElement;

  var stored = null;
  try {
    stored = localStorage.getItem('coolify-mcp-theme');
  } catch (e) {}
  if (stored === 'light' || stored === 'dark') root.setAttribute('data-theme', stored);

  var toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.hidden = false;
    toggle.addEventListener('click', function () {
      var current = root.getAttribute('data-theme');
      if (!current) {
        current = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
      }
      var next = current === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try {
        localStorage.setItem('coolify-mcp-theme', next);
      } catch (e) {}
    });
  }

  var url = window.location.origin + '/mcp';
  var target = document.getElementById('mcp-url');
  if (target) target.textContent = url;
  Array.prototype.forEach.call(document.querySelectorAll('.mcp-url-slot'), function (slot) {
    slot.textContent = url;
  });
  Array.prototype.forEach.call(document.querySelectorAll('.mcp-cli-slot'), function (slot) {
    slot.textContent = 'claude mcp add --transport http coolify ' + url;
  });

  var copy = document.getElementById('copy-url');
  if (copy && navigator.clipboard) {
    copy.addEventListener('click', function () {
      navigator.clipboard.writeText(url).then(function () {
        copy.textContent = copy.dataset.done;
        setTimeout(function () {
          copy.textContent = copy.dataset.idle;
        }, 1600);
      });
    });
  } else if (copy) {
    copy.hidden = true;
  }
})();
