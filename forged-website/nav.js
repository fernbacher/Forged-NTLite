(function () {
  'use strict';

  // ── Mobile sidebar toggle ────────────────────────────────────
  var toggle = document.getElementById('navToggle');
  var sidebar = document.getElementById('sidebar');
  var overlay = document.getElementById('sidebarOverlay');

  function closeNav() {
    if (!sidebar || !overlay || !toggle) return;
    sidebar.classList.remove('open');
    overlay.classList.remove('visible');
    toggle.setAttribute('aria-expanded', 'false');
  }

  if (toggle && sidebar && overlay) {
    toggle.addEventListener('click', function () {
      var isOpen = sidebar.classList.toggle('open');
      overlay.classList.toggle('visible');
      toggle.setAttribute('aria-expanded', String(isOpen));
    });
    overlay.addEventListener('click', closeNav);
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') closeNav();
    });
  }

  // ── Hero logo animation replay (landing page only) ───────────
  var logoContainer = document.getElementById('logoContainer');
  if (logoContainer) {
    function restartAnimation() {
      var svg = logoContainer.querySelector('svg');
      if (!svg) return;
      svg.style.display = 'none';
      void svg.offsetHeight;
      svg.style.display = 'block';
    }
    logoContainer.addEventListener('click', restartAnimation);
    logoContainer.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        restartAnimation();
      }
    });
  }

  // ── Code panel — tabs, drag, resize, persist across pages ────
  (function initCodePanel() {
    var FILES = [
      {
        id: 'postinstall',
        label: 'PostInstall.ps1',
        rawUrl: 'https://raw.githubusercontent.com/fernbacher/Forged/main/payload/Forge-PostInstall.ps1',
        ghUrl: 'https://github.com/fernbacher/Forged/blob/main/payload/Forge-PostInstall.ps1',
        lang: 'ps'
      },
      {
        id: 'iso',
        label: 'forge-iso.sh',
        rawUrl: 'https://raw.githubusercontent.com/fernbacher/Forged/main/forge-iso.sh',
        ghUrl: 'https://github.com/fernbacher/Forged/blob/main/forge-iso.sh',
        lang: 'sh'
      }
    ];

    var STORAGE_KEY = 'forged-panel';

    // ── Persistence helpers ─────────────────────────────────────
    function loadState() {
      try {
        var raw = sessionStorage.getItem(STORAGE_KEY);
        return raw ? JSON.parse(raw) : {};
      } catch (e) { return {}; }
    }

    function saveState(updates) {
      try {
        var state = loadState();
        for (var k in updates) { state[k] = updates[k]; }
        sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state));
      } catch (e) { /* quota exceeded */ }
    }

    function cacheCode(id, text) {
      try { sessionStorage.setItem('forged-code-' + id, text); } catch (e) { /* ignore */ }
    }
    function getCachedCode(id) {
      try { return sessionStorage.getItem('forged-code-' + id); } catch (e) { return null; }
    }

    var saved = loadState();
    var activeFileId = saved.activeTab || 'postinstall';
    var isFloating = saved.floating === true;
    var mobileOpen = false;

    // ── Build panel DOM ──────────────────────────────────────────
    var panel = document.createElement('aside');
    panel.className = 'code-panel' + (isFloating ? ' floating' : '');
    panel.setAttribute('aria-label', 'Source code viewer');
    panel.id = 'codePanel';

    // Resize handles
    var handles = ['n', 'ne', 'e', 'se', 's', 'sw', 'w', 'nw']
      .map(function (d) { return '<div class="resize-handle resize-' + d + '" data-dir="' + d + '"></div>'; })
      .join('');

    // Build tab buttons
    var tabsHtml = FILES.map(function (f) {
      var activeClass = f.id === activeFileId ? ' active' : '';
      return '<button class="code-panel-tab' + activeClass + '" data-file="' + f.id + '">' + f.label + '</button>';
    }).join('');

    var activeFile = FILES.find(function (f) { return f.id === activeFileId; }) || FILES[0];

    panel.innerHTML =
      '<div class="code-panel-header" id="codePanelHeader">' +
        '<div class="code-panel-tabs">' + tabsHtml + '</div>' +
        '<div class="code-panel-actions">' +
          '<a href="' + activeFile.ghUrl + '" class="code-panel-gh-link" id="ghLink" target="_blank" rel="noopener noreferrer" title="Open on GitHub">GitHub</a>' +
          '<button class="code-panel-btn" id="popoutBtn" title="Pop out / Dock">' +
            '<svg class="popout-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="2" width="12" height="12" rx="2"/><line x1="9" y1="2" x2="9" y2="7"/><line x1="9" y1="7" x2="14" y2="7"/><polyline points="9 7 14 2"/></svg>' +
            '<svg class="dock-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="6" width="12" height="8" rx="2"/><line x1="7" y1="10" x2="7" y2="14"/><line x1="7" y1="14" x2="11" y2="14"/></svg>' +
          '</button>' +
        '</div>' +
      '</div>' +
      '<div class="code-panel-body" id="codePanelBody"><div class="code-panel-loading">Loading&hellip;</div></div>' +
      handles;

    document.body.appendChild(panel);
    var body = document.getElementById('codePanelBody');
    var header = document.getElementById('codePanelHeader');
    var ghLink = document.getElementById('ghLink');
    var popoutBtn = document.getElementById('popoutBtn');

    // Mark ready (makes it visible via CSS)
    panel.classList.add('ready');

    // ── Restore saved position/size ─────────────────────────────
    if (isFloating) {
      if (saved.left) panel.style.left = saved.left;
      if (saved.top) panel.style.top = saved.top;
      if (saved.width) panel.style.width = saved.width;
      if (saved.height) panel.style.height = saved.height;
      if (saved.left || saved.top) {
        // Remove default transform so custom position takes effect
        panel.style.transform = 'none';
      }
      var main = document.querySelector('.main-content');
      if (main && window.innerWidth >= 1500) main.style.marginRight = '0';
    }

    // ── Toggle button (narrow screens) ───────────────────────────
    var toggleBtn = document.createElement('button');
    toggleBtn.className = 'code-panel-toggle';
    toggleBtn.setAttribute('aria-label', 'Toggle source code panel');
    toggleBtn.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>';
    document.body.appendChild(toggleBtn);

    toggleBtn.addEventListener('click', function () {
      if (isFloating) {
        closeFloating();
        return;
      }
      mobileOpen = !mobileOpen;
      panel.classList.toggle('mobile-open', mobileOpen);
      toggleBtn.setAttribute('aria-expanded', String(mobileOpen));
    });

    // ── Pop-out / Dock ───────────────────────────────────────────
    function floatPanel() {
      isFloating = true;
      panel.classList.add('floating');
      panel.classList.remove('mobile-open');
      mobileOpen = false;
      toggleBtn.setAttribute('aria-expanded', 'false');
      panel.style.transform = 'none';
      var main = document.querySelector('.main-content');
      if (main && window.innerWidth >= 1500) main.style.marginRight = '0';
      saveState({ floating: true });
    }

    function dockPanel() {
      isFloating = false;
      panel.classList.remove('floating');
      panel.style.left = '';
      panel.style.top = '';
      panel.style.width = '';
      panel.style.height = '';
      panel.style.transform = '';
      var main = document.querySelector('.main-content');
      if (main && window.innerWidth >= 1500) main.style.marginRight = '';
      saveState({ floating: false, left: null, top: null, width: null, height: null });
    }

    function closeFloating() {
      panel.classList.add('floating');
      panel.style.display = 'none';
      mobileOpen = false;
      toggleBtn.setAttribute('aria-expanded', 'false');
    }

    popoutBtn.addEventListener('click', function () {
      if (isFloating) {
        dockPanel();
      } else {
        floatPanel();
        panel.style.display = '';
      }
    });

    // ── Drag ─────────────────────────────────────────────────────
    var dragging = false;
    var dragStartX, dragStartY, panelStartLeft, panelStartTop;

    header.addEventListener('mousedown', function (e) {
      if (!isFloating) return;
      if (e.target.closest('button') || e.target.closest('a')) return;
      dragging = true;
      dragStartX = e.clientX;
      dragStartY = e.clientY;
      panelStartLeft = panel.offsetLeft;
      panelStartTop = panel.offsetTop;
      panel.style.transition = 'none';
      document.body.style.userSelect = 'none';
      e.preventDefault();
    });

    document.addEventListener('mousemove', function (e) {
      if (!dragging) return;
      var dx = e.clientX - dragStartX;
      var dy = e.clientY - dragStartY;
      var newLeft = panelStartLeft + dx;
      var newTop = panelStartTop + dy;
      newLeft = Math.max(0, Math.min(newLeft, window.innerWidth - panel.offsetWidth));
      newTop = Math.max(0, Math.min(newTop, window.innerHeight - 60));
      panel.style.left = newLeft + 'px';
      panel.style.top = newTop + 'px';
      panel.style.transform = 'none';
    });

    document.addEventListener('mouseup', function () {
      if (!dragging) return;
      dragging = false;
      panel.style.transition = '';
      document.body.style.userSelect = '';
      saveState({ left: panel.style.left, top: panel.style.top });
    });

    // Touch drag
    header.addEventListener('touchstart', function (e) {
      if (!isFloating) return;
      if (e.target.closest('button') || e.target.closest('a')) return;
      dragging = true;
      dragStartX = e.touches[0].clientX;
      dragStartY = e.touches[0].clientY;
      panelStartLeft = panel.offsetLeft;
      panelStartTop = panel.offsetTop;
      panel.style.transition = 'none';
    }, { passive: false });

    document.addEventListener('touchmove', function (e) {
      if (!dragging) return;
      var dx = e.touches[0].clientX - dragStartX;
      var dy = e.touches[0].clientY - dragStartY;
      var newLeft = panelStartLeft + dx;
      var newTop = panelStartTop + dy;
      newLeft = Math.max(0, Math.min(newLeft, window.innerWidth - panel.offsetWidth));
      newTop = Math.max(0, Math.min(newTop, window.innerHeight - 60));
      panel.style.left = newLeft + 'px';
      panel.style.top = newTop + 'px';
      panel.style.transform = 'none';
    }, { passive: false });

    document.addEventListener('touchend', function () {
      if (!dragging) return;
      dragging = false;
      panel.style.transition = '';
      saveState({ left: panel.style.left, top: panel.style.top });
    });

    // ── Resize ───────────────────────────────────────────────────
    var resizing = false;
    var resizeDir = '';
    var resizeStartX, resizeStartY, resizeStartW, resizeStartH, resizeStartL, resizeStartT;

    var resizeHandles = panel.querySelectorAll('.resize-handle');
    for (var i = 0; i < resizeHandles.length; i++) {
      resizeHandles[i].addEventListener('mousedown', function (e) {
        if (!isFloating) return;
        resizing = true;
        resizeDir = this.getAttribute('data-dir');
        resizeStartX = e.clientX;
        resizeStartY = e.clientY;
        resizeStartW = panel.offsetWidth;
        resizeStartH = panel.offsetHeight;
        resizeStartL = panel.offsetLeft;
        resizeStartT = panel.offsetTop;
        panel.style.transition = 'none';
        document.body.style.userSelect = 'none';
        this.classList.add('active');
        e.preventDefault();
        e.stopPropagation();
      });
    }

    document.addEventListener('mousemove', function (e) {
      if (!resizing) return;
      var dx = e.clientX - resizeStartX;
      var dy = e.clientY - resizeStartY;
      var dir = resizeDir;
      var newW = resizeStartW;
      var newH = resizeStartH;
      var newL = resizeStartL;
      var newT = resizeStartT;
      var minW = 320;
      var minH = 240;

      if (dir.indexOf('e') !== -1) newW = Math.max(minW, resizeStartW + dx);
      if (dir.indexOf('w') !== -1) { newW = Math.max(minW, resizeStartW - dx); newL = resizeStartL + (resizeStartW - newW); }
      if (dir.indexOf('s') !== -1) newH = Math.max(minH, resizeStartH + dy);
      if (dir.indexOf('n') !== -1) { newH = Math.max(minH, resizeStartH - dy); newT = resizeStartT + (resizeStartH - newH); }

      if (newL < 0) { newW += newL; newL = 0; }
      if (newT < 0) { newH += newT; newT = 0; }
      if (newL + newW > window.innerWidth) newW = window.innerWidth - newL;
      if (newT + newH > window.innerHeight) newH = window.innerHeight - newT;

      panel.style.width = newW + 'px';
      panel.style.height = newH + 'px';
      panel.style.left = newL + 'px';
      panel.style.top = newT + 'px';
      panel.style.transform = 'none';
    });

    document.addEventListener('mouseup', function () {
      if (!resizing) return;
      resizing = false;
      panel.style.transition = '';
      document.body.style.userSelect = '';
      for (var j = 0; j < resizeHandles.length; j++) resizeHandles[j].classList.remove('active');
      saveState({ left: panel.style.left, top: panel.style.top, width: panel.style.width, height: panel.style.height });
    });

    // ── Keyboard: Escape docks ──────────────────────────────────
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && isFloating && panel.style.display !== 'none') {
        dockPanel();
      }
    });

    // ── Tab switching ────────────────────────────────────────────
    var tabButtons = panel.querySelectorAll('.code-panel-tab');

    function switchTab(fileId) {
      activeFileId = fileId;
      var file = FILES.find(function (f) { return f.id === fileId; }) || FILES[0];

      // Update active tab styling
      for (var i = 0; i < tabButtons.length; i++) {
        tabButtons[i].classList.toggle('active', tabButtons[i].getAttribute('data-file') === fileId);
      }

      // Update GitHub link
      ghLink.href = file.ghUrl;
      saveState({ activeTab: fileId });

      // Show cached content or fetch
      var cached = getCachedCode(fileId);
      if (cached) {
        body.innerHTML = '<pre><code>' + highlight(cached, file.lang) + '</code></pre>';
        return;
      }

      body.innerHTML = '<div class="code-panel-loading">Loading&hellip;</div>';

      fetch(file.rawUrl)
        .then(function (res) {
          if (!res.ok) throw new Error('HTTP ' + res.status);
          return res.text();
        })
        .then(function (text) {
          cacheCode(fileId, text);
          body.innerHTML = '<pre><code>' + highlight(text, file.lang) + '</code></pre>';
        })
        .catch(function () {
          body.innerHTML =
            '<div class="code-panel-error">' +
              '<span>Couldn&rsquo;t load the script.</span>' +
              '<a href="' + file.ghUrl + '" target="_blank" rel="noopener noreferrer">Open on GitHub</a>' +
            '</div>';
        });
    }

    for (var ti = 0; ti < tabButtons.length; ti++) {
      tabButtons[ti].addEventListener('click', function () {
        switchTab(this.getAttribute('data-file'));
      });
    }

    // ── Highlighters ─────────────────────────────────────────────
    function highlight(code, lang) {
      if (lang === 'sh') return highlightSH(code);
      return highlightPS(code);
    }

    function highlightPS(code) {
      var lines = code.split('\n');
      var out = [];
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        if (/^\s*#/.test(line) || /^\s*<#/.test(line) || /^\s*#>/.test(line)) {
          out.push('<span class="ps-comment">' + esc(line) + '</span>');
          continue;
        }
        var hl = esc(line)
          .replace(/\b(function|param|process|begin|end|return|if|else|elseif|foreach|for|while|do|switch|try|catch|finally|throw|exit|break|continue|Write-Host|Write-Output|Write-Error|Write-Warning|Set-ItemProperty|New-Item|Remove-Item|Get-Item|Get-ChildItem|Start-Service|Stop-Service|Set-Service|New-Service|Get-Service|Invoke-Command|Start-Process|Stop-Process|Get-Process|Out-Null|Where-Object|ForEach-Object|Select-Object|New-Object)\b/gi, '<span class="ps-keyword">$1</span>')
          .replace(/(''[^']*''|"[^"]*")/g, '<span class="ps-string">$1</span>')
          .replace(/(\$\w[\w-]*)/g, '<span class="ps-variable">$1</span>')
          .replace(/(-[A-Za-z]+)\b/g, '<span class="ps-param">$1</span>');
        out.push(hl);
      }
      return out.join('\n');
    }

    function highlightSH(code) {
      var lines = code.split('\n');
      var out = [];
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        if (/^\s*#/.test(line)) {
          out.push('<span class="sh-comment">' + esc(line) + '</span>');
          continue;
        }
        var hl = esc(line)
          .replace(/\b(echo|cd|ls|cp|mv|rm|mkdir|chmod|chown|export|source|exit|return|if|then|else|elif|fi|for|while|do|done|case|esac|function|local|read|set|unset|trap|sudo|pacman|apt|dnf|git|7z|wimlib-imagex|xorrisofs|tee)\b/gi, '<span class="sh-keyword">$1</span>')
          .replace(/\b(wimlib-imagex|p7zip|libisoburn|python3|wimtools|xorriso|wimlib-utils|forge-iso\.sh)\b/gi, '<span class="sh-builtin">$1</span>')
          .replace(/("[^"]*"|'[^']*')/g, '<span class="sh-string">$1</span>')
          .replace(/(\$\{?\w+[\w-]*\}?)/g, '<span class="ps-variable">$1</span>');
        out.push(hl);
      }
      return out.join('\n');
    }

    function esc(s) {
      return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    // ── Initial load ─────────────────────────────────────────────
    switchTab(activeFileId);
  })();
})();
