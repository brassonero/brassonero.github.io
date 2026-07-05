// =============================================
// THE WARRIORS — /eventos
// =============================================
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var RM = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  var PAGE_URL = 'https://thewarriors.mx/eventos';
  var EVENT_START = new Date('2026-07-18T21:00:00-06:00');
  var EVENT_END = new Date('2026-07-19T06:00:00-06:00');

  // ===========================================================
  // 1. AMBIENT BACKGROUND — starfield + perspective grid
  // ===========================================================

  var cv = $('bg'), ctx = cv.getContext('2d');
  var W = 0, H = 0, DPR = 1, stars = [];

  function resize() {
    DPR = Math.min(window.devicePixelRatio || 1, 2);
    W = window.innerWidth; H = window.innerHeight;
    cv.width = W * DPR; cv.height = H * DPR;
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    makeStars();
    if (RM) drawBG(0);
  }

  function makeStars() {
    stars = [];
    var n = Math.round((W * H) / 9000);
    for (var i = 0; i < n; i++) {
      stars.push({
        x: Math.random() * W,
        y: Math.random() * H,
        r: Math.random() < 0.82 ? 1 : 1.6,
        gold: Math.random() < 0.12,
        ph: Math.random() * Math.PI * 2,
        sp: 0.4 + Math.random() * 1.1
      });
    }
  }

  function drawBG(t) {
    ctx.fillStyle = '#0e0c0a';
    ctx.fillRect(0, 0, W, H);

    // stars
    for (var i = 0; i < stars.length; i++) {
      var s = stars[i];
      var a = 0.18 + 0.32 * (0.5 + 0.5 * Math.sin(t * 0.001 * s.sp + s.ph));
      ctx.fillStyle = s.gold
        ? 'rgba(255,204,51,' + (a * 0.9).toFixed(3) + ')'
        : 'rgba(190,215,195,' + a.toFixed(3) + ')';
      ctx.fillRect(s.x, s.y, s.r, s.r);
    }

    // perspective grid floor
    var horizon = H * 0.58, cx = W * 0.5;
    ctx.lineWidth = 1;

    ctx.strokeStyle = 'rgba(200,60,30,0.10)';
    for (var k = -7; k <= 7; k++) {
      ctx.beginPath();
      ctx.moveTo(cx, horizon);
      ctx.lineTo(cx + k * W * 0.15, H + 40);
      ctx.stroke();
    }

    for (var j = 0; j < 9; j++) {
      var dd = (j / 9 + t * 0.000125) % 1;
      var y = horizon + (H - horizon) * dd * dd;
      ctx.strokeStyle = 'rgba(200,60,30,' + (0.04 + 0.28 * dd).toFixed(3) + ')';
      ctx.beginPath();
      ctx.moveTo(0, y); ctx.lineTo(W, y);
      ctx.stroke();
    }

    ctx.strokeStyle = 'rgba(200,60,30,0.18)';
    ctx.beginPath();
    ctx.moveTo(0, horizon); ctx.lineTo(W, horizon);
    ctx.stroke();

    // green signal wave on the horizon
    ctx.strokeStyle = 'rgba(45,170,90,0.30)';
    ctx.beginPath();
    for (var x = 0; x <= W; x += 8) {
      var wy = horizon - 6 + Math.sin(x * 0.02 + t * 0.0012) * 3;
      if (x === 0) ctx.moveTo(x, wy); else ctx.lineTo(x, wy);
    }
    ctx.stroke();
  }

  function loop(t) {
    drawBG(t);
    requestAnimationFrame(loop);
  }

  window.addEventListener('resize', resize);
  resize();
  if (!RM) requestAnimationFrame(loop);

  // ===========================================================
  // 2. COUNTDOWN
  // ===========================================================

  var cdD = $('cdD'), cdH = $('cdH'), cdM = $('cdM'), cdS = $('cdS');
  var cdBox = $('countdown'), cdStatus = $('cdStatus');
  var cdTimer = null;

  function pad(n) { return (n < 10 ? '0' : '') + n; }

  function tickCountdown() {
    var now = Date.now();
    if (now >= EVENT_END.getTime()) {
      cdBox.classList.add('over');
      cdStatus.textContent = 'TRANSMISIÓN FINALIZADA // GRACIAS GUERREROS';
      cdStatus.className = 'cd-status done';
      clearInterval(cdTimer);
      return;
    }
    if (now >= EVENT_START.getTime()) {
      cdBox.classList.add('over');
      cdStatus.textContent = 'EN VIVO // HASTA EL AMANECER';
      cdStatus.className = 'cd-status live';
      return;
    }
    var diff = Math.floor((EVENT_START.getTime() - now) / 1000);
    var d = Math.floor(diff / 86400);
    var h = Math.floor((diff % 86400) / 3600);
    var m = Math.floor((diff % 3600) / 60);
    var s = diff % 60;
    cdD.textContent = pad(d);
    cdH.textContent = pad(h);
    cdM.textContent = pad(m);
    cdS.textContent = pad(s);
  }

  tickCountdown();
  cdTimer = setInterval(tickCountdown, 1000);

  // ===========================================================
  // 3. POSTER — tilt + lightbox
  // ===========================================================

  var frame = $('posterFrame');
  var canTilt = !RM && window.matchMedia('(hover: hover) and (pointer: fine)').matches;

  if (canTilt) {
    frame.addEventListener('pointermove', function (e) {
      var r = frame.getBoundingClientRect();
      var nx = (e.clientX - r.left) / r.width - 0.5;
      var ny = (e.clientY - r.top) / r.height - 0.5;
      frame.style.setProperty('--rx', (-ny * 8).toFixed(2) + 'deg');
      frame.style.setProperty('--ry', (nx * 10).toFixed(2) + 'deg');
    });
    frame.addEventListener('pointerleave', function () {
      frame.style.setProperty('--rx', '0deg');
      frame.style.setProperty('--ry', '0deg');
    });
  }

  var lb = $('lightbox'), lbClose = $('lbClose');
  var mqExpand = window.matchMedia('(min-width: 880px)');

  function openLB() {
    lb.hidden = false;
    document.body.style.overflow = 'hidden';
    lbClose.focus();
  }

  function closeLB() {
    lb.hidden = true;
    document.body.style.overflow = '';
    frame.focus();
  }

  frame.addEventListener('click', function () {
    if (!mqExpand.matches) return;   // expand disabled on mobile
    openLB();
  });
  lbClose.addEventListener('click', closeLB);
  lb.addEventListener('click', function (e) { if (e.target === lb) closeLB(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !lb.hidden) closeLB();
  });

  // ===========================================================
  // 4. SHARE + CALENDAR
  // ===========================================================

  var shareTitle = 'EL PRIMATE GALÁCTICO — LOS WARRIORS';
  var shareText = 'EL PRIMATE GALÁCTICO 🦍🚀 — LOS WARRIORS\n' +
    'Sábado 18 de julio · 9 PM hasta el amanecer\n' +
    'Música electrónica & vibras bohemias 🔥 Fogata mística · Show de fuego · Percusiones';

  var waHref = 'https://wa.me/?text=' + encodeURIComponent(shareText + '\n\n' + PAGE_URL);
  var shareBtn = $('shareBtn');
  shareBtn.href = waHref;

  if (navigator.share) {
    shareBtn.addEventListener('click', function (e) {
      e.preventDefault();
      navigator.share({ title: shareTitle, text: shareText, url: PAGE_URL })
        .catch(function () { /* usuario canceló */ });
    });
  } else {
    shareBtn.target = '_blank';
    shareBtn.rel = 'noopener';
  }

  var calHref = 'https://calendar.google.com/calendar/render?action=TEMPLATE' +
    '&text=' + encodeURIComponent('El Primate Galáctico — Los Warriors') +
    '&dates=' + encodeURIComponent('20260719T030000Z/20260719T120000Z') +
    '&details=' + encodeURIComponent('Música electrónica & vibras bohemias · Fogata mística, show de fuego y percusiones.\nInfo: ' + PAGE_URL) +
    '&location=' + encodeURIComponent('Por anunciar');
  $('calBtn').href = calHref;

})();
