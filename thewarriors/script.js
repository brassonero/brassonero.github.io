// =============================================
// THE WARRIORS — Game Script
// =============================================
// Sections:
//   1. CONFIG
//   2. STATE
//   3. CORRIDOR (perspective math)
//   4. ENTITIES (player, enemies, particles, combat)
//   5. RENDERER (canvas drawing)
//   6. INPUT (keyboard + mobile touch)
//   7. UI (HUD + screens)
//   8. GAME LOOP
//   9. BOOT
// =============================================

(function () {
  'use strict';

  // ===========================================================
  // 1. CONFIG
  // ===========================================================

  const COLORS = {
    RED: '#c83c1e',
    RED_B: '#e04a26',
    RED_G: '#ff5533',
    GRN: '#2daa5a',
    GRN_B: '#3ddd6a',
    GRN_D: '#1e7a3e',
    DARK: '#0e0c0a',
  };

  const CORRIDOR_CFG = {
    VP_X: 0.5,
    VP_Y: 0.38,
    FLOOR_Y: 0.85,
    CEIL_Y: 0.08,
  };

  const PLAYER_CFG = {
    DEPTH: 0.05,
    LANE_SCALE: 0.7,
    MOVE_SPEED: 0.04,
    LERP: 0.15,
    SIZE_FACTOR: 0.07,
    ATTACK_CD: 12,
    ATTACK_RANGE: 0.18,
    ATTACK_DEPTH: 0.5,
  };

  const SPAWN_CFG = {
    BASE_INTERVAL: 80,
    MIN_INTERVAL: 20,
    WAVE_REDUCTION: 8,
    BASE_SPEED: 0.003,
    WAVE_SPEED: 0.0008,
    RAND_SPEED: 0.002,
    FAST_CHANCE: 0.3,
    FAST_MULT: 1.5,
  };

  const WAVE_CFG = {
    BASE_KILLS: 5,
    KILLS_PER_WAVE: 3,
  };

  const ENEMY_CHARS = ['伪', '敌', '鬼', '魔'];
  const PARTICLE_CHARS = ['斩', '破', '灭', '击'];

  const VERDICTS = [
    { min: 10000, cn: '真战士', en: 'TRUE WARRIOR' },
    { min: 5000, cn: '战士', en: 'WARRIOR' },
    { min: 1000, cn: '学徒', en: 'APPRENTICE' },
    { min: 0, cn: '伪战士', en: 'FALSE WARRIOR' },
  ];


  // ===========================================================
  // 2. STATE
  // ===========================================================

  const S = {
    phase: 'title',
    score: 0, hi: 0, wave: 1, lives: 3,
    combo: 0, maxCombo: 0,
    playerX: 0, playerY: 0,
    targetX: 0, targetY: 0,
    attackCooldown: 0,
    spawnTimer: 60, waveTimer: 0,
    shakeT: 0, flashT: 0, tick: 0,
    enemies: [], particles: [], enemiesKilled: 0,
    W: 0, H: 0, cx: 0, cy: 0,
  };

  function resetState() {
    S.phase = 'playing';
    S.score = 0; S.wave = 1; S.lives = 3;
    S.combo = 0; S.maxCombo = 0;
    S.playerX = 0; S.playerY = 0;
    S.targetX = 0; S.targetY = 0;
    S.attackCooldown = 0;
    S.spawnTimer = 60; S.waveTimer = 0;
    S.shakeT = 0; S.flashT = 0;
    S.enemies = []; S.particles = []; S.enemiesKilled = 0;
  }


  // ===========================================================
  // 3. CORRIDOR
  // ===========================================================

  function corridorX(laneX, depth) {
    const vpx = CORRIDOR_CFG.VP_X * S.W;
    const near = S.cx + laneX * S.W * 0.45;
    return near + (vpx - near) * depth;
  }

  function corridorY(laneY, depth) {
    const vpy = CORRIDOR_CFG.VP_Y * S.H;
    const near = (laneY < 0 ? CORRIDOR_CFG.CEIL_Y : CORRIDOR_CFG.FLOOR_Y) * S.H;
    return near + (vpy - near) * depth + laneY * (1 - depth) * S.H * 0.15;
  }

  function corridorScale(depth) {
    return 1 - depth * 0.85;
  }


  // ===========================================================
  // 4. ENTITIES
  // ===========================================================

  // --- Player helpers ---

  function getPlayerPos() {
    return {
      x: corridorX(S.playerX * PLAYER_CFG.LANE_SCALE, PLAYER_CFG.DEPTH),
      y: corridorY(0.5, PLAYER_CFG.DEPTH) + S.playerY * S.H * 0.08,
      s: corridorScale(PLAYER_CFG.DEPTH) * Math.min(S.W, S.H) * PLAYER_CFG.SIZE_FACTOR,
    };
  }

  // --- Enemies ---

  function spawnEnemy() {
    const lane = (Math.random() - 0.5) * 1.6;
    const speed = SPAWN_CFG.BASE_SPEED + S.wave * SPAWN_CFG.WAVE_SPEED + Math.random() * SPAWN_CFG.RAND_SPEED;
    const fast = Math.random() < SPAWN_CFG.FAST_CHANCE;

    S.enemies.push({
      lane, depth: 1,
      speed: fast ? speed * SPAWN_CFG.FAST_MULT : speed,
      type: fast ? 'fast' : 'normal',
      hp: fast ? 1 : 1 + Math.floor(S.wave / 3),
      flash: 0,
      char: ENEMY_CHARS[Math.floor(Math.random() * ENEMY_CHARS.length)],
    });
  }

  function getEnemyPos(e) {
    return {
      x: corridorX(e.lane, e.depth),
      y: corridorY(0.3, e.depth),
      s: corridorScale(e.depth) * Math.min(S.W, S.H) * 0.065,
    };
  }

  // --- Particles ---

  function spawnParticles(x, y, color, n) {
    for (let i = 0; i < n; i++) {
      const a = Math.random() * Math.PI * 2;
      const sp = 1 + Math.random() * 4;
      S.particles.push({
        x, y,
        vx: Math.cos(a) * sp,
        vy: Math.sin(a) * sp - 1,
        life: 30 + Math.random() * 20,
        color,
        char: PARTICLE_CHARS[Math.floor(Math.random() * PARTICLE_CHARS.length)],
      });
    }
  }

  function updateParticles() {
    for (let i = S.particles.length - 1; i >= 0; i--) {
      const p = S.particles[i];
      p.x += p.vx; p.y += p.vy; p.vy += 0.1; p.life--;
      if (p.life <= 0) S.particles.splice(i, 1);
    }
  }

  // --- Attack ---

  function attack() {
    if (S.attackCooldown > 0) return;
    S.attackCooldown = PLAYER_CFG.ATTACK_CD;

    const p = getPlayerPos();
    const range = Math.min(S.W, S.H) * PLAYER_CFG.ATTACK_RANGE;
    let hit = false;

    for (let i = S.enemies.length - 1; i >= 0; i--) {
      const e = S.enemies[i];
      const ep = getEnemyPos(e);

      if (Math.hypot(ep.x - p.x, ep.y - p.y) < range && e.depth < PLAYER_CFG.ATTACK_DEPTH) {
        e.hp--; e.flash = 4;

        if (e.hp <= 0) {
          S.combo++;
          if (S.combo > S.maxCombo) S.maxCombo = S.combo;
          S.score += 100 * S.combo * S.wave;
          spawnParticles(ep.x, ep.y, COLORS.RED_G, 8);
          S.enemies.splice(i, 1);
          S.enemiesKilled++;
          S.shakeT = 6;
          hit = true;
        } else {
          spawnParticles(ep.x, ep.y, COLORS.GRN_B, 3);
          hit = true;
        }
      }
    }

    if (!hit) {
      S.combo = 0;
      spawnParticles(p.x, p.y - 20, COLORS.RED, 2);
    }
  }


  // ===========================================================
  // 5. RENDERER
  // ===========================================================

  let canvas, ctx;
  const dpr = Math.min(window.devicePixelRatio || 1, 2);

  function initRenderer() {
    canvas = document.getElementById('game');
    ctx = canvas.getContext('2d');
    resize();
    let rt;
    window.addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(resize, 80); });
    window.addEventListener('orientationchange', () => setTimeout(resize, 200));
  }

  function resize() {
    S.W = window.innerWidth; S.H = window.innerHeight;
    S.cx = S.W / 2; S.cy = S.H / 2;
    canvas.width = S.W * dpr;
    canvas.height = S.H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  // --- Drawing helpers ---

  function drawAmbient() {
    const g = ctx.createRadialGradient(S.cx, S.H * .35, 0, S.cx, S.H * .35, S.W * .5);
    g.addColorStop(0, 'rgba(200,60,30,0.04)');
    g.addColorStop(1, 'transparent');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, S.W, S.H);
  }

  function drawGrid() {
    const { W, H, cx } = S;
    const vpx = CORRIDOR_CFG.VP_X * W, vpy = CORRIDOR_CFG.VP_Y * H;
    ctx.save();

    for (let i = 0; i < 12; i++) {
      const d = i / 12, y = CORRIDOR_CFG.FLOOR_Y * H + (vpy - CORRIDOR_CFG.FLOOR_Y * H) * d;
      ctx.strokeStyle = COLORS.RED; ctx.globalAlpha = .6 - d * .4; ctx.lineWidth = 1.2 - d * .8;
      ctx.beginPath(); ctx.moveTo(corridorX(-1, d), y); ctx.lineTo(corridorX(1, d), y); ctx.stroke();
    }
    for (let i = -5; i <= 5; i++) {
      ctx.strokeStyle = COLORS.RED; ctx.globalAlpha = .5 - Math.abs(i) * .03; ctx.lineWidth = .8;
      ctx.beginPath(); ctx.moveTo(cx + (i / 5) * W * .5, CORRIDOR_CFG.FLOOR_Y * H); ctx.lineTo(vpx, vpy); ctx.stroke();
    }
    for (let i = 0; i < 6; i++) {
      const d = i / 6, y = CORRIDOR_CFG.CEIL_Y * H + (vpy - CORRIDOR_CFG.CEIL_Y * H) * d;
      ctx.strokeStyle = COLORS.RED; ctx.globalAlpha = .35 - d * .25; ctx.lineWidth = .8 - d * .4;
      ctx.beginPath(); ctx.moveTo(corridorX(-1, d), y); ctx.lineTo(corridorX(1, d), y); ctx.stroke();
    }
    for (let i = -3; i <= 3; i++) {
      ctx.strokeStyle = COLORS.RED; ctx.globalAlpha = .3; ctx.lineWidth = .6;
      ctx.beginPath(); ctx.moveTo(cx + (i / 3) * W * .45, CORRIDOR_CFG.CEIL_Y * H); ctx.lineTo(vpx, vpy); ctx.stroke();
    }

    ctx.strokeStyle = COLORS.RED; ctx.globalAlpha = .7; ctx.lineWidth = 2;
    ctx.strokeRect(W * .04, CORRIDOR_CFG.CEIL_Y * H, W * .92, (CORRIDOR_CFG.FLOOR_Y - CORRIDOR_CFG.CEIL_Y) * H);
    ctx.restore();
  }

  function drawReticle() {
    const vpx = CORRIDOR_CFG.VP_X * S.W, vpy = CORRIDOR_CFG.VP_Y * S.H;
    ctx.save(); ctx.translate(vpx, vpy);
    ctx.strokeStyle = COLORS.RED;
    ctx.globalAlpha = .5 + Math.sin(S.tick * .05) * .2;
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(0, -14); ctx.lineTo(14, 0); ctx.lineTo(0, 14); ctx.lineTo(-14, 0); ctx.closePath(); ctx.stroke();
    ctx.beginPath(); ctx.arc(0, 0, 2 + Math.sin(S.tick * .08), 0, Math.PI * 2);
    ctx.fillStyle = COLORS.RED; ctx.fill();
    ctx.restore();
  }

  function drawPlayer() {
    const p = getPlayerPos();
    ctx.save(); ctx.translate(p.x, p.y);
    ctx.shadowColor = COLORS.RED_G; ctx.shadowBlur = 20;
    ctx.fillStyle = COLORS.RED_B;
    ctx.font = `900 ${p.s}px sans-serif`;
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillText('战', 0, 0);
    ctx.shadowBlur = 0; ctx.strokeStyle = COLORS.RED_G; ctx.lineWidth = 1;
    ctx.strokeText('战', 0, 0);
    if (S.attackCooldown > 0) {
      ctx.globalAlpha = S.attackCooldown / 10;
      ctx.strokeStyle = COLORS.GRN_B; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.arc(0, 0, p.s * .8, 0, Math.PI * 2); ctx.stroke();
    }
    ctx.restore();
  }

  function drawEnemies() {
    S.enemies.sort((a, b) => b.depth - a.depth);
    for (const e of S.enemies) {
      const ep = getEnemyPos(e);
      ctx.save(); ctx.translate(ep.x, ep.y);
      ctx.globalAlpha = Math.min(1, (1 - e.depth) * 3);
      if (e.flash > 0) {
        ctx.shadowColor = '#fff'; ctx.shadowBlur = 30; ctx.fillStyle = '#fff'; e.flash--;
      } else {
        ctx.shadowColor = COLORS.GRN; ctx.shadowBlur = 12;
        ctx.fillStyle = e.type === 'fast' ? COLORS.GRN_B : COLORS.GRN;
      }
      ctx.font = `900 ${ep.s}px sans-serif`; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillText(e.char, 0, 0);
      if (e.hp > 1) {
        ctx.fillStyle = COLORS.RED; ctx.globalAlpha = .6;
        ctx.fillRect(-ep.s * .4, -ep.s * .7, ep.s * .8 * (e.hp / (1 + Math.floor(S.wave / 3))), 2);
      }
      ctx.restore();
    }
  }

  function drawParticles() {
    ctx.save();
    for (const p of S.particles) {
      ctx.globalAlpha = p.life / 50;
      ctx.fillStyle = p.color;
      ctx.font = `700 ${8 + p.life * .3}px sans-serif`;
      ctx.textAlign = 'center';
      ctx.fillText(p.char, p.x, p.y);
    }
    ctx.restore();
  }

  function drawScan() {
    ctx.save();
    ctx.globalAlpha = .08; ctx.fillStyle = COLORS.GRN;
    ctx.fillRect(0, (S.tick * .5) % S.H, S.W, 2);
    ctx.restore();
  }

  function drawFrame() {
    const { W, H, cx, cy } = S;
    ctx.save();
    if (S.shakeT > 0) {
      ctx.translate((Math.random() - .5) * S.shakeT * 2, (Math.random() - .5) * S.shakeT * 2);
      S.shakeT--;
    }

    ctx.fillStyle = COLORS.DARK; ctx.fillRect(0, 0, W, H);
    drawAmbient(); drawGrid(); drawReticle();
    drawEnemies(); drawPlayer(); drawParticles(); drawScan();

    if (S.flashT > 0) {
      ctx.globalAlpha = S.flashT / 15;
      ctx.fillStyle = COLORS.RED_G;
      ctx.fillRect(0, 0, W, H);
      S.flashT--;
    }

    if (S.waveTimer < 60 && S.wave > 1) {
      ctx.save();
      ctx.globalAlpha = 1 - S.waveTimer / 60;
      ctx.fillStyle = COLORS.RED_B;
      ctx.font = `700 ${Math.min(48, Math.max(20, W * .05))}px 'Chakra Petch', sans-serif`;
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillText(`WAVE ${S.wave}`, cx, cy);
      ctx.restore();
    }
    ctx.restore();
  }


  // ===========================================================
  // 6. INPUT
  // ===========================================================

  const keys = {};
  const dpadVec = { x: 0, y: 0 };

  function initInput() {
    // Keyboard
    window.addEventListener('keydown', e => {
      keys[e.key] = true;
      if (e.key === ' ' && S.phase === 'playing') { e.preventDefault(); attack(); }
    });
    window.addEventListener('keyup', e => { keys[e.key] = false; });

    // Mobile D-pad
    const dpad = document.getElementById('dpad');
    if (dpad) {
      let dpadTouchId = null;
      let dpadRect = null;

      function updDpad(tx, ty) {
        if (!dpadRect) return;
        const cx = dpadRect.left + dpadRect.width / 2;
        const cy = dpadRect.top + dpadRect.height / 2;
        const r = dpadRect.width / 2;
        let dx = (tx - cx) / r, dy = (ty - cy) / r;
        const m = Math.hypot(dx, dy);
        if (m > 1) { dx /= m; dy /= m; }
        dpadVec.x = dx; dpadVec.y = dy;
      }

      dpad.addEventListener('touchstart', e => {
        e.preventDefault(); e.stopPropagation();
        dpadRect = dpad.getBoundingClientRect();
        const t = e.changedTouches[0];
        dpadTouchId = t.identifier;
        updDpad(t.clientX, t.clientY);
        dpad.classList.add('active');
      }, { passive: false });

      dpad.addEventListener('touchmove', e => {
        e.preventDefault(); e.stopPropagation();
        for (const t of e.changedTouches)
          if (t.identifier === dpadTouchId) updDpad(t.clientX, t.clientY);
      }, { passive: false });

      const endDpad = e => {
        for (const t of e.changedTouches)
          if (t.identifier === dpadTouchId) {
            dpadVec.x = 0; dpadVec.y = 0; dpadTouchId = null;
            dpad.classList.remove('active');
          }
      };
      dpad.addEventListener('touchend', endDpad);
      dpad.addEventListener('touchcancel', endDpad);
      window.addEventListener('resize', () => { dpadRect = null; });
    }

    // Mobile attack button
    const atkBtn = document.getElementById('atkBtn');
    if (atkBtn) {
      atkBtn.addEventListener('touchstart', e => {
        e.preventDefault(); e.stopPropagation();
        if (S.phase === 'playing') attack();
        atkBtn.classList.add('active');
      }, { passive: false });
      atkBtn.addEventListener('touchend', e => { e.preventDefault(); atkBtn.classList.remove('active'); });
      atkBtn.addEventListener('touchcancel', () => atkBtn.classList.remove('active'));
    }
  }


  // ===========================================================
  // 7. UI
  // ===========================================================

  const $ = id => document.getElementById(id);

  function updateHUD() {
    $('hudWave').textContent = S.wave;
    $('hudScore').textContent = S.score.toLocaleString();
    $('hudHi').textContent = 'HI ' + S.hi.toLocaleString();
    $('hudCombo').textContent = S.combo > 1 ? `COMBO x${S.combo}` : '';

    const lc = $('hudLives'); lc.innerHTML = '';
    for (let i = 0; i < 3; i++) {
      const d = document.createElement('div');
      d.className = 'hud-life' + (i >= S.lives ? ' lost' : '');
      lc.appendChild(d);
    }
  }

  function showGameOver() {
    if (S.score > S.hi) S.hi = S.score;
    $('finalScore').textContent = S.score.toLocaleString();
    const v = VERDICTS.find(v => S.score >= v.min);
    $('verdictText').textContent = `${v.cn} — ${v.en}`;
    $('gameOverScreen').classList.remove('hidden');
  }


  // ===========================================================
  // 8. GAME LOOP
  // ===========================================================

  function startGame() {
    resetState();
    $('titleScreen').classList.add('hidden');
    $('gameOverScreen').classList.add('hidden');
    updateHUD();
  }

  function gameOver() {
    S.phase = 'over';
    showGameOver();
  }

  function update() {
    const sp = PLAYER_CFG.MOVE_SPEED;

    if (keys['ArrowLeft'] || keys['a'] || keys['A']) S.targetX -= sp;
    if (keys['ArrowRight'] || keys['d'] || keys['D']) S.targetX += sp;
    if (keys['ArrowUp'] || keys['w'] || keys['W']) S.targetY -= sp;
    if (keys['ArrowDown'] || keys['s'] || keys['S']) S.targetY += sp;

    S.targetX += dpadVec.x * sp;
    S.targetY += dpadVec.y * sp;

    S.targetX = Math.max(-1, Math.min(1, S.targetX));
    S.targetY = Math.max(-1, Math.min(1, S.targetY));
    S.playerX += (S.targetX - S.playerX) * PLAYER_CFG.LERP;
    S.playerY += (S.targetY - S.playerY) * PLAYER_CFG.LERP;

    if (S.attackCooldown > 0) S.attackCooldown--;

    S.spawnTimer--;
    if (S.spawnTimer <= 0) {
      spawnEnemy();
      S.spawnTimer = Math.max(SPAWN_CFG.MIN_INTERVAL, SPAWN_CFG.BASE_INTERVAL - S.wave * SPAWN_CFG.WAVE_REDUCTION);
    }

    S.waveTimer++;
    if (S.enemiesKilled >= WAVE_CFG.BASE_KILLS + S.wave * WAVE_CFG.KILLS_PER_WAVE) {
      S.wave++; S.enemiesKilled = 0; S.flashT = 10; S.waveTimer = 0;
    }

    const p = getPlayerPos();
    for (let i = S.enemies.length - 1; i >= 0; i--) {
      const e = S.enemies[i];
      e.depth -= e.speed;
      if (e.depth < 0.03) {
        S.enemies.splice(i, 1);
        S.lives--; S.combo = 0; S.shakeT = 12; S.flashT = 8;
        spawnParticles(p.x, p.y, COLORS.RED_G, 12);
        if (S.lives <= 0) return gameOver();
      }
    }

    updateParticles();
    updateHUD();
  }

  function loop() {
    S.tick++;
    if (S.phase === 'playing') update();
    if (S.phase !== 'title') drawFrame();
    requestAnimationFrame(loop);
  }


  // ===========================================================
  // 9. BOOT
  // ===========================================================

  function init() {
    initRenderer();
    initInput();
    $('startBtn').addEventListener('click', startGame);
    $('retryBtn').addEventListener('click', startGame);
    loop();
  }

  init();

})();
