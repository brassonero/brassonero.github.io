// =============================================
// THE WARRIORS — Game Script
// =============================================

(function () {
  'use strict';

  // ===========================================================
  // 1. CONFIG
  // ===========================================================

  const COLORS = {
    RED: '#c83c1e', RED_B: '#e04a26', RED_G: '#ff5533',
    GRN: '#2daa5a', GRN_B: '#3ddd6a', GRN_D: '#1e7a3e',
    DARK: '#0e0c0a',
    GOLD: '#ffcc33', GOLD_D: '#cc9900',
    CYAN: '#33ddff', WHITE: '#ffffff',
  };

  const CORRIDOR_CFG = { VP_X: 0.5, VP_Y: 0.38, FLOOR_Y: 0.85, CEIL_Y: 0.08 };

  const PLAYER_CFG = {
    DEPTH: 0.05, LANE_SCALE: 0.7, MOVE_SPEED: 0.04, LERP: 0.15,
    SIZE_FACTOR: 0.07, ATTACK_CD: 12, ATTACK_RANGE: 0.18, ATTACK_DEPTH: 0.5,
    DASH_CD: 45, DASH_SPEED: 0.25, DASH_DUR: 6, IFRAMES: 20,
  };

  const SPAWN_CFG = {
    BASE_INTERVAL: 80, MIN_INTERVAL: 18, WAVE_REDUCTION: 8,
    BASE_SPEED: 0.003, WAVE_SPEED: 0.0008, RAND_SPEED: 0.002,
    FAST_CHANCE: 0.3, FAST_MULT: 1.5,
    SHIELD_CHANCE_BASE: 0, SHIELD_CHANCE_WAVE: 0.03,
  };

  const WAVE_CFG = { BASE_KILLS: 5, KILLS_PER_WAVE: 3, BOSS_EVERY: 5 };

  const ENEMY_CHARS = ['伪', '敌', '鬼', '魔', '邪'];
  const FAST_CHARS = ['影', '疾', '风'];
  const BOSS_CHARS = ['龙', '王', '帝'];
  const SHIELD_CHARS = ['盾', '甲'];
  const PARTICLE_CHARS = ['斩', '破', '灭', '击', '杀', '诛'];
  const POWERUP_TYPES = [
    { type: 'heal', char: '命', color: COLORS.RED_B, desc: '+1 LIFE' },
    { type: 'score', char: '金', color: COLORS.GOLD, desc: '+2000' },
    { type: 'fury', char: '怒', color: COLORS.CYAN, desc: 'FURY MODE' },
  ];

  const VERDICTS = [
    { min: 25000, cn: '神战士', en: 'GOD WARRIOR' },
    { min: 15000, cn: '真战士', en: 'TRUE WARRIOR' },
    { min: 8000, cn: '战士', en: 'WARRIOR' },
    { min: 3000, cn: '学徒', en: 'APPRENTICE' },
    { min: 1000, cn: '初学者', en: 'NOVICE' },
    { min: 0, cn: '伪战士', en: 'FALSE WARRIOR' },
  ];

  // ===========================================================
  // 2. AUDIO
  // ===========================================================

  let audioCtx = null;

  function ensureAudio() {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    if (audioCtx.state === 'suspended') audioCtx.resume();
  }

  function playTone(freq, dur, vol, type, decay) {
    if (!audioCtx) return;
    const t = audioCtx.currentTime;
    const o = audioCtx.createOscillator();
    const g = audioCtx.createGain();
    o.type = type || 'square';
    o.frequency.setValueAtTime(freq, t);
    if (decay) o.frequency.exponentialRampToValueAtTime(freq * decay, t + dur);
    g.gain.setValueAtTime(vol || 0.08, t);
    g.gain.exponentialRampToValueAtTime(0.001, t + dur);
    o.connect(g).connect(audioCtx.destination);
    o.start(t); o.stop(t + dur);
  }

  function playNoise(dur, vol) {
    if (!audioCtx) return;
    const t = audioCtx.currentTime;
    const buf = audioCtx.createBuffer(1, audioCtx.sampleRate * dur, audioCtx.sampleRate);
    const d = buf.getChannelData(0);
    for (let i = 0; i < d.length; i++) d[i] = Math.random() * 2 - 1;
    const src = audioCtx.createBufferSource(); src.buffer = buf;
    const g = audioCtx.createGain();
    g.gain.setValueAtTime(vol || 0.06, t);
    g.gain.exponentialRampToValueAtTime(0.001, t + dur);
    const filt = audioCtx.createBiquadFilter(); filt.type = 'highpass'; filt.frequency.value = 800;
    src.connect(filt).connect(g).connect(audioCtx.destination);
    src.start(t);
  }

  const SFX = {
    slash: () => { playTone(220, 0.08, 0.1, 'sawtooth', 0.3); playNoise(0.06, 0.08); },
    hit: () => { playTone(330, 0.06, 0.12, 'square', 0.5); playNoise(0.04, 0.06); },
    kill: () => { playTone(440, 0.12, 0.1, 'square', 2); playTone(660, 0.15, 0.06, 'sine'); },
    bosshit: () => { playTone(110, 0.15, 0.12, 'sawtooth', 0.3); playNoise(0.1, 0.1); },
    bosskill: () => {
      playTone(220, 0.3, 0.12, 'square', 4);
      setTimeout(() => playTone(440, 0.2, 0.08, 'sine', 2), 100);
      setTimeout(() => playTone(880, 0.3, 0.06, 'sine'), 200);
    },
    damage: () => { playTone(80, 0.25, 0.15, 'sawtooth', 0.2); playNoise(0.15, 0.12); },
    wave: () => {
      playTone(330, 0.15, 0.06, 'sine');
      setTimeout(() => playTone(440, 0.15, 0.06, 'sine'), 100);
      setTimeout(() => playTone(550, 0.2, 0.06, 'sine'), 200);
    },
    powerup: () => {
      playTone(523, 0.1, 0.08, 'sine');
      setTimeout(() => playTone(659, 0.1, 0.08, 'sine'), 80);
      setTimeout(() => playTone(784, 0.15, 0.08, 'sine'), 160);
    },
    dash: () => { playTone(600, 0.06, 0.06, 'sawtooth', 0.1); playNoise(0.04, 0.04); },
    miss: () => { playNoise(0.05, 0.03); },
    shield: () => { playTone(180, 0.08, 0.08, 'triangle'); },
    gameover: () => {
      playTone(440, 0.3, 0.1, 'sawtooth', 0.1);
      setTimeout(() => playTone(220, 0.3, 0.1, 'sawtooth', 0.1), 200);
      setTimeout(() => playTone(110, 0.5, 0.12, 'sawtooth', 0.05), 400);
    },
  };

  // ===========================================================
  // 3. STATE
  // ===========================================================

  const S = {
    phase: 'title', score: 0, hi: 0, wave: 1, lives: 3, maxLives: 5,
    combo: 0, maxCombo: 0,
    playerX: 0, playerY: 0, targetX: 0, targetY: 0,
    attackCooldown: 0,
    dashCooldown: 0, dashTimer: 0, dashDirX: 0, dashDirY: 0,
    iframes: 0, furyTimer: 0,
    slashArc: 0, slashAngle: 0,
    spawnTimer: 60, waveTimer: 0,
    shakeT: 0, flashT: 0, flashColor: COLORS.RED_G, tick: 0,
    enemies: [], particles: [], floats: [], powerups: [], trails: [],
    enemiesKilled: 0, bossActive: false, bossWarning: 0, totalKills: 0,
    W: 0, H: 0, cx: 0, cy: 0,
  };

  function resetState() {
    Object.assign(S, {
      phase: 'playing', score: 0, wave: 1, lives: 3,
      combo: 0, maxCombo: 0, playerX: 0, playerY: 0, targetX: 0, targetY: 0,
      attackCooldown: 0, dashCooldown: 0, dashTimer: 0, iframes: 0, furyTimer: 0, slashArc: 0,
      spawnTimer: 60, waveTimer: 0, shakeT: 0, flashT: 0,
      enemies: [], particles: [], floats: [], powerups: [], trails: [],
      enemiesKilled: 0, totalKills: 0, bossActive: false, bossWarning: 0,
    });
  }

  // ===========================================================
  // 4. CORRIDOR
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

  function corridorScale(depth) { return 1 - depth * 0.85; }

  // ===========================================================
  // 5. ENTITIES
  // ===========================================================

  function getPlayerPos() {
    return {
      x: corridorX(S.playerX * PLAYER_CFG.LANE_SCALE, PLAYER_CFG.DEPTH),
      y: corridorY(0.5, PLAYER_CFG.DEPTH) + S.playerY * S.H * 0.08,
      s: corridorScale(PLAYER_CFG.DEPTH) * Math.min(S.W, S.H) * PLAYER_CFG.SIZE_FACTOR,
    };
  }

  function spawnFloat(x, y, text, color, size) {
    S.floats.push({ x, y, text, color, size: size || 16, life: 50, vy: -1.5 });
  }

  function updateFloats() {
    for (let i = S.floats.length - 1; i >= 0; i--) {
      const f = S.floats[i]; f.y += f.vy; f.vy *= 0.97; f.life--;
      if (f.life <= 0) S.floats.splice(i, 1);
    }
  }

  function addTrail() {
    const p = getPlayerPos();
    S.trails.push({ x: p.x, y: p.y, life: 12 });
  }

  function updateTrails() {
    for (let i = S.trails.length - 1; i >= 0; i--) {
      S.trails[i].life--;
      if (S.trails[i].life <= 0) S.trails.splice(i, 1);
    }
  }

  function spawnEnemy() {
    const lane = (Math.random() - 0.5) * 1.6;
    const speed = SPAWN_CFG.BASE_SPEED + S.wave * SPAWN_CFG.WAVE_SPEED + Math.random() * SPAWN_CFG.RAND_SPEED;
    const fast = Math.random() < SPAWN_CFG.FAST_CHANCE;
    const shieldChance = Math.min(0.3, SPAWN_CFG.SHIELD_CHANCE_BASE + S.wave * SPAWN_CFG.SHIELD_CHANCE_WAVE);
    const shielded = !fast && Math.random() < shieldChance;

    let type = 'normal', hp, char;
    if (fast) {
      type = 'fast'; hp = 1;
      char = FAST_CHARS[Math.floor(Math.random() * FAST_CHARS.length)];
    } else if (shielded) {
      type = 'shield'; hp = 2 + Math.floor(S.wave / 4);
      char = SHIELD_CHARS[Math.floor(Math.random() * SHIELD_CHARS.length)];
    } else {
      hp = 1 + Math.floor(S.wave / 3);
      char = ENEMY_CHARS[Math.floor(Math.random() * ENEMY_CHARS.length)];
    }

    S.enemies.push({
      lane, depth: 1, speed: fast ? speed * SPAWN_CFG.FAST_MULT : speed,
      type, hp, maxHp: hp, flash: 0, wobble: 0, char,
    });
  }

  function spawnBoss() {
    S.bossActive = true;
    const hp = 5 + S.wave * 2;
    S.enemies.push({
      lane: 0, depth: 1,
      speed: SPAWN_CFG.BASE_SPEED * 0.7 + S.wave * SPAWN_CFG.WAVE_SPEED * 0.5,
      type: 'boss', hp, maxHp: hp, flash: 0, wobble: 0,
      char: BOSS_CHARS[Math.floor(Math.random() * BOSS_CHARS.length)],
    });
  }

  function getEnemyPos(e) {
    const sizeMult = e.type === 'boss' ? 0.11 : 0.065;
    return {
      x: corridorX(e.lane, e.depth) + Math.sin(e.wobble) * 3,
      y: corridorY(0.3, e.depth),
      s: corridorScale(e.depth) * Math.min(S.W, S.H) * sizeMult,
    };
  }

  function spawnPowerup(x, y) {
    const def = POWERUP_TYPES[Math.floor(Math.random() * POWERUP_TYPES.length)];
    S.powerups.push({ x, y, vy: -1, life: 180, ...def });
  }

  function updatePowerups() {
    const p = getPlayerPos();
    for (let i = S.powerups.length - 1; i >= 0; i--) {
      const pu = S.powerups[i];
      pu.y += pu.vy; pu.vy += 0.04; pu.life--;
      if (Math.hypot(pu.x - p.x, pu.y - p.y) < p.s * 2.5) {
        SFX.powerup();
        spawnFloat(pu.x, pu.y - 20, pu.desc, pu.color, 20);
        spawnParticles(pu.x, pu.y, pu.color, 6);
        if (pu.type === 'heal') { S.lives = Math.min(S.lives + 1, S.maxLives); S.flashT = 6; S.flashColor = COLORS.RED_B; }
        else if (pu.type === 'score') S.score += 2000;
        else if (pu.type === 'fury') { S.furyTimer = 300; S.flashT = 8; S.flashColor = COLORS.CYAN; }
        S.powerups.splice(i, 1); continue;
      }
      if (pu.life <= 0) S.powerups.splice(i, 1);
    }
  }

  function spawnParticles(x, y, color, n) {
    for (let i = 0; i < n; i++) {
      const a = Math.random() * Math.PI * 2, sp = 1 + Math.random() * 5;
      S.particles.push({
        x, y, vx: Math.cos(a) * sp, vy: Math.sin(a) * sp - 1.5,
        life: 30 + Math.random() * 25, color, size: 0.8 + Math.random() * 0.4,
        char: PARTICLE_CHARS[Math.floor(Math.random() * PARTICLE_CHARS.length)],
      });
    }
  }

  function updateParticles() {
    for (let i = S.particles.length - 1; i >= 0; i--) {
      const p = S.particles[i];
      p.x += p.vx; p.y += p.vy; p.vy += 0.1; p.vx *= 0.98; p.life--;
      if (p.life <= 0) S.particles.splice(i, 1);
    }
  }

  function dash() {
    if (S.dashCooldown > 0 || S.dashTimer > 0) return;
    S.dashCooldown = PLAYER_CFG.DASH_CD;
    S.dashTimer = PLAYER_CFG.DASH_DUR;
    S.iframes = PLAYER_CFG.IFRAMES;
    const mx = S.targetX - S.playerX, my = S.targetY - S.playerY;
    const m = Math.hypot(mx, my);
    if (m > 0.01) { S.dashDirX = mx / m; S.dashDirY = my / m; }
    else { S.dashDirX = 0; S.dashDirY = -1; }
    SFX.dash();
  }

  function attack() {
    if (S.attackCooldown > 0) return;
    const cdMult = S.furyTimer > 0 ? 0.5 : 1;
    S.attackCooldown = Math.floor(PLAYER_CFG.ATTACK_CD * cdMult);
    S.slashArc = 10; S.slashAngle = Math.random() * Math.PI * 2;
    SFX.slash();

    const p = getPlayerPos();
    const rangeMult = S.furyTimer > 0 ? 1.4 : 1;
    const range = Math.min(S.W, S.H) * PLAYER_CFG.ATTACK_RANGE * rangeMult;
    let hit = false;

    for (let i = S.enemies.length - 1; i >= 0; i--) {
      const e = S.enemies[i], ep = getEnemyPos(e);
      if (Math.hypot(ep.x - p.x, ep.y - p.y) < range && e.depth < PLAYER_CFG.ATTACK_DEPTH) {
        if (e.type === 'shield' && e.hp > 1) SFX.shield();
        const dmg = S.furyTimer > 0 ? 2 : 1;
        e.hp -= dmg; e.flash = 5; e.wobble += 0.5;

        if (e.hp <= 0) {
          S.combo++; if (S.combo > S.maxCombo) S.maxCombo = S.combo;
          const pts = (e.type === 'boss' ? 500 : 100) * S.combo * S.wave;
          S.score += pts; S.totalKills++;

          if (e.type === 'boss') {
            SFX.bosskill(); spawnParticles(ep.x, ep.y, COLORS.GOLD, 20);
            spawnParticles(ep.x, ep.y, COLORS.RED_G, 12);
            spawnFloat(ep.x, ep.y - 30, pts.toLocaleString(), COLORS.GOLD, 28);
            S.shakeT = 15; S.bossActive = false; spawnPowerup(ep.x, ep.y);
          } else {
            SFX.kill(); spawnParticles(ep.x, ep.y, COLORS.RED_G, 10);
            spawnFloat(ep.x, ep.y - 20, pts.toLocaleString(), COLORS.GRN_B, 16);
            S.shakeT = 6;
            if (Math.random() < 0.08) spawnPowerup(ep.x, ep.y);
          }
          S.enemies.splice(i, 1); S.enemiesKilled++; hit = true;
        } else {
          if (e.type === 'boss') SFX.bosshit(); else SFX.hit();
          spawnParticles(ep.x, ep.y, e.type === 'boss' ? COLORS.GOLD : COLORS.GRN_B, 4);
          spawnFloat(ep.x, ep.y - 15, `-${dmg}`, COLORS.WHITE, 12);
          hit = true;
        }
      }
    }

    if (!hit) { S.combo = 0; SFX.miss(); spawnParticles(p.x, p.y - 20, COLORS.RED, 2); }
  }

  // ===========================================================
  // 6. RENDERER
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
    canvas.width = S.W * dpr; canvas.height = S.H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function drawAmbient() {
    const g = ctx.createRadialGradient(S.cx, S.H * .35, 0, S.cx, S.H * .35, S.W * .5);
    const fury = S.furyTimer > 0;
    g.addColorStop(0, fury ? 'rgba(50,180,220,0.08)' : 'rgba(200,60,30,0.04)');
    g.addColorStop(1, 'transparent');
    ctx.fillStyle = g; ctx.fillRect(0, 0, S.W, S.H);
  }

  function drawGrid() {
    const { W, H, cx } = S;
    const vpx = CORRIDOR_CFG.VP_X * W, vpy = CORRIDOR_CFG.VP_Y * H;
    const c = S.furyTimer > 0 ? COLORS.CYAN : COLORS.RED;
    ctx.save();
    for (let i = 0; i < 12; i++) {
      const d = i / 12, y = CORRIDOR_CFG.FLOOR_Y * H + (vpy - CORRIDOR_CFG.FLOOR_Y * H) * d;
      ctx.strokeStyle = c; ctx.globalAlpha = .6 - d * .4; ctx.lineWidth = 1.2 - d * .8;
      ctx.beginPath(); ctx.moveTo(corridorX(-1, d), y); ctx.lineTo(corridorX(1, d), y); ctx.stroke();
    }
    for (let i = -5; i <= 5; i++) {
      ctx.strokeStyle = c; ctx.globalAlpha = .5 - Math.abs(i) * .03; ctx.lineWidth = .8;
      ctx.beginPath(); ctx.moveTo(cx + (i / 5) * W * .5, CORRIDOR_CFG.FLOOR_Y * H); ctx.lineTo(vpx, vpy); ctx.stroke();
    }
    for (let i = 0; i < 6; i++) {
      const d = i / 6, y = CORRIDOR_CFG.CEIL_Y * H + (vpy - CORRIDOR_CFG.CEIL_Y * H) * d;
      ctx.strokeStyle = c; ctx.globalAlpha = .35 - d * .25; ctx.lineWidth = .8 - d * .4;
      ctx.beginPath(); ctx.moveTo(corridorX(-1, d), y); ctx.lineTo(corridorX(1, d), y); ctx.stroke();
    }
    for (let i = -3; i <= 3; i++) {
      ctx.strokeStyle = c; ctx.globalAlpha = .3; ctx.lineWidth = .6;
      ctx.beginPath(); ctx.moveTo(cx + (i / 3) * W * .45, CORRIDOR_CFG.CEIL_Y * H); ctx.lineTo(vpx, vpy); ctx.stroke();
    }
    ctx.strokeStyle = c; ctx.globalAlpha = .7; ctx.lineWidth = 2;
    ctx.strokeRect(W * .04, CORRIDOR_CFG.CEIL_Y * H, W * .92, (CORRIDOR_CFG.FLOOR_Y - CORRIDOR_CFG.CEIL_Y) * H);
    ctx.restore();
  }

  function drawReticle() {
    const vpx = CORRIDOR_CFG.VP_X * S.W, vpy = CORRIDOR_CFG.VP_Y * S.H;
    const c = S.furyTimer > 0 ? COLORS.CYAN : COLORS.RED;
    ctx.save(); ctx.translate(vpx, vpy);
    ctx.strokeStyle = c; ctx.globalAlpha = .5 + Math.sin(S.tick * .05) * .2; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(0, -14); ctx.lineTo(14, 0); ctx.lineTo(0, 14); ctx.lineTo(-14, 0); ctx.closePath(); ctx.stroke();
    ctx.beginPath(); ctx.arc(0, 0, 2 + Math.sin(S.tick * .08), 0, Math.PI * 2);
    ctx.fillStyle = c; ctx.fill();
    ctx.restore();
  }

  function drawTrails() {
    ctx.save();
    for (const t of S.trails) {
      ctx.globalAlpha = (t.life / 12) * 0.25;
      ctx.fillStyle = S.furyTimer > 0 ? COLORS.CYAN : COLORS.RED_B;
      ctx.font = `900 ${Math.min(S.W, S.H) * PLAYER_CFG.SIZE_FACTOR * (t.life / 12)}px sans-serif`;
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillText('战', t.x, t.y);
    }
    ctx.restore();
  }

  function drawPlayer() {
    const p = getPlayerPos();
    ctx.save(); ctx.translate(p.x, p.y);
    if (S.iframes > 0 && S.tick % 4 < 2) { ctx.restore(); return; }
    const fury = S.furyTimer > 0;
    const mc = fury ? COLORS.CYAN : COLORS.RED_B;
    const gc = fury ? COLORS.CYAN : COLORS.RED_G;
    ctx.shadowColor = gc; ctx.shadowBlur = fury ? 30 : 20;
    ctx.fillStyle = mc;
    ctx.font = `900 ${p.s}px sans-serif`; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillText('战', 0, 0);
    ctx.shadowBlur = 0; ctx.strokeStyle = gc; ctx.lineWidth = 1; ctx.strokeText('战', 0, 0);

    if (S.slashArc > 0) {
      ctx.strokeStyle = fury ? COLORS.CYAN : COLORS.GRN_B; ctx.lineWidth = 3;
      ctx.globalAlpha = S.slashArc / 10;
      const prog = 1 - S.slashArc / 10;
      ctx.beginPath(); ctx.arc(0, 0, p.s * (1 + prog * 1.5), S.slashAngle, S.slashAngle + Math.PI * prog * 1.2); ctx.stroke();
      S.slashArc--;
    }

    if (S.attackCooldown > 0) {
      ctx.globalAlpha = S.attackCooldown / 10;
      ctx.strokeStyle = COLORS.GRN_B; ctx.lineWidth = 2;
      const cd = S.attackCooldown / PLAYER_CFG.ATTACK_CD;
      ctx.beginPath(); ctx.arc(0, 0, p.s * .8, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * cd); ctx.stroke();
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
      } else if (e.type === 'boss') {
        ctx.shadowColor = COLORS.GOLD; ctx.shadowBlur = 20; ctx.fillStyle = COLORS.GOLD;
      } else if (e.type === 'shield') {
        ctx.shadowColor = COLORS.CYAN; ctx.shadowBlur = 14; ctx.fillStyle = COLORS.CYAN;
      } else {
        ctx.shadowColor = COLORS.GRN; ctx.shadowBlur = 12;
        ctx.fillStyle = e.type === 'fast' ? COLORS.GRN_B : COLORS.GRN;
      }
      ctx.font = `900 ${ep.s}px sans-serif`; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillText(e.char, 0, 0);
      if (e.type === 'boss') { ctx.strokeStyle = COLORS.GOLD_D; ctx.lineWidth = 2; ctx.shadowBlur = 0; ctx.strokeText(e.char, 0, 0); }

      if (e.maxHp > 1) {
        const bw = ep.s * 0.9, bh = Math.max(2, ep.s * 0.05);
        ctx.shadowBlur = 0; ctx.fillStyle = 'rgba(0,0,0,0.5)'; ctx.fillRect(-bw / 2, -ep.s * .7, bw, bh);
        ctx.fillStyle = e.type === 'boss' ? COLORS.GOLD : (e.type === 'shield' ? COLORS.CYAN : COLORS.RED);
        ctx.globalAlpha = .8; ctx.fillRect(-bw / 2, -ep.s * .7, bw * (e.hp / e.maxHp), bh);
      }

      if (e.depth < 0.15 && e.depth > 0.03) {
        ctx.globalAlpha = (0.15 - e.depth) / 0.12 * (0.5 + Math.sin(S.tick * 0.3) * 0.3);
        ctx.strokeStyle = COLORS.RED_G; ctx.lineWidth = 1.5;
        ctx.beginPath(); ctx.arc(0, 0, ep.s * 0.9, 0, Math.PI * 2); ctx.stroke();
      }
      ctx.restore();
    }
  }

  function drawParticles() {
    ctx.save();
    for (const p of S.particles) {
      ctx.globalAlpha = p.life / 50; ctx.fillStyle = p.color;
      ctx.font = `700 ${(8 + p.life * .3) * p.size}px sans-serif`;
      ctx.textAlign = 'center'; ctx.fillText(p.char, p.x, p.y);
    }
    ctx.restore();
  }

  function drawFloats() {
    ctx.save();
    for (const f of S.floats) {
      ctx.globalAlpha = Math.min(1, f.life / 20); ctx.fillStyle = f.color;
      ctx.font = `700 ${f.size}px 'Chakra Petch', sans-serif`;
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.shadowColor = f.color; ctx.shadowBlur = 8;
      ctx.fillText(f.text, f.x, f.y);
    }
    ctx.restore();
  }

  function drawPowerups() {
    ctx.save();
    for (const pu of S.powerups) {
      const pulse = 1 + Math.sin(S.tick * 0.15) * 0.15;
      ctx.globalAlpha = Math.min(1, pu.life / 30);
      ctx.shadowColor = pu.color; ctx.shadowBlur = 15; ctx.fillStyle = pu.color;
      ctx.font = `900 ${20 * pulse}px sans-serif`; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillText(pu.char, pu.x, pu.y);
      ctx.strokeStyle = pu.color; ctx.lineWidth = 1; ctx.globalAlpha *= 0.4;
      ctx.beginPath(); ctx.arc(pu.x, pu.y, 14 * pulse, 0, Math.PI * 2); ctx.stroke();
    }
    ctx.restore();
  }

  function drawScan() {
    ctx.save(); ctx.globalAlpha = .08;
    ctx.fillStyle = S.furyTimer > 0 ? COLORS.CYAN : COLORS.GRN;
    ctx.fillRect(0, (S.tick * .5) % S.H, S.W, 2);
    ctx.restore();
  }

  function drawBossWarning() {
    if (S.bossWarning <= 0) return;
    ctx.save();
    ctx.globalAlpha = (S.bossWarning / 60) * (0.5 + Math.sin(S.tick * 0.3) * 0.3);
    ctx.fillStyle = COLORS.GOLD;
    ctx.font = `700 ${Math.min(36, S.W * 0.04)}px 'Chakra Petch', sans-serif`;
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillText('⚠ BOSS INCOMING ⚠', S.cx, S.cy - S.H * 0.15);
    ctx.restore(); S.bossWarning--;
  }

  function drawComboMeter() {
    if (S.combo < 2) return;
    ctx.save();
    const bx = S.W * 0.5, by = S.H * 0.92, mw = S.W * 0.2;
    ctx.globalAlpha = 0.6; ctx.fillStyle = COLORS.GRN_D;
    ctx.fillRect(bx - mw / 2, by, mw, 3);
    const fill = Math.min(1, S.combo / 20);
    const col = S.combo >= 10 ? COLORS.GOLD : COLORS.GRN_B;
    ctx.fillStyle = col; ctx.shadowColor = col; ctx.shadowBlur = 6;
    ctx.fillRect(bx - mw / 2, by, mw * fill, 3);
    ctx.shadowBlur = 0; ctx.globalAlpha = 0.8; ctx.fillStyle = col;
    ctx.font = `700 ${Math.min(14, 10 + S.combo * 0.3)}px 'Chakra Petch', sans-serif`;
    ctx.textAlign = 'center'; ctx.fillText(`×${S.combo}`, bx, by - 5);
    ctx.restore();
  }

  function drawFuryOverlay() {
    if (S.furyTimer <= 0) return;
    ctx.save();
    ctx.globalAlpha = 0.03 + Math.sin(S.tick * 0.1) * 0.02; ctx.fillStyle = COLORS.CYAN;
    ctx.fillRect(0, 0, S.W, S.H);
    ctx.globalAlpha = 0.15;
    const g = ctx.createLinearGradient(0, 0, 0, S.H);
    g.addColorStop(0, COLORS.CYAN); g.addColorStop(0.1, 'transparent');
    g.addColorStop(0.9, 'transparent'); g.addColorStop(1, COLORS.CYAN);
    ctx.fillStyle = g; ctx.fillRect(0, 0, S.W, S.H);
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
    drawAmbient(); drawGrid(); drawReticle(); drawTrails(); drawPowerups();
    drawEnemies(); drawPlayer(); drawParticles(); drawFloats();
    drawComboMeter(); drawFuryOverlay(); drawBossWarning(); drawScan();

    if (S.flashT > 0) {
      ctx.globalAlpha = S.flashT / 15; ctx.fillStyle = S.flashColor;
      ctx.fillRect(0, 0, W, H); S.flashT--;
    }
    if (S.waveTimer < 60 && S.wave > 1) {
      ctx.save(); ctx.globalAlpha = 1 - S.waveTimer / 60; ctx.fillStyle = COLORS.RED_B;
      ctx.font = `700 ${Math.min(48, Math.max(20, W * .05))}px 'Chakra Petch', sans-serif`;
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillText(`WAVE ${S.wave}`, cx, cy); ctx.restore();
    }
    ctx.restore();
  }

  // ===========================================================
  // 7. INPUT
  // ===========================================================

  const keys = {};
  const dpadVec = { x: 0, y: 0 };

  function initInput() {
    window.addEventListener('keydown', e => {
      keys[e.key] = true;
      if (e.key === ' ' && S.phase === 'playing') { e.preventDefault(); attack(); }
      if ((e.key === 'Shift' || e.key === 'e' || e.key === 'E') && S.phase === 'playing') { e.preventDefault(); dash(); }
    });
    window.addEventListener('keyup', e => { keys[e.key] = false; });

    const dpad = document.getElementById('dpad');
    if (dpad) {
      let dpadTouchId = null, dpadRect = null;
      function updDpad(tx, ty) {
        if (!dpadRect) return;
        const cx = dpadRect.left + dpadRect.width / 2, cy = dpadRect.top + dpadRect.height / 2;
        const r = dpadRect.width / 2;
        let dx = (tx - cx) / r, dy = (ty - cy) / r;
        const m = Math.hypot(dx, dy);
        if (m > 1) { dx /= m; dy /= m; }
        dpadVec.x = dx; dpadVec.y = dy;
      }
      dpad.addEventListener('touchstart', e => {
        e.preventDefault(); e.stopPropagation();
        dpadRect = dpad.getBoundingClientRect();
        const t = e.changedTouches[0]; dpadTouchId = t.identifier;
        updDpad(t.clientX, t.clientY); dpad.classList.add('active');
      }, { passive: false });
      dpad.addEventListener('touchmove', e => {
        e.preventDefault(); e.stopPropagation();
        for (const t of e.changedTouches) if (t.identifier === dpadTouchId) updDpad(t.clientX, t.clientY);
      }, { passive: false });
      const endDpad = e => {
        for (const t of e.changedTouches)
          if (t.identifier === dpadTouchId) { dpadVec.x = 0; dpadVec.y = 0; dpadTouchId = null; dpad.classList.remove('active'); }
      };
      dpad.addEventListener('touchend', endDpad);
      dpad.addEventListener('touchcancel', endDpad);
      window.addEventListener('resize', () => { dpadRect = null; });
    }

    const atkBtn = document.getElementById('atkBtn');
    if (atkBtn) {
      atkBtn.addEventListener('touchstart', e => {
        e.preventDefault(); e.stopPropagation();
        if (S.phase === 'playing') attack(); atkBtn.classList.add('active');
      }, { passive: false });
      atkBtn.addEventListener('touchend', e => { e.preventDefault(); atkBtn.classList.remove('active'); });
      atkBtn.addEventListener('touchcancel', () => atkBtn.classList.remove('active'));
    }

    const dashBtn = document.getElementById('dashBtn');
    if (dashBtn) {
      dashBtn.addEventListener('touchstart', e => {
        e.preventDefault(); e.stopPropagation();
        if (S.phase === 'playing') dash(); dashBtn.classList.add('active');
      }, { passive: false });
      dashBtn.addEventListener('touchend', e => { e.preventDefault(); dashBtn.classList.remove('active'); });
      dashBtn.addEventListener('touchcancel', () => dashBtn.classList.remove('active'));
    }
  }

  // ===========================================================
  // 8. UI
  // ===========================================================

  const $ = id => document.getElementById(id);

  function updateHUD() {
    $('hudWave').textContent = S.wave;
    $('hudScore').textContent = S.score.toLocaleString();
    $('hudHi').textContent = 'HI ' + S.hi.toLocaleString();
    $('hudCombo').textContent = S.combo > 1 ? `COMBO ×${S.combo}` : '';
    const lc = $('hudLives'); lc.innerHTML = '';
    for (let i = 0; i < S.maxLives; i++) {
      const d = document.createElement('div');
      d.className = 'hud-life' + (i >= S.lives ? ' lost' : '');
      lc.appendChild(d);
    }
    const furyEl = $('hudFury');
    if (furyEl) {
      if (S.furyTimer > 0) { furyEl.textContent = `FURY ${Math.ceil(S.furyTimer / 60)}s`; furyEl.style.display = 'block'; }
      else furyEl.style.display = 'none';
    }
  }

  function showGameOver() {
    if (S.score > S.hi) { S.hi = S.score; try { localStorage.setItem('warriors_hi', S.hi); } catch (e) { } }
    $('finalScore').textContent = S.score.toLocaleString();
    const v = VERDICTS.find(v => S.score >= v.min);
    $('verdictText').textContent = `${v.cn} — ${v.en}`;
    $('gameOverScreen').classList.remove('hidden');
    const statsEl = $('finalStats');
    if (statsEl) statsEl.textContent = `WAVE ${S.wave} · ${S.totalKills} KILLS · MAX COMBO ×${S.maxCombo}`;
  }

  // ===========================================================
  // 9. GAME LOOP
  // ===========================================================

  function startGame() {
    ensureAudio(); resetState();
    $('titleScreen').classList.add('hidden');
    $('gameOverScreen').classList.add('hidden');
    updateHUD();
  }

  function gameOver() { S.phase = 'over'; SFX.gameover(); showGameOver(); }

  function update() {
    const sp = PLAYER_CFG.MOVE_SPEED;
    if (S.dashTimer > 0) {
      S.targetX += S.dashDirX * PLAYER_CFG.DASH_SPEED;
      S.targetY += S.dashDirY * PLAYER_CFG.DASH_SPEED;
      S.dashTimer--;
      if (S.tick % 2 === 0) addTrail();
    } else {
      if (keys['ArrowLeft'] || keys['a'] || keys['A']) S.targetX -= sp;
      if (keys['ArrowRight'] || keys['d'] || keys['D']) S.targetX += sp;
      if (keys['ArrowUp'] || keys['w'] || keys['W']) S.targetY -= sp;
      if (keys['ArrowDown'] || keys['s'] || keys['S']) S.targetY += sp;
      S.targetX += dpadVec.x * sp; S.targetY += dpadVec.y * sp;
    }

    S.targetX = Math.max(-1, Math.min(1, S.targetX));
    S.targetY = Math.max(-1, Math.min(1, S.targetY));
    S.playerX += (S.targetX - S.playerX) * PLAYER_CFG.LERP;
    S.playerY += (S.targetY - S.playerY) * PLAYER_CFG.LERP;

    if (S.attackCooldown > 0) S.attackCooldown--;
    if (S.dashCooldown > 0) S.dashCooldown--;
    if (S.iframes > 0) S.iframes--;
    if (S.furyTimer > 0) S.furyTimer--;

    S.spawnTimer--;
    if (S.spawnTimer <= 0 && !S.bossActive) {
      spawnEnemy();
      S.spawnTimer = Math.max(SPAWN_CFG.MIN_INTERVAL, SPAWN_CFG.BASE_INTERVAL - S.wave * SPAWN_CFG.WAVE_REDUCTION);
    }

    S.waveTimer++;
    if (S.enemiesKilled >= WAVE_CFG.BASE_KILLS + S.wave * WAVE_CFG.KILLS_PER_WAVE) {
      S.wave++; S.enemiesKilled = 0; S.flashT = 10; S.flashColor = COLORS.RED_G; S.waveTimer = 0;
      SFX.wave();
      if (S.wave % WAVE_CFG.BOSS_EVERY === 0) {
        S.bossWarning = 90;
        setTimeout(() => { if (S.phase === 'playing') spawnBoss(); }, 1500);
      }
    }

    const p = getPlayerPos();
    for (let i = S.enemies.length - 1; i >= 0; i--) {
      const e = S.enemies[i];
      e.depth -= e.speed; e.wobble += 0.05;
      if (e.type === 'boss') e.lane += (S.playerX * 0.3 - e.lane) * 0.005;

      if (e.depth < 0.03) {
        S.enemies.splice(i, 1);
        if (e.type === 'boss') S.bossActive = false;
        if (S.iframes > 0) continue;
        const dmg = e.type === 'boss' ? 2 : 1;
        S.lives -= dmg; S.combo = 0; S.shakeT = 14; S.flashT = 10; S.flashColor = COLORS.RED_G;
        SFX.damage(); spawnParticles(p.x, p.y, COLORS.RED_G, 14);
        if (S.lives <= 0) { S.lives = 0; return gameOver(); }
      }
    }

    updateParticles(); updateFloats(); updateTrails(); updatePowerups(); updateHUD();
  }

  function loop() {
    S.tick++;
    if (S.phase === 'playing') update();
    if (S.phase !== 'title') drawFrame();
    requestAnimationFrame(loop);
  }

  // ===========================================================
  // 10. BOOT
  // ===========================================================

  function init() {
    try { S.hi = parseInt(localStorage.getItem('warriors_hi')) || 0; } catch (e) { }
    initRenderer(); initInput();
    $('startBtn').addEventListener('click', startGame);
    $('retryBtn').addEventListener('click', startGame);
    loop();
  }

  init();
})();
