// ── DOM references ──
const audio = document.getElementById('backgroundAudio');
const audioControl = document.querySelector('.audio-control');
const cursorGlow = document.querySelector('.cursor-glow');
const bars = document.querySelectorAll('.bar');
const planckEl = document.getElementById('planckSymbol');
const grainCanvas = document.getElementById('grainCanvas');
const gCtx = grainCanvas.getContext('2d');
const orb1 = document.getElementById('orb1');
const orb2 = document.getElementById('orb2');
const stage = document.getElementById('stage');
const bg = document.querySelector('.bg');

// ── State ──
let isPlaying = false;
let hasPlayed = false;
let audioContext = null;
let analyser = null;
let dataArray = null;
let source = null;
let mouseX = 0.5;
let mouseY = 0.5;

const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

const isMobile =
    /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) ||
    window.matchMedia('(max-width: 768px)').matches ||
    window.matchMedia('(pointer: coarse)').matches;

// ── Film grain ──
// A handful of noise frames are rendered ONCE into offscreen canvases;
// each tick just blits a cached frame (sub-millisecond) instead of
// filling a megapixel buffer with Math.random() on the main thread.
const GRAIN_SIZE = isMobile ? 320 : 640;
const GRAIN_FRAMES = 6;
const GRAIN_INTERVAL_MS = 100;
const grainFrames = [];
let grainIdx = 0;

const isLittleEndian = (() => {
    const buf = new ArrayBuffer(4);
    new Uint32Array(buf)[0] = 0x0a0b0c0d;
    return new Uint8Array(buf)[0] === 0x0d;
})();

function makeGrainFrame() {
    const c = document.createElement('canvas');
    c.width = GRAIN_SIZE;
    c.height = GRAIN_SIZE;
    const ctx = c.getContext('2d');
    const img = ctx.createImageData(GRAIN_SIZE, GRAIN_SIZE);
    const px = new Uint32Array(img.data.buffer);
    if (isLittleEndian) {
        for (let i = 0; i < px.length; i++) {
            const v = (Math.random() * 256) | 0;
            px[i] = 0xFF000000 | (v << 16) | (v << 8) | v; // ABGR
        }
    } else {
        for (let i = 0; i < px.length; i++) {
            const v = (Math.random() * 256) | 0;
            px[i] = (v << 24) | (v << 16) | (v << 8) | 0xFF; // RGBA
        }
    }
    ctx.putImageData(img, 0, 0);
    return c;
}

function initGrain() {
    grainCanvas.width = GRAIN_SIZE;
    grainCanvas.height = GRAIN_SIZE;
    grainFrames.push(makeGrainFrame());
    gCtx.drawImage(grainFrames[0], 0, 0);
    // Build the remaining frames off the critical path.
    const buildNext = () => {
        if (grainFrames.length < GRAIN_FRAMES) {
            grainFrames.push(makeGrainFrame());
            setTimeout(buildNext, 50);
        }
    };
    setTimeout(buildNext, 80);
}

initGrain();
setInterval(() => {
    if (document.hidden || prefersReducedMotion.matches || grainFrames.length < 2) return;
    grainIdx = (grainIdx + 1) % grainFrames.length;
    gCtx.drawImage(grainFrames[grainIdx], 0, 0);
}, GRAIN_INTERVAL_MS);

// ── Web Audio API setup ──
function initAudioContext() {
    if (audioContext) return;
    audioContext = new (window.AudioContext || window.webkitAudioContext)();
    analyser = audioContext.createAnalyser();
    analyser.fftSize = 256;
    analyser.smoothingTimeConstant = 0.8;
    dataArray = new Uint8Array(analyser.frequencyBinCount);
    source = audioContext.createMediaElementSource(audio);
    source.connect(analyser);
    analyser.connect(audioContext.destination);
}

// ── Audio-reactive helpers ──
// Reads the frequency data once per frame; every consumer shares it.
function readFrequencyBands() {
    if (!analyser || !isPlaying) return null;
    analyser.getByteFrequencyData(dataArray);
    const len = dataArray.length;
    let bass = 0, mid = 0, high = 0, sum = 0;
    for (let i = 0; i < len; i++) {
        sum += dataArray[i];
        if (i < len * 0.15) bass += dataArray[i];
        else if (i < len * 0.5) mid += dataArray[i];
        else high += dataArray[i];
    }
    const bassCount = Math.floor(len * 0.15) || 1;
    const midCount = Math.floor(len * 0.35) || 1;
    const highCount = len - Math.floor(len * 0.5) || 1;
    return {
        bass: bass / bassCount / 255,
        mid: mid / midCount / 255,
        high: high / highCount / 255,
        average: sum / len / 255,
    };
}

// ── Update ℏ symbol from audio ──
// Only two cheap writes per frame: a composited transform, and a --pulse
// custom property that drives the glow layer's opacity in CSS. The heavy
// per-frame text-shadow / color / filter repaints are gone — the ambient
// defocus and base glow live entirely in CSS now.
let planckScale = 1;
let planckPulse = 0;
let planckSettled = true;

function updatePlanck(bands) {
    if (!bands) {
        if (planckSettled) return;
        planckScale += (1 - planckScale) * ease(0.06);
        planckPulse += (0 - planckPulse) * ease(0.08);
        if (Math.abs(planckScale - 1) < 0.005 && planckPulse < 0.01) {
            planckEl.style.removeProperty('transform');
            planckEl.style.removeProperty('--pulse');
            planckSettled = true;
            return;
        }
    } else {
        planckSettled = false;
        const targetScale = 1 + bands.bass * 0.18 + bands.average * 0.06;
        const targetPulse = Math.min(1, bands.average * 0.85 + bands.bass * 0.5);
        planckScale += (targetScale - planckScale) * ease(0.18);
        planckPulse += (targetPulse - planckPulse) * ease(0.15);
    }
    planckEl.style.transform = `translate(-50%, -50%) scale(${planckScale.toFixed(4)})`;
    planckEl.style.setProperty('--pulse', planckPulse.toFixed(3));
}

// ── Drive visualizer bars from real audio data ──
function updateBars(bands) {
    if (!bands) return;
    const step = Math.floor(dataArray.length / bars.length);
    bars.forEach((bar, i) => {
        const val = dataArray[i * step] / 255;
        const h = 3 + val * 21;
        bar.style.height = h + 'px';
        bar.style.opacity = 0.5 + val * 0.5;
    });
}

// ── Orb audio reactivity + mouse parallax ──
// The floating orbs are moved by a CSS animation, which overrides any
// inline transform — so reactivity is fed through custom properties
// (--px / --py / --s) that the float keyframes compose in. Writes are
// skipped when the value hasn't meaningfully changed.
const orbState = [
    { el: orb1, band: 'bass', amount: 0.15, parallax: 0.8, s: 1, x: 0, y: 0, ws: NaN, wx: NaN, wy: NaN },
    { el: orb2, band: 'mid', amount: 0.10, parallax: -0.5, s: 1, x: 0, y: 0, ws: NaN, wx: NaN, wy: NaN },
];
let orbsSettled = true;

function updateOrbs(bands) {
    const active = !!bands;
    if (!active && orbsSettled) return;

    const px = (active && !isMobile) ? (mouseX - 0.5) * 30 : 0;
    const py = (active && !isMobile) ? (mouseY - 0.5) * 30 : 0;
    let allSettled = true;

    for (const o of orbState) {
        const targetS = active ? 1 + bands[o.band] * o.amount : 1;
        const k = ease(0.15);
        o.s += (targetS - o.s) * k;
        o.x += (px * o.parallax - o.x) * k;
        o.y += (py * o.parallax - o.y) * k;

        if (Math.abs(o.s - 1) > 0.002 || Math.abs(o.x) > 0.05 || Math.abs(o.y) > 0.05) {
            allSettled = false;
        }
        if (Math.abs(o.s - o.ws) > 0.003 || !isFinite(o.ws)) {
            o.el.style.setProperty('--s', o.s.toFixed(3));
            o.ws = o.s;
        }
        if (Math.abs(o.x - o.wx) > 0.25 || !isFinite(o.wx)) {
            o.el.style.setProperty('--px', o.x.toFixed(1) + 'px');
            o.wx = o.x;
        }
        if (Math.abs(o.y - o.wy) > 0.25 || !isFinite(o.wy)) {
            o.el.style.setProperty('--py', o.y.toFixed(1) + 'px');
            o.wy = o.y;
        }
    }

    if (!active && allSettled) {
        for (const o of orbState) {
            o.el.style.removeProperty('--s');
            o.el.style.removeProperty('--px');
            o.el.style.removeProperty('--py');
            o.ws = o.wx = o.wy = NaN;
        }
        orbsSettled = true;
    } else {
        orbsSettled = false;
    }
}

// ── Cursor glow (desktop) ──
let rawMouseX = 0, rawMouseY = 0;
let glowX = 0, glowY = 0;
let glowInitialized = false;

function updateGlow() {
    if (isMobile || !glowInitialized) return;
    const k = ease(0.08);
    glowX += (rawMouseX - glowX) * k;
    glowY += (rawMouseY - glowY) * k;
    cursorGlow.style.transform = `translate3d(${glowX}px, ${glowY}px, 0) translate(-50%, -50%)`;
}

// ── Main animation loop (one rAF for everything) ──
// Smoothing factors are corrected by real elapsed time so the easing
// speed is identical at 30fps on a weak phone and 120fps on a desktop.
let lastFrameTime = performance.now();
let frameScale = 1;

function ease(ratePerFrameAt60) {
    return 1 - Math.pow(1 - ratePerFrameAt60, frameScale);
}

function animate(now) {
    const dt = Math.min(100, now - lastFrameTime) || 16.7;
    lastFrameTime = now;
    frameScale = dt / 16.7;

    const bands = readFrequencyBands();
    updatePlanck(bands);
    updateBars(bands);
    updateOrbs(bands);
    updateGlow();
    requestAnimationFrame(animate);
}
requestAnimationFrame(animate);

// ── Toggle audio ──
function syncControlState() {
    audioControl.setAttribute('aria-pressed', String(isPlaying));
    audioControl.setAttribute('aria-label', isPlaying ? 'Pausar la música' : 'Reproducir la música');
}

function toggleAudio() {
    if (!isPlaying) {
        initAudioContext();
        if (audioContext.state === 'suspended') {
            audioContext.resume();
        }
        if (hasPlayed && audio.ended) {
            audio.currentTime = 0;
            hasPlayed = false;
        }

        audio.play().then(() => {
            isPlaying = true;
            hasPlayed = true;
            document.body.classList.add('playing');
            syncControlState();
        }).catch(error => {
            console.log('Play failed:', error);
        });
    } else {
        audio.pause();
        isPlaying = false;
        document.body.classList.remove('playing');
        stage.style.filter = '';
        syncControlState();
    }
}

// ── Media Session (lock screen / hardware keys) ──
if ('mediaSession' in navigator) {
    try {
        navigator.mediaSession.metadata = new MediaMetadata({ title: 'brassonero' });
        navigator.mediaSession.setActionHandler('play', () => { if (!isPlaying) toggleAudio(); });
        navigator.mediaSession.setActionHandler('pause', () => { if (isPlaying) toggleAudio(); });
    } catch (e) { /* optional enhancement only */ }
}

// ── Event listeners ──
audio.addEventListener('ended', () => {
    isPlaying = false;
    document.body.classList.remove('playing');
    stage.style.filter = '';
    syncControlState();
});

audio.addEventListener('error', () => {
    console.warn('No se pudo cargar el audio:', audio.error);
});
const audioSource = audio.querySelector('source');
if (audioSource) {
    audioSource.addEventListener('error', () => {
        console.warn('No se pudo cargar el audio (fuente no disponible).');
    });
}

audioControl.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleAudio();
});

// Keyboard activation for the role="button" control.
audioControl.addEventListener('keydown', (e) => {
    if (e.code === 'Space' || e.code === 'Enter') {
        e.preventDefault();
        e.stopPropagation();
        if (!e.repeat) toggleAudio();
    }
});

document.body.addEventListener('click', (e) => {
    if (!isPlaying && e.target === document.body) {
        toggleAudio();
    }
});

// ── Touch: pull-to-refresh guard (tap-to-play is handled by 'click') ──
let touchStartY = null;

document.addEventListener('touchstart', (e) => {
    touchStartY = e.touches[0].clientY;
}, { passive: true });

document.addEventListener('touchmove', (e) => {
    if (touchStartY === null) return;
    const touchDiff = e.touches[0].clientY - touchStartY;
    if (touchDiff > 0 && window.scrollY === 0) {
        e.preventDefault(); // block pull-to-refresh
    }
}, { passive: false });

document.addEventListener('touchend', () => {
    touchStartY = null;
}, { passive: true });

// ── Desktop mouse interactions ──
if (!isMobile) {
    document.addEventListener('mousemove', (e) => {
        rawMouseX = e.clientX;
        rawMouseY = e.clientY;
        mouseX = e.clientX / window.innerWidth;
        mouseY = e.clientY / window.innerHeight;

        if (!glowInitialized) {
            glowX = rawMouseX;
            glowY = rawMouseY;
            glowInitialized = true;
            cursorGlow.style.opacity = '1';
        }

        if (prefersReducedMotion.matches) return;

        const hueRotation = mouseX * 60 - 30;
        const brightness = 0.95 + mouseY * 0.1;

        if (isPlaying) {
            stage.style.filter = `hue-rotate(${hueRotation}deg) brightness(${brightness}) saturate(1.4)`;
        }

        const duration = isPlaying
            ? `${10 + mouseY * 5}s, ${4 + mouseX * 2}s`
            : `${20 + mouseY * 10}s, ${6 + mouseX * 4}s`;
        bg.style.animationDuration = duration;
    });

    document.addEventListener('mouseenter', () => {
        cursorGlow.style.opacity = '1';
    });

    document.addEventListener('mouseleave', () => {
        cursorGlow.style.opacity = '0';
    });
}

document.addEventListener('keydown', (e) => {
    if (e.code === 'Space') {
        e.preventDefault();
        if (!e.repeat) toggleAudio();
    }

    if (e.code === 'KeyP' && !isMobile && !prefersReducedMotion.matches) {
        stage.style.filter = `hue-rotate(${Math.random() * 360}deg) brightness(1.2) saturate(2)`;
        setTimeout(() => {
            stage.style.filter = isPlaying ? 'brightness(1.1) saturate(1.3)' : '';
        }, 2000);
    }
});