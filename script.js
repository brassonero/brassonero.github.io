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
const orb3 = document.getElementById('orb3');

// ── State ──
let isPlaying = false;
let hasPlayed = false;
let audioContext = null;
let analyser = null;
let dataArray = null;
let source = null;
let mouseX = 0.5;
let mouseY = 0.5;
let planckScale = 1;
let planckGlow = 0;
let planckBlur = 8;

const isMobile =
    /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) ||
    window.matchMedia('(max-width: 768px)').matches;

// ── Film grain ──
function initGrain() {
    grainCanvas.width = 1024;
    grainCanvas.height = 1024;
    generateGrain();
}

function generateGrain() {
    const imageData = gCtx.createImageData(1024, 1024);
    const data = imageData.data;
    for (let i = 0; i < data.length; i += 4) {
        const v = Math.random() * 255;
        data[i] = v;
        data[i + 1] = v;
        data[i + 2] = v;
        data[i + 3] = 255;
    }
    gCtx.putImageData(imageData, 0, 0);
}

setInterval(generateGrain, 100);
initGrain();

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
function getFrequencyBands() {
    if (!analyser || !isPlaying) return { bass: 0, mid: 0, high: 0, average: 0 };
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
function updatePlanck(bands) {
    if (!isPlaying) {
        planckScale += (1 - planckScale) * 0.05;
        planckGlow += (0 - planckGlow) * 0.05;
        planckBlur += (8 - planckBlur) * 0.05;
        if (Math.abs(planckScale - 1) < 0.01) {
            planckEl.style.removeProperty('transform');
            planckEl.style.removeProperty('color');
            planckEl.style.removeProperty('text-shadow');
            planckEl.style.removeProperty('filter');
        }
        return;
    }

    planckEl.style.animation = 'none';

    const targetScale = 1 + bands.bass * 0.18 + bands.average * 0.06;
    const targetGlow = bands.average;
    const targetBlur = 6 - bands.bass * 4 - bands.average * 2;
    const clampedBlur = Math.max(0.5, targetBlur);

    planckScale += (targetScale - planckScale) * 0.18;
    planckGlow += (targetGlow - planckGlow) * 0.15;
    planckBlur += (clampedBlur - planckBlur) * 0.12;

    const alpha = 0.25 + planckGlow * 0.5;
    const innerGlow = 20 + planckGlow * 60;
    const magentaGlow = 40 + bands.bass * 120;
    const violetGlow = 80 + bands.mid * 160;
    const cyanGlow = 160 + bands.high * 300;
    const magentaAlpha = 0.1 + bands.bass * 0.4;
    const violetAlpha = 0.06 + bands.mid * 0.25;
    const cyanAlpha = 0.02 + bands.high * 0.1;

    planckEl.style.transform = `translate(-50%, -50%) scale(${planckScale})`;
    planckEl.style.color = `rgba(255, 255, 255, ${alpha})`;
    planckEl.style.filter = `blur(${planckBlur}px)`;
    planckEl.style.textShadow = `0 0 ${innerGlow}px rgba(255, 255, 255, ${alpha * 0.3}), 0 0 ${magentaGlow}px rgba(255, 20, 147, ${magentaAlpha}), 0 0 ${violetGlow}px rgba(138, 43, 226, ${violetAlpha}), 0 0 ${cyanGlow}px rgba(0, 255, 255, ${cyanAlpha})`;
}

// ── Drive visualizer bars from real audio data ──
function updateBars(bands) {
    if (!isPlaying || !analyser) return;
    analyser.getByteFrequencyData(dataArray);
    const step = Math.floor(dataArray.length / bars.length);
    bars.forEach((bar, i) => {
        const val = dataArray[i * step] / 255;
        const h = 3 + val * 21;
        bar.style.height = h + 'px';
        bar.style.opacity = 0.5 + val * 0.5;
    });
}

// ── Orb audio reactivity + mouse parallax ──
function updateOrbs(bands) {
    if (!isPlaying) return;
    const bassScale = 1 + bands.bass * 0.15;
    const midScale = 1 + bands.mid * 0.1;
    const px = isMobile ? 0 : (mouseX - 0.5) * 30;
    const py = isMobile ? 0 : (mouseY - 0.5) * 30;

    orb1.style.transform = `translate(${px * 0.8}px, ${py * 0.8}px) scale(${bassScale})`;
    orb2.style.transform = `translate(${-px * 0.5}px, ${-py * 0.5}px) scale(${midScale})`;
    orb3.style.transform = `translate(${px * 0.3 - 50}%, ${py * 0.3 - 50}%) scale(${1 + bands.high * 0.12})`;
}

// ── Main animation loop ──
function animate() {
    const bands = getFrequencyBands();
    updatePlanck(bands);
    updateBars(bands);
    updateOrbs(bands);
    requestAnimationFrame(animate);
}
requestAnimationFrame(animate);

// ── Toggle audio ──
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
        }).catch(error => {
            console.log('Play failed:', error);
        });
    } else {
        audio.pause();
        isPlaying = false;
        document.body.classList.remove('playing');
        document.body.style.filter = '';
        planckEl.style.animation = '';
    }
}

// ── Event listeners ──
audio.addEventListener('ended', () => {
    isPlaying = false;
    document.body.classList.remove('playing');
    document.body.style.filter = '';
    planckEl.style.animation = '';
});

audioControl.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleAudio();
});

document.body.addEventListener('click', (e) => {
    if (!isPlaying && e.target === document.body) {
        toggleAudio();
    }
});

let touchStart = null;
document.body.addEventListener('touchstart', (e) => {
    touchStart = e.touches[0];
});

document.body.addEventListener('touchend', (e) => {
    if (touchStart && !isPlaying && e.target === document.body) {
        const touchEnd = e.changedTouches[0];
        const distance = Math.sqrt(
            Math.pow(touchEnd.clientX - touchStart.clientX, 2) +
            Math.pow(touchEnd.clientY - touchStart.clientY, 2)
        );
        if (distance < 10) {
            toggleAudio();
        }
    }
    touchStart = null;
});

// ── Desktop mouse interactions ──
if (!isMobile) {
    let rawMouseX = 0, rawMouseY = 0;
    let glowX = 0, glowY = 0;

    function animateGlow() {
        glowX += (rawMouseX - glowX) * 0.08;
        glowY += (rawMouseY - glowY) * 0.08;

        cursorGlow.style.left = glowX + 'px';
        cursorGlow.style.top = glowY + 'px';

        requestAnimationFrame(animateGlow);
    }
    animateGlow();

    document.addEventListener('mousemove', (e) => {
        rawMouseX = e.clientX;
        rawMouseY = e.clientY;
        mouseX = e.clientX / window.innerWidth;
        mouseY = e.clientY / window.innerHeight;

        const hueRotation = mouseX * 60 - 30;
        const brightness = 0.95 + mouseY * 0.1;

        if (isPlaying) {
            document.body.style.filter = `hue-rotate(${hueRotation}deg) brightness(${brightness}) saturate(1.4)`;
        }

        const duration = isPlaying
            ? `${10 + mouseY * 5}s, ${4 + mouseX * 2}s`
            : `${20 + mouseY * 10}s, ${6 + mouseX * 4}s`;
        document.body.style.animationDuration = duration;
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
        toggleAudio();
    }

    if (e.code === 'KeyP' && !isMobile) {
        document.body.style.filter = `hue-rotate(${Math.random() * 360}deg) brightness(1.2) saturate(2)`;
        setTimeout(() => {
            document.body.style.filter = isPlaying ? 'brightness(1.1) saturate(1.3)' : '';
        }, 2000);
    }
});

// ── Viewport ──
function setViewportHeight() {
    const vh = window.innerHeight * 0.01;
    document.documentElement.style.setProperty('--vh', `${vh}px`);
}
setViewportHeight();
window.addEventListener('resize', setViewportHeight);
window.addEventListener('orientationchange', setViewportHeight);

if (isMobile) {
    document.body.style.willChange = 'transform';
}

let touchStartY = 0;
document.addEventListener('touchstart', (e) => {
    touchStartY = e.touches[0].clientY;
}, { passive: false });

document.addEventListener('touchmove', (e) => {
    const touchY = e.touches[0].clientY;
    const touchDiff = touchY - touchStartY;
    if (touchDiff > 0 && window.scrollY === 0) {
        e.preventDefault();
    }
}, { passive: false });
