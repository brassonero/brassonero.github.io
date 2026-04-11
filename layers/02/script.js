// =============================================
// THE WARRIORS — Poster Interactions
// =============================================

(function () {
    'use strict';

    // === DOM REFERENCES ===
    const poster = document.getElementById('poster');
    const grid = document.querySelector('.grid-container');
    const globe = document.querySelector('.globe-container');
    const canvas = document.getElementById('waveCanvas');
    const ctx = canvas.getContext('2d');
    const chars = document.querySelectorAll('.cn-char');

    // === GRID FLICKER ===
    function initGridFlicker() {
        setInterval(() => {
            grid.style.opacity = 0.92 + Math.random() * 0.08;
        }, 150);
    }

    // === MOUSE & TOUCH PARALLAX ===
    function handleMove(clientX, clientY) {
        const rect = poster.getBoundingClientRect();
        const x = (clientX - rect.left) / rect.width - 0.5;
        const y = (clientY - rect.top) / rect.height - 0.5;
        globe.style.transform = `translateX(calc(-50% + ${x * 12}px)) translateY(${y * 6}px)`;
    }

    function initParallax() {
        poster.addEventListener('mousemove', (e) => handleMove(e.clientX, e.clientY));
        poster.addEventListener('touchmove', (e) => {
            const t = e.touches[0];
            handleMove(t.clientX, t.clientY);
        }, { passive: true });
    }

    // === ANIMATED WAVEFORM ===
    let wavePhase = 0;

    function resizeCanvas() {
        const rect = canvas.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) return;
        canvas.width = rect.width * 2;
        canvas.height = rect.height * 2;
        ctx.scale(2, 2);
    }

    function drawWave() {
        const w = canvas.width / 2;
        const h = canvas.height / 2;
        ctx.clearRect(0, 0, w, h);

        // Primary waveform
        ctx.strokeStyle = '#2daa5a';
        ctx.lineWidth = 1.5;
        ctx.shadowColor = 'rgba(45,170,90,0.5)';
        ctx.shadowBlur = 4;
        ctx.beginPath();

        const mid = h / 2;
        for (let x = 0; x < w; x++) {
            const t = x / w;
            const amp = Math.sin(t * Math.PI) * mid * 0.8;
            const noise = Math.sin(t * 40 + wavePhase) * 0.5 +
                Math.sin(t * 23 + wavePhase * 1.3) * 0.3 +
                Math.sin(t * 67 + wavePhase * 0.7) * 0.2;
            const y = mid + noise * amp;
            x === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
        }
        ctx.stroke();

        // Ghost waveform
        ctx.strokeStyle = 'rgba(45,170,90,0.2)';
        ctx.shadowBlur = 0;
        ctx.beginPath();
        for (let x = 0; x < w; x++) {
            const t = x / w;
            const amp = Math.sin(t * Math.PI) * mid * 0.4;
            const noise = Math.sin(t * 40 + wavePhase + 1) * 0.5 +
                Math.sin(t * 23 + wavePhase * 1.3 + 1) * 0.3;
            const y = mid + noise * amp;
            x === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
        }
        ctx.stroke();

        wavePhase += 0.04;
        requestAnimationFrame(drawWave);
    }

    function initWaveform() {
        resizeCanvas();

        let resizeTimeout;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(() => {
                ctx.setTransform(1, 0, 0, 1, 0, 0);
                resizeCanvas();
            }, 150);
        });

        drawWave();
    }

    // === GLITCH ON CHINESE CHARS ===
    function triggerGlitch() {
        const idx = Math.floor(Math.random() * chars.length);
        const el = chars[idx];
        el.classList.add('glitch');
        setTimeout(() => el.classList.remove('glitch'), 150);
        setTimeout(triggerGlitch, 2000 + Math.random() * 5000);
    }

    function glitchAll() {
        chars.forEach((el, i) => {
            setTimeout(() => {
                el.classList.add('glitch');
                setTimeout(() => el.classList.remove('glitch'), 150);
            }, i * 50);
        });
    }

    function initGlitch() {
        setTimeout(triggerGlitch, 3000);
        poster.addEventListener('click', glitchAll);
        poster.addEventListener('touchstart', glitchAll, { passive: true });
    }

    // === BOOT ===
    function init() {
        initGridFlicker();
        initParallax();
        initWaveform();
        initGlitch();
    }

    // Run when DOM is ready (script is deferred, so this is safe)
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
