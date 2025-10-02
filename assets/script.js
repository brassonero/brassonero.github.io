const AudioPlayer = {
    audio: null,
    audioControl: null,
    playIcon: null,
    pauseIcon: null,
    visualizer: null,
    controlText: null,
    isPlaying: false,

    init(trackNumber) {
        this.audio = document.getElementById('backgroundAudio');
        this.audioControl = document.getElementById('audioControl');
        this.playIcon = document.querySelector('.play-icon');
        this.pauseIcon = document.querySelector('.pause-icon');
        this.visualizer = document.querySelector('.visualizer');
        this.controlText = document.querySelector('.control-text');

        if (!this.audio) {
            console.error('Audio element not found');
            return;
        }

        this.audio.loop = true;
        this.setupEventListeners(trackNumber);
    },

    toggleAudio(trackNumber) {
        if (!this.isPlaying) {
            this.audio.play().then(() => {
                this.isPlaying = true;
                document.body.classList.add('playing');
                this.controlText.textContent = '∞';
                this.playIcon.style.display = 'none';
                this.pauseIcon.style.display = 'block';
                this.visualizer.style.display = 'flex';
            }).catch(error => {
                console.log('Play failed:', error);
                alert(`Please convert ${trackNumber}.mid to ${trackNumber}.wav and place it in the assets folder`);
            });
        } else {
            this.audio.pause();
            this.isPlaying = false;
            document.body.classList.remove('playing');
            this.controlText.textContent = 'ℎ';
            this.playIcon.style.display = 'block';
            this.pauseIcon.style.display = 'none';
            this.visualizer.style.display = 'none';
        }
    },

    setupEventListeners(trackNumber) {
        this.audioControl.addEventListener('click', (e) => {
            e.stopPropagation();
            this.toggleAudio(trackNumber);
        });

        document.addEventListener('keydown', (e) => {
            if (e.code === 'Space') {
                e.preventDefault();
                this.toggleAudio(trackNumber);
            }
        });

        window.addEventListener('load', () => {
            document.addEventListener('click', function initAudio() {
                if (!AudioPlayer.isPlaying) {
                    AudioPlayer.audio.play().then(() => {
                        AudioPlayer.isPlaying = true;
                        document.body.classList.add('playing');
                        AudioPlayer.controlText.textContent = '∞';
                        AudioPlayer.playIcon.style.display = 'none';
                        AudioPlayer.pauseIcon.style.display = 'block';
                        AudioPlayer.visualizer.style.display = 'flex';
                        document.removeEventListener('click', initAudio);
                    }).catch(() => { });
                }
            }, { once: true });
        });

        this.audio.addEventListener('ended', () => {
            if (this.audio.loop) {
                console.log('Looping...');
            } else {
                this.isPlaying = false;
                document.body.classList.remove('playing');
                this.controlText.textContent = 'ℎ';
                this.playIcon.style.display = 'block';
                this.pauseIcon.style.display = 'none';
                this.visualizer.style.display = 'none';
            }
        });
    }
};

const Navigation = {
    navToggle: null,
    navMenu: null,
    navLinks: null,
    isNavOpen: false,
    touchStartX: 0,
    touchEndX: 0,

    init() {
        this.navToggle = document.getElementById('navToggle');
        this.navMenu = document.getElementById('navMenu');
        this.navLinks = document.querySelectorAll('.nav-link');

        this.setupEventListeners();
        this.highlightCurrentPage();
    },

    setupEventListeners() {
        this.navToggle.addEventListener('click', (e) => {
            e.stopPropagation();
            this.isNavOpen = !this.isNavOpen;
            this.navMenu.classList.toggle('open');
            this.navToggle.classList.toggle('active');
        });

        this.navMenu.addEventListener('click', (e) => {
            e.stopPropagation();
        });

        document.addEventListener('click', (e) => {
            if (!this.navMenu.contains(e.target) && this.isNavOpen) {
                this.closeNav();
            }
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.isNavOpen) {
                this.closeNav();
            }

            if (e.key >= '1' && e.key <= '9' && !e.ctrlKey && !e.altKey && !e.metaKey) {
                const trackNumber = e.key.padStart(2, '0');
                const targetLink = document.querySelector(`[data-track="${trackNumber}"]`);
                if (targetLink) {
                    targetLink.click();
                }
            }
        });

        this.navLinks.forEach(link => {
            link.addEventListener('click', () => {
                setTimeout(() => {
                    this.closeNav();
                }, 300);
            });
        });

        this.navMenu.addEventListener('touchstart', (e) => {
            this.touchStartX = e.changedTouches[0].screenX;
        });

        this.navMenu.addEventListener('touchend', (e) => {
            this.touchEndX = e.changedTouches[0].screenX;
            this.handleSwipe();
        });
    },

    closeNav() {
        this.navMenu.classList.remove('open');
        this.navToggle.classList.remove('active');
        this.isNavOpen = false;
    },

    handleSwipe() {
        if (this.touchEndX > this.touchStartX + 50 && this.isNavOpen) {
            this.closeNav();
        }
    },

    highlightCurrentPage() {
        const currentPage = window.location.pathname.split('/').pop() || 'index';
        this.navLinks.forEach(link => {
            const href = link.getAttribute('href');
            if (href && (href.includes(currentPage) || href.replace('../', '') === currentPage)) {
                link.classList.add('active');
            }
        });
    }
};

const ViewportHelper = {
    init() {
        this.setViewportHeight();
        window.addEventListener('resize', () => this.setViewportHeight());
        window.addEventListener('orientationchange', () => this.setViewportHeight());
    },

    setViewportHeight() {
        const vh = window.innerHeight * 0.01;
        document.documentElement.style.setProperty('--vh', `${vh}px`);
    }
};

function initApp(config = {}) {
    const {
        trackNumber = '01',
        trackClass = 'track-01'
    } = config;

    document.body.classList.add(trackClass);

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            AudioPlayer.init(trackNumber);
            Navigation.init();
            ViewportHelper.init();
        });
    } else {
        AudioPlayer.init(trackNumber);
        Navigation.init();
        ViewportHelper.init();
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { initApp, AudioPlayer, Navigation, ViewportHelper };
}