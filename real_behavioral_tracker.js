/**
 * REAL BEHAVIORAL TRACKER
 * Gerçek kullanıcı davranışı tracking sistemi
 */

class RealBehavioralTracker {
    constructor(sessionId) {
        this.sessionId = sessionId || this.generateSessionId();
        this.startTime = Date.now();
        this.behavioralData = {
            sessionId: this.sessionId,
            startTime: this.startTime,
            mouseMovements: [],
            clicks: [],
            keystrokes: [],
            scrollEvents: [],
            focusEvents: [],
            pageInteractions: [],
            timingMetrics: {},
            deviceInfo: this.getDeviceInfo()
        };
        
        this.lastMousePosition = { x: 0, y: 0 };
        this.lastMouseTime = Date.now();
        this.keystrokeBuffer = [];
        this.isTracking = false;
        
        this.init();
    }
    
    generateSessionId() {
        return 'session_' + Math.random().toString(36).substr(2, 16) + '_' + Date.now();
    }
    
    getDeviceInfo() {
        return {
            userAgent: navigator.userAgent,
            screenWidth: screen.width,
            screenHeight: screen.height,
            viewportWidth: window.innerWidth,
            viewportHeight: window.innerHeight,
            colorDepth: screen.colorDepth,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            language: navigator.language,
            platform: navigator.platform,
            cookieEnabled: navigator.cookieEnabled,
            onlineStatus: navigator.onLine
        };
    }
    
    init() {
        console.log('🎯 Real Behavioral Tracker initialized:', this.sessionId);
        this.startTracking();
        this.setupEventListeners();
    }
    
    startTracking() {
        this.isTracking = true;
        this.behavioralData.timingMetrics.sessionStart = Date.now();
    }
    
    stopTracking() {
        this.isTracking = false;
        this.behavioralData.timingMetrics.sessionEnd = Date.now();
        this.behavioralData.timingMetrics.totalDuration = 
            this.behavioralData.timingMetrics.sessionEnd - this.behavioralData.timingMetrics.sessionStart;
    }
    
    setupEventListeners() {
        // Mouse Movement Tracking
        document.addEventListener('mousemove', (e) => this.trackMouseMovement(e), { passive: true });
        
        // Click Tracking
        document.addEventListener('click', (e) => this.trackClick(e), { passive: true });
        
        // Keyboard Tracking
        document.addEventListener('keydown', (e) => this.trackKeyDown(e), { passive: true });
        document.addEventListener('keyup', (e) => this.trackKeyUp(e), { passive: true });
        
        // Scroll Tracking
        document.addEventListener('scroll', (e) => this.trackScroll(e), { passive: true });
        
        // Focus/Blur Tracking
        window.addEventListener('focus', (e) => this.trackFocus(e));
        window.addEventListener('blur', (e) => this.trackBlur(e));
        
        // Page Visibility
        document.addEventListener('visibilitychange', (e) => this.trackVisibilityChange(e));
        
        // Page Unload
        window.addEventListener('beforeunload', () => this.sendBehavioralData());
        
        // Periodic data sending
        setInterval(() => this.sendBehavioralData(), 30000); // Her 30 saniyede bir gönder
    }
    
    trackMouseMovement(event) {
        if (!this.isTracking) return;
        
        const currentTime = Date.now();
        const currentPosition = { x: event.clientX, y: event.clientY };
        
        // Calculate movement metrics
        const distance = Math.sqrt(
            Math.pow(currentPosition.x - this.lastMousePosition.x, 2) + 
            Math.pow(currentPosition.y - this.lastMousePosition.y, 2)
        );
        
        const timeDelta = currentTime - this.lastMouseTime;
        const velocity = timeDelta > 0 ? distance / timeDelta : 0;
        
        // Only track significant movements (reduce noise)
        if (distance > 5 || timeDelta > 100) {
            this.behavioralData.mouseMovements.push({
                timestamp: currentTime,
                x: currentPosition.x,
                y: currentPosition.y,
                distance: Math.round(distance),
                velocity: Math.round(velocity * 1000) / 1000,
                timeDelta: timeDelta
            });
            
            // Keep only recent movements (last 1000)
            if (this.behavioralData.mouseMovements.length > 1000) {
                this.behavioralData.mouseMovements.shift();
            }
        }
        
        this.lastMousePosition = currentPosition;
        this.lastMouseTime = currentTime;
    }
    
    trackClick(event) {
        if (!this.isTracking) return;
        
        this.behavioralData.clicks.push({
            timestamp: Date.now(),
            x: event.clientX,
            y: event.clientY,
            button: event.button,
            target: event.target.tagName,
            targetId: event.target.id || null,
            targetClass: event.target.className || null
        });
    }
    
    trackKeyDown(event) {
        if (!this.isTracking) return;
        
        this.keystrokeBuffer.push({
            timestamp: Date.now(),
            key: event.key,
            code: event.code,
            type: 'keydown'
        });
    }
    
    trackKeyUp(event) {
        if (!this.isTracking) return;
        
        const now = Date.now();
        const recentKeystrokes = this.keystrokeBuffer.filter(k => now - k.timestamp < 5000);
        
        this.behavioralData.keystrokes.push({
            timestamp: now,
            key: event.key,
            type: 'keyup',
            typingSpeed: recentKeystrokes.length / 5
        });
    }
    
    trackScroll(event) {
        if (!this.isTracking) return;
        
        this.behavioralData.scrollEvents.push({
            timestamp: Date.now(),
            scrollX: window.scrollX,
            scrollY: window.scrollY
        });
    }
    
    trackFocus(event) {
        this.behavioralData.focusEvents.push({
            timestamp: Date.now(),
            type: 'focus'
        });
    }
    
    trackBlur(event) {
        this.behavioralData.focusEvents.push({
            timestamp: Date.now(),
            type: 'blur'
        });
    }
    
    trackVisibilityChange(event) {
        this.behavioralData.pageInteractions.push({
            timestamp: Date.now(),
            type: 'visibility',
            visible: !document.hidden
        });
    }
    
    // Behavioral Analysis Methods
    analyzeBehavior() {
        return {
            sessionDuration: Date.now() - this.startTime,
            mouseMetrics: this.analyzeMouseBehavior(),
            clickMetrics: this.analyzeClickBehavior(),
            keyboardMetrics: this.analyzeKeyboardBehavior(),
            engagementMetrics: this.analyzeEngagement(),
            suspiciousPatterns: this.detectSuspiciousPatterns()
        };
    }
    
    analyzeMouseBehavior() {
        const movements = this.behavioralData.mouseMovements;
        if (movements.length < 2) return { insufficient_data: true };
        
        const velocities = movements.map(m => m.velocity).filter(v => v > 0);
        const distances = movements.map(m => m.distance).filter(d => d > 0);
        
        return {
            totalMovements: movements.length,
            averageVelocity: this.average(velocities),
            maxVelocity: Math.max(...velocities),
            averageDistance: this.average(distances),
            humanLikeness: this.calculateHumanLikeness(velocities)
        };
    }
    
    analyzeClickBehavior() {
        const clicks = this.behavioralData.clicks;
        if (clicks.length < 2) return { insufficient_data: true };
        
        const intervals = [];
        for (let i = 1; i < clicks.length; i++) {
            intervals.push(clicks[i].timestamp - clicks[i-1].timestamp);
        }
        
        return {
            totalClicks: clicks.length,
            averageInterval: this.average(intervals),
            rapidClicks: intervals.filter(i => i < 100).length
        };
    }
    
    analyzeKeyboardBehavior() {
        const keystrokes = this.behavioralData.keystrokes;
        if (keystrokes.length < 2) return { insufficient_data: true };
        
        const typingSpeeds = keystrokes.map(k => k.typingSpeed).filter(s => s > 0);
        
        return {
            totalKeystrokes: keystrokes.length,
            averageTypingSpeed: this.average(typingSpeeds)
        };
    }
    
    analyzeEngagement() {
        const totalTime = Date.now() - this.startTime;
        const activeTime = this.calculateActiveTime();
        
        return {
            totalSessionTime: totalTime,
            activeTime: activeTime,
            engagementRatio: activeTime / totalTime,
            interactionCount: this.behavioralData.pageInteractions.length
        };
    }
    
    calculateActiveTime() {
        let activeTime = 0;
        const allEvents = [
            ...this.behavioralData.mouseMovements.map(e => e.timestamp),
            ...this.behavioralData.clicks.map(e => e.timestamp),
            ...this.behavioralData.keystrokes.map(e => e.timestamp)
        ].sort();
        
        let lastActivity = allEvents[0] || this.startTime;
        for (let timestamp of allEvents) {
            if (timestamp - lastActivity < 30000) {
                activeTime += timestamp - lastActivity;
            }
            lastActivity = timestamp;
        }
        
        return activeTime;
    }
    
    detectSuspiciousPatterns() {
        const patterns = [];
        
        // Bot-like patterns
        const clickMetrics = this.analyzeClickBehavior();
        if (clickMetrics.rapidClicks > 5) {
            patterns.push('rapid_clicking');
        }
        
        if (clickMetrics.averageInterval < 200 && clickMetrics.totalClicks > 10) {
            patterns.push('no_human_pauses');
        }
        
        return patterns;
    }
    
    average(arr) {
        return arr.length > 0 ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;
    }
    
    calculateHumanLikeness(velocities) {
        if (velocities.length < 5) return 0.5;
        
        const avg = this.average(velocities);
        const variance = velocities.reduce((sum, v) => sum + Math.pow(v - avg, 2), 0) / velocities.length;
        const coefficientOfVariation = Math.sqrt(variance) / avg;
        
        // Human-like if coefficient of variation is between 0.3 and 2.0
        return Math.min(1.0, Math.max(0.0, (coefficientOfVariation - 0.1) / 1.9));
    }
    
    async sendBehavioralData() {
        if (!this.isTracking) return;
        
        try {
            const analysis = this.analyzeBehavior();
            const payload = {
                sessionId: this.sessionId,
                analysis: analysis,
                timestamp: Date.now()
            };
            
            const response = await fetch('/behavioral/track', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            
            if (response.ok) {
                console.log('✅ Behavioral data sent successfully');
            }
        } catch (error) {
            console.error('❌ Error sending behavioral data:', error);
        }
    }
    
    getBehavioralSummary() {
        return {
            sessionId: this.sessionId,
            sessionDuration: Date.now() - this.startTime,
            totalInteractions: this.behavioralData.mouseMovements.length + 
                             this.behavioralData.clicks.length + 
                             this.behavioralData.keystrokes.length,
            analysis: this.analyzeBehavior()
        };
    }
}

// Export for use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = RealBehavioralTracker;
} 