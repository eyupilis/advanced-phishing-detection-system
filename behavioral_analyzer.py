"""
BEHAVIORAL ANALYZER
Kullanıcı davranış analizi ve şüpheli aktivite tespiti
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
from urllib.parse import urlparse
import re
import hashlib
import time
import statistics

logger = logging.getLogger(__name__)

class BehavioralAnalyzer:
    def __init__(self):
        # Kullanıcı session tracking
        self.user_sessions = defaultdict(lambda: {
            'urls_visited': [],
            'click_patterns': [],
            'time_patterns': [],
            'user_agent_changes': [],
            'referrer_chain': [],
            'first_seen': None,
            'last_activity': None,
            'risk_score': 0.0,
            'behavioral_flags': []
        })
        
        # Behavioral patterns
        self.suspicious_patterns = {
            'rapid_clicking': {'threshold': 5, 'window': 60},  # 5 clicks in 60 seconds
            'url_hopping': {'threshold': 10, 'window': 300},   # 10 URLs in 5 minutes
            'midnight_activity': {'start': 0, 'end': 6},       # Activity between midnight-6am
            'suspicious_referrers': [
                'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
                'short.link', 'ow.ly', 'tiny.cc'
            ],
            'bot_indicators': [
                r'bot|crawler|spider|scraper',
                r'automated|script|tool',
                r'python|curl|wget|postman'
            ]
        }
        
        # Machine learning features for behavior
        self.behavioral_features = [
            'session_duration',
            'urls_per_session',
            'click_frequency',
            'time_between_requests',
            'user_agent_consistency',
            'referrer_pattern',
            'geographic_consistency',
            'device_fingerprint_changes'
        ]
        
        # Threat scoring weights
        self.scoring_weights = {
            'bot_behavior': 0.3,
            'rapid_activity': 0.2,
            'suspicious_timing': 0.15,
            'referrer_anomaly': 0.15,
            'session_anomaly': 0.1,
            'device_inconsistency': 0.1
        }
        
    async def analyze_url_behavior(self, url: str, session_id: str, 
                                 user_agent: Optional[str] = None,
                                 referrer: Optional[str] = None,
                                 source_ip: Optional[str] = None) -> Dict:
        """URL ziyareti için behavioral analiz"""
        try:
            analysis_result = {
                'session_id': session_id,
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'risk_score': 0.0,
                'behavioral_flags': [],
                'session_analysis': {},
                'patterns_detected': [],
                'recommendations': []
            }
            
            # Session güncelle
            await self._update_session(session_id, url, user_agent, referrer, source_ip)
            
            # Behavioral analysis yap
            session_risk = await self._analyze_session_behavior(session_id)
            url_risk = await self._analyze_url_behavior_patterns(url, session_id)
            timing_risk = await self._analyze_timing_patterns(session_id)
            device_risk = await self._analyze_device_consistency(session_id, user_agent)
            
            # Risk skorunu hesapla
            total_risk = (
                session_risk * self.scoring_weights['session_anomaly'] +
                url_risk * self.scoring_weights['rapid_activity'] +
                timing_risk * self.scoring_weights['suspicious_timing'] +
                device_risk * self.scoring_weights['device_inconsistency']
            )
            
            analysis_result['risk_score'] = round(total_risk, 3)
            
            # Behavioral flags topla
            flags = []
            if session_risk > 0.7:
                flags.append('suspicious_session_pattern')
            if url_risk > 0.8:
                flags.append('rapid_url_access')
            if timing_risk > 0.6:
                flags.append('unusual_timing')
            if device_risk > 0.5:
                flags.append('device_inconsistency')
            
            analysis_result['behavioral_flags'] = flags
            
            # Session detayları
            session = self.user_sessions[session_id]
            analysis_result['session_analysis'] = {
                'urls_count': len(session['urls_visited']),
                'session_duration': self._calculate_session_duration(session),
                'click_frequency': self._calculate_click_frequency(session),
                'last_activity': session['last_activity']
            }
            
            # Pattern detection
            patterns = await self._detect_behavioral_patterns(session_id)
            analysis_result['patterns_detected'] = patterns
            
            # Recommendations
            recommendations = self._generate_behavioral_recommendations(analysis_result)
            analysis_result['recommendations'] = recommendations
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"❌ Behavioral analysis error: {e}")
            return {
                'session_id': session_id,
                'url': url,
                'error': str(e),
                'risk_score': 0.0,
                'behavioral_flags': ['analysis_error']
            }
    
    async def _update_session(self, session_id: str, url: str, 
                            user_agent: Optional[str], 
                            referrer: Optional[str],
                            source_ip: Optional[str]):
        """Session verilerini güncelle"""
        try:
            session = self.user_sessions[session_id]
            current_time = datetime.now()
            
            # İlk ziyaret mi?
            if session['first_seen'] is None:
                session['first_seen'] = current_time
            
            # URL ekle
            session['urls_visited'].append({
                'url': url,
                'timestamp': current_time,
                'user_agent': user_agent,
                'referrer': referrer,
                'source_ip': source_ip
            })
            
            # Click pattern güncelle
            session['click_patterns'].append(current_time)
            
            # Referrer chain güncelle
            if referrer:
                session['referrer_chain'].append(referrer)
            
            # User agent değişikliklerini takip et
            if user_agent and session['urls_visited']:
                last_user_agent = None
                for visit in reversed(session['urls_visited'][:-1]):
                    if visit.get('user_agent'):
                        last_user_agent = visit['user_agent']
                        break
                
                if last_user_agent and last_user_agent != user_agent:
                    session['user_agent_changes'].append({
                        'from': last_user_agent,
                        'to': user_agent,
                        'timestamp': current_time
                    })
            
            session['last_activity'] = current_time
            
            # Eski verileri temizle (sadece son 24 saat)
            cutoff_time = current_time - timedelta(hours=24)
            session['urls_visited'] = [
                visit for visit in session['urls_visited']
                if visit['timestamp'] > cutoff_time
            ]
            session['click_patterns'] = [
                click for click in session['click_patterns']
                if click > cutoff_time
            ]
            
        except Exception as e:
            logger.error(f"❌ Session update error: {e}")
    
    async def _analyze_session_behavior(self, session_id: str) -> float:
        """Session davranış analizi"""
        try:
            session = self.user_sessions[session_id]
            risk_score = 0.0
            
            # URL sayısı kontrolü
            url_count = len(session['urls_visited'])
            if url_count > 50:  # Çok fazla URL
                risk_score += 0.3
            elif url_count > 20:
                risk_score += 0.1
            
            # Session süresi kontrolü
            duration = self._calculate_session_duration(session)
            if duration and duration < 30:  # Çok kısa session
                risk_score += 0.2
            elif duration and duration > 7200:  # Çok uzun session (2+ saat)
                risk_score += 0.1
            
            # Click frequency kontrolü
            click_freq = self._calculate_click_frequency(session)
            if click_freq > 2:  # Saniyede 2'den fazla click
                risk_score += 0.4
            elif click_freq > 1:
                risk_score += 0.2
            
            return min(risk_score, 1.0)
            
        except Exception as e:
            logger.error(f"❌ Session behavior analysis error: {e}")
            return 0.0
    
    async def _analyze_url_behavior_patterns(self, url: str, session_id: str) -> float:
        """URL davranış pattern analizi"""
        try:
            session = self.user_sessions[session_id]
            risk_score = 0.0
            
            # Son 5 dakikadaki URL sayısı
            current_time = datetime.now()
            recent_cutoff = current_time - timedelta(minutes=5)
            recent_urls = [
                visit for visit in session['urls_visited']
                if visit['timestamp'] > recent_cutoff
            ]
            
            if len(recent_urls) > 10:  # 5 dakikada 10+ URL
                risk_score += 0.5
            elif len(recent_urls) > 5:
                risk_score += 0.2
            
            # URL pattern analizi
            parsed_url = urlparse(url)
            
            # Şüpheli domain pattern kontrolü
            domain_patterns = [
                r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP address
                r'.*-.*-.*-.*\.com',                  # Çok tire
                r'.*\d{3,}.*',                       # Çok sayı
                r'.*[aeiou]{4,}.*'                   # Çok sesli harf
            ]
            
            for pattern in domain_patterns:
                if re.search(pattern, parsed_url.netloc):
                    risk_score += 0.1
            
            return min(risk_score, 1.0)
            
        except Exception as e:
            logger.error(f"❌ URL behavior pattern analysis error: {e}")
            return 0.0
    
    async def _analyze_timing_patterns(self, session_id: str) -> float:
        """Timing pattern analizi"""
        try:
            session = self.user_sessions[session_id]
            risk_score = 0.0
            
            # Gece yarısı aktivite kontrolü
            for visit in session['urls_visited']:
                hour = visit['timestamp'].hour
                if 0 <= hour <= 6:  # Gece yarısı - sabah 6
                    risk_score += 0.1
            
            # Request interval analizi
            if len(session['urls_visited']) > 1:
                intervals = []
                for i in range(1, len(session['urls_visited'])):
                    prev_time = session['urls_visited'][i-1]['timestamp']
                    curr_time = session['urls_visited'][i]['timestamp']
                    interval = (curr_time - prev_time).total_seconds()
                    intervals.append(interval)
                
                if intervals:
                    avg_interval = statistics.mean(intervals)
                    
                    # Çok hızlı istekler
                    if avg_interval < 1:  # 1 saniyeden hızlı
                        risk_score += 0.4
                    elif avg_interval < 3:  # 3 saniyeden hızlı
                        risk_score += 0.2
                    
                    # Çok düzenli intervallar (bot indicator)
                    if len(set(intervals)) == 1:  # Tam aynı interval
                        risk_score += 0.3
            
            return min(risk_score, 1.0)
            
        except Exception as e:
            logger.error(f"❌ Timing pattern analysis error: {e}")
            return 0.0
    
    async def _analyze_device_consistency(self, session_id: str, current_user_agent: Optional[str]) -> float:
        """Device consistency analizi"""
        try:
            session = self.user_sessions[session_id]
            risk_score = 0.0
            
            # User agent değişiklikleri
            if len(session['user_agent_changes']) > 0:
                risk_score += len(session['user_agent_changes']) * 0.1
            
            # Bot pattern kontrolü user agent'ta
            if current_user_agent:
                for pattern in self.suspicious_patterns['bot_indicators']:
                    if re.search(pattern, current_user_agent, re.IGNORECASE):
                        risk_score += 0.5
                        break
            
            return min(risk_score, 1.0)
            
        except Exception as e:
            logger.error(f"❌ Device consistency analysis error: {e}")
            return 0.0
    
    async def _detect_behavioral_patterns(self, session_id: str) -> List[str]:
        """Behavioral pattern tespiti"""
        try:
            session = self.user_sessions[session_id]
            patterns = []
            
            # Rapid clicking pattern
            recent_clicks = [
                click for click in session['click_patterns']
                if (datetime.now() - click).total_seconds() < 60
            ]
            if len(recent_clicks) >= self.suspicious_patterns['rapid_clicking']['threshold']:
                patterns.append('rapid_clicking')
            
            # URL hopping pattern
            recent_urls = [
                visit for visit in session['urls_visited']
                if (datetime.now() - visit['timestamp']).total_seconds() < 300
            ]
            if len(recent_urls) >= self.suspicious_patterns['url_hopping']['threshold']:
                patterns.append('url_hopping')
            
            # Suspicious referrer pattern
            for referrer in session['referrer_chain']:
                for suspicious_ref in self.suspicious_patterns['suspicious_referrers']:
                    if suspicious_ref in referrer:
                        patterns.append('suspicious_referrer')
                        break
            
            return patterns
            
        except Exception as e:
            logger.error(f"❌ Pattern detection error: {e}")
            return []
    
    def _calculate_session_duration(self, session: Dict) -> Optional[float]:
        """Session süresini hesapla (saniye)"""
        try:
            if session['first_seen'] and session['last_activity']:
                duration = (session['last_activity'] - session['first_seen']).total_seconds()
                return duration
            return None
        except:
            return None
    
    def _calculate_click_frequency(self, session: Dict) -> float:
        """Click frequency hesapla (click/saniye)"""
        try:
            if len(session['click_patterns']) < 2:
                return 0.0
            
            # Son 60 saniyedeki click'leri say
            current_time = datetime.now()
            recent_clicks = [
                click for click in session['click_patterns']
                if (current_time - click).total_seconds() < 60
            ]
            
            return len(recent_clicks) / 60.0
            
        except:
            return 0.0
    
    def _generate_behavioral_recommendations(self, analysis_result: Dict) -> List[str]:
        """Behavioral analiz sonucuna göre öneriler"""
        recommendations = []
        
        risk_score = analysis_result.get('risk_score', 0)
        flags = analysis_result.get('behavioral_flags', [])
        
        if risk_score > 0.8:
            recommendations.append("🚨 Yüksek riskli davranış tespit edildi - ek doğrulama yapın")
            recommendations.append("🔒 Bu kullanıcı için ek güvenlik kontrolleri uygulayın")
        
        if 'rapid_url_access' in flags:
            recommendations.append("⚡ Hızlı URL erişimi tespit edildi - rate limiting uygulayın")
        
        if 'device_inconsistency' in flags:
            recommendations.append("📱 Device değişikliği tespit edildi - kimlik doğrulama yapın")
        
        if 'suspicious_session_pattern' in flags:
            recommendations.append("👤 Şüpheli session davranışı - kullanıcı doğrulaması gerekebilir")
        
        if 'unusual_timing' in flags:
            recommendations.append("🕐 Olağandışı timing pattern - bot aktivitesi olabilir")
        
        return recommendations
    
    def get_session_summary(self, session_id: str) -> Dict:
        """Session özeti getir"""
        try:
            session = self.user_sessions.get(session_id, {})
            
            if not session:
                return {'error': 'Session not found'}
            
            return {
                'session_id': session_id,
                'first_seen': session.get('first_seen'),
                'last_activity': session.get('last_activity'),
                'total_urls': len(session.get('urls_visited', [])),
                'total_clicks': len(session.get('click_patterns', [])),
                'user_agent_changes': len(session.get('user_agent_changes', [])),
                'risk_score': session.get('risk_score', 0),
                'behavioral_flags': session.get('behavioral_flags', []),
                'session_duration': self._calculate_session_duration(session),
                'click_frequency': self._calculate_click_frequency(session)
            }
            
        except Exception as e:
            logger.error(f"❌ Session summary error: {e}")
            return {'error': str(e)}

# Global instance
behavioral_analyzer = BehavioralAnalyzer() 