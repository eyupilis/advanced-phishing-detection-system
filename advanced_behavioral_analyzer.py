"""
ADVANCED BEHAVIORAL ANALYZER
Gelişmiş kullanıcı davranış analizi ve anomali tespiti
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, Optional, List
from behavioral_analyzer import behavioral_analyzer

logger = logging.getLogger(__name__)

class AdvancedBehavioralAnalyzer:
    def __init__(self):
        self.base_analyzer = behavioral_analyzer
        self.advanced_weights = {
            'session_consistency': 0.3,
            'temporal_patterns': 0.25,
            'behavioral_anomalies': 0.25,
            'automation_detection': 0.2
        }
    
    async def analyze_url_behavior(self, url: str, session_id: str, 
                                 user_agent: Optional[str] = None) -> Dict:
        """Gelişmiş behavioral analiz"""
        try:
            # Base behavioral analiz
            base_result = await self.base_analyzer.analyze_url_behavior(
                url, session_id, user_agent
            )
            
            # Advanced analysis ekle
            advanced_result = {
                'url': url,
                'session_id': session_id,
                'timestamp': datetime.now().isoformat(),
                'risk_score': base_result.get('risk_score', 0.0),
                'behavioral_flags': base_result.get('behavioral_flags', []),
                'advanced_analysis': {
                    'automation_score': self._detect_automation(user_agent),
                    'session_quality': self._analyze_session_quality(base_result),
                    'threat_indicators': self._identify_threat_indicators(base_result)
                },
                'recommendations': []
            }
            
            # Risk score adjustment
            automation_risk = advanced_result['advanced_analysis']['automation_score']
            if automation_risk > 0.7:
                advanced_result['risk_score'] = min(1.0, advanced_result['risk_score'] + 0.3)
                advanced_result['behavioral_flags'].append('automation_detected')
            
            # Generate recommendations
            recommendations = self._generate_advanced_recommendations(advanced_result)
            advanced_result['recommendations'] = recommendations
            
            return advanced_result
            
        except Exception as e:
            logger.error(f"❌ Advanced behavioral analysis error: {e}")
            return {
                'url': url,
                'session_id': session_id,
                'error': str(e),
                'risk_score': 0.0,
                'behavioral_flags': ['analysis_error']
            }
    
    def _detect_automation(self, user_agent: Optional[str]) -> float:
        """Automation detection"""
        if not user_agent:
            return 0.5
        
        automation_indicators = [
            'bot', 'crawler', 'spider', 'scraper', 'python', 'curl', 'wget'
        ]
        
        score = 0.0
        for indicator in automation_indicators:
            if indicator.lower() in user_agent.lower():
                score += 0.3
        
        return min(1.0, score)
    
    def _analyze_session_quality(self, base_result: Dict) -> float:
        """Session quality analysis"""
        session_analysis = base_result.get('session_analysis', {})
        
        quality_score = 1.0
        
        # Check session duration
        duration = session_analysis.get('session_duration', 0)
        if duration < 10:  # Very short session
            quality_score -= 0.3
        
        # Check URL count
        url_count = session_analysis.get('urls_count', 0)
        if url_count > 50:  # Too many URLs
            quality_score -= 0.4
        
        return max(0.0, quality_score)
    
    def _identify_threat_indicators(self, base_result: Dict) -> List[str]:
        """Threat indicator identification"""
        indicators = []
        
        flags = base_result.get('behavioral_flags', [])
        
        if 'rapid_url_access' in flags:
            indicators.append('rapid_browsing_pattern')
        
        if 'device_inconsistency' in flags:
            indicators.append('device_spoofing_possible')
        
        if 'unusual_timing' in flags:
            indicators.append('off_hours_activity')
        
        return indicators
    
    def _generate_advanced_recommendations(self, analysis_result: Dict) -> List[str]:
        """Generate advanced recommendations"""
        recommendations = []
        
        risk_score = analysis_result.get('risk_score', 0)
        flags = analysis_result.get('behavioral_flags', [])
        
        if risk_score > 0.8:
            recommendations.append("🚨 Yüksek behavioral risk tespit edildi")
            recommendations.append("🔍 Kullanıcı aktivitesini yakından izleyin")
        
        if 'automation_detected' in flags:
            recommendations.append("🤖 Bot aktivitesi tespit edildi")
            recommendations.append("🚫 CAPTCHA doğrulaması gerekebilir")
        
        return recommendations

# Global instance
advanced_behavioral_analyzer = AdvancedBehavioralAnalyzer() 