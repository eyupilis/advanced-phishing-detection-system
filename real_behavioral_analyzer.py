"""
REAL BEHAVIORAL ANALYZER
Gerçek kullanıcı davranışı analizi sistemi
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List
from collections import defaultdict

logger = logging.getLogger(__name__)

class RealBehavioralAnalyzer:
    def __init__(self):
        self.sessions = defaultdict(lambda: {
            'session_id': '',
            'start_time': None,
            'last_activity': None,
            'behavioral_data': [],
            'analysis_history': [],
            'risk_factors': [],
            'human_score': 0.5,
            'automation_score': 0.0,
            'total_interactions': 0
        })
        
        self.thresholds = {
            'human_mouse_velocity_range': (50, 500),
            'human_click_interval_range': (200, 5000),
            'human_typing_speed_range': (1, 8),
            'bot_rapid_clicks': 5,
            'human_engagement_min': 0.3
        }
        
        self.pattern_weights = {
            'mouse_humanness': 0.25,
            'click_patterns': 0.20,
            'keyboard_patterns': 0.15,
            'engagement_quality': 0.20,
            'timing_consistency': 0.20
        }
        
    async def analyze_behavioral_data(self, session_id: str, behavioral_data: Dict) -> Dict:
        """Gerçek behavioral data'yı analiz et"""
        try:
            logger.info(f"🧠 Analyzing real behavioral data for session: {session_id}")
            
            session = self.sessions[session_id]
            session['session_id'] = session_id
            session['last_activity'] = datetime.now()
            
            if session['start_time'] is None:
                session['start_time'] = datetime.now()
            
            session['behavioral_data'].append({
                'timestamp': datetime.now(),
                'data': behavioral_data
            })
            
            analysis_result = await self._perform_comprehensive_analysis(session_id, behavioral_data)
            session['analysis_history'].append(analysis_result)
            self._update_session_metrics(session, analysis_result)
            
            logger.info(f"✅ Behavioral analysis completed for {session_id}")
            return analysis_result
            
        except Exception as e:
            logger.error(f"❌ Real behavioral analysis error: {e}")
            return {
                'session_id': session_id,
                'error': str(e),
                'risk_score': 0.5,
                'analysis_status': 'error'
            }
    
    async def _perform_comprehensive_analysis(self, session_id: str, behavioral_data: Dict) -> Dict:
        """Comprehensive behavioral analysis"""
        try:
            analysis = behavioral_data.get('analysis', {})
            
            mouse_analysis = await self._analyze_mouse_behavior(analysis.get('mouseMetrics', {}))
            click_analysis = await self._analyze_click_behavior(analysis.get('clickMetrics', {}))
            keyboard_analysis = await self._analyze_keyboard_behavior(analysis.get('keyboardMetrics', {}))
            engagement_analysis = await self._analyze_engagement(analysis.get('engagementMetrics', {}))
            pattern_analysis = await self._analyze_suspicious_patterns(analysis.get('suspiciousPatterns', []))
            
            risk_score = self._calculate_comprehensive_risk_score({
                'mouse': mouse_analysis,
                'click': click_analysis,
                'keyboard': keyboard_analysis,
                'engagement': engagement_analysis,
                'patterns': pattern_analysis
            })
            
            human_score = self._calculate_human_score({
                'mouse': mouse_analysis,
                'click': click_analysis,
                'keyboard': keyboard_analysis,
                'engagement': engagement_analysis
            })
            
            behavioral_flags = self._generate_behavioral_flags({
                'mouse': mouse_analysis,
                'click': click_analysis,
                'keyboard': keyboard_analysis,
                'patterns': pattern_analysis,
                'risk_score': risk_score,
                'human_score': human_score
            })
            
            session_quality = self._assess_session_quality(risk_score, human_score, behavioral_flags)
            
            return {
                'session_id': session_id,
                'timestamp': datetime.now().isoformat(),
                'analysis_status': 'completed',
                'risk_score': round(risk_score, 3),
                'human_score': round(human_score, 3),
                'automation_detected': human_score < 0.3,
                'session_quality': session_quality,
                'behavioral_flags': behavioral_flags,
                'detailed_analysis': {
                    'mouse_behavior': mouse_analysis,
                    'click_behavior': click_analysis,
                    'keyboard_behavior': keyboard_analysis,
                    'engagement_metrics': engagement_analysis,
                    'pattern_analysis': pattern_analysis
                },
                'recommendations': self._generate_recommendations(risk_score, human_score, behavioral_flags)
            }
            
        except Exception as e:
            logger.error(f"❌ Comprehensive analysis error: {e}")
            return {
                'session_id': session_id,
                'error': str(e),
                'risk_score': 0.5,
                'analysis_status': 'error'
            }
    
    async def _analyze_mouse_behavior(self, mouse_metrics: Dict) -> Dict:
        """Mouse behavior analysis"""
        try:
            if mouse_metrics.get('insufficient_data'):
                return {'status': 'insufficient_data', 'risk_score': 0.3}
            
            avg_velocity = mouse_metrics.get('averageVelocity', 0)
            human_likeness = mouse_metrics.get('humanLikeness', 0.5)
            total_movements = mouse_metrics.get('totalMovements', 0)
            
            risk_factors = []
            risk_score = 0.0
            
            if avg_velocity < self.thresholds['human_mouse_velocity_range'][0]:
                risk_factors.append('too_slow_mouse_movement')
                risk_score += 0.2
            elif avg_velocity > self.thresholds['human_mouse_velocity_range'][1]:
                risk_factors.append('too_fast_mouse_movement')
                risk_score += 0.3
            
            if human_likeness < 0.3:
                risk_factors.append('non_human_mouse_pattern')
                risk_score += 0.4
            
            return {
                'status': 'analyzed',
                'risk_score': max(0.0, min(1.0, risk_score)),
                'risk_factors': risk_factors,
                'metrics': {
                    'average_velocity': avg_velocity,
                    'human_likeness': human_likeness,
                    'total_movements': total_movements
                }
            }
            
        except Exception as e:
            logger.error(f"❌ Mouse behavior analysis error: {e}")
            return {'status': 'error', 'risk_score': 0.3}
    
    async def _analyze_click_behavior(self, click_metrics: Dict) -> Dict:
        """Click behavior analysis"""
        try:
            if click_metrics.get('insufficient_data'):
                return {'status': 'insufficient_data', 'risk_score': 0.3}
            
            total_clicks = click_metrics.get('totalClicks', 0)
            avg_interval = click_metrics.get('averageInterval', 0)
            rapid_clicks = click_metrics.get('rapidClicks', 0)
            
            risk_factors = []
            risk_score = 0.0
            
            if avg_interval < self.thresholds['human_click_interval_range'][0]:
                risk_factors.append('too_fast_clicking')
                risk_score += 0.4
            
            if rapid_clicks > self.thresholds['bot_rapid_clicks']:
                risk_factors.append('excessive_rapid_clicks')
                risk_score += 0.5
            
            return {
                'status': 'analyzed',
                'risk_score': max(0.0, min(1.0, risk_score)),
                'risk_factors': risk_factors,
                'metrics': {
                    'total_clicks': total_clicks,
                    'average_interval': avg_interval,
                    'rapid_clicks': rapid_clicks
                }
            }
            
        except Exception as e:
            logger.error(f"❌ Click behavior analysis error: {e}")
            return {'status': 'error', 'risk_score': 0.3}
    
    async def _analyze_keyboard_behavior(self, keyboard_metrics: Dict) -> Dict:
        """Keyboard behavior analysis"""
        try:
            if keyboard_metrics.get('insufficient_data'):
                return {'status': 'insufficient_data', 'risk_score': 0.2}
            
            total_keystrokes = keyboard_metrics.get('totalKeystrokes', 0)
            avg_typing_speed = keyboard_metrics.get('averageTypingSpeed', 0)
            
            risk_factors = []
            risk_score = 0.0
            
            if avg_typing_speed > self.thresholds['human_typing_speed_range'][1]:
                risk_factors.append('too_fast_typing')
                risk_score += 0.3
            
            return {
                'status': 'analyzed',
                'risk_score': max(0.0, min(1.0, risk_score)),
                'risk_factors': risk_factors,
                'metrics': {
                    'total_keystrokes': total_keystrokes,
                    'average_typing_speed': avg_typing_speed
                }
            }
            
        except Exception as e:
            logger.error(f"❌ Keyboard behavior analysis error: {e}")
            return {'status': 'error', 'risk_score': 0.2}
    
    async def _analyze_engagement(self, engagement_metrics: Dict) -> Dict:
        """Engagement analysis"""
        try:
            engagement_ratio = engagement_metrics.get('engagementRatio', 0)
            interaction_count = engagement_metrics.get('interactionCount', 0)
            
            risk_factors = []
            risk_score = 0.0
            
            if engagement_ratio < self.thresholds['human_engagement_min']:
                risk_factors.append('low_engagement')
                risk_score += 0.3
            
            return {
                'status': 'analyzed',
                'risk_score': max(0.0, min(1.0, risk_score)),
                'risk_factors': risk_factors,
                'metrics': {
                    'engagement_ratio': engagement_ratio,
                    'interaction_count': interaction_count
                }
            }
            
        except Exception as e:
            logger.error(f"❌ Engagement analysis error: {e}")
            return {'status': 'error', 'risk_score': 0.3}
    
    async def _analyze_suspicious_patterns(self, suspicious_patterns: List) -> Dict:
        """Suspicious pattern analysis"""
        try:
            risk_score = 0.0
            detected_patterns = []
            
            pattern_risks = {
                'rapid_clicking': 0.4,
                'no_human_pauses': 0.3,
                'automation_detected': 0.5
            }
            
            for pattern in suspicious_patterns:
                if pattern in pattern_risks:
                    risk_score += pattern_risks[pattern]
                    detected_patterns.append(pattern)
            
            return {
                'status': 'analyzed',
                'risk_score': max(0.0, min(1.0, risk_score)),
                'detected_patterns': detected_patterns,
                'pattern_count': len(detected_patterns)
            }
            
        except Exception as e:
            logger.error(f"❌ Pattern analysis error: {e}")
            return {'status': 'error', 'risk_score': 0.3}
    
    def _calculate_comprehensive_risk_score(self, analyses: Dict) -> float:
        """Risk score calculation"""
        try:
            weighted_score = 0.0
            
            for component, weight in self.pattern_weights.items():
                if component == 'mouse_humanness':
                    score = analyses.get('mouse', {}).get('risk_score', 0.3)
                elif component == 'click_patterns':
                    score = analyses.get('click', {}).get('risk_score', 0.3)
                elif component == 'keyboard_patterns':
                    score = analyses.get('keyboard', {}).get('risk_score', 0.2)
                elif component == 'engagement_quality':
                    score = analyses.get('engagement', {}).get('risk_score', 0.3)
                elif component == 'timing_consistency':
                    score = analyses.get('patterns', {}).get('risk_score', 0.3)
                else:
                    score = 0.3
                
                weighted_score += score * weight
            
            return max(0.0, min(1.0, weighted_score))
            
        except Exception as e:
            logger.error(f"❌ Risk score calculation error: {e}")
            return 0.5
    
    def _calculate_human_score(self, analyses: Dict) -> float:
        """Human score calculation"""
        try:
            human_indicators = 0.0
            total_weight = 0.0
            
            mouse_analysis = analyses.get('mouse', {})
            if mouse_analysis.get('status') == 'analyzed':
                mouse_metrics = mouse_analysis.get('metrics', {})
                human_likeness = mouse_metrics.get('human_likeness', 0.5)
                human_indicators += human_likeness * 0.5
                total_weight += 0.5
            
            click_analysis = analyses.get('click', {})
            if click_analysis.get('status') == 'analyzed':
                click_metrics = click_analysis.get('metrics', {})
                avg_interval = click_metrics.get('average_interval', 0)
                rapid_clicks = click_metrics.get('rapid_clicks', 0)
                
                if 200 <= avg_interval <= 2000 and rapid_clicks <= 2:
                    human_indicators += 0.8 * 0.3
                else:
                    human_indicators += 0.3 * 0.3
                total_weight += 0.3
            
            engagement_analysis = analyses.get('engagement', {})
            if engagement_analysis.get('status') == 'analyzed':
                engagement_metrics = engagement_analysis.get('metrics', {})
                engagement_ratio = engagement_metrics.get('engagement_ratio', 0)
                
                if 0.3 <= engagement_ratio <= 0.8:
                    human_indicators += 0.9 * 0.2
                else:
                    human_indicators += 0.4 * 0.2
                total_weight += 0.2
            
            return human_indicators / total_weight if total_weight > 0 else 0.5
                
        except Exception as e:
            logger.error(f"❌ Human score calculation error: {e}")
            return 0.5
    
    def _generate_behavioral_flags(self, analysis_data: Dict) -> List[str]:
        """Generate behavioral flags"""
        flags = []
        
        risk_score = analysis_data.get('risk_score', 0)
        human_score = analysis_data.get('human_score', 0.5)
        
        if risk_score > 0.8:
            flags.append('high_risk_behavior')
        elif risk_score > 0.6:
            flags.append('suspicious_behavior')
        
        if human_score < 0.3:
            flags.append('automation_detected')
        elif human_score < 0.5:
            flags.append('suspicious_automation')
        elif human_score > 0.8:
            flags.append('human_verified')
        
        for component, analysis in analysis_data.items():
            if isinstance(analysis, dict) and 'risk_factors' in analysis:
                flags.extend(analysis['risk_factors'])
        
        return list(set(flags))
    
    def _assess_session_quality(self, risk_score: float, human_score: float, flags: List[str]) -> str:
        """Session quality assessment"""
        if 'automation_detected' in flags or risk_score > 0.8:
            return 'automated'
        elif 'high_risk_behavior' in flags or risk_score > 0.6:
            return 'high_risk'
        elif 'suspicious_behavior' in flags or human_score < 0.5:
            return 'suspicious'
        elif human_score > 0.7 and risk_score < 0.3:
            return 'clean'
        else:
            return 'normal'
    
    def _generate_recommendations(self, risk_score: float, human_score: float, flags: List[str]) -> List[str]:
        """Generate recommendations"""
        recommendations = []
        
        if risk_score > 0.8:
            recommendations.append("🚨 Yüksek riskli davranış - ek doğrulama gerekli")
        
        if 'automation_detected' in flags:
            recommendations.append("🤖 Bot aktivitesi tespit edildi - CAPTCHA uygulayın")
        
        if 'rapid_clicking' in flags:
            recommendations.append("⚡ Hızlı tıklama tespit edildi - rate limiting uygulayın")
        
        if human_score > 0.8 and risk_score < 0.3:
            recommendations.append("✅ İnsan davranışı doğrulandı - normal işlem")
        
        return recommendations
    
    def _update_session_metrics(self, session: Dict, analysis_result: Dict):
        """Update session metrics"""
        session['human_score'] = analysis_result.get('human_score', 0.5)
        session['automation_score'] = 1.0 - session['human_score']
        session['total_interactions'] += 1
        
        flags = analysis_result.get('behavioral_flags', [])
        for flag in flags:
            if flag not in session['risk_factors']:
                session['risk_factors'].append(flag)

    def get_session_summary(self, session_id: str) -> Dict:
        """Session özetini döndür - Enhanced ensemble analyzer için"""
        try:
            session = self.sessions.get(session_id, {})
            
            if not session or not session.get('session_id'):
                return {
                    'session_id': session_id,
                    'status': 'not_found',
                    'risk_score': 0.5,
                    'human_score': 0.5,
                    'confidence': 0.1,
                    'analysis': 'Session not found'
                }
            
            # Son analiz sonucunu al
            latest_analysis = session.get('analysis_history', [])
            if latest_analysis:
                latest = latest_analysis[-1]
                return {
                    'session_id': session_id,
                    'status': 'active',
                    'risk_score': latest.get('risk_score', 0.5),
                    'human_score': latest.get('human_score', 0.5),
                    'confidence': 0.8 if len(latest_analysis) > 3 else 0.4,
                    'total_interactions': session.get('total_interactions', 0),
                    'automation_detected': latest.get('automation_detected', False),
                    'behavioral_flags': latest.get('behavioral_flags', []),
                    'analysis': 'Behavioral analysis completed'
                }
            
            # Temel session bilgileri
            return {
                'session_id': session_id,
                'status': 'minimal_data',
                'risk_score': session.get('human_score', 0.5),
                'human_score': session.get('human_score', 0.5),
                'confidence': 0.3,
                'total_interactions': session.get('total_interactions', 0),
                'analysis': 'Limited behavioral data available'
            }
            
        except Exception as e:
            logger.error(f"❌ get_session_summary error: {e}")
            return {
                'session_id': session_id,
                'status': 'error',
                'risk_score': 0.5,
                'human_score': 0.5,
                'confidence': 0.1,
                'analysis': f'Error: {str(e)}'
            }

# Global instance
real_behavioral_analyzer = RealBehavioralAnalyzer()
