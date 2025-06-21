"""
ENHANCED ENSEMBLE ANALYZER
Gelişmiş ensemble analiz sistemi - Tüm motorları entegre eder
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import time
from analysis_logger import AnalysisLogger

# Import all analysis engines
from ensemble_phishing_detector import initialize_ensemble
from external_threat_intelligence import external_intel  
from url_truncation_analyzer import url_truncation_analyzer
from dynamic_model_weighting import dynamic_weighting
from false_positive_tracker import false_positive_tracker
from whitelist_blacklist_manager import whitelist_blacklist_manager

# Import new analysis engines
from behavioral_analyzer import behavioral_analyzer
from network_analyzer import network_analyzer
from content_analyzer import ContentAnalyzer

# Import advanced engines
try:
    from advanced_behavioral_analyzer import AdvancedBehavioralAnalyzer
    advanced_behavioral_analyzer = AdvancedBehavioralAnalyzer()
    ADVANCED_BEHAVIORAL_AVAILABLE = True
except ImportError:
    ADVANCED_BEHAVIORAL_AVAILABLE = False
    advanced_behavioral_analyzer = None

try:
    from content_security_analyzer import ContentSecurityAnalyzer
    content_security_analyzer = ContentSecurityAnalyzer()
    CONTENT_SECURITY_AVAILABLE = True
except ImportError:
    CONTENT_SECURITY_AVAILABLE = False
    content_security_analyzer = None

try:
    from visual_phishing_detector import VisualPhishingDetector
    visual_phishing_detector = VisualPhishingDetector()
    VISUAL_DETECTOR_AVAILABLE = True
except ImportError:
    VISUAL_DETECTOR_AVAILABLE = False
    visual_phishing_detector = None

logger = logging.getLogger(__name__)

class EnhancedEnsembleAnalyzer:
    def __init__(self):
        # Initialize ML ensemble
        self.ml_ensemble = initialize_ensemble()
        self.content_analyzer = ContentAnalyzer()
        
        # Initialize analysis logger
        self.analysis_logger = AnalysisLogger()
        
        # Analysis engine weights
        self.engine_weights = {
            'ml_ensemble': 0.35,           # 7 ML modeli (ana güç)
            'external_threat_intel': 0.15, # Dış tehdit istihbaratı
            'network_analysis': 0.12,      # Network güvenlik analizi
            'content_security': 0.10,      # İçerik güvenlik analizi
            'behavioral_analysis': 0.08,   # Davranış analizi
            'visual_detection': 0.08,      # Görsel phishing analizi  
            'url_truncation': 0.05,        # URL manipülasyon analizi
            'whitelist_blacklist': 0.04,   # Beyaz/kara liste
            'false_positive': 0.03         # False positive düzeltmesi
        }
        
        # Analysis results cache
        self.analysis_cache = {}
        
    async def comprehensive_analyze(self, url: str, session_id: Optional[str] = None,
                                  user_agent: Optional[str] = None,
                                  deep_scan: bool = False) -> Dict:
        """Kapsamlı URL analizi - Tüm motorlar"""
        
        analysis_start_time = time.time()
        logger.info(f"🚀 KAPSAMLI ANALİZ BAŞLADI: {url}")
        
        # Start analysis logging
        if not session_id:
            import hashlib
            session_id = hashlib.md5(f"{url}_{datetime.now().timestamp()}".encode()).hexdigest()[:16]
        
        self.analysis_logger.start_analysis(url, session_id)
        
        try:
            # Initialize comprehensive result
            comprehensive_result = {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'analysis_duration': 0.0,
                'final_risk_score': 0.0,
                'final_decision': 'UNKNOWN',
                'confidence': 0.0,
                
                # Analysis engine results
                'analysis_engines': {
                    'ml_ensemble': {},
                    'external_threat_intel': {},
                    'network_analysis': {},
                    'content_security': {},
                    'behavioral_analysis': {},
                    'visual_detection': {},
                    'url_truncation': {},
                    'whitelist_blacklist': {},
                    'false_positive': {}
                },
                
                # Weighted scores
                'weighted_scores': {},
                
                # Summary
                'threats_detected': [],
                'recommendations': [],
                'detailed_analysis': {}
            }
            
            # PHASE 1: Quick whitelist/blacklist check
            logger.info("🔍 PHASE 1: Whitelist/Blacklist Check")
            self.analysis_logger.log_step('whitelist_blacklist', 'Whitelist/Blacklist Kontrolü', 'processing')
            wbl_result = await self._analyze_whitelist_blacklist(url)
            comprehensive_result['analysis_engines']['whitelist_blacklist'] = wbl_result
            self.analysis_logger.log_whitelist_blacklist_results(wbl_result)
            
            # If blacklisted, return immediately with high risk
            if wbl_result.get('is_blacklisted', False):
                comprehensive_result['final_decision'] = 'PHISHING'
                comprehensive_result['final_risk_score'] = 0.95
                comprehensive_result['confidence'] = 0.9
                comprehensive_result['threats_detected'] = ['blacklisted_domain']
                return comprehensive_result
            
            # PHASE 2: External Threat Intelligence
            logger.info("🌐 PHASE 2: External Threat Intelligence")
            self.analysis_logger.log_step('threat_intelligence', 'Tehdit İstihbaratı Analizi', 'processing')
            threat_intel_result = await self._analyze_external_threat_intel(url)
            comprehensive_result['analysis_engines']['external_threat_intel'] = threat_intel_result
            self.analysis_logger.log_threat_intel_results(threat_intel_result)
            
            # PHASE 3: ML Ensemble Analysis (Ana Güç)
            logger.info("🤖 PHASE 3: ML Ensemble Analysis (7 Models)")
            self.analysis_logger.log_step('ml_ensemble', 'ML Model Ensemble Analizi', 'processing')
            ml_result = await self._analyze_ml_ensemble(url)
            comprehensive_result['analysis_engines']['ml_ensemble'] = ml_result
            self.analysis_logger.log_ml_model_results(ml_result)
            
            # PHASE 4: Network Security Analysis
            logger.info("🌐 PHASE 4: Network Security Analysis")
            self.analysis_logger.log_step('network_analysis', 'Ağ Güvenlik Analizi', 'processing')
            network_result = await self._analyze_network_security(url, deep_scan)
            comprehensive_result['analysis_engines']['network_analysis'] = network_result
            self.analysis_logger.log_network_analysis_results(network_result)
            
            # PHASE 5: Content Security Analysis
            logger.info("📄 PHASE 5: Content Security Analysis")
            self.analysis_logger.log_step('content_security', 'İçerik Güvenlik Analizi', 'processing')
            content_result = await self._analyze_content_security(url, deep_scan)
            comprehensive_result['analysis_engines']['content_security'] = content_result
            self.analysis_logger.log_content_security_results(content_result)
            
            # PHASE 6: Behavioral Analysis 
            logger.info("👤 PHASE 6: Behavioral Analysis")
            self.analysis_logger.log_step('behavioral_analysis', 'Davranış Analizi', 'processing')
            
            behavioral_result = await self._analyze_behavioral(url, session_id, user_agent)
            comprehensive_result['analysis_engines']['behavioral_analysis'] = behavioral_result
            self.analysis_logger.log_behavioral_analysis_results(behavioral_result)
            
            # PHASE 7: Visual Phishing Detection
            logger.info("👁️ PHASE 7: Visual Phishing Detection")
            self.analysis_logger.log_step('visual_detection', 'Görsel Tespit Analizi', 'processing')
            visual_result = await self._analyze_visual_phishing(url)
            comprehensive_result['analysis_engines']['visual_detection'] = visual_result
            self.analysis_logger.log_visual_detection_results(visual_result)
            
            # PHASE 8: URL Truncation Analysis
            logger.info("🔗 PHASE 8: URL Truncation Analysis")
            self.analysis_logger.log_step('url_analysis', 'URL Analizi', 'processing')
            truncation_result = await self._analyze_url_truncation(url)
            comprehensive_result['analysis_engines']['url_truncation'] = truncation_result
            self.analysis_logger.log_url_analysis_results(truncation_result)
            
            # PHASE 9: False Positive Check
            logger.info("✅ PHASE 9: False Positive Analysis")
            self.analysis_logger.log_step('false_positive', 'Yanlış Pozitif Kontrolü', 'processing')
            fp_result = await self._analyze_false_positive(url)
            comprehensive_result['analysis_engines']['false_positive'] = fp_result
            self.analysis_logger.log_false_positive_check(fp_result)
            
            # FINAL PHASE: Weighted Decision Making
            logger.info("⚖️ FINAL PHASE: Weighted Decision Making")
            self.analysis_logger.log_step('final_decision', 'Nihai Karar Hesaplaması', 'processing')
            final_decision = await self._calculate_final_decision(comprehensive_result)
            comprehensive_result.update(final_decision)
            self.analysis_logger.log_final_decision(final_decision)
            
            # Calculate total analysis time
            analysis_duration = time.time() - analysis_start_time
            comprehensive_result['analysis_duration'] = round(analysis_duration, 3)
            
            # Complete analysis logging
            self.analysis_logger.complete_analysis(analysis_duration * 1000)
            
            # Add analysis log to result
            comprehensive_result['analysis_log'] = self.analysis_logger.get_analysis_log()
            
            logger.info(f"✅ ANALIZ TAMAMLANDI: {analysis_duration:.3f}s")
            logger.info(f"📊 Final Score: {comprehensive_result['final_risk_score']:.3f}")
            logger.info(f"🎯 Final Decision: {comprehensive_result['final_decision']}")
            
            return comprehensive_result
            
        except Exception as e:
            logger.error(f"❌ Comprehensive analysis error: {e}")
            return {
                'url': url,
                'error': str(e),
                'final_risk_score': 0.5,
                'final_decision': 'ERROR',
                'analysis_engines': {}
            }
    
    async def _analyze_whitelist_blacklist(self, url: str) -> Dict:
        """Enhanced Whitelist/Blacklist analizi"""
        try:
            # İlk önce temel liste kontrolü yap
            wbl_check = whitelist_blacklist_manager.check_url(url)
            
            # Enhanced reputation analizi yap
            reputation_result = whitelist_blacklist_manager.analyze_url_reputation(url)
            
            # Sonuçları birleştir
            if wbl_check is not None:
                # Lista da bulundu
                is_safe = wbl_check.get('prediction') == 'safe'
                is_phishing = wbl_check.get('prediction') == 'phishing'
                confidence = wbl_check.get('confidence', 0.0)
                risk_score = 0.0 if is_safe else (confidence if is_phishing else 0.0)
                
                result = {
                    'status': 'completed',
                    'risk_score': risk_score,
                    'is_whitelisted': is_safe,
                    'is_blacklisted': is_phishing,
                    'source': wbl_check.get('source', 'unknown'),
                    'confidence': confidence,
                    'reason': wbl_check.get('reason', '')
                }
            else:
                # Lista da yok, reputation analizi kullan
                reputation_score = reputation_result.get('reputation_score', 0.5)
                recommendation = reputation_result.get('recommendation', 'unknown')
                
                # Reputation score'u risk score'a çevir (0.5'ten küçükse risk, büyükse güvenli)
                if reputation_score >= 0.7:
                    risk_score = 0.0  # Güvenli
                elif reputation_score <= 0.3:
                    risk_score = 1.0 - reputation_score  # Riskli
                else:
                    risk_score = 0.5 - reputation_score  # Neutral
                
                risk_score = max(0.0, risk_score)
                
                result = {
                    'status': 'completed',
                    'risk_score': risk_score,
                    'is_whitelisted': recommendation in ['trusted', 'likely_safe'],
                    'is_blacklisted': recommendation in ['block', 'suspicious'],
                    'source': 'reputation_analysis',
                    'confidence': abs(reputation_score - 0.5) * 2,  # Distance from neutral
                    'reason': f"Reputation analysis: {recommendation}"
                }
            
            # Enhanced analiz detaylarını ekle
            result.update({
                'reputation_analysis': reputation_result,
                'risk_indicators': reputation_result.get('risk_indicators', []),
                'trust_indicators': reputation_result.get('trust_indicators', [])
            })
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Whitelist/Blacklist analysis error: {e}")
            return {'status': 'error', 'error': str(e), 'risk_score': 0.0}
    
    async def _analyze_external_threat_intel(self, url: str) -> Dict:
        """External threat intelligence analizi"""
        try:
            threat_result = await external_intel.check_all_apis(url)
            
            # Risk score hesaplama - API confidence'dan türet
            is_phishing = threat_result.get('is_phishing', False)
            confidence_score = threat_result.get('confidence_score', 0.0)
            
            # Risk score = phishing ise confidence, safe ise 1-confidence
            risk_score = confidence_score if is_phishing else max(0.0, 1.0 - confidence_score)
            
            # Extract detailed information for web interface
            google_result = threat_result.get('google_safe_browsing', {})
            virustotal_result = threat_result.get('virustotal', {})
            
            return {
                'status': 'completed',
                'risk_score': risk_score,
                'apis_checked': threat_result.get('apis_checked', 0),
                'apis_available': threat_result.get('apis_available', 0),
                'is_phishing': is_phishing,
                'confidence_score': confidence_score,
                'threat_level': threat_result.get('threat_level', 'unknown'),
                'sources': threat_result.get('sources', []),
                'errors': threat_result.get('errors', []),
                'threat_sources': threat_result.get('sources', []),
                'threat_categories': threat_result.get('categories', []),
                'google_safe_browsing': {
                    'threat_types': google_result.get('threat_types', []),
                    'confidence': google_result.get('confidence', 0.0),
                    'is_threat': google_result.get('is_threat', False)
                },
                'virustotal': {
                    'positives': virustotal_result.get('positives', 0),
                    'total': virustotal_result.get('total', 0),
                    'risk_score': virustotal_result.get('risk_score', 0.0),
                    'categories': virustotal_result.get('categories', []),
                    'detection_ratio': virustotal_result.get('detection_ratio', 0.0)
                },
                'response_time_ms': threat_result.get('response_time_ms', 0),
                'cache_hit': threat_result.get('cache_hit', False)
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e), 'risk_score': 0.0}
    
    async def _analyze_ml_ensemble(self, url: str) -> Dict:
        """ML Ensemble analizi"""
        try:
            ml_result = self.ml_ensemble.predict_ensemble_optimized(url)
            
            # Risk score hesaplaması: Safe ise düşük risk, Phishing ise yüksek risk
            final_label = ml_result.get('final_label', 'Unknown')
            confidence = ml_result.get('confidence', 0.5)
            
            if final_label == 'Safe':
                # Safe ise risk score düşük olmalı (1 - confidence)
                risk_score = 1.0 - confidence
            elif final_label == 'Phishing':
                # Phishing ise risk score yüksek olmalı (confidence)
                risk_score = confidence
            else:
                # Unknown durumunda orta risk
                risk_score = 0.5
            
            return {
                'status': 'completed',
                'risk_score': risk_score,
                'ensemble_prediction': final_label,
                'ensemble_confidence': confidence,
                'total_models': ml_result.get('total_models', 0),
                'active_models': ml_result.get('active_models', 0),
                'threat_votes': ml_result.get('phishing_votes', 0),
                'safe_votes': ml_result.get('safe_votes', 0),
                'individual_models': ml_result.get('model_predictions', {})
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e), 'risk_score': 0.5}
    
    async def _analyze_network_security(self, url: str, deep_scan: bool = False) -> Dict:
        """Network security analizi"""
        try:
            network_result = await network_analyzer.analyze_url_network(url, deep_scan)
            
            # Network security explanation oluştur
            explanation = self._generate_network_security_explanation(network_result)
            
            return {
                'status': 'completed',
                'risk_score': network_result.get('risk_score', 0.0),
                'network_accessible': network_result.get('network_accessible', False),
                'ssl_analysis': network_result.get('ssl_analysis', {}),
                'dns_analysis': network_result.get('dns_analysis', {}),
                'ip_analysis': network_result.get('ip_analysis', {}),
                'network_flags': network_result.get('network_flags', []),
                'explanation': explanation
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e), 'risk_score': 0.3}
    
    async def _analyze_content_security(self, url: str, deep_scan: bool = False) -> Dict:
        """Content security analizi"""
        try:
            if CONTENT_SECURITY_AVAILABLE:
                content_result = await content_security_analyzer.analyze_url_content(url, deep_scan)
            else:
                # Fallback to basic content analyzer
                content_result = await self.content_analyzer.analyze_url_content(url, deep_scan)
            
            return {
                'status': 'completed',
                'risk_score': content_result.get('risk_score', 0.0),
                'content_flags': content_result.get('content_flags', []),
                'security_analysis': content_result.get('security_analysis', {}),
                'phishing_indicators': content_result.get('security_analysis', {}).get('phishing_indicators', {})
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e), 'risk_score': 0.2}
    
    async def _analyze_behavioral(self, url: str, session_id: str, user_agent: Optional[str]) -> Dict:
        """Real Behavioral Analysis - Gerçek kullanıcı davranışı analizi"""
        try:
            # Try real behavioral tracking first
            try:
                from real_behavioral_analyzer import real_behavioral_analyzer
                
                # Check if we have real behavioral data for this session
                session_summary = real_behavioral_analyzer.get_session_summary(session_id)
                
                if session_summary and not session_summary.get('error'):
                    # We have real behavioral data!
                    logger.info(f"🎯 Using REAL behavioral data for session: {session_id}")
                    
                    human_score = session_summary.get('human_score', 0.5)
                    automation_score = session_summary.get('automation_score', 0.0)
                    risk_factors = session_summary.get('risk_factors', [])
                    
                    # Calculate risk score from real data
                    risk_score = automation_score * 0.7  # High weight for automation
                    
                    # Add URL-based risk factors
                    url_risk = await self._calculate_url_behavioral_risk(url, user_agent)
                    risk_score = min(1.0, risk_score + url_risk * 0.3)
                    
                    behavioral_flags = risk_factors.copy()
                    if automation_score > 0.7:
                        behavioral_flags.append('high_automation_detected')
                    if human_score < 0.3:
                        behavioral_flags.append('non_human_behavior')
                    
                    session_quality = self._assess_real_session_quality(human_score, automation_score, risk_factors)
                    
                    return {
                        'status': 'completed',
                        'tracking_type': 'real_behavioral_data',
                        'risk_score': round(risk_score, 3),
                        'behavioral_flags': behavioral_flags,
                        'session_analysis': {
                            'human_score': human_score,
                            'automation_score': automation_score,
                            'session_duration': session_summary.get('duration_seconds', 0),
                            'total_interactions': session_summary.get('total_interactions', 0),
                            'analysis_count': session_summary.get('analysis_count', 0)
                        },
                        'advanced_analysis': {
                            'data_source': 'real_behavioral_tracking',
                            'session_quality': session_quality,
                            'automation_detected': automation_score > 0.3,
                            'human_verified': human_score > 0.8
                        },
                        'automation_detected': automation_score > 0.3,
                        'session_quality': session_quality,
                        'recommendations': self._generate_real_behavioral_recommendations(human_score, automation_score, risk_factors)
                    }
                else:
                    logger.info(f"📊 No real behavioral data found for session: {session_id}, using simulated analysis")
                    
            except ImportError:
                logger.warning("⚠️ Real behavioral analyzer not available, using fallback")
            except Exception as e:
                logger.warning(f"⚠️ Real behavioral analysis error: {e}, using fallback")
            
            # Fallback to simulated behavioral analysis
            if ADVANCED_BEHAVIORAL_AVAILABLE:
                behavioral_result = await advanced_behavioral_analyzer.analyze_url_behavior(url, session_id, user_agent)
            else:
                # Basic behavioral analyzer
                behavioral_result = await behavioral_analyzer.analyze_url_behavior(url, session_id, user_agent)
            
            # Enhanced behavioral analysis with URL-based insights
            enhanced_result = await self._enhance_behavioral_analysis(url, user_agent, behavioral_result)
            enhanced_result['tracking_type'] = 'simulated_analysis'
            
            return {
                'status': 'completed',
                'tracking_type': 'simulated_analysis',
                'risk_score': enhanced_result.get('risk_score', 0.0),
                'behavioral_flags': enhanced_result.get('behavioral_flags', []),
                'session_analysis': enhanced_result.get('session_analysis', {}),
                'advanced_analysis': enhanced_result.get('advanced_analysis', {}),
                'automation_detected': enhanced_result.get('automation_detected', False),
                'session_quality': enhanced_result.get('session_quality', 'normal'),
                'recommendations': enhanced_result.get('recommendations', [])
            }
        except Exception as e:
            return {
                'status': 'error', 
                'error': str(e), 
                'risk_score': 0.1,
                'tracking_type': 'error'
            }
    
    async def _enhance_behavioral_analysis(self, url: str, user_agent: Optional[str], base_result: Dict) -> Dict:
        """Enhanced behavioral analysis with URL-based behavioral insights"""
        try:
            from urllib.parse import urlparse
            import re
            
            enhanced_result = base_result.copy()
            base_risk = enhanced_result.get('risk_score', 0.0)
            additional_risk = 0.0
            behavioral_flags = enhanced_result.get('behavioral_flags', [])
            
            # URL-based behavioral analysis
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path.lower()
            
            # 1. User Agent Analysis
            automation_score = 0.0
            if user_agent:
                # Bot/automation indicators
                bot_patterns = [
                    r'bot|crawler|spider|scraper',
                    r'automated|script|tool|test',
                    r'python|curl|wget|postman|httpie',
                    r'selenium|phantomjs|headless'
                ]
                
                for pattern in bot_patterns:
                    if re.search(pattern, user_agent, re.IGNORECASE):
                        automation_score += 0.3
                        behavioral_flags.append('automation_detected')
                        break
                
                # Suspicious user agent patterns
                if len(user_agent) < 20:  # Very short user agent
                    automation_score += 0.2
                    behavioral_flags.append('suspicious_user_agent')
                elif 'compatible' not in user_agent.lower() and 'mozilla' in user_agent.lower():
                    automation_score += 0.1
                    behavioral_flags.append('unusual_user_agent')
            else:
                # No user agent provided
                automation_score = 0.4
                behavioral_flags.append('missing_user_agent')
            
            # 2. URL Pattern Analysis for Behavioral Insights
            suspicious_patterns = [
                (r'admin|wp-admin|phpmyadmin', 0.3, 'admin_panel_access'),
                (r'login|signin|auth', 0.1, 'login_attempt'),
                (r'download|file|attachment', 0.1, 'file_access'),
                (r'api|webhook|callback', 0.2, 'api_access'),
                (r'redirect|forward|proxy', 0.2, 'redirect_behavior')
            ]
            
            for pattern, risk_add, flag in suspicious_patterns:
                if re.search(pattern, f"{domain}{path}", re.IGNORECASE):
                    additional_risk += risk_add
                    behavioral_flags.append(flag)
            
            # 3. Domain Behavioral Analysis
            domain_risk = 0.0
            
            # IP address instead of domain
            if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
                domain_risk += 0.3
                behavioral_flags.append('ip_address_access')
            
            # Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.click', '.download']
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    domain_risk += 0.2
                    behavioral_flags.append('suspicious_tld')
                    break
            
            # Very long domain (potential typosquatting)
            if len(domain) > 30:
                domain_risk += 0.1
                behavioral_flags.append('long_domain')
            
            # Multiple subdomains
            subdomain_count = domain.count('.') - 1
            if subdomain_count > 3:
                domain_risk += 0.1
                behavioral_flags.append('multiple_subdomains')
            
            # 4. Calculate enhanced risk score
            total_additional_risk = automation_score + additional_risk + domain_risk
            enhanced_risk = min(1.0, base_risk + (total_additional_risk * 0.5))  # Weight additional risk
            
            # 5. Session Quality Assessment
            session_quality = 'normal'
            if automation_score > 0.7:
                session_quality = 'automated'
            elif automation_score > 0.3 or additional_risk > 0.3:
                session_quality = 'suspicious'
            elif base_risk > 0.5:
                session_quality = 'high_risk'
            elif total_additional_risk < 0.1:
                session_quality = 'clean'
            
            # 6. Enhanced session analysis
            session_analysis = enhanced_result.get('session_analysis', {})
            session_analysis.update({
                'automation_score': round(automation_score, 3),
                'domain_risk_score': round(domain_risk, 3),
                'url_pattern_risk': round(additional_risk, 3),
                'user_agent_provided': user_agent is not None,
                'user_agent_length': len(user_agent) if user_agent else 0
            })
            
            # 7. Advanced analysis
            advanced_analysis = enhanced_result.get('advanced_analysis', {})
            advanced_analysis.update({
                'automation_score': automation_score,
                'session_quality': session_quality,
                'threat_indicators': [flag for flag in behavioral_flags if 'detected' in flag or 'suspicious' in flag]
            })
            
            # Update enhanced result
            enhanced_result.update({
                'risk_score': round(enhanced_risk, 3),
                'behavioral_flags': list(set(behavioral_flags)),
                'session_analysis': session_analysis,
                'advanced_analysis': advanced_analysis,
                'automation_detected': automation_score > 0.3,
                'session_quality': session_quality
            })
            
            return enhanced_result
            
        except Exception as e:
            logger.error(f"❌ Enhanced behavioral analysis error: {e}")
            return base_result
    
    async def _calculate_url_behavioral_risk(self, url: str, user_agent: Optional[str]) -> float:
        """Calculate URL-based behavioral risk factors"""
        try:
            from urllib.parse import urlparse
            import re
            
            risk_score = 0.0
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path.lower()
            
            # IP address instead of domain
            if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
                risk_score += 0.3
            
            # Suspicious paths
            suspicious_paths = ['admin', 'login', 'auth', 'api', 'download']
            for sus_path in suspicious_paths:
                if sus_path in path:
                    risk_score += 0.1
                    break
            
            # User agent analysis
            if user_agent:
                bot_indicators = ['bot', 'crawler', 'spider', 'python', 'curl', 'automated']
                for indicator in bot_indicators:
                    if indicator in user_agent.lower():
                        risk_score += 0.2
                        break
            else:
                risk_score += 0.1  # Missing user agent
            
            return min(1.0, risk_score)
            
        except Exception as e:
            logger.error(f"❌ URL behavioral risk calculation error: {e}")
            return 0.0
    
    def _assess_real_session_quality(self, human_score: float, automation_score: float, risk_factors: List[str]) -> str:
        """Assess session quality based on real behavioral data"""
        try:
            if automation_score > 0.8:
                return 'automated'
            elif 'automation_detected' in risk_factors or automation_score > 0.5:
                return 'high_risk'
            elif 'suspicious_automation' in risk_factors or human_score < 0.4:
                return 'suspicious'
            elif human_score > 0.8 and automation_score < 0.2:
                return 'clean'
            else:
                return 'normal'
        except Exception:
            return 'unknown'
    
    def _generate_real_behavioral_recommendations(self, human_score: float, automation_score: float, risk_factors: List[str]) -> List[str]:
        """Generate recommendations based on real behavioral analysis"""
        recommendations = []
        
        if automation_score > 0.8:
            recommendations.append("🤖 Yüksek otomasyon tespit edildi - CAPTCHA veya ek doğrulama uygulayın")
            recommendations.append("🚫 Bot trafiğini engelleyin")
        
        if human_score < 0.3:
            recommendations.append("👤 İnsan davranışı tespit edilemedi - kullanıcı doğrulaması gerekli")
        
        if 'rapid_clicking' in risk_factors:
            recommendations.append("⚡ Hızlı tıklama tespit edildi - rate limiting uygulayın")
        
        if 'suspicious_automation' in risk_factors:
            recommendations.append("⚠️ Şüpheli otomasyon - ek güvenlik önlemleri alın")
        
        if human_score > 0.8 and automation_score < 0.2:
            recommendations.append("✅ İnsan davranışı doğrulandı - normal işlem devam edebilir")
        
        if not recommendations:
            recommendations.append("📊 Normal davranış profili - standart güvenlik önlemleri yeterli")
        
        return recommendations
    
    async def _analyze_visual_phishing(self, url: str) -> Dict:
        """Production-level visual phishing analizi"""
        try:
            if VISUAL_DETECTOR_AVAILABLE:
                # Use the new comprehensive visual analysis method
                visual_result = await visual_phishing_detector.analyze_url_visual(url, capture_screenshot=True, deep_analysis=True)
                
                visual_analysis = visual_result.get('visual_analysis', {})
                risk_assessment = visual_result.get('risk_assessment', {})
                
                # Extract key visual indicators
                visual_flags = []
                
                # Brand impersonation flags
                brand_imp = visual_analysis.get('brand_impersonation')
                if brand_imp:
                    visual_flags.append(f"brand_impersonation:{brand_imp['suspected_brand']}")
                    visual_flags.append(f"domain_similarity:{brand_imp.get('domain_similarity', 0):.2f}")
                
                # UI manipulation flags
                if visual_analysis.get('ui_manipulation_detected'):
                    visual_flags.append("ui_manipulation_detected")
                
                # Social engineering flags
                social_eng = visual_analysis.get('social_engineering_elements', [])
                if social_eng:
                    visual_flags.extend([f"social_engineering:{len(social_eng)}"])
                
                # DOM analysis flags
                dom_data = visual_analysis.get('dom_analysis', {})
                credential_inputs = dom_data.get('credential_inputs', 0)
                financial_inputs = dom_data.get('financial_inputs', 0)
                forms_detected = dom_data.get('forms_detected', 0)
                
                if credential_inputs > 0:
                    visual_flags.append(f"credential_harvesting:{credential_inputs}")
                if financial_inputs > 0:
                    visual_flags.append(f"financial_forms:{financial_inputs}")
                if forms_detected > 2:
                    visual_flags.append(f"multiple_forms:{forms_detected}")
                
                # Screenshot analysis flags
                if visual_analysis.get('screenshot_captured'):
                    visual_flags.append("screenshot_analyzed")
                
                # External resources analysis
                external_resources = dom_data.get('external_resources', [])
                if len(external_resources) > 5:
                    visual_flags.append(f"many_external_resources:{len(external_resources)}")
                
                # JavaScript analysis flags
                js_analysis = dom_data.get('javascript_analysis', {})
                if js_analysis.get('hasObfuscatedCode'):
                    visual_flags.append("obfuscated_javascript")
                if js_analysis.get('hasHiddenInputs', 0) > 3:
                    visual_flags.append("many_hidden_inputs")
                
                return {
                    'status': 'completed',
                    'risk_score': risk_assessment.get('visual_risk_score', 0.0),
                    'confidence': risk_assessment.get('confidence', 0.0),
                    'visual_flags': visual_flags,
                    'brand_impersonation': brand_imp,
                    'ui_manipulation_detected': visual_analysis.get('ui_manipulation_detected', False),
                    'social_engineering_count': len(social_eng),
                    'forms_analysis': {
                        'total_forms': forms_detected,
                        'credential_inputs': credential_inputs,
                        'financial_inputs': financial_inputs
                    },
                    'dom_analysis': dom_data,
                    'screenshot_captured': visual_analysis.get('screenshot_captured', False),
                    'recommendations': risk_assessment.get('recommendations', []),
                    'technical_details': visual_result.get('technical_details', {}),
                    'analysis_timestamp': visual_result.get('timestamp')
                }
            else:
                return {
                    'status': 'disabled', 
                    'risk_score': 0.0,
                    'visual_flags': ['visual_detector_unavailable'],
                    'recommendations': ['🔧 Visual detection engine is disabled - enable Selenium for full analysis']
                }
        except Exception as e:
            logger.error(f"❌ Visual phishing analysis error: {e}")
            return {
                'status': 'error', 
                'error': str(e), 
                'risk_score': 0.1,
                'visual_flags': ['analysis_error'],
                'recommendations': ['⚠️ Visual analysis failed - manual inspection recommended']
            }
    
    async def _analyze_url_truncation(self, url: str) -> Dict:
        """Enhanced URL Truncation analizi"""
        try:
            # Enhanced URL truncation analizi yap
            truncation_result = url_truncation_analyzer.analyze_url_manipulation(url)
            
            # Risk score hesapla
            risk_score = truncation_result.get('risk_score', 0.0)
            manipulation_detected = truncation_result.get('manipulation_detected', False)
            manipulation_types = truncation_result.get('manipulation_types', [])
            
            # Eğer risk score 0 ise ama manipulation tipleri varsa, risk score'u güncelle
            if risk_score == 0.0 and manipulation_types:
                risk_score = min(0.3, len(manipulation_types) * 0.1)
            
            # ML cascade analizi de deneyelim
            try:
                def ml_analyzer_func(test_url):
                    return self.ml_ensemble.predict_ensemble_optimized(test_url)
                
                cascade_result = url_truncation_analyzer.cascading_analysis(url, ml_analyzer_func)
                
                if 'final_decision' in cascade_result:
                    decision = cascade_result['final_decision']
                    cascade_confidence = decision.get('confidence', 0)
                    if decision.get('decision', '').lower() in ['phishing', 'suspicious']:
                        # Cascade analizinden gelen risk'i de hesaba kat
                        risk_score = max(risk_score, cascade_confidence * 0.5)
                        manipulation_detected = True
                        
            except Exception as cascade_error:
                logger.warning(f"⚠️ Cascade analysis failed: {cascade_error}")
            
            return {
                'status': 'completed',
                'risk_score': min(1.0, risk_score),
                'manipulation_detected': manipulation_detected,
                'manipulation_types': manipulation_types,
                'truncation_flags': truncation_result.get('flags', []),
                'subdomain_analysis': truncation_result.get('subdomain_analysis', {}),
                'path_analysis': truncation_result.get('path_analysis', {}),
                'parameter_analysis': truncation_result.get('parameter_analysis', {}),
                'typosquatting_analysis': truncation_result.get('typosquatting_analysis', {}),
                'url_shortening_analysis': truncation_result.get('url_shortening_analysis', {})
            }
        except Exception as e:
            logger.error(f"❌ URL truncation analysis error: {e}")
            return {'status': 'error', 'error': str(e), 'risk_score': 0.0}
    
    async def _analyze_false_positive(self, url: str) -> Dict:
        """Enhanced False Positive analizi"""
        try:
            # Enhanced false positive kontrolü yap
            fp_result = false_positive_tracker.check_false_positive(url, prediction_confidence=0.8)
            
            is_fp = fp_result.get('is_false_positive', False)
            confidence = fp_result.get('confidence', 0.0)
            reasons = fp_result.get('reasons', [])
            
            # Risk score hesaplama
            if is_fp:
                # False positive ise negatif risk (güvenli yönünde etki)
                risk_score = -0.3 * confidence
            else:
                # False positive değilse nötr
                risk_score = 0.0
            
            return {
                'status': 'completed',
                'risk_score': risk_score,
                'is_false_positive': is_fp,
                'confidence': confidence,
                'reasons': reasons,
                'pattern_matches': fp_result.get('pattern_matches', []),
                'historical_analysis': fp_result.get('historical_analysis', {}),
                'domain_reputation': fp_result.get('domain_reputation', {})
            }
        except Exception as e:
            logger.error(f"❌ False positive analysis error: {e}")
            return {'status': 'error', 'error': str(e), 'risk_score': 0.0}
    
    async def _calculate_final_decision(self, comprehensive_result: Dict) -> Dict:
        """Final weighted decision calculation"""
        
        analysis_engines = comprehensive_result['analysis_engines']
        weighted_scores = {}
        total_weighted_score = 0.0
        active_engines = 0
        
        # Calculate weighted scores for each engine
        for engine_name, weight in self.engine_weights.items():
            engine_result = analysis_engines.get(engine_name, {})
            
            if engine_result.get('status') == 'completed':
                risk_score = engine_result.get('risk_score', 0.0)
                weighted_score = risk_score * weight
                weighted_scores[engine_name] = {
                    'raw_score': risk_score,
                    'weight': weight,
                    'weighted_score': weighted_score
                }
                total_weighted_score += weighted_score
                active_engines += 1
        
        # Calculate confidence based on number of active engines
        confidence = min(0.95, active_engines / len(self.engine_weights))
        
        # ML Ensemble özel kontrolü - TIE durumu için
        ml_result = analysis_engines.get('ml_ensemble', {})
        ml_threat_votes = ml_result.get('threat_votes', 0)
        ml_safe_votes = ml_result.get('safe_votes', 0)
        ml_total_models = ml_result.get('active_models', 0)
        
        # Determine final decision
        if total_weighted_score >= 0.7:
            final_decision = 'PHISHING'
        elif total_weighted_score >= 0.3:
            final_decision = 'SUSPICIOUS'
        # TIE DURUMU ÖZEL KONTROLÜ: 3-3 voting durumunda SUSPICIOUS yap
        elif ml_total_models >= 6 and ml_threat_votes == ml_safe_votes and ml_threat_votes >= 3:
            final_decision = 'SUSPICIOUS'
            logger.info(f"🎯 TIE DURUMU: {ml_threat_votes}-{ml_safe_votes} voting → SUSPICIOUS decision")
        else:
            final_decision = 'SAFE'
        
        # Collect all threats detected
        threats_detected = []
        recommendations = []
        
        for engine_name, engine_result in analysis_engines.items():
            if engine_result.get('status') == 'completed':
                # Add engine-specific threats
                if engine_result.get('risk_score', 0) > 0.5:
                    threats_detected.append(f"{engine_name}_threat")
                
                # Add engine-specific recommendations
                engine_recommendations = engine_result.get('recommendations', [])
                recommendations.extend(engine_recommendations)
        
        return {
            'final_risk_score': round(total_weighted_score, 3),
            'final_decision': final_decision,
            'confidence': round(confidence, 3),
            'weighted_scores': weighted_scores,
            'active_engines': active_engines,
            'total_engines': len(self.engine_weights),
            'threats_detected': list(set(threats_detected)),
            'recommendations': recommendations[:10],  # Top 10 recommendations
            'detailed_analysis': {
                'high_risk_engines': [name for name, scores in weighted_scores.items() if scores['raw_score'] > 0.7],
                'medium_risk_engines': [name for name, scores in weighted_scores.items() if 0.3 <= scores['raw_score'] <= 0.7],
                'low_risk_engines': [name for name, scores in weighted_scores.items() if scores['raw_score'] < 0.3]
            }
        }

    def _generate_network_security_explanation(self, network_result: Dict) -> Dict:
        """Network security analizi için açıklama oluştur"""
        try:
            explanation = {
                'decision_reason': '',
                'risk_factors': [],
                'confidence_factors': []
            }
            
            risk_score = network_result.get('risk_score', 0.0)
            ssl_analysis = network_result.get('ssl_analysis', {})
            dns_analysis = network_result.get('dns_analysis', {})
            
            # Ana karar açıklaması
            if risk_score >= 0.7:
                explanation['decision_reason'] = "Network güvenlik analizi yüksek risk tespit etti"
            elif risk_score >= 0.3:
                explanation['decision_reason'] = "Network güvenlik analizi orta seviye risk tespit etti"
            else:
                explanation['decision_reason'] = "Network güvenlik analizi güvenli olarak değerlendirdi"
            
            # SSL/TLS Analizi
            ssl_flags = ssl_analysis.get('ssl_flags', [])
            if 'modern_ssl_version' in ssl_flags:
                explanation['confidence_factors'].append("Modern TLS 1.3 protokolü kullanılıyor")
            elif 'acceptable_ssl_version' in ssl_flags:
                explanation['confidence_factors'].append("Kabul edilebilir TLS 1.2 protokolü")
            elif 'outdated_ssl_version' in ssl_flags:
                explanation['risk_factors'].append("Eski SSL/TLS sürümü tespit edildi")
            elif 'critically_outdated_ssl' in ssl_flags:
                explanation['risk_factors'].append("Kritik derecede eski SSL sürümü")
            
            if 'strong_key_length' in ssl_flags:
                explanation['confidence_factors'].append("Güçlü şifreleme anahtarı (≥2048 bit)")
            elif 'weak_key_length' in ssl_flags:
                explanation['risk_factors'].append("Zayıf şifreleme anahtarı tespit edildi")
            elif 'very_weak_key' in ssl_flags:
                explanation['risk_factors'].append("Çok zayıf şifreleme anahtarı (<1024 bit)")
            
            # Certificate Authority kontrolü
            cert_info = ssl_analysis.get('certificate_info', {})
            if cert_info.get('trusted_ca'):
                issuer_cn = cert_info.get('issuer_cn', '')
                explanation['confidence_factors'].append(f"Güvenilir CA tarafından imzalanmış: {issuer_cn}")
            elif 'untrusted_ca' in ssl_flags:
                explanation['risk_factors'].append("Güvenilmeyen Certificate Authority")
            
            # Certificate expiry
            if 'certificate_expired' in ssl_flags:
                explanation['risk_factors'].append("SSL sertifikası süresi dolmuş")
            elif 'certificate_expiring_soon' in ssl_flags:
                explanation['risk_factors'].append("SSL sertifikası yakında sürecek")
            else:
                days_left = cert_info.get('days_until_expiry')
                if days_left and days_left > 30:
                    explanation['confidence_factors'].append(f"SSL sertifikası geçerli ({days_left} gün kaldı)")
            
            # DNS Analizi
            dns_flags = dns_analysis.get('dns_flags', [])
            if 'has_spf_record' in dns_flags:
                explanation['confidence_factors'].append("SPF email güvenlik kaydı mevcut")
            elif 'no_spf_record' in dns_flags:
                explanation['risk_factors'].append("SPF email güvenlik kaydı eksik")
            
            if 'has_dmarc_record' in dns_flags:
                explanation['confidence_factors'].append("DMARC email güvenlik kaydı mevcut")
            elif 'no_dmarc_record' in dns_flags:
                explanation['risk_factors'].append("DMARC email güvenlik kaydı eksik")
            
            # DNS record sayıları
            dns_records = dns_analysis.get('dns_records', {})
            if dns_records:
                record_counts = []
                for record_type, records in dns_records.items():
                    if records:
                        record_counts.append(f"{record_type}({len(records)})")
                if record_counts:
                    explanation['confidence_factors'].append(f"DNS kayıtları mevcut: {', '.join(record_counts)}")
            
            # Network accessibility
            if network_result.get('network_accessible'):
                explanation['confidence_factors'].append("Network erişilebilirliği normal")
            else:
                explanation['risk_factors'].append("Network erişim sorunu tespit edildi")
            
            return explanation
            
        except Exception as e:
            return {
                'decision_reason': "Network güvenlik analizi tamamlandı",
                'risk_factors': [],
                'confidence_factors': []
            }

# Global instance
enhanced_ensemble_analyzer = EnhancedEnsembleAnalyzer() 