"""
ANALYSIS LOGGER
Tüm analiz sürecini detaylı bir şekilde loglar ve kullanıcıya sunar
"""

import logging
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import defaultdict

class AnalysisLogger:
    def __init__(self):
        self.analysis_steps = []
        self.start_time = None
        self.end_time = None
        self.current_step = 0
        self.url = ""
        self.session_id = ""
        
        # Analysis phases
        self.phases = {
            'initialization': 'Analiz Başlatılıyor',
            'data_collection': 'Veri Toplama',
            'ml_ensemble': 'ML Model Ensemble',
            'threat_intelligence': 'Tehdit İstihbaratı',
            'network_analysis': 'Ağ Güvenlik Analizi',
            'content_security': 'İçerik Güvenliği',
            'behavioral_analysis': 'Davranış Analizi',
            'visual_detection': 'Görsel Tespit',
            'url_analysis': 'URL Analizi',
            'whitelist_blacklist': 'Liste Kontrolü',
            'false_positive': 'Yanlış Pozitif Kontrolü',
            'final_decision': 'Nihai Karar',
            'completed': 'Analiz Tamamlandı'
        }
        
        self.logger = logging.getLogger(__name__)

    def start_analysis(self, url: str, session_id: str = None):
        """Analiz sürecini başlat"""
        self.start_time = datetime.now()
        self.url = url
        self.session_id = session_id or f"session_{int(time.time())}"
        self.analysis_steps = []
        self.current_step = 0
        
        self.log_step(
            phase='initialization',
            step_name='Analiz Başlatma',
            status='started',
            details={
                'url': url,
                'session_id': self.session_id,
                'timestamp': self.start_time.isoformat(),
                'message': f'🚀 {url} için phishing analizi başlatıldı'
            }
        )

    def log_step(self, phase: str, step_name: str, status: str, details: Dict[str, Any] = None):
        """Analiz adımını logla"""
        self.current_step += 1
        timestamp = datetime.now()
        
        step_data = {
            'step_number': self.current_step,
            'phase': phase,
            'phase_name': self.phases.get(phase, phase),
            'step_name': step_name,
            'status': status,  # started, processing, completed, error, warning
            'timestamp': timestamp.isoformat(),
            'duration_ms': 0,
            'details': details or {}
        }
        
        # Önceki adımın süresini hesapla
        if len(self.analysis_steps) > 0:
            prev_step = self.analysis_steps[-1]
            prev_time = datetime.fromisoformat(prev_step['timestamp'])
            duration = (timestamp - prev_time).total_seconds() * 1000
            prev_step['duration_ms'] = round(duration, 2)
        
        self.analysis_steps.append(step_data)
        
        # Console log
        emoji_map = {
            'started': '🔄',
            'processing': '⚙️',
            'completed': '✅',
            'error': '❌',
            'warning': '⚠️'
        }
        
        emoji = emoji_map.get(status, '📝')
        phase_name = self.phases.get(phase, phase)
        
        self.logger.info(f"{emoji} [{self.current_step:02d}] {phase_name} - {step_name}: {status}")
        
        if details:
            for key, value in details.items():
                if key != 'message':
                    self.logger.debug(f"    └─ {key}: {value}")

    def log_ml_model_results(self, model_results: Dict[str, Any]):
        """ML model sonuçlarını logla"""
        self.log_step(
            phase='ml_ensemble',
            step_name='ML Model Ensemble Analizi',
            status='processing',
            details={
                'total_models': model_results.get('total_models', 0),
                'active_models': model_results.get('active_models', 0),
                'phishing_votes': model_results.get('phishing_votes', 0),
                'safe_votes': model_results.get('safe_votes', 0),
                'ensemble_score': model_results.get('ensemble_score', 0),
                'confidence': model_results.get('confidence', 0),
                'message': f"🤖 {model_results.get('active_models', 0)} ML model analizi tamamlandı"
            }
        )

    def log_threat_intel_results(self, threat_results: Dict[str, Any]):
        """Threat intelligence sonuçlarını logla"""
        details = {
            'google_safe_browsing': threat_results.get('google_safe_browsing', {}),
            'virustotal': threat_results.get('virustotal', {}),
            'threat_sources': len(threat_results.get('threat_sources', [])),
            'risk_score': threat_results.get('risk_score', 0),
            'message': '🌐 Tehdit istihbaratı kontrolü tamamlandı'
        }
        
        # Google Safe Browsing durumu
        gsb = threat_results.get('google_safe_browsing', {})
        if gsb.get('threat_types'):
            details['message'] = f"🚨 Google Safe Browsing tehdit tespit etti: {', '.join(gsb.get('threat_types', []))}"
        
        # VirusTotal durumu
        vt = threat_results.get('virustotal', {})
        if vt.get('positives', 0) > 0:
            details['message'] += f" | VirusTotal: {vt.get('positives', 0)}/{vt.get('total', 0)} tespit"
        
        self.log_step(
            phase='threat_intelligence',
            step_name='Tehdit İstihbaratı Kontrolü',
            status='completed',
            details=details
        )

    def log_network_analysis_results(self, network_results: Dict[str, Any]):
        """Network analysis sonuçlarını logla"""
        ssl_status = network_results.get('ssl_analysis', {}).get('status', 'unknown')
        dns_status = network_results.get('dns_analysis', {}).get('status', 'unknown')
        
        self.log_step(
            phase='network_analysis',
            step_name='Ağ Güvenlik Analizi',
            status='completed',
            details={
                'ssl_status': ssl_status,
                'dns_status': dns_status,
                'connectivity': network_results.get('connectivity', {}),
                'risk_score': network_results.get('risk_score', 0),
                'security_flags': network_results.get('security_flags', []),
                'message': f'🔒 SSL: {ssl_status}, DNS: {dns_status}'
            }
        )

    def log_content_security_results(self, content_results: Dict[str, Any]):
        """Content security sonuçlarını logla"""
        # Handle both content_security_analyzer and basic content analyzer formats
        if 'security_analysis' in content_results:
            # Enhanced content security analyzer
            js_analysis = content_results.get('security_analysis', {}).get('javascript_security', {})
            social_eng = content_results.get('security_analysis', {}).get('social_engineering', {})
            form_security = content_results.get('security_analysis', {}).get('form_security', {})
            
            message = f"📄 JavaScript: {js_analysis.get('script_count', 0)} script"
            if social_eng.get('urgency_indicators'):
                message += f", {len(social_eng.get('urgency_indicators', []))} aciliyet göstergesi"
            if form_security.get('credential_forms', 0) > 0:
                message += f", {form_security.get('credential_forms', 0)} kimlik bilgisi formu"
            
            self.log_step(
                phase='content_security',
                step_name='İçerik Güvenlik Analizi',
                status='completed',
                details={
                    'javascript_security': js_analysis,
                    'social_engineering': social_eng,
                    'form_security': form_security,
                    'brand_protection': content_results.get('security_analysis', {}).get('brand_protection', {}),
                    'risk_score': content_results.get('risk_score', 0),
                    'message': message
                }
            )
        else:
            # Basic content analyzer format
            message = f"📄 İçerik analizi tamamlandı"
            if content_results.get('suspicious_indicators'):
                indicators_count = len(content_results.get('suspicious_indicators', []))
                message += f" - {indicators_count} şüpheli gösterge tespit edildi"
            
            self.log_step(
                phase='content_security',
                step_name='İçerik Güvenlik Analizi',
                status='completed',
                details={
                    'content_analysis': content_results.get('content_analysis', {}),
                    'suspicious_indicators': content_results.get('suspicious_indicators', []),
                    'risk_score': content_results.get('risk_score', 0),
                    'message': message
                }
            )

    def log_behavioral_analysis_results(self, behavioral_results: Dict[str, Any]):
        """Behavioral analysis sonuçlarını logla"""
        tracking_type = behavioral_results.get('tracking_type', 'simulated_analysis')
        session_quality = behavioral_results.get('session_quality', 'normal')
        human_score = behavioral_results.get('human_score', 0.5)
        automation_detected = behavioral_results.get('automation_detected', False)
        
        message = f"👤 Tracking: {tracking_type}, Kalite: {session_quality}"
        if automation_detected:
            message = "🤖 OTOMASYON TESPİT EDİLDİ!"
        elif human_score > 0.8:
            message += " - Yüksek insan benzeri davranış"
        elif human_score < 0.3:
            message += " - Şüpheli davranış paterni"
        
        self.log_step(
            phase='behavioral_analysis',
            step_name='Davranış Analizi',
            status='completed',
            details={
                'tracking_type': tracking_type,
                'session_quality': session_quality,
                'human_score': human_score,
                'automation_detected': automation_detected,
                'automation_score': behavioral_results.get('automation_score', 0),
                'behavioral_flags': behavioral_results.get('behavioral_flags', []),
                'risk_score': behavioral_results.get('risk_score', 0),
                'message': message
            }
        )

    def log_visual_detection_results(self, visual_results: Dict[str, Any]):
        """Visual detection sonuçlarını logla"""
        brand_impersonation = visual_results.get('brand_impersonation')
        visual_spoofing = visual_results.get('visual_spoofing_detected', False)
        
        message = "👁️ Görsel analiz tamamlandı"
        if brand_impersonation:
            message = f"🎭 Marka taklidi tespit edildi: {brand_impersonation}"
        elif visual_spoofing:
            message = "⚠️ Görsel aldatmaca tespit edildi"
        
        self.log_step(
            phase='visual_detection',
            step_name='Görsel Tespit Analizi',
            status='completed',
            details={
                'brand_impersonation': brand_impersonation,
                'visual_spoofing_detected': visual_spoofing,
                'confidence_score': visual_results.get('confidence_score', 0),
                'risk_score': visual_results.get('risk_score', 0),
                'message': message
            }
        )

    def log_url_analysis_results(self, url_results: Dict[str, Any]):
        """URL analysis sonuçlarını logla"""
        manipulation_detected = url_results.get('manipulation_detected', False)
        truncation_risk = url_results.get('truncation_risk', 0)
        
        message = "🔗 URL analizi tamamlandı"
        if manipulation_detected:
            message = "⚠️ URL manipülasyonu tespit edildi"
        
        self.log_step(
            phase='url_analysis',
            step_name='URL Analizi',
            status='completed',
            details={
                'manipulation_detected': manipulation_detected,
                'truncation_risk': truncation_risk,
                'url_features': url_results.get('url_features', {}),
                'risk_score': url_results.get('risk_score', 0),
                'message': message
            }
        )

    def log_whitelist_blacklist_results(self, wbl_results: Dict[str, Any]):
        """Whitelist/Blacklist sonuçlarını logla"""
        list_status = wbl_results.get('list_status', 'not_found')
        list_source = wbl_results.get('list_source')
        
        status_messages = {
            'whitelisted': '✅ Güvenli listede bulundu',
            'blacklisted': '🚨 Kara listede bulundu',
            'not_found': '📋 Listede bulunamadı'
        }
        
        message = status_messages.get(list_status, f"📋 Liste durumu: {list_status}")
        if list_source:
            message += f" (Kaynak: {list_source})"
        
        self.log_step(
            phase='whitelist_blacklist',
            step_name='Liste Kontrolü',
            status='completed',
            details={
                'list_status': list_status,
                'list_source': list_source,
                'confidence': wbl_results.get('confidence', 0),
                'risk_score': wbl_results.get('risk_score', 0),
                'message': message
            }
        )

    def log_false_positive_check(self, fp_results: Dict[str, Any]):
        """False positive check sonuçlarını logla"""
        known_fp = fp_results.get('known_false_positive', False)
        fp_confidence = fp_results.get('confidence', 0)
        
        message = "🔍 Yanlış pozitif kontrolü tamamlandı"
        if known_fp:
            message = f"✅ Bilinen güvenli site (güven: {fp_confidence:.2f})"
        
        self.log_step(
            phase='false_positive',
            step_name='Yanlış Pozitif Kontrolü',
            status='completed',
            details={
                'known_false_positive': known_fp,
                'confidence': fp_confidence,
                'fp_indicators': fp_results.get('fp_indicators', []),
                'risk_score': fp_results.get('risk_score', 0),
                'message': message
            }
        )

    def log_visual_detection_results(self, visual_results: Dict[str, Any]):
        """Visual detection sonuçlarını logla"""
        brand_impersonation = visual_results.get('brand_impersonation')
        visual_spoofing = visual_results.get('visual_spoofing_detected', False)
        
        message = "👁️ Görsel analiz tamamlandı"
        if brand_impersonation:
            message = f"🎭 Marka taklidi tespit edildi: {brand_impersonation}"
        elif visual_spoofing:
            message = "⚠️ Görsel aldatmaca tespit edildi"
        
        self.log_step(
            phase='visual_detection',
            step_name='Görsel Tespit Analizi',
            status='completed',
            details={
                'brand_impersonation': brand_impersonation,
                'visual_spoofing_detected': visual_spoofing,
                'confidence_score': visual_results.get('confidence_score', 0),
                'risk_score': visual_results.get('risk_score', 0),
                'message': message
            }
        )

    def log_url_analysis_results(self, url_results: Dict[str, Any]):
        """URL analysis sonuçlarını logla"""
        manipulation_detected = url_results.get('manipulation_detected', False)
        truncation_risk = url_results.get('truncation_risk', 0)
        
        message = "🔗 URL analizi tamamlandı"
        if manipulation_detected:
            message = "⚠️ URL manipülasyonu tespit edildi"
        
        self.log_step(
            phase='url_analysis',
            step_name='URL Analizi',
            status='completed',
            details={
                'manipulation_detected': manipulation_detected,
                'truncation_risk': truncation_risk,
                'url_features': url_results.get('url_features', {}),
                'risk_score': url_results.get('risk_score', 0),
                'message': message
            }
        )

    def log_whitelist_blacklist_results(self, wbl_results: Dict[str, Any]):
        """Whitelist/Blacklist sonuçlarını logla"""
        list_status = wbl_results.get('list_status', 'not_found')
        list_source = wbl_results.get('list_source')
        
        status_messages = {
            'whitelisted': '✅ Güvenli listede bulundu',
            'blacklisted': '🚨 Kara listede bulundu',
            'not_found': '📋 Listede bulunamadı'
        }
        
        message = status_messages.get(list_status, f"📋 Liste durumu: {list_status}")
        if list_source:
            message += f" (Kaynak: {list_source})"
        
        self.log_step(
            phase='whitelist_blacklist',
            step_name='Liste Kontrolü',
            status='completed',
            details={
                'list_status': list_status,
                'list_source': list_source,
                'confidence': wbl_results.get('confidence', 0),
                'risk_score': wbl_results.get('risk_score', 0),
                'message': message
            }
        )

    def log_false_positive_check(self, fp_results: Dict[str, Any]):
        """False positive check sonuçlarını logla"""
        known_fp = fp_results.get('known_false_positive', False)
        fp_confidence = fp_results.get('confidence', 0)
        
        message = "🔍 Yanlış pozitif kontrolü tamamlandı"
        if known_fp:
            message = f"✅ Bilinen güvenli site (güven: {fp_confidence:.2f})"
        
        self.log_step(
            phase='false_positive',
            step_name='Yanlış Pozitif Kontrolü',
            status='completed',
            details={
                'known_false_positive': known_fp,
                'confidence': fp_confidence,
                'fp_indicators': fp_results.get('fp_indicators', []),
                'risk_score': fp_results.get('risk_score', 0),
                'message': message
            }
        )

    def log_final_decision(self, final_analysis: Dict[str, Any]):
        """Final karar sürecini logla"""
        final_decision = final_analysis.get('final_decision', 'unknown')
        final_risk_score = final_analysis.get('final_risk_score', 0)
        confidence = final_analysis.get('confidence', 0)
        reasoning = final_analysis.get('reasoning', [])
        
        decision_messages = {
            'safe': '✅ GÜVENLİ - Site temiz olarak değerlendirildi',
            'phishing': '🚨 TEHLİKELİ - Phishing site tespit edildi',
            'suspicious': '⚠️ ŞÜPHELİ - Dikkatli olunması öneriliyor'
        }
        
        message = decision_messages.get(final_decision, f"❓ BELIRSIZ - {final_decision}")
        
        self.log_step(
            phase='final_decision',
            step_name='Nihai Karar Verme',
            status='completed',
            details={
                'final_decision': final_decision,
                'final_risk_score': final_risk_score,
                'confidence': confidence,
                'reasoning': reasoning,
                'decision_factors': final_analysis.get('decision_factors', {}),
                'message': message
            }
        )

    def complete_analysis(self, total_duration_ms: float = None):
        """Analizi tamamla"""
        self.end_time = datetime.now()
        
        if total_duration_ms is None:
            total_duration_ms = (self.end_time - self.start_time).total_seconds() * 1000
        
        self.log_step(
            phase='completed',
            step_name='Analiz Tamamlandı',
            status='completed',
            details={
                'total_duration_ms': round(total_duration_ms, 2),
                'total_steps': self.current_step,
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'message': f'🎯 Analiz {total_duration_ms/1000:.2f} saniyede tamamlandı'
            }
        )

    def get_analysis_log(self) -> Dict[str, Any]:
        """Tüm analiz logunu döndür"""
        total_duration = 0
        if self.start_time and self.end_time:
            total_duration = (self.end_time - self.start_time).total_seconds() * 1000
        
        return {
            'session_id': self.session_id,
            'url': self.url,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'total_duration_ms': round(total_duration, 2),
            'total_steps': self.current_step,
            'analysis_steps': self.analysis_steps,
            'summary': self._generate_summary()
        }

    def _generate_summary(self) -> Dict[str, Any]:
        """Analiz özetini oluştur"""
        phases_completed = set()
        errors = []
        warnings = []
        
        for step in self.analysis_steps:
            phases_completed.add(step['phase'])
            if step['status'] == 'error':
                errors.append(step['step_name'])
            elif step['status'] == 'warning':
                warnings.append(step['step_name'])
        
        return {
            'phases_completed': len(phases_completed),
            'total_phases': len(self.phases),
            'errors': errors,
            'warnings': warnings,
            'success_rate': (self.current_step - len(errors)) / max(self.current_step, 1) * 100
        }

    def log_error(self, phase: str, step_name: str, error_message: str, error_details: Dict = None):
        """Hata durumunu logla"""
        self.log_step(
            phase=phase,
            step_name=step_name,
            status='error',
            details={
                'error_message': error_message,
                'error_details': error_details or {},
                'message': f'❌ HATA: {error_message}'
            }
        )

    def log_warning(self, phase: str, step_name: str, warning_message: str, warning_details: Dict = None):
        """Uyarı durumunu logla"""
        self.log_step(
            phase=phase,
            step_name=step_name,
            status='warning',
            details={
                'warning_message': warning_message,
                'warning_details': warning_details or {},
                'message': f'⚠️ UYARI: {warning_message}'
            }
        )

# Global instance
analysis_logger = AnalysisLogger() 