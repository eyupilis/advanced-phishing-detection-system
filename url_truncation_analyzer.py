"""
URL TRUNCATION ANALYZER
Alt URL'lerde hata varsa .com'dan sonrasını alıp cascade analiz
"""

import re
import tldextract
from urllib.parse import urlparse, urljoin, unquote
from typing import List, Dict, Tuple, Optional
import logging

logger = logging.getLogger(__name__)

class URLTruncationAnalyzer:
    def __init__(self):
        self.truncation_levels = [
            'full_url',
            'no_fragment',
            'no_query',
            'no_path',
            'no_subdomain',
            'base_domain_only'
        ]
    
    def cascading_analysis(self, original_url: str, ml_analyzer_func) -> Dict:
        """
        Cascade URL analysis - Full URL'den başlayıp aşamalı olarak truncate et
        
        Args:
            original_url: Analiz edilecek URL
            ml_analyzer_func: ML analiz fonksiyonu
        
        Returns:
            Dict: Cascade analiz sonuçları
        """
        try:
            results = {
                'original_url': original_url,
                'truncation_results': [],
                'final_decision': {},
                'confidence_evolution': []
            }
            
            # URL variations oluştur
            url_variations = self._generate_url_variations(original_url)
            
            logger.info(f"🔍 Starting cascade analysis for: {original_url}")
            logger.info(f"📊 Generated {len(url_variations)} URL variations")
            
            # Her varyasyon için analiz yap
            for level, url_variant in url_variations:
                try:
                    # ML analizi çalıştır
                    analysis_result = ml_analyzer_func(url_variant)
                    
                    truncation_result = {
                        'level': level,
                        'url': url_variant,
                        'prediction': analysis_result.get('ensemble_prediction', ''),
                        'confidence': analysis_result.get('ensemble_confidence', 0),
                        'individual_models': analysis_result.get('individual_models', {}),
                        'features': analysis_result.get('features', {})
                    }
                    
                    results['truncation_results'].append(truncation_result)
                    results['confidence_evolution'].append({
                        'level': level,
                        'confidence': analysis_result.get('ensemble_confidence', 0)
                    })
                    
                    logger.info(f"📈 {level}: {analysis_result.get('ensemble_prediction', '')} "
                              f"(conf: {analysis_result.get('ensemble_confidence', 0):.3f})")
                    
                except Exception as e:
                    logger.error(f"❌ Analysis failed for {level}: {e}")
                    continue
            
            # Final decision al
            results['final_decision'] = self._make_cascade_decision(results['truncation_results'])
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Cascading analysis error: {e}")
            return {'error': str(e)}
    
    def _generate_url_variations(self, url: str) -> List[Tuple[str, str]]:
        """URL'nin farklı truncation seviyelerini oluştur"""
        try:
            variations = []
            
            # URL'yi normalize et
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            
            # 1. Full URL (original)
            variations.append(('full_url', url))
            
            # 2. Fragment olmadan (#section kısmı)
            if parsed.fragment:
                no_fragment = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if parsed.query:
                    no_fragment += f"?{parsed.query}"
                variations.append(('no_fragment', no_fragment))
            
            # 3. Query parameters olmadan (?param=value kısmı)
            if parsed.query:
                no_query = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                variations.append(('no_query', no_query))
            
            # 4. Path olmadan (sadece domain)
            if parsed.path and parsed.path != '/':
                no_path = f"{parsed.scheme}://{parsed.netloc}/"
                variations.append(('no_path', no_path))
            
            # 5. Subdomain olmadan (ana domain)
            if extracted.subdomain:
                base_domain = f"{extracted.domain}.{extracted.suffix}"
                no_subdomain = f"{parsed.scheme}://{base_domain}/"
                variations.append(('no_subdomain', no_subdomain))
            
            # 6. Sadece base domain (protocol olmadan)
            base_domain_only = f"{extracted.domain}.{extracted.suffix}"
            if base_domain_only != parsed.netloc.lower():
                variations.append(('base_domain_only', f"http://{base_domain_only}/"))
            
            # Duplicate'ları kaldır
            seen_urls = set()
            unique_variations = []
            
            for level, variant_url in variations:
                if variant_url not in seen_urls:
                    seen_urls.add(variant_url)
                    unique_variations.append((level, variant_url))
            
            return unique_variations
            
        except Exception as e:
            logger.error(f"❌ Generate URL variations error: {e}")
            return [('full_url', url)]
    
    def _make_cascade_decision(self, truncation_results: List[Dict]) -> Dict:
        """
        Cascade analiz sonuçlarına göre final karar ver
        
        Strategy:
        1. Eğer full URL phishing ise ama truncated version safe ise → investigate
        2. Eğer full URL safe ise ama base domain phishing ise → warning
        3. Consistent results → high confidence
        4. Mixed results → medium confidence with explanation
        """
        try:
            if not truncation_results:
                return {'decision': 'unknown', 'confidence': 0, 'reason': 'No analysis results'}
            
            # Sonuçları organize et
            results_by_level = {}
            for result in truncation_results:
                results_by_level[result['level']] = result
            
            # Pattern analysis
            patterns = self._analyze_truncation_patterns(results_by_level)
            
            # Decision logic
            final_decision = {
                'decision': 'safe',
                'confidence': 0.5,
                'reason': '',
                'analysis_type': 'cascade_truncation',
                'patterns': patterns,
                'recommendation': ''
            }
            
            # Full URL result
            full_url_result = results_by_level.get('full_url', {})
            full_url_prediction = full_url_result.get('prediction', '').lower()
            full_url_confidence = full_url_result.get('confidence', 0)
            
            # Base domain result
            base_domain_result = (results_by_level.get('base_domain_only') or 
                                results_by_level.get('no_subdomain') or 
                                results_by_level.get('no_path'))
            
            base_domain_prediction = ''
            base_domain_confidence = 0
            if base_domain_result:
                base_domain_prediction = base_domain_result.get('prediction', '').lower()
                base_domain_confidence = base_domain_result.get('confidence', 0)
            
            # Decision patterns
            if patterns['all_same']:
                # Tutarlı sonuçlar
                final_decision['decision'] = full_url_prediction
                final_decision['confidence'] = full_url_confidence
                final_decision['reason'] = f"Consistent {full_url_prediction} prediction across all truncation levels"
                final_decision['recommendation'] = 'High confidence result'
            
            elif patterns['full_phishing_base_safe']:
                # Full URL phishing ama base domain safe → subdomain/path manipulation
                final_decision['decision'] = 'phishing'
                final_decision['confidence'] = 0.9
                final_decision['reason'] = "Full URL appears phishing but base domain is safe - likely subdomain/path manipulation"
                final_decision['recommendation'] = 'Block - suspicious URL structure'
            
            elif patterns['full_safe_base_phishing']:
                # Full URL safe ama base domain phishing → compromised domain
                final_decision['decision'] = 'phishing'
                final_decision['confidence'] = 0.8
                final_decision['reason'] = "Base domain flagged as phishing - possibly compromised legitimate domain"
                final_decision['recommendation'] = 'Block - compromised domain detected'
            
            elif patterns['confidence_improves']:
                # Confidence truncation ile artıyor → URL manipulation
                best_result = max(truncation_results, key=lambda x: x.get('confidence', 0))
                final_decision['decision'] = best_result.get('prediction', 'safe')
                final_decision['confidence'] = best_result.get('confidence', 0.5)
                final_decision['reason'] = f"Confidence improved with truncation to {best_result.get('level')}"
                final_decision['recommendation'] = 'Check for URL manipulation'
            
            else:
                # Mixed results → conservative approach
                phishing_count = sum(1 for r in truncation_results 
                                   if r.get('prediction', '').lower() == 'phishing')
                total_count = len(truncation_results)
                
                if phishing_count > total_count / 2:
                    final_decision['decision'] = 'phishing'
                    final_decision['confidence'] = 0.7
                    final_decision['reason'] = f"Majority phishing votes ({phishing_count}/{total_count})"
                    final_decision['recommendation'] = 'Block - mixed signals favor phishing'
                else:
                    final_decision['decision'] = 'safe'
                    final_decision['confidence'] = 0.6
                    final_decision['reason'] = f"Majority safe votes ({total_count - phishing_count}/{total_count})"
                    final_decision['recommendation'] = 'Allow but monitor'
            
            return final_decision
            
        except Exception as e:
            logger.error(f"❌ Make cascade decision error: {e}")
            return {'decision': 'unknown', 'confidence': 0, 'error': str(e)}
    
    def _analyze_truncation_patterns(self, results_by_level: Dict) -> Dict:
        """Truncation pattern'lerini analiz et"""
        try:
            patterns = {
                'all_same': True,
                'full_phishing_base_safe': False,
                'full_safe_base_phishing': False,
                'confidence_improves': False,
                'confidence_degrades': False,
                'mixed_results': False
            }
            
            if not results_by_level:
                return patterns
            
            # Predictions al
            predictions = [result.get('prediction', '').lower() 
                         for result in results_by_level.values()]
            confidences = [result.get('confidence', 0) 
                         for result in results_by_level.values()]
            
            # All same kontrolü
            unique_predictions = set(predictions)
            patterns['all_same'] = len(unique_predictions) == 1
            
            # Full vs base comparison
            full_url_pred = results_by_level.get('full_url', {}).get('prediction', '').lower()
            
            base_domain_pred = ''
            for level in ['base_domain_only', 'no_subdomain', 'no_path']:
                if level in results_by_level:
                    base_domain_pred = results_by_level[level].get('prediction', '').lower()
                    break
            
            if full_url_pred and base_domain_pred:
                patterns['full_phishing_base_safe'] = (full_url_pred == 'phishing' and 
                                                     base_domain_pred == 'safe')
                patterns['full_safe_base_phishing'] = (full_url_pred == 'safe' and 
                                                     base_domain_pred == 'phishing')
            
            # Confidence trend
            if len(confidences) > 1:
                confidence_trend = []
                for i in range(1, len(confidences)):
                    if confidences[i] > confidences[i-1]:
                        confidence_trend.append('up')
                    elif confidences[i] < confidences[i-1]:
                        confidence_trend.append('down')
                    else:
                        confidence_trend.append('same')
                
                patterns['confidence_improves'] = confidence_trend.count('up') > confidence_trend.count('down')
                patterns['confidence_degrades'] = confidence_trend.count('down') > confidence_trend.count('up')
            
            # Mixed results
            patterns['mixed_results'] = len(unique_predictions) > 1
            
            return patterns
            
        except Exception as e:
            logger.error(f"❌ Analyze truncation patterns error: {e}")
            return {}
    
    def should_use_truncation(self, analysis_result: Dict, confidence_threshold: float = 0.8) -> bool:
        """
        Truncation analizi gerekli mi karar ver
        
        Args:
            analysis_result: İlk ML analiz sonucu
            confidence_threshold: Confidence eşik değeri
            
        Returns:
            bool: Truncation gerekli mi?
        """
        try:
            confidence = analysis_result.get('ensemble_confidence', 0)
            prediction = analysis_result.get('ensemble_prediction', '').lower()
            
            # Low confidence → truncation gerekli
            if confidence < confidence_threshold:
                logger.info(f"🔍 Low confidence ({confidence:.3f}) - truncation recommended")
                return True
            
            # Phishing prediction ama medium confidence → double check
            if prediction == 'phishing' and confidence < 0.9:
                logger.info(f"🚨 Phishing with medium confidence ({confidence:.3f}) - truncation recommended")
                return True
            
            # Model disagreement varsa → truncation
            individual_models = analysis_result.get('individual_models', {})
            if individual_models:
                predictions = [model.get('prediction', '').lower() 
                             for model in individual_models.values()]
                unique_predictions = set(predictions)
                
                if len(unique_predictions) > 1:
                    logger.info(f"🤔 Model disagreement detected - truncation recommended")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"❌ Should use truncation error: {e}")
            return False

    def analyze_url_manipulation(self, url: str) -> Dict:
        """
        Enhanced URL manipulation detection
        
        Args:
            url: URL to analyze
            
        Returns:
            Dict: Manipulation analysis results
        """
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                # Try to add http if missing
                if not url.startswith(('http://', 'https://')):
                    url = 'http://' + url
                    parsed = urlparse(url)
                
                if not parsed.netloc:
                    return {
                        'risk_score': 0.0,
                        'manipulation_detected': False,
                        'manipulation_types': [],
                        'flags': ['invalid_url']
                    }
            
            manipulation_types = []
            risk_score = 0.0
            flags = []
            
            # Subdomain manipulation
            subdomain_analysis = self._analyze_subdomain_manipulation(parsed)
            if subdomain_analysis['is_suspicious']:
                manipulation_types.append('subdomain_manipulation')
                risk_score += subdomain_analysis['risk_score']
                flags.extend(subdomain_analysis['flags'])
            
            # Path manipulation
            path_analysis = self._analyze_path_manipulation(parsed)
            if path_analysis['is_suspicious']:
                manipulation_types.append('path_manipulation')
                risk_score += path_analysis['risk_score']
                flags.extend(path_analysis['flags'])
            
            # Parameter manipulation
            param_analysis = self._analyze_parameter_manipulation(parsed)
            if param_analysis['is_suspicious']:
                manipulation_types.append('parameter_manipulation')
                risk_score += param_analysis['risk_score']
                flags.extend(param_analysis['flags'])
            
            # Typosquatting detection
            typo_analysis = self._analyze_typosquatting(parsed.netloc)
            if typo_analysis['is_suspicious']:
                manipulation_types.append('typosquatting')
                risk_score += typo_analysis['risk_score']
                flags.extend(typo_analysis['flags'])
            
            # URL shortening detection
            shortening_analysis = self._analyze_url_shortening(parsed.netloc)
            if shortening_analysis['is_suspicious']:
                manipulation_types.append('url_shortening')
                risk_score += shortening_analysis['risk_score']
                flags.extend(shortening_analysis['flags'])
            
            # Normalize risk score (0.0-1.0)
            risk_score = min(1.0, risk_score)
            manipulation_detected = len(manipulation_types) > 0
            
            # Calculate confidence based on analysis quality
            confidence = 0.5  # Base confidence
            if flags:
                confidence += len(flags) * 0.05  # More flags = higher confidence
            if manipulation_types:
                confidence += len(manipulation_types) * 0.15  # Detection types = higher confidence
            confidence = min(confidence, 0.95)  # Max confidence cap
            
            return {
                'risk_score': risk_score,
                'confidence': confidence,  # ✅ EKSİK CONFIDENCE EKLENDI
                'manipulation_detected': manipulation_detected,
                'manipulation_types': manipulation_types,
                'flags': flags,
                'subdomain_analysis': subdomain_analysis,
                'path_analysis': path_analysis,
                'parameter_analysis': param_analysis,
                'typosquatting_analysis': typo_analysis,
                'url_shortening_analysis': shortening_analysis
            }
            
        except Exception as e:
            logger.error(f"❌ URL manipulation analysis error: {e}")
            return {
                'risk_score': 0.0,
                'manipulation_detected': False,
                'manipulation_types': [],
                'flags': ['analysis_error'],
                'error': str(e)
            }
    
    def _analyze_subdomain_manipulation(self, parsed) -> Dict:
        """Subdomain manipulation analizi"""
        try:
            hostname = parsed.netloc.lower()
            subdomains = hostname.split('.')[:-2]  # TLD ve domain hariç
            
            if not subdomains:
                return {'is_suspicious': False, 'risk_score': 0.0, 'flags': []}
            
            flags = []
            risk_score = 0.0
            
            # Çok fazla subdomain
            if len(subdomains) > 3:
                flags.append('excessive_subdomains')
                risk_score += 0.2
            
            # Şüpheli subdomain isimleri
            suspicious_keywords = ['secure', 'login', 'account', 'verify', 'update', 'confirm', 'bank', 'paypal']
            for subdomain in subdomains:
                if any(keyword in subdomain for keyword in suspicious_keywords):
                    flags.append(f'suspicious_subdomain_{subdomain}')
                    risk_score += 0.3
            
            # Rastgele görünümlü subdomain
            for subdomain in subdomains:
                if len(subdomain) > 10 and not any(char in 'aeiou' for char in subdomain):
                    flags.append(f'random_subdomain_{subdomain}')
                    risk_score += 0.2
            
            return {
                'is_suspicious': len(flags) > 0,
                'risk_score': min(0.8, risk_score),
                'flags': flags,
                'subdomain_count': len(subdomains)
            }
            
        except Exception as e:
            return {'is_suspicious': False, 'risk_score': 0.0, 'flags': ['subdomain_analysis_error']}
    
    def _analyze_path_manipulation(self, parsed) -> Dict:
        """Path manipulation analizi"""
        try:
            path = parsed.path
            if not path or path == '/':
                return {'is_suspicious': False, 'risk_score': 0.0, 'flags': []}
            
            flags = []
            risk_score = 0.0
            
            # Çok derin path
            path_segments = [p for p in path.split('/') if p]
            if len(path_segments) > 5:
                flags.append('deep_path_structure')
                risk_score += 0.1
            
            # Şüpheli path segmentleri
            suspicious_segments = ['admin', 'login', 'secure', 'account', 'verify', 'update', 'phishing', 'fake']
            for segment in path_segments:
                if any(sus in segment.lower() for sus in suspicious_segments):
                    flags.append(f'suspicious_path_segment_{segment}')
                    risk_score += 0.3
            
            # URL encoding abuse
            if '%' in path and path.count('%') > 3:
                flags.append('excessive_url_encoding')
                risk_score += 0.2
            
            return {
                'is_suspicious': len(flags) > 0,
                'risk_score': min(0.8, risk_score),
                'flags': flags,
                'path_depth': len(path_segments)
            }
            
        except Exception as e:
            return {'is_suspicious': False, 'risk_score': 0.0, 'flags': ['path_analysis_error']}
    
    def _analyze_parameter_manipulation(self, parsed) -> Dict:
        """Parameter manipulation analizi"""
        try:
            query = parsed.query
            if not query:
                return {'is_suspicious': False, 'risk_score': 0.0, 'flags': []}
            
            flags = []
            risk_score = 0.0
            
            # Çok fazla parameter
            params = query.split('&')
            if len(params) > 10:
                flags.append('excessive_parameters')
                risk_score += 0.1
            
            # Redirect parametreleri
            redirect_params = ['redirect', 'return', 'url', 'next', 'goto', 'forward']
            for param in params:
                param_name = param.split('=')[0].lower()
                if param_name in redirect_params:
                    flags.append(f'redirect_parameter_{param_name}')
                    risk_score += 0.4
            
            # Base64 encoded değerler
            for param in params:
                if '=' in param:
                    value = param.split('=')[1]
                    if len(value) > 20 and value.endswith('='):
                        flags.append('base64_encoded_parameter')
                        risk_score += 0.2
            
            return {
                'is_suspicious': len(flags) > 0,
                'risk_score': min(0.8, risk_score),
                'flags': flags,
                'parameter_count': len(params)
            }
            
        except Exception as e:
            return {'is_suspicious': False, 'risk_score': 0.0, 'flags': ['parameter_analysis_error']}
    
    def _analyze_typosquatting(self, hostname: str) -> Dict:
        """Typosquatting detection"""
        try:
            flags = []
            risk_score = 0.0
            
            # Bilinen markaların typosquatting kontrolü
            known_brands = ['google', 'facebook', 'microsoft', 'apple', 'amazon', 'paypal', 'netflix', 'instagram']
            
            for brand in known_brands:
                if brand in hostname.lower() and brand != hostname.lower().split('.')[0]:
                    # Levenshtein distance hesapla (basitleştirilmiş)
                    if self._simple_similarity(hostname.lower(), brand) > 0.7:
                        flags.append(f'typosquatting_{brand}')
                        risk_score += 0.6
            
            # Character substitution patterns
            substitutions = {'0': 'o', '1': 'l', '3': 'e', '5': 's', '@': 'a'}
            normalized_hostname = hostname.lower()
            for char, replacement in substitutions.items():
                if char in normalized_hostname:
                    flags.append(f'character_substitution_{char}')
                    risk_score += 0.2
            
            return {
                'is_suspicious': len(flags) > 0,
                'risk_score': min(0.8, risk_score),
                'flags': flags
            }
            
        except Exception as e:
            return {'is_suspicious': False, 'risk_score': 0.0, 'flags': ['typosquatting_analysis_error']}
    
    def _analyze_url_shortening(self, hostname: str) -> Dict:
        """URL shortening service detection"""
        try:
            shortening_services = [
                'bit.ly', 'tinyurl.com', 'short.ly', 'ow.ly', 't.co', 'goo.gl',
                'tiny.cc', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly'
            ]
            
            flags = []
            risk_score = 0.0
            
            if hostname.lower() in shortening_services:
                flags.append(f'known_shortening_service_{hostname}')
                risk_score += 0.4
            
            # Custom shortening patterns
            if len(hostname) < 8 and '.' in hostname:
                flags.append('possible_custom_shortener')
                risk_score += 0.3
            
            return {
                'is_suspicious': len(flags) > 0,
                'risk_score': min(0.8, risk_score),
                'flags': flags
            }
            
        except Exception as e:
            return {'is_suspicious': False, 'risk_score': 0.0, 'flags': ['shortening_analysis_error']}
    
    def _simple_similarity(self, str1: str, str2: str) -> float:
        """Basitleştirilmiş string similarity"""
        try:
            if len(str1) == 0 or len(str2) == 0:
                return 0.0
            
            # Common characters ratio
            common_chars = set(str1) & set(str2)
            total_chars = set(str1) | set(str2)
            
            return len(common_chars) / len(total_chars) if total_chars else 0.0
            
        except Exception:
            return 0.0

# Global instance
url_truncation_analyzer = URLTruncationAnalyzer() 