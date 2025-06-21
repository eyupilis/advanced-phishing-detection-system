"""
ENHANCED CONTENT SECURITY ANALYZER
Advanced content security analysis ve comprehensive phishing detection
"""

import asyncio
import logging
import aiohttp
import re
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup, Comment
import base64

logger = logging.getLogger(__name__)

class ContentSecurityAnalyzer:
    def __init__(self):
        # Advanced analysis weights
        self.analysis_weights = {
            'javascript_security': 0.25,
            'social_engineering': 0.25,
            'form_security': 0.20,
            'content_authenticity': 0.15,
            'brand_protection': 0.15
        }
        
        # JavaScript threat patterns
        self.js_threat_patterns = {
            'obfuscation': [
                r'eval\s*\(',
                r'document\.write\s*\(',
                r'unescape\s*\(',
                r'String\.fromCharCode\s*\(',
                r'\\x[0-9a-fA-F]{2}',  # Hex encoding
                r'\\u[0-9a-fA-F]{4}',  # Unicode encoding
                r'atob\s*\(',  # Base64 decode
                r'btoa\s*\(',  # Base64 encode
            ],
            'malicious_functions': [
                r'createElement\s*\(\s*["\']script["\']',
                r'innerHTML\s*=',
                r'document\.location\s*=',
                r'window\.location\s*=',
                r'location\.href\s*=',
                r'setTimeout\s*\(',
                r'setInterval\s*\(',
            ],
            'suspicious_apis': [
                r'XMLHttpRequest',
                r'fetch\s*\(',
                r'addEventListener\s*\(',
                r'postMessage\s*\(',
                r'localStorage',
                r'sessionStorage',
                r'document\.cookie',
            ]
        }
        
        # Advanced social engineering patterns
        self.social_engineering_patterns = {
            'urgency_indicators': [
                'urgent action required', 'act immediately', 'expires today',
                'limited time offer', 'expires in', 'hurry up', 'don\'t delay',
                'immediate verification', 'account will be closed', 'suspended',
                'within 24 hours', 'expires soon', 'time sensitive', 'act now'
            ],
            'authority_impersonation': [
                'bank representative', 'security team', 'customer service',
                'technical support', 'account manager', 'fraud department',
                'billing department', 'verification team', 'compliance officer'
            ],
            'fear_inducing': [
                'suspicious activity', 'unauthorized access', 'security breach',
                'account compromised', 'fraudulent transaction', 'identity theft',
                'data breach', 'security alert', 'unusual login', 'hack attempt'
            ],
            'trust_indicators': [
                'secure connection', 'ssl protected', 'verified site',
                'trusted by millions', 'bank-grade security', 'guaranteed safe',
                'certified secure', 'protected transaction', '100% secure'
            ]
        }
        
        # Brand protection patterns
        self.major_brands = {
            'paypal': ['paypal', 'pypal', 'payp4l', 'paypaI'],
            'amazon': ['amazon', 'amaz0n', 'amazom', 'amazone'],
            'apple': ['apple', 'appl3', 'appIe', 'aple'],
            'microsoft': ['microsoft', 'micr0soft', 'microsooft'],
            'google': ['google', 'g00gle', 'googIe', 'gooogle'],
            'facebook': ['facebook', 'faceb00k', 'facebook', 'facebk'],
            'instagram': ['instagram', 'insta9ram', 'instagr4m'],
            'twitter': ['twitter', 'twitt3r', 'twtter'],
            'linkedin': ['linkedin', 'Iinkedin', 'linked1n'],
            'netflix': ['netflix', 'netfIix', 'netfl1x']
        }
        
        # Form security patterns
        self.sensitive_form_patterns = {
            'credentials': ['password', 'passwd', 'pwd', 'login', 'signin'],
            'financial': ['credit card', 'card number', 'cvv', 'cvc', 'expiry', 'billing'],
            'personal': ['ssn', 'social security', 'date of birth', 'mother maiden'],
            'banking': ['account number', 'routing number', 'sort code', 'iban'],
            'identity': ['driver license', 'passport', 'national id', 'tax id']
        }
        
        # Content authenticity indicators
        self.legitimacy_indicators = {
            'positive': [
                'privacy policy', 'terms of service', 'contact us', 'about us',
                'customer support', 'help center', 'faq', 'refund policy',
                'company address', 'phone number', 'email address'
            ],
            'negative': [
                'no contact information', 'no privacy policy', 'no terms',
                'temporary site', 'under construction', 'coming soon'
            ]
        }
    
    async def analyze_url_content(self, url: str, deep_scan: bool = False) -> Dict:
        """Enhanced comprehensive content security analysis"""
        try:
            analysis_result = {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'content_available': False,
                'risk_score': 0.0,
                'content_flags': [],
                'security_analysis': {
                    'javascript_security': {},
                    'social_engineering': {},
                    'form_security': {},
                    'content_authenticity': {},
                    'brand_protection': {}
                },
                'detailed_findings': [],
                'recommendations': []
            }
            
            # Fetch page content
            content_data = await self._fetch_enhanced_content(url)
            
            if not content_data or content_data.get('error'):
                analysis_result['error'] = content_data.get('error', 'Failed to fetch content')
                analysis_result['risk_score'] = 0.5
                return analysis_result
            
            analysis_result['content_available'] = True
            soup = BeautifulSoup(content_data['content'], 'html.parser')
            
            # JavaScript Security Analysis
            js_analysis = await self._analyze_javascript_security(soup, content_data)
            analysis_result['security_analysis']['javascript_security'] = js_analysis
            
            # Social Engineering Detection
            social_analysis = await self._analyze_social_engineering(soup, url)
            analysis_result['security_analysis']['social_engineering'] = social_analysis
            
            # Form Security Analysis
            form_analysis = await self._analyze_advanced_form_security(soup)
            analysis_result['security_analysis']['form_security'] = form_analysis
            
            # Content Authenticity Check
            auth_analysis = await self._analyze_content_authenticity(soup, url)
            analysis_result['security_analysis']['content_authenticity'] = auth_analysis
            
            # Brand Protection Analysis
            brand_analysis = await self._analyze_brand_protection(soup, url)
            analysis_result['security_analysis']['brand_protection'] = brand_analysis
            
            # Calculate weighted risk score
            total_risk = (
                js_analysis.get('risk_score', 0) * self.analysis_weights['javascript_security'] +
                social_analysis.get('risk_score', 0) * self.analysis_weights['social_engineering'] +
                form_analysis.get('risk_score', 0) * self.analysis_weights['form_security'] +
                auth_analysis.get('risk_score', 0) * self.analysis_weights['content_authenticity'] +
                brand_analysis.get('risk_score', 0) * self.analysis_weights['brand_protection']
            )
            
            analysis_result['risk_score'] = round(total_risk, 3)
            
            # Generate content flags
            flags = self._generate_content_flags(analysis_result)
            analysis_result['content_flags'] = flags
            
            # Generate detailed findings
            findings = self._generate_detailed_findings(analysis_result)
            analysis_result['detailed_findings'] = findings
            
            # Generate recommendations
            recommendations = self._generate_enhanced_recommendations(analysis_result)
            analysis_result['recommendations'] = recommendations
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"❌ Enhanced content security analysis error: {e}")
            return {
                'url': url,
                'error': str(e),
                'risk_score': 0.5,
                'content_flags': ['analysis_error']
            }
    async def _fetch_enhanced_content(self, url: str, timeout: int = 15) -> Dict:
        """Enhanced content fetching with security headers"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=timeout, headers=headers, 
                                     allow_redirects=True, max_redirects=5) as response:
                    content = await response.text()
                    
                    return {
                        'content': content,
                        'status_code': response.status,
                        'headers': dict(response.headers),
                        'url': str(response.url),  # Final URL after redirects
                        'content_type': response.headers.get('content-type', ''),
                        'content_length': len(content)
                    }
                    
        except asyncio.TimeoutError:
            return {'error': 'Request timeout'}
        except Exception as e:
            return {'error': f'Fetch error: {str(e)}'}

    async def _analyze_javascript_security(self, soup: BeautifulSoup, content_data: Dict) -> Dict:
        """Advanced JavaScript security analysis"""
        js_analysis = {
            'risk_score': 0.0,
            'script_count': 0,
            'external_scripts': 0,
            'inline_scripts': 0,
            'obfuscated_scripts': 0,
            'malicious_patterns': [],
            'suspicious_functions': [],
            'external_domains': set(),
            'script_integrity_checks': 0,
            'csp_present': False
        }
        
        # Find all scripts
        scripts = soup.find_all('script')
        js_analysis['script_count'] = len(scripts)
        
        # Check for Content Security Policy
        csp_meta = soup.find('meta', {'http-equiv': 'Content-Security-Policy'}) or \
                  soup.find('meta', {'name': 'Content-Security-Policy'})
        js_analysis['csp_present'] = bool(csp_meta)
        
        if not js_analysis['csp_present']:
            js_analysis['risk_score'] += 0.2
        
        for script in scripts:
            if script.get('src'):
                # External script
                js_analysis['external_scripts'] += 1
                src_domain = urlparse(script['src']).netloc
                if src_domain:
                    js_analysis['external_domains'].add(src_domain)
                
                # Check for integrity attribute
                if script.get('integrity'):
                    js_analysis['script_integrity_checks'] += 1
                else:
                    js_analysis['risk_score'] += 0.1
            else:
                # Inline script
                js_analysis['inline_scripts'] += 1
                script_content = script.string or ''
                
                # Check for obfuscation patterns
                for pattern_type, patterns in self.js_threat_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, script_content, re.IGNORECASE):
                            if pattern_type == 'obfuscation':
                                js_analysis['obfuscated_scripts'] += 1
                                js_analysis['risk_score'] += 0.3
                            elif pattern_type == 'malicious_functions':
                                js_analysis['malicious_patterns'].append(pattern)
                                js_analysis['risk_score'] += 0.4
                            elif pattern_type == 'suspicious_apis':
                                js_analysis['suspicious_functions'].append(pattern)
                                js_analysis['risk_score'] += 0.1
        
        # Risk scoring
        if js_analysis['external_scripts'] > 10:
            js_analysis['risk_score'] += 0.2
        
        if js_analysis['obfuscated_scripts'] > 0:
            js_analysis['risk_score'] += 0.3
        
        if len(js_analysis['external_domains']) > 5:
            js_analysis['risk_score'] += 0.2
        
        js_analysis['external_domains'] = list(js_analysis['external_domains'])
        js_analysis['risk_score'] = min(1.0, js_analysis['risk_score'])
        
        return js_analysis

    async def _analyze_social_engineering(self, soup: BeautifulSoup, url: str) -> Dict:
        """Advanced social engineering pattern detection"""
        social_analysis = {
            'risk_score': 0.0,
            'urgency_indicators': [],
            'authority_claims': [],
            'fear_tactics': [],
            'fake_trust_badges': [],
            'emotional_manipulation': 0,
            'scarcity_tactics': [],
            'legitimacy_claims': []
        }
        
        # Get all text content
        page_text = soup.get_text().lower()
        
        # Check for urgency indicators
        for indicator in self.social_engineering_patterns['urgency_indicators']:
            if indicator.lower() in page_text:
                social_analysis['urgency_indicators'].append(indicator)
                social_analysis['risk_score'] += 0.15
        
        # Check for authority impersonation
        for authority in self.social_engineering_patterns['authority_impersonation']:
            if authority.lower() in page_text:
                social_analysis['authority_claims'].append(authority)
                social_analysis['risk_score'] += 0.2
        
        # Check for fear-inducing language
        for fear_term in self.social_engineering_patterns['fear_inducing']:
            if fear_term.lower() in page_text:
                social_analysis['fear_tactics'].append(fear_term)
                social_analysis['risk_score'] += 0.25
        
        # Check for fake trust indicators
        for trust_term in self.social_engineering_patterns['trust_indicators']:
            if trust_term.lower() in page_text:
                social_analysis['legitimacy_claims'].append(trust_term)
                social_analysis['risk_score'] += 0.1
        
        # Check for scarcity tactics
        scarcity_patterns = [
            r'only \d+ left', r'limited quantity', r'while supplies last',
            r'exclusive offer', r'\d+ people viewing', r'almost sold out'
        ]
        
        for pattern in scarcity_patterns:
            matches = re.findall(pattern, page_text, re.IGNORECASE)
            if matches:
                social_analysis['scarcity_tactics'].extend(matches)
                social_analysis['risk_score'] += 0.1
        
        # Emotional manipulation scoring
        emotional_words = ['amazing', 'incredible', 'unbelievable', 'guaranteed', 
                          'free', 'winner', 'congratulations', 'selected']
        
        emotion_count = sum(1 for word in emotional_words if word in page_text)
        social_analysis['emotional_manipulation'] = emotion_count
        
        if emotion_count > 5:
            social_analysis['risk_score'] += 0.2
        
        social_analysis['risk_score'] = min(1.0, social_analysis['risk_score'])
        
        return social_analysis

    async def _analyze_advanced_form_security(self, soup: BeautifulSoup) -> Dict:
        """Advanced form security analysis"""
        form_analysis = {
            'risk_score': 0.0,
            'form_count': 0,
            'credential_forms': 0,
            'financial_forms': 0,
            'personal_data_forms': 0,
            'hidden_fields': 0,
            'suspicious_actions': [],
            'insecure_transmission': 0,
            'password_fields': 0,
            'auto_submit_forms': 0
        }
        
        forms = soup.find_all('form')
        form_analysis['form_count'] = len(forms)
        
        for form in forms:
            # Check form action
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            # Check for suspicious form actions
            if action:
                parsed_action = urlparse(action)
                if parsed_action.netloc and parsed_action.netloc not in soup.find('base', href=True):
                    form_analysis['suspicious_actions'].append(action)
                    form_analysis['risk_score'] += 0.3
            
            # Check for insecure transmission
            if method == 'get':
                form_analysis['insecure_transmission'] += 1
                form_analysis['risk_score'] += 0.2
            
            # Analyze form fields
            inputs = form.find_all(['input', 'select', 'textarea'])
            
            for input_field in inputs:
                field_type = input_field.get('type', '').lower()
                field_name = (input_field.get('name', '') + ' ' + 
                            input_field.get('placeholder', '') + ' ' +
                            input_field.get('id', '')).lower()
                
                # Check for hidden fields
                if field_type == 'hidden':
                    form_analysis['hidden_fields'] += 1
                
                # Check for password fields
                if field_type == 'password':
                    form_analysis['password_fields'] += 1
                
                # Check for sensitive data patterns
                for category, patterns in self.sensitive_form_patterns.items():
                    for pattern in patterns:
                        if pattern in field_name:
                            if category == 'credentials':
                                form_analysis['credential_forms'] += 1
                                form_analysis['risk_score'] += 0.4
                            elif category == 'financial':
                                form_analysis['financial_forms'] += 1
                                form_analysis['risk_score'] += 0.5
                            elif category == 'personal':
                                form_analysis['personal_data_forms'] += 1
                                form_analysis['risk_score'] += 0.3
                            elif category in ['banking', 'identity']:
                                form_analysis['risk_score'] += 0.6
                            break
            
            # Check for auto-submit forms
            if form.find('script') or 'onload' in str(form) or 'onsubmit' in str(form):
                form_analysis['auto_submit_forms'] += 1
                form_analysis['risk_score'] += 0.3
        
        form_analysis['risk_score'] = min(1.0, form_analysis['risk_score'])
        
        return form_analysis

    async def _analyze_content_authenticity(self, soup: BeautifulSoup, url: str) -> Dict:
        """Content authenticity and legitimacy analysis"""
        auth_analysis = {
            'risk_score': 0.0,
            'has_contact_info': False,
            'has_privacy_policy': False,
            'has_terms_of_service': False,
            'professional_design': True,
            'spelling_errors': 0,
            'grammar_issues': 0,
            'legitimate_elements': [],
            'missing_elements': [],
            'content_quality_score': 0.0
        }
        
        page_text = soup.get_text().lower()
        
        # Check for legitimacy indicators
        for indicator in self.legitimacy_indicators['positive']:
            if indicator in page_text:
                auth_analysis['legitimate_elements'].append(indicator)
                if 'contact' in indicator:
                    auth_analysis['has_contact_info'] = True
                elif 'privacy' in indicator:
                    auth_analysis['has_privacy_policy'] = True
                elif 'terms' in indicator:
                    auth_analysis['has_terms_of_service'] = True
        
        # Check for missing legitimacy elements
        for indicator in self.legitimacy_indicators['negative']:
            if indicator in page_text:
                auth_analysis['missing_elements'].append(indicator)
                auth_analysis['risk_score'] += 0.2
        
        # Basic content quality analysis
        sentences = page_text.split('.')
        if len(sentences) > 0:
            avg_sentence_length = sum(len(s.split()) for s in sentences) / len(sentences)
            if avg_sentence_length < 5 or avg_sentence_length > 50:
                auth_analysis['content_quality_score'] += 0.2
        
        # Check for common spelling errors in phishing sites
        common_errors = ['recieve', 'seperate', 'occured', 'untill', 'loosing']
        for error in common_errors:
            if error in page_text:
                auth_analysis['spelling_errors'] += 1
                auth_analysis['risk_score'] += 0.1
        
        # Risk scoring based on missing elements
        if not auth_analysis['has_contact_info']:
            auth_analysis['risk_score'] += 0.3
        if not auth_analysis['has_privacy_policy']:
            auth_analysis['risk_score'] += 0.2
        if not auth_analysis['has_terms_of_service']:
            auth_analysis['risk_score'] += 0.2
        
        auth_analysis['risk_score'] = min(1.0, auth_analysis['risk_score'])
        
        return auth_analysis

    async def _analyze_brand_protection(self, soup: BeautifulSoup, url: str) -> Dict:
        """Brand protection and impersonation detection"""
        brand_analysis = {
            'risk_score': 0.0,
            'suspected_brand': None,
            'impersonation_confidence': 0.0,
            'domain_similarity': 0.0,
            'visual_similarity': 0.0,
            'brand_keywords': [],
            'typosquatting_detected': False,
            'favicon_analysis': {}
        }
        
        domain = urlparse(url).netloc.lower()
        page_text = soup.get_text().lower()
        title_text = (soup.title.string or '').lower() if soup.title else ''
        
        # Check for brand impersonation
        for brand, variations in self.major_brands.items():
            brand_score = 0
            
            # Check domain similarity
            for variation in variations:
                if variation in domain:
                    brand_score += 0.8
                    brand_analysis['typosquatting_detected'] = True
                    break
            
            # Check page content for brand mentions
            brand_mentions = page_text.count(brand) + title_text.count(brand)
            if brand_mentions > 3:
                brand_score += 0.5
                brand_analysis['brand_keywords'].append(brand)
            
            # Check for official domain
            official_domains = [f'{brand}.com', f'www.{brand}.com']
            if domain not in official_domains and brand_score > 0.3:
                brand_analysis['suspected_brand'] = brand
                brand_analysis['impersonation_confidence'] = brand_score
                brand_analysis['risk_score'] += brand_score
                break
        
        # Favicon analysis
        favicon = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
        if favicon:
            brand_analysis['favicon_analysis'] = {
                'present': True,
                'url': favicon.get('href', ''),
                'suspicious': any(brand in favicon.get('href', '').lower() 
                                for brand in self.major_brands.keys())
            }
        
        brand_analysis['risk_score'] = min(1.0, brand_analysis['risk_score'])
        
        return brand_analysis

    def _generate_content_flags(self, analysis_result: Dict) -> List[str]:
        """Generate content security flags"""
        flags = []
        security_analysis = analysis_result.get('security_analysis', {})
        
        # JavaScript security flags
        js_analysis = security_analysis.get('javascript_security', {})
        if js_analysis.get('obfuscated_scripts', 0) > 0:
            flags.append('obfuscated_javascript')
        if js_analysis.get('malicious_patterns'):
            flags.append('malicious_javascript_patterns')
        if not js_analysis.get('csp_present', False):
            flags.append('missing_content_security_policy')
        
        # Social engineering flags
        social_analysis = security_analysis.get('social_engineering', {})
        if social_analysis.get('urgency_indicators'):
            flags.append('urgency_tactics')
        if social_analysis.get('fear_tactics'):
            flags.append('fear_inducing_language')
        if social_analysis.get('authority_claims'):
            flags.append('authority_impersonation')
        
        # Form security flags
        form_analysis = security_analysis.get('form_security', {})
        if form_analysis.get('credential_forms', 0) > 0:
            flags.append('credential_harvesting_forms')
        if form_analysis.get('financial_forms', 0) > 0:
            flags.append('financial_data_collection')
        if form_analysis.get('suspicious_actions'):
            flags.append('suspicious_form_actions')
        
        # Brand protection flags
        brand_analysis = security_analysis.get('brand_protection', {})
        if brand_analysis.get('typosquatting_detected'):
            flags.append('brand_impersonation')
        if brand_analysis.get('suspected_brand'):
            flags.append('suspected_brand_spoofing')
        
        # Content authenticity flags
        auth_analysis = security_analysis.get('content_authenticity', {})
        if not auth_analysis.get('has_contact_info'):
            flags.append('missing_contact_information')
        if not auth_analysis.get('has_privacy_policy'):
            flags.append('missing_privacy_policy')
        if auth_analysis.get('spelling_errors', 0) > 2:
            flags.append('poor_content_quality')
        
        return flags

    def _generate_detailed_findings(self, analysis_result: Dict) -> List[Dict]:
        """Generate detailed security findings"""
        findings = []
        security_analysis = analysis_result.get('security_analysis', {})
        
        # JavaScript findings
        js_analysis = security_analysis.get('javascript_security', {})
        if js_analysis.get('obfuscated_scripts', 0) > 0:
            findings.append({
                'category': 'JavaScript Security',
                'severity': 'HIGH',
                'finding': f"Detected {js_analysis['obfuscated_scripts']} obfuscated scripts",
                'risk_impact': 'Obfuscated code may hide malicious functionality'
            })
        
        # Social engineering findings
        social_analysis = security_analysis.get('social_engineering', {})
        if social_analysis.get('fear_tactics'):
            findings.append({
                'category': 'Social Engineering',
                'severity': 'MEDIUM',
                'finding': 'Fear-inducing language detected',
                'risk_impact': 'May manipulate users into hasty decisions'
            })
        
        # Form security findings
        form_analysis = security_analysis.get('form_security', {})
        if form_analysis.get('credential_forms', 0) > 0:
            findings.append({
                'category': 'Form Security',
                'severity': 'HIGH',
                'finding': 'Credential harvesting forms detected',
                'risk_impact': 'Site may be collecting user login credentials'
            })
        
        return findings

    def _generate_enhanced_recommendations(self, analysis_result: Dict) -> List[str]:
        """Generate enhanced security recommendations"""
        recommendations = []
        risk_score = analysis_result.get('risk_score', 0)
        security_analysis = analysis_result.get('security_analysis', {})
        
        if risk_score > 0.8:
            recommendations.append("🚨 HIGH RISK: Avoid interacting with this site")
            recommendations.append("🔒 Do not enter any personal information")
        
        # JavaScript-specific recommendations
        js_analysis = security_analysis.get('javascript_security', {})
        if js_analysis.get('obfuscated_scripts', 0) > 0:
            recommendations.append("⚠️ Obfuscated JavaScript detected - exercise extreme caution")
        
        # Form-specific recommendations
        form_analysis = security_analysis.get('form_security', {})
        if form_analysis.get('credential_forms', 0) > 0:
            recommendations.append("🚫 Do not enter passwords or login credentials")
        if form_analysis.get('financial_forms', 0) > 0:
            recommendations.append("💳 Do not enter financial information")
        
        # Brand protection recommendations
        brand_analysis = security_analysis.get('brand_protection', {})
        if brand_analysis.get('suspected_brand'):
            brand = brand_analysis['suspected_brand']
            recommendations.append(f"🎭 Possible {brand.title()} impersonation - verify official domain")
        
        return recommendations

# Global instance
content_security_analyzer = ContentSecurityAnalyzer() 