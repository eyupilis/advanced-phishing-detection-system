"""
CONTENT ANALYZER
Derin içerik analizi ve phishing pattern tespiti
"""

import asyncio
import logging
import aiohttp
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import hashlib
import json

logger = logging.getLogger(__name__)

class ContentAnalyzer:
    def __init__(self):
        # Content analysis patterns
        self.phishing_keywords = [
            # Account-related
            'verify account', 'suspend account', 'account locked',
            'update payment', 'billing problem', 'payment failed',
            'security alert', 'unusual activity', 'sign in immediately',
            
            # Urgency indicators
            'urgent action', 'act now', 'expires today', 'limited time',
            'immediate attention', 'within 24 hours', 'expires soon',
            
            # Trust indicators (fake)
            'secure site', 'protected', 'verified', 'trusted',
            'ssl secured', 'bank grade security',
            
            # Common phishing phrases
            'click here to verify', 'confirm your identity',
            'update your information', 'avoid suspension'
        ]
        
        self.suspicious_domains = [
            # Brand typosquatting patterns
            'paypal', 'amazon', 'apple', 'microsoft', 'google',
            'facebook', 'twitter', 'instagram', 'linkedin',
            'bank', 'secure', 'verify', 'account'
        ]
        
        self.phishing_form_indicators = [
            'password', 'ssn', 'social security', 'credit card',
            'cvv', 'pin', 'account number', 'routing number',
            'date of birth', 'mother maiden name'
        ]
        
        self.legitimate_indicators = [
            'privacy policy', 'terms of service', 'contact us',
            'about us', 'help', 'support', 'faq'
        ]
        
        # Content scoring weights
        self.content_weights = {
            'phishing_keywords': 0.3,
            'suspicious_forms': 0.25,
            'domain_spoofing': 0.2,
            'missing_legitimacy': 0.1,
            'suspicious_links': 0.1,
            'meta_analysis': 0.05
        }
        
    async def analyze_url_content(self, url: str, deep_scan: bool = False,
                                timeout: int = 10) -> Dict:
        """URL içeriği için derin analiz"""
        try:
            analysis_result = {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'content_available': False,
                'risk_score': 0.0,
                'content_flags': [],
                'page_analysis': {},
                'form_analysis': {},
                'link_analysis': {},
                'meta_analysis': {},
                'recommendations': []
            }
            
            # Content fetch
            content_data = await self._fetch_page_content(url, timeout)
            
            if not content_data or content_data.get('error'):
                analysis_result['error'] = content_data.get('error', 'Failed to fetch content')
                analysis_result['risk_score'] = 0.5  # Unknown = medium risk
                return analysis_result
            
            analysis_result['content_available'] = True
            analysis_result['page_analysis']['status_code'] = content_data.get('status_code')
            analysis_result['page_analysis']['content_length'] = len(content_data.get('content', ''))
            
            # Parse HTML content
            soup = BeautifulSoup(content_data['content'], 'html.parser')
            
            # Content analysis
            keyword_risk = await self._analyze_phishing_keywords(soup)
            form_risk = await self._analyze_forms(soup)
            domain_risk = await self._analyze_domain_spoofing(url, soup)
            legitimacy_risk = await self._analyze_legitimacy_indicators(soup)
            link_risk = await self._analyze_suspicious_links(soup, url)
            meta_risk = await self._analyze_meta_data(soup)
            
            # Calculate total risk score
            total_risk = (
                keyword_risk * self.content_weights['phishing_keywords'] +
                form_risk * self.content_weights['suspicious_forms'] +
                domain_risk * self.content_weights['domain_spoofing'] +
                legitimacy_risk * self.content_weights['missing_legitimacy'] +
                link_risk * self.content_weights['suspicious_links'] +
                meta_risk * self.content_weights['meta_analysis']
            )
            
            analysis_result['risk_score'] = round(total_risk, 3)
            
            # Detailed analysis results
            analysis_result['page_analysis'].update({
                'title': soup.title.string if soup.title else '',
                'keyword_risk_score': keyword_risk,
                'has_forms': form_risk > 0,
                'domain_risk_score': domain_risk,
                'legitimacy_score': 1 - legitimacy_risk,
                'suspicious_links_count': await self._count_suspicious_links(soup, url)
            })
            
            # Form analysis details
            forms = soup.find_all('form')
            analysis_result['form_analysis'] = {
                'form_count': len(forms),
                'suspicious_forms': await self._get_suspicious_forms_details(forms),
                'form_risk_score': form_risk
            }
            
            # Link analysis details
            links = soup.find_all('a', href=True)
            analysis_result['link_analysis'] = {
                'total_links': len(links),
                'external_links': await self._count_external_links(links, url),
                'suspicious_links': await self._get_suspicious_links_details(links, url),
                'link_risk_score': link_risk
            }
            
            # Meta analysis
            analysis_result['meta_analysis'] = {
                'meta_tags_count': len(soup.find_all('meta')),
                'has_description': bool(soup.find('meta', attrs={'name': 'description'})),
                'has_keywords': bool(soup.find('meta', attrs={'name': 'keywords'})),
                'meta_risk_score': meta_risk
            }
            
            # Content flags
            flags = []
            if keyword_risk > 0.6:
                flags.append('high_phishing_keywords')
            if form_risk > 0.7:
                flags.append('suspicious_forms_detected')
            if domain_risk > 0.8:
                flags.append('domain_spoofing_suspected')
            if legitimacy_risk > 0.7:
                flags.append('lacks_legitimacy_indicators')
            if link_risk > 0.6:
                flags.append('suspicious_links_present')
            
            analysis_result['content_flags'] = flags
            
            # Generate recommendations
            recommendations = self._generate_content_recommendations(analysis_result)
            analysis_result['recommendations'] = recommendations
            
            # Deep scan additional analysis
            if deep_scan:
                deep_analysis = await self._perform_deep_scan(soup, url)
                analysis_result['deep_scan_analysis'] = deep_analysis
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"❌ Content analysis error: {e}")
            return {
                'url': url,
                'error': str(e),
                'risk_score': 0.5,
                'content_flags': ['analysis_error']
            }
    
    async def _fetch_page_content(self, url: str, timeout: int) -> Dict:
        """Web sayfası içeriğini fetch et"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=timeout, headers=headers) as response:
                    content = await response.text()
                    
                    return {
                        'status_code': response.status,
                        'content': content,
                        'headers': dict(response.headers),
                        'url': str(response.url)
                    }
                    
        except asyncio.TimeoutError:
            return {'error': 'Request timeout'}
        except aiohttp.ClientError as e:
            return {'error': f'Request failed: {str(e)}'}
        except Exception as e:
            return {'error': f'Unexpected error: {str(e)}'}
    
    async def _analyze_phishing_keywords(self, soup: BeautifulSoup) -> float:
        """Phishing anahtar kelime analizi"""
        try:
            text_content = soup.get_text().lower()
            keyword_matches = 0
            
            for keyword in self.phishing_keywords:
                if keyword.lower() in text_content:
                    keyword_matches += 1
            
            # Score based on keyword density
            if len(text_content) > 0:
                keyword_density = keyword_matches / len(self.phishing_keywords)
                return min(keyword_density * 2, 1.0)  # Max 1.0
            
            return 0.0
            
        except Exception as e:
            logger.error(f"❌ Keyword analysis error: {e}")
            return 0.0
    
    async def _analyze_forms(self, soup: BeautifulSoup) -> float:
        """Form analizi"""
        try:
            forms = soup.find_all('form')
            if not forms:
                return 0.0
            
            risk_score = 0.0
            
            for form in forms:
                form_text = form.get_text().lower()
                input_fields = form.find_all(['input', 'textarea', 'select'])
                
                # Check for sensitive input fields
                sensitive_field_count = 0
                for field in input_fields:
                    field_name = (field.get('name', '') + ' ' + field.get('placeholder', '')).lower()
                    field_type = field.get('type', '').lower()
                    
                    for indicator in self.phishing_form_indicators:
                        if indicator in field_name or indicator in field_type:
                            sensitive_field_count += 1
                            break
                
                # Score this form
                if sensitive_field_count > 0:
                    form_risk = min(sensitive_field_count / 3, 1.0)  # 3+ sensitive fields = max risk
                    risk_score = max(risk_score, form_risk)
            
            return risk_score
            
        except Exception as e:
            logger.error(f"❌ Form analysis error: {e}")
            return 0.0
    
    async def _analyze_domain_spoofing(self, url: str, soup: BeautifulSoup) -> float:
        """Domain spoofing analizi"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            risk_score = 0.0
            
            # Check domain against known brand patterns
            for brand in self.suspicious_domains:
                if brand in domain and brand != domain:
                    # Potential typosquatting
                    risk_score += 0.3
            
            # Check page content for brand impersonation
            page_text = soup.get_text().lower()
            title_text = soup.title.string.lower() if soup.title else ''
            
            for brand in self.suspicious_domains:
                if brand in page_text or brand in title_text:
                    if brand not in domain:
                        # Content mentions brand but domain doesn't match
                        risk_score += 0.4
            
            # Check for suspicious TLDs with brand names
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    risk_score += 0.2
            
            return min(risk_score, 1.0)
            
        except Exception as e:
            logger.error(f"❌ Domain spoofing analysis error: {e}")
            return 0.0
    
    async def _analyze_legitimacy_indicators(self, soup: BeautifulSoup) -> float:
        """Meşruiyet göstergeleri analizi"""
        try:
            page_text = soup.get_text().lower()
            
            legitimacy_score = 0.0
            
            for indicator in self.legitimate_indicators:
                if indicator in page_text:
                    legitimacy_score += 1
            
            # Normalize score (missing legitimacy = risk)
            max_possible = len(self.legitimate_indicators)
            legitimacy_ratio = legitimacy_score / max_possible
            
            # Return inverse (missing legitimacy indicators = higher risk)
            return 1 - legitimacy_ratio
            
        except Exception as e:
            logger.error(f"❌ Legitimacy analysis error: {e}")
            return 0.0
    
    async def _analyze_suspicious_links(self, soup: BeautifulSoup, base_url: str) -> float:
        """Şüpheli link analizi"""
        try:
            links = soup.find_all('a', href=True)
            if not links:
                return 0.0
            
            suspicious_count = 0
            total_links = len(links)
            
            for link in links:
                href = link.get('href')
                
                # Skip internal/relative links
                if href.startswith('#') or href.startswith('mailto:'):
                    continue
                
                # Resolve relative URLs
                if not href.startswith(('http://', 'https://')):
                    href = urljoin(base_url, href)
                
                # Check for suspicious patterns
                if self._is_suspicious_link(href):
                    suspicious_count += 1
            
            if total_links > 0:
                return suspicious_count / total_links
            
            return 0.0
            
        except Exception as e:
            logger.error(f"❌ Link analysis error: {e}")
            return 0.0
    
    def _is_suspicious_link(self, url: str) -> bool:
        """Link'in şüpheli olup olmadığını kontrol et"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link']
            if any(shortener in domain for shortener in shorteners):
                return True
            
            # Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                return True
            
            # IP addresses instead of domains
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                return True
            
            # Very long domains
            if len(domain) > 50:
                return True
            
            return False
            
        except:
            return False
    
    async def _analyze_meta_data(self, soup: BeautifulSoup) -> float:
        """Meta data analizi"""
        try:
            risk_score = 0.0
            
            # Check for missing important meta tags
            description = soup.find('meta', attrs={'name': 'description'})
            if not description or not description.get('content'):
                risk_score += 0.3
            
            # Check for suspicious meta tags
            meta_tags = soup.find_all('meta')
            for meta in meta_tags:
                content = meta.get('content', '').lower()
                
                # Check for phishing keywords in meta content
                for keyword in self.phishing_keywords[:5]:  # Check first 5
                    if keyword.lower() in content:
                        risk_score += 0.1
            
            return min(risk_score, 1.0)
            
        except Exception as e:
            logger.error(f"❌ Meta analysis error: {e}")
            return 0.0
    
    async def _count_suspicious_links(self, soup: BeautifulSoup, base_url: str) -> int:
        """Şüpheli link sayısını say"""
        try:
            links = soup.find_all('a', href=True)
            count = 0
            
            for link in links:
                href = link.get('href')
                if not href.startswith(('http://', 'https://')):
                    href = urljoin(base_url, href)
                
                if self._is_suspicious_link(href):
                    count += 1
            
            return count
            
        except:
            return 0
    
    async def _get_suspicious_forms_details(self, forms) -> List[Dict]:
        """Şüpheli form detayları"""
        try:
            suspicious_forms = []
            
            for i, form in enumerate(forms):
                form_details = {
                    'form_index': i,
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET'),
                    'sensitive_fields': [],
                    'risk_indicators': []
                }
                
                # Check input fields
                inputs = form.find_all(['input', 'textarea', 'select'])
                for input_field in inputs:
                    field_name = input_field.get('name', '')
                    field_type = input_field.get('type', '')
                    placeholder = input_field.get('placeholder', '')
                    
                    field_text = f"{field_name} {field_type} {placeholder}".lower()
                    
                    for indicator in self.phishing_form_indicators:
                        if indicator in field_text:
                            form_details['sensitive_fields'].append({
                                'name': field_name,
                                'type': field_type,
                                'indicator': indicator
                            })
                
                if form_details['sensitive_fields']:
                    suspicious_forms.append(form_details)
            
            return suspicious_forms
            
        except:
            return []
    
    async def _count_external_links(self, links, base_url: str) -> int:
        """External link sayısını say"""
        try:
            base_domain = urlparse(base_url).netloc
            external_count = 0
            
            for link in links:
                href = link.get('href', '')
                if href.startswith(('http://', 'https://')):
                    link_domain = urlparse(href).netloc
                    if link_domain != base_domain:
                        external_count += 1
            
            return external_count
            
        except:
            return 0
    
    async def _get_suspicious_links_details(self, links, base_url: str) -> List[Dict]:
        """Şüpheli link detayları"""
        try:
            suspicious_links = []
            
            for link in links:
                href = link.get('href', '')
                if not href.startswith(('http://', 'https://')):
                    href = urljoin(base_url, href)
                
                if self._is_suspicious_link(href):
                    suspicious_links.append({
                        'url': href,
                        'text': link.get_text()[:100],  # First 100 chars
                        'reason': self._get_suspicion_reason(href)
                    })
            
            return suspicious_links
            
        except:
            return []
    
    def _get_suspicion_reason(self, url: str) -> str:
        """Link'in şüpheli olma sebebini getir"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
            if any(shortener in domain for shortener in shorteners):
                return "URL shortener"
            
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                return "IP address instead of domain"
            
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                return "Suspicious TLD"
            
            if len(domain) > 50:
                return "Unusually long domain"
            
            return "Pattern match"
            
        except:
            return "Unknown"
    
    async def _perform_deep_scan(self, soup: BeautifulSoup, url: str) -> Dict:
        """Derin tarama analizi"""
        try:
            deep_analysis = {
                'javascript_analysis': {},
                'css_analysis': {},
                'image_analysis': {},
                'additional_indicators': []
            }
            
            # JavaScript analysis
            scripts = soup.find_all('script')
            js_risk_indicators = ['eval(', 'document.write', 'innerHTML', 'unescape']
            js_risk_count = 0
            
            for script in scripts:
                script_content = script.string or ''
                for indicator in js_risk_indicators:
                    if indicator in script_content:
                        js_risk_count += 1
            
            deep_analysis['javascript_analysis'] = {
                'script_count': len(scripts),
                'risk_indicators': js_risk_count,
                'risk_score': min(js_risk_count / 5, 1.0)
            }
            
            # CSS analysis (hidden content detection)
            styles = soup.find_all(['style', 'link'])
            hidden_content_indicators = ['display:none', 'visibility:hidden', 'opacity:0']
            
            # Image analysis
            images = soup.find_all('img')
            external_images = 0
            base_domain = urlparse(url).netloc
            
            for img in images:
                src = img.get('src', '')
                if src.startswith(('http://', 'https://')):
                    img_domain = urlparse(src).netloc
                    if img_domain != base_domain:
                        external_images += 1
            
            deep_analysis['image_analysis'] = {
                'total_images': len(images),
                'external_images': external_images,
                'external_ratio': external_images / len(images) if images else 0
            }
            
            return deep_analysis
            
        except Exception as e:
            logger.error(f"❌ Deep scan error: {e}")
            return {'error': str(e)}
    
    def _generate_content_recommendations(self, analysis_result: Dict) -> List[str]:
        """İçerik analizi sonucuna göre öneriler"""
        recommendations = []
        
        risk_score = analysis_result.get('risk_score', 0)
        flags = analysis_result.get('content_flags', [])
        
        if risk_score > 0.8:
            recommendations.append("🚨 Yüksek riskli içerik tespit edildi")
            recommendations.append("⚠️ Bu sayfayı ziyaret etmeyin")
        
        if 'high_phishing_keywords' in flags:
            recommendations.append("🎯 Phishing anahtar kelimeleri tespit edildi")
        
        if 'suspicious_forms_detected' in flags:
            recommendations.append("📝 Şüpheli formlar var - bilgi girmeyin")
        
        if 'domain_spoofing_suspected' in flags:
            recommendations.append("🕵️ Domain taklit şüphesi var")
        
        if 'suspicious_links_present' in flags:
            recommendations.append("🔗 Şüpheli linkler mevcut")
        
        if 'lacks_legitimacy_indicators' in flags:
            recommendations.append("🏛️ Meşruiyet göstergeleri eksik")
        
        return recommendations

# Global instance
content_analyzer = ContentAnalyzer() 