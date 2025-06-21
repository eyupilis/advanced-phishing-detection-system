"""
VISUAL PHISHING DETECTOR
Production-level görsel phishing tespit sistemi
"""

import asyncio
import aiohttp
import hashlib
import logging
import time
import re
import urllib.parse
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from PIL import Image, ImageChops
import io
import base64
import json
from dataclasses import dataclass

# Screenshot capabilities
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class BrandProfile:
    """Marka profil bilgileri"""
    name: str
    keywords: List[str]
    domains: List[str]
    colors: List[str]
    logo_patterns: List[str]
    common_paths: List[str]

class VisualPhishingDetector:
    """Production-level Visual Phishing Detection Engine"""
    
    def __init__(self):
        self.session_timeout = 30  # seconds
        self.screenshot_timeout = 15  # seconds
        self.max_image_size = 5 * 1024 * 1024  # 5MB
        
        # Initialize browser driver pool
        self.browser_pool = []
        self.max_browsers = 3
        
        # Known brand profiles
        self.brand_profiles = self._initialize_brand_profiles()
        
        # Visual phishing patterns
        self.phishing_patterns = self._initialize_phishing_patterns()
        
        # DOM analysis patterns
        self.dom_patterns = self._initialize_dom_patterns()
        
        logger.info("🎨 Visual Phishing Detector initialized")
    
    def _initialize_brand_profiles(self) -> Dict[str, BrandProfile]:
        """Popüler markaların profil bilgilerini başlat"""
        profiles = {}
        
        # PayPal
        profiles['paypal'] = BrandProfile(
            name="PayPal",
            keywords=['paypal', 'payment', 'secure', 'account', 'verify'],
            domains=['paypal.com', 'paypal.me'],
            colors=['#003087', '#0070ba', '#ffc439'],
            logo_patterns=['paypal-logo', 'pp-logo'],
            common_paths=['/signin', '/home', '/myaccount', '/verify']
        )
        
        # Apple
        profiles['apple'] = BrandProfile(
            name="Apple",
            keywords=['apple', 'icloud', 'itunes', 'app store', 'apple id'],
            domains=['apple.com', 'icloud.com', 'itunes.com'],
            colors=['#000000', '#ffffff', '#007aff'],
            logo_patterns=['apple-logo', 'apple-icon'],
            common_paths=['/signin', '/account', '/id']
        )
        
        # Microsoft
        profiles['microsoft'] = BrandProfile(
            name="Microsoft",
            keywords=['microsoft', 'outlook', 'office', 'windows', 'xbox'],
            domains=['microsoft.com', 'outlook.com', 'office.com', 'live.com'],
            colors=['#00bcf2', '#ffb900', '#e74856'],
            logo_patterns=['microsoft-logo', 'ms-logo'],
            common_paths=['/login', '/account', '/signin']
        )
        
        # Google
        profiles['google'] = BrandProfile(
            name="Google",
            keywords=['google', 'gmail', 'drive', 'youtube', 'chrome'],
            domains=['google.com', 'gmail.com', 'youtube.com', 'drive.google.com'],
            colors=['#4285f4', '#ea4335', '#fbbc05', '#34a853'],
            logo_patterns=['google-logo', 'gmail-logo'],
            common_paths=['/signin', '/accounts', '/drive', '/mail']
        )
        
        # Amazon
        profiles['amazon'] = BrandProfile(
            name="Amazon",
            keywords=['amazon', 'aws', 'prime', 'kindle'],
            domains=['amazon.com', 'aws.amazon.com', 'prime.amazon.com'],
            colors=['#ff9900', '#232f3e'],
            logo_patterns=['amazon-logo', 'aws-logo'],
            common_paths=['/signin', '/gp/signin', '/ap/signin']
        )
        
        return profiles
    
    def _initialize_phishing_patterns(self) -> Dict[str, List[str]]:
        """Görsel phishing pattern'ları başlat"""
        return {
            'suspicious_forms': [
                'verify.*account',
                'confirm.*identity', 
                'update.*payment',
                'urgent.*action',
                'suspended.*account',
                'click.*here.*immediately'
            ],
            'urgency_indicators': [
                'expires.*today',
                'immediate.*action',
                'account.*suspended',
                'verify.*within.*24',
                'urgent.*security',
                'limited.*time'
            ],
            'fake_security': [
                'ssl.*secure',
                'bank.*grade.*security',
                'military.*encryption',
                '256.*bit.*encryption',
                'verified.*secure'
            ],
            'spoofed_elements': [
                'fake.*address.*bar',
                'overlay.*browser',
                'iframe.*spoof',
                'popup.*browser',
                'custom.*chrome'
            ]
        }
    
    def _initialize_dom_patterns(self) -> Dict[str, List[str]]:
        """DOM analiz pattern'ları başlat"""
        return {
            'credential_theft': [
                'input[type="password"]',
                'input[name*="pass"]',
                'input[name*="login"]',
                'input[name*="email"]',
                'input[name*="user"]'
            ],
            'financial_forms': [
                'input[name*="card"]',
                'input[name*="cvv"]',
                'input[name*="ssn"]',
                'input[name*="account"]',
                'input[name*="routing"]'
            ],
            'social_engineering': [
                '.urgent',
                '.warning',
                '.alert',
                '.suspended',
                '.verify'
            ]
        }
    
    async def analyze_url_visual(self, url: str, capture_screenshot: bool = True, 
                               deep_analysis: bool = False) -> Dict[str, Any]:
        """Comprehensive visual analysis of URL"""
        start_time = time.time()
        
        analysis_result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'visual_analysis': {
                'screenshot_captured': False,
                'brand_impersonation': None,
                'visual_spoofing_detected': False,
                'ui_manipulation_detected': False,
                'social_engineering_elements': [],
                'credential_harvesting_forms': 0,
                'suspicious_redirects': [],
                'dom_analysis': {},
                'visual_similarity_score': 0.0
            },
            'risk_assessment': {
                'visual_risk_score': 0.0,
                'confidence': 0.0,
                'risk_factors': [],
                'recommendations': []
            },
            'technical_details': {
                'response_time_ms': 0,
                'page_load_time': 0,
                'screenshot_size': 0,
                'dom_elements_count': 0,
                'external_resources': []
            },
            'status': 'pending'
        }
        
        try:
            # 1. URL Pre-analysis
            url_analysis = await self._analyze_url_structure(url)
            analysis_result['url_analysis'] = url_analysis
            
            # 2. Screenshot capture and visual analysis
            if capture_screenshot and SELENIUM_AVAILABLE:
                screenshot_data = await self._capture_screenshot(url)
                if screenshot_data:
                    analysis_result['visual_analysis']['screenshot_captured'] = True
                    analysis_result['technical_details']['screenshot_size'] = len(screenshot_data)
                    
                    # Visual analysis on screenshot
                    visual_analysis = await self._analyze_screenshot(screenshot_data, url)
                    analysis_result['visual_analysis'].update(visual_analysis)
            
            # 3. DOM Analysis
            dom_analysis = await self._analyze_dom_structure(url)
            analysis_result['visual_analysis']['dom_analysis'] = dom_analysis
            
            # 4. Brand Impersonation Detection
            brand_analysis = await self._detect_brand_impersonation(url, analysis_result['visual_analysis'])
            analysis_result['visual_analysis']['brand_impersonation'] = brand_analysis
            
            # 5. UI Manipulation Detection
            ui_manipulation = await self._detect_ui_manipulation(url, analysis_result['visual_analysis'])
            analysis_result['visual_analysis']['ui_manipulation_detected'] = ui_manipulation
            
            # 6. Social Engineering Detection
            social_eng = await self._detect_social_engineering(analysis_result['visual_analysis'])
            analysis_result['visual_analysis']['social_engineering_elements'] = social_eng
            
            # 7. Risk Assessment
            risk_assessment = self._calculate_visual_risk(analysis_result['visual_analysis'])
            analysis_result['risk_assessment'] = risk_assessment
            
            # 8. Generate recommendations
            recommendations = self._generate_visual_recommendations(analysis_result)
            analysis_result['risk_assessment']['recommendations'] = recommendations
            
            analysis_result['status'] = 'completed'
            
        except Exception as e:
            logger.error(f"❌ Visual analysis error for {url}: {e}")
            analysis_result['status'] = 'error'
            analysis_result['error'] = str(e)
            analysis_result['risk_assessment']['visual_risk_score'] = 0.5  # Moderate risk when analysis fails
        
        finally:
            analysis_result['technical_details']['response_time_ms'] = round((time.time() - start_time) * 1000, 2)
        
        return analysis_result
    
    async def _analyze_url_structure(self, url: str) -> Dict[str, Any]:
        """URL yapısını analiz et"""
        parsed = urllib.parse.urlparse(url)
        
        analysis = {
            'domain': parsed.netloc,
            'path': parsed.path,
            'suspicious_patterns': [],
            'domain_analysis': {},
            'ssl_spoofing': False
        }
        
        # Domain analysis
        domain = parsed.netloc.lower()
        
        # Check for suspicious domain patterns
        suspicious_patterns = [
            r'payp[a4]l',
            r'g[o0][o0]gle',
            r'[a4]pp[l1]e',
            r'm[i1]cr[o0]s[o0]ft',
            r'[a4]m[a4]z[o0]n',
            r'f[a4]ceb[o0][o0]k',
            r'tw[i1]tt[e3]r'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain):
                analysis['suspicious_patterns'].append(f"Suspicious domain pattern: {pattern}")
        
        # Check for homograph attacks
        if any(ord(char) > 127 for char in domain):
            analysis['suspicious_patterns'].append("Non-ASCII characters in domain (possible homograph attack)")
        
        # Check for SSL spoofing indicators
        if parsed.scheme == 'https' and ('ssl' in domain or 'secure' in domain or 'bank' in domain):
            analysis['ssl_spoofing'] = True
        
        return analysis
    
    async def _capture_screenshot(self, url: str) -> Optional[bytes]:
        """Websitenin screenshot'ını çek"""
        if not SELENIUM_AVAILABLE:
            logger.warning("⚠️ Selenium not available, skipping screenshot")
            return None
        
        driver = None
        try:
            # Chrome options for headless mode
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-plugins')
            chrome_options.add_argument('--disable-images')  # Faster loading
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            # Webdriver-manager ile otomatik ChromeDriver yönetimi
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            driver.set_page_load_timeout(self.screenshot_timeout)
            
            # Navigate to URL
            driver.get(url)
            
            # Wait for page to load
            WebDriverWait(driver, 10).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
            
            # Take screenshot
            screenshot = driver.get_screenshot_as_png()
            return screenshot
            
        except TimeoutException:
            logger.warning(f"⏰ Screenshot timeout for {url}")
            return None
        except WebDriverException as e:
            logger.warning(f"🌐 WebDriver error for {url}: {e}")
            return None
        except Exception as e:
            logger.error(f"❌ Screenshot error for {url}: {e}")
            return None
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass
    
    async def _analyze_screenshot(self, screenshot_data: bytes, url: str) -> Dict[str, Any]:
        """Screenshot'ı analiz et"""
        analysis = {
            'image_analysis': {},
            'text_detection': [],
            'color_analysis': {},
            'layout_analysis': {}
        }
        
        try:
            # Convert to PIL Image
            image = Image.open(io.BytesIO(screenshot_data))
            
            # Basic image analysis
            analysis['image_analysis'] = {
                'width': image.width,
                'height': image.height,
                'mode': image.mode,
                'format': image.format or 'PNG'
            }
            
            # Color analysis
            colors = image.getcolors(maxcolors=256*256*256)
            if colors:
                dominant_colors = sorted(colors, key=lambda x: x[0], reverse=True)[:5]
                analysis['color_analysis'] = {
                    'dominant_colors': [{'count': count, 'color': color} for count, color in dominant_colors],
                    'total_colors': len(colors)
                }
            
            # Layout analysis (basic)
            # This would be enhanced with OCR or ML-based text detection in production
            analysis['layout_analysis'] = {
                'aspect_ratio': image.width / image.height,
                'estimated_content_regions': self._estimate_content_regions(image)
            }
            
        except Exception as e:
            logger.error(f"❌ Screenshot analysis error: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    async def _analyze_dom_structure(self, url: str) -> Dict[str, Any]:
        """DOM yapısını analiz et"""
        analysis = {
            'forms_detected': 0,
            'credential_inputs': 0,
            'financial_inputs': 0,
            'suspicious_elements': [],
            'external_resources': [],
            'javascript_analysis': {}
        }
        
        if not SELENIUM_AVAILABLE:
            return analysis
        
        driver = None
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            
            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(15)
            driver.get(url)
            
            # Wait for page load
            WebDriverWait(driver, 10).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
            
            # Analyze forms
            forms = driver.find_elements(By.TAG_NAME, "form")
            analysis['forms_detected'] = len(forms)
            
            # Check for credential inputs
            credential_patterns = ['password', 'email', 'login', 'user', 'username']
            for pattern in credential_patterns:
                inputs = driver.find_elements(By.CSS_SELECTOR, f'input[name*="{pattern}"], input[type="{pattern}"]')
                analysis['credential_inputs'] += len(inputs)
            
            # Check for financial inputs
            financial_patterns = ['card', 'cvv', 'ssn', 'account', 'routing', 'credit']
            for pattern in financial_patterns:
                inputs = driver.find_elements(By.CSS_SELECTOR, f'input[name*="{pattern}"]')
                analysis['financial_inputs'] += len(inputs)
            
            # Check for suspicious elements
            suspicious_selectors = ['.urgent', '.warning', '.alert', '.suspended', '.verify']
            for selector in suspicious_selectors:
                elements = driver.find_elements(By.CSS_SELECTOR, selector)
                if elements:
                    analysis['suspicious_elements'].append({
                        'selector': selector,
                        'count': len(elements),
                        'texts': [elem.text[:100] for elem in elements[:3]]  # First 3 elements, max 100 chars
                    })
            
            # Analyze external resources
            scripts = driver.find_elements(By.TAG_NAME, "script")
            external_scripts = []
            for script in scripts:
                src = script.get_attribute('src')
                if src and not src.startswith(('/', '#')) and url not in src:
                    external_scripts.append(src)
            
            analysis['external_resources'] = external_scripts[:10]  # Limit to 10
            
            # JavaScript analysis
            try:
                js_result = driver.execute_script("""
                    return {
                        hasObfuscatedCode: document.documentElement.innerHTML.includes('eval('),
                        hasFormSubmitListeners: document.querySelectorAll('form[onsubmit]').length > 0,
                        hasPasswordFields: document.querySelectorAll('input[type="password"]').length,
                        hasHiddenInputs: document.querySelectorAll('input[type="hidden"]').length
                    };
                """)
                analysis['javascript_analysis'] = js_result
            except:
                pass
            
        except Exception as e:
            logger.error(f"❌ DOM analysis error for {url}: {e}")
            analysis['error'] = str(e)
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass
        
        return analysis
    
    async def _detect_brand_impersonation(self, url: str, visual_data: Dict) -> Optional[Dict[str, Any]]:
        """Marka taklit tespiti"""
        domain = urllib.parse.urlparse(url).netloc.lower()
        
        for brand_key, brand_profile in self.brand_profiles.items():
            # Check domain similarity
            domain_similarity = 0
            for official_domain in brand_profile.domains:
                if official_domain in domain and domain != official_domain:
                    domain_similarity = 0.8  # High similarity but not exact match
                    break
                elif self._calculate_domain_similarity(domain, official_domain) > 0.7:
                    domain_similarity = 0.7
            
            # Check for brand keywords in content
            keyword_matches = 0
            dom_data = visual_data.get('dom_analysis', {})
            
            # This would be enhanced with actual page content analysis
            for keyword in brand_profile.keywords:
                if keyword.lower() in url.lower():
                    keyword_matches += 1
            
            if domain_similarity > 0.5 or keyword_matches >= 2:
                return {
                    'suspected_brand': brand_profile.name,
                    'confidence': max(domain_similarity, keyword_matches / len(brand_profile.keywords)),
                    'domain_similarity': domain_similarity,
                    'keyword_matches': keyword_matches,
                    'indicators': [
                        f"Domain similarity: {domain_similarity:.2f}",
                        f"Keyword matches: {keyword_matches}/{len(brand_profile.keywords)}"
                    ]
                }
        
        return None
    
    async def _detect_ui_manipulation(self, url: str, visual_data: Dict) -> bool:
        """UI manipülasyon tespiti"""
        manipulation_indicators = 0
        
        dom_data = visual_data.get('dom_analysis', {})
        
        # Check for iframe spoofing
        if 'iframe' in str(dom_data):
            manipulation_indicators += 1
        
        # Check for suspicious JavaScript
        js_analysis = dom_data.get('javascript_analysis', {})
        if js_analysis.get('hasObfuscatedCode', False):
            manipulation_indicators += 1
        
        # Check for hidden inputs (potential data harvesting)
        if js_analysis.get('hasHiddenInputs', 0) > 3:
            manipulation_indicators += 1
        
        # Check for external resources from suspicious domains
        external_resources = dom_data.get('external_resources', [])
        for resource in external_resources:
            if any(sus in resource.lower() for sus in ['bit.ly', 'tinyurl', 'shorturl']):
                manipulation_indicators += 1
                break
        
        return manipulation_indicators >= 2
    
    async def _detect_social_engineering(self, visual_data: Dict) -> List[str]:
        """Sosyal mühendislik tespiti"""
        indicators = []
        
        dom_data = visual_data.get('dom_analysis', {})
        suspicious_elements = dom_data.get('suspicious_elements', [])
        
        for element in suspicious_elements:
            selector = element['selector']
            texts = element.get('texts', [])
            
            for text in texts:
                text_lower = text.lower()
                
                # Check for urgency indicators
                urgency_keywords = ['urgent', 'immediate', 'expires', 'suspended', 'limited time']
                if any(keyword in text_lower for keyword in urgency_keywords):
                    indicators.append(f"Urgency indicator: {text[:50]}...")
                
                # Check for verification requests
                if any(keyword in text_lower for keyword in ['verify', 'confirm', 'update']):
                    indicators.append(f"Verification request: {text[:50]}...")
                
                # Check for fear tactics
                if any(keyword in text_lower for keyword in ['suspended', 'blocked', 'frozen', 'security breach']):
                    indicators.append(f"Fear tactic: {text[:50]}...")
        
        return indicators[:5]  # Limit to 5 indicators
    
    def _calculate_visual_risk(self, visual_data: Dict) -> Dict[str, Any]:
        """Görsel risk skorunu hesapla"""
        risk_score = 0.0
        risk_factors = []
        confidence = 0.0
        
        # Brand impersonation risk
        brand_imp = visual_data.get('brand_impersonation')
        if brand_imp:
            brand_risk = brand_imp['confidence'] * 0.4
            risk_score += brand_risk
            risk_factors.append(f"Brand impersonation detected: {brand_imp['suspected_brand']}")
            confidence += 0.3
        
        # UI manipulation risk
        if visual_data.get('ui_manipulation_detected', False):
            risk_score += 0.3
            risk_factors.append("UI manipulation techniques detected")
            confidence += 0.2
        
        # Social engineering risk
        social_eng = visual_data.get('social_engineering_elements', [])
        if social_eng:
            social_risk = min(len(social_eng) * 0.1, 0.3)
            risk_score += social_risk
            risk_factors.append(f"Social engineering elements: {len(social_eng)}")
            confidence += 0.2
        
        # DOM analysis risk
        dom_data = visual_data.get('dom_analysis', {})
        
        # Credential harvesting forms
        credential_inputs = dom_data.get('credential_inputs', 0)
        if credential_inputs > 0:
            cred_risk = min(credential_inputs * 0.15, 0.3)
            risk_score += cred_risk
            risk_factors.append(f"Credential harvesting forms: {credential_inputs}")
            confidence += 0.15
        
        # Financial input forms
        financial_inputs = dom_data.get('financial_inputs', 0)
        if financial_inputs > 0:
            fin_risk = min(financial_inputs * 0.2, 0.4)
            risk_score += fin_risk
            risk_factors.append(f"Financial input forms: {financial_inputs}")
            confidence += 0.2
        
        # External suspicious resources
        external_resources = dom_data.get('external_resources', [])
        if len(external_resources) > 5:
            risk_score += 0.1
            risk_factors.append(f"Many external resources: {len(external_resources)}")
            confidence += 0.1
        
        # Normalize risk score
        risk_score = min(risk_score, 1.0)
        confidence = min(confidence, 1.0)
        
        return {
            'visual_risk_score': round(risk_score, 3),
            'confidence': round(confidence, 3),
            'risk_factors': risk_factors
        }
    
    def _generate_visual_recommendations(self, analysis_result: Dict) -> List[str]:
        """Görsel analiz önerilerini oluştur"""
        recommendations = []
        risk_score = analysis_result['risk_assessment']['visual_risk_score']
        
        if risk_score > 0.7:
            recommendations.append("🚨 Yüksek görsel risk tespit edildi - siteyi kullanmayın")
            recommendations.append("🔒 Kişisel bilgilerinizi kesinlikle paylaşmayın")
        elif risk_score > 0.4:
            recommendations.append("⚠️ Şüpheli görsel öğeler tespit edildi - dikkatli olun")
            recommendations.append("🔍 URL adresini dikkatli kontrol edin")
        else:
            recommendations.append("✅ Görsel analizde kritik risk tespit edilmedi")
        
        # Specific recommendations based on findings
        visual_data = analysis_result['visual_analysis']
        
        if visual_data.get('brand_impersonation'):
            recommendations.append("🏢 Marka taklit şüphesi - resmi domaini kontrol edin")
        
        if visual_data.get('ui_manipulation_detected'):
            recommendations.append("🎭 UI manipülasyon tespit edildi - dikkatli olun")
        
        if visual_data.get('social_engineering_elements'):
            recommendations.append("🧠 Sosyal mühendislik teknikleri kullanılıyor")
        
        dom_data = visual_data.get('dom_analysis', {})
        if dom_data.get('credential_inputs', 0) > 0:
            recommendations.append("🔑 Kimlik bilgisi formları mevcut - doğruluğu kontrol edin")
        
        if dom_data.get('financial_inputs', 0) > 0:
            recommendations.append("💳 Finansal bilgi formları mevcut - güvenli bağlantı kontrol edin")
        
        return recommendations[:5]  # Limit to 5 recommendations
    
    def _estimate_content_regions(self, image: Image.Image) -> Dict[str, Any]:
        """Basit content region tahmini"""
        width, height = image.size
        
        return {
            'header_region': {'x': 0, 'y': 0, 'width': width, 'height': height // 8},
            'content_region': {'x': 0, 'y': height // 8, 'width': width, 'height': height * 3 // 4},
            'footer_region': {'x': 0, 'y': height * 7 // 8, 'width': width, 'height': height // 8}
        }
    
    def _calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """İki domain arasındaki benzerlik skorunu hesapla"""
        # Simple Levenshtein distance based similarity
        if len(domain1) == 0 or len(domain2) == 0:
            return 0.0
        
        # Remove common prefixes/suffixes
        domain1 = domain1.replace('www.', '').split('.')[0]
        domain2 = domain2.replace('www.', '').split('.')[0]
        
        # Calculate edit distance
        len1, len2 = len(domain1), len(domain2)
        if len1 > len2:
            domain1, domain2 = domain2, domain1
            len1, len2 = len2, len1
        
        current_row = list(range(len1 + 1))
        for i in range(1, len2 + 1):
            previous_row, current_row = current_row, [i] + [0] * len1
            for j in range(1, len1 + 1):
                add, delete, change = previous_row[j] + 1, current_row[j - 1] + 1, previous_row[j - 1]
                if domain1[j - 1] != domain2[i - 1]:
                    change += 1
                current_row[j] = min(add, delete, change)
        
        edit_distance = current_row[len1]
        max_len = max(len(domain1), len(domain2))
        
        return 1.0 - (edit_distance / max_len) if max_len > 0 else 0.0
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Visual detector özet bilgileri"""
        return {
            'detector_name': 'Visual Phishing Detector',
            'version': '1.0.0',
            'capabilities': [
                'Screenshot capture',
                'Brand impersonation detection',
                'UI manipulation detection',
                'Social engineering detection',
                'DOM structure analysis',
                'Visual risk assessment'
            ],
            'supported_browsers': ['Chrome'] if SELENIUM_AVAILABLE else [],
            'brand_profiles_count': len(self.brand_profiles),
            'selenium_available': SELENIUM_AVAILABLE
        }

# Global instance
visual_phishing_detector = VisualPhishingDetector() 