"""
WHITELIST/BLACKLIST MANAGER
Bilinen güvenli ve tehlikeli sitelerin yönetimi
"""

import json
import requests
import tldextract
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
import logging
from urllib.parse import urlparse
import re

logger = logging.getLogger(__name__)

class WhitelistBlacklistManager:
    def __init__(self):
        self.whitelist_domains = set()
        self.blacklist_domains = set()
        self.whitelist_patterns = []
        self.blacklist_patterns = []
        
        # Dosya adları
        self.whitelist_file = "whitelist_domains.json"
        self.blacklist_file = "blacklist_domains.json"
        self.patterns_file = "domain_patterns.json"
        
        # Cache için
        self.cache = {}
        self.cache_ttl = timedelta(hours=1)
        self.last_cache_update = datetime.now()
        
        # Load existing lists
        self._load_lists()
        self._initialize_default_lists()
    
    def _load_lists(self):
        """Kayıtlı listeleri yükle"""
        try:
            # Whitelist yükle
            try:
                with open(self.whitelist_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.whitelist_domains = set(data.get('domains', []))
                    logger.info(f"✅ Loaded {len(self.whitelist_domains)} whitelist domains")
            except FileNotFoundError:
                logger.info("📁 No whitelist file found, starting fresh")
            
            # Blacklist yükle
            try:
                with open(self.blacklist_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.blacklist_domains = set(data.get('domains', []))
                    logger.info(f"✅ Loaded {len(self.blacklist_domains)} blacklist domains")
            except FileNotFoundError:
                logger.info("📁 No blacklist file found, starting fresh")
            
            # Patterns yükle
            try:
                with open(self.patterns_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.whitelist_patterns = data.get('whitelist_patterns', [])
                    self.blacklist_patterns = data.get('blacklist_patterns', [])
                    logger.info(f"✅ Loaded {len(self.whitelist_patterns)} whitelist patterns, {len(self.blacklist_patterns)} blacklist patterns")
            except FileNotFoundError:
                logger.info("📁 No patterns file found, starting fresh")
                
        except Exception as e:
            logger.error(f"❌ Load lists error: {e}")
    
    def _initialize_default_lists(self):
        """Varsayılan güvenli ve tehlikeli domain'leri ekle"""
        try:
            # Varsayılan güvenli domain'ler
            default_safe_domains = {
                # Major Tech Companies
                'google.com', 'youtube.com', 'gmail.com', 'google.co.uk', 'google.de',
                'microsoft.com', 'outlook.com', 'office.com', 'xbox.com', 'skype.com',
                'apple.com', 'icloud.com', 'itunes.com', 'app-store.com',
                'amazon.com', 'amazon.co.uk', 'amazon.de', 'aws.amazon.com',
                'facebook.com', 'instagram.com', 'whatsapp.com', 'messenger.com',
                'twitter.com', 'x.com', 'linkedin.com', 'tiktok.com',
                
                # Banking (Major Turkish Banks)
                'akbank.com', 'garanti.com.tr', 'isbank.com.tr', 'ykb.com',
                'ziraatbank.com.tr', 'halkbank.com.tr', 'vakifbank.com.tr',
                'denizbank.com', 'ingbank.com.tr', 'hsbc.com.tr',
                
                # International Banks
                'chase.com', 'bankofamerica.com', 'wells.com', 'citi.com',
                'hsbc.com', 'barclays.com', 'santander.com',
                
                # Government
                'gov.tr', 'meb.gov.tr', 'saglik.gov.tr', 'icisleri.gov.tr',
                'gov.uk', 'gov.us', 'europa.eu',
                
                # Education
                'edu.tr', 'metu.edu.tr', 'boun.edu.tr', 'itu.edu.tr',
                'mit.edu', 'harvard.edu', 'stanford.edu', 'berkeley.edu',
                
                # Major E-commerce
                'ebay.com', 'alibaba.com', 'etsy.com', 'shopify.com',
                'hepsiburada.com', 'trendyol.com', 'gittigidiyor.com',
                
                # Major News
                'bbc.com', 'cnn.com', 'reuters.com', 'ap.org',
                'hurriyet.com.tr', 'milliyet.com.tr', 'sabah.com.tr',
                
                # CDN & Infrastructure
                'cloudflare.com', 'amazonaws.com', 'googleusercontent.com',
                'akamai.com', 'fastly.com', 'jsdelivr.net', 'unpkg.com'
            }
            
            # Mevcut whitelist'e ekle (duplicate'ları önle)
            for domain in default_safe_domains:
                if domain not in self.whitelist_domains:
                    self.whitelist_domains.add(domain)
            
            # Varsayılan şüpheli pattern'ler
            default_suspicious_patterns = [
                r'.*-[a-z0-9]{8,}\.com$',  # Random string appends
                r'.*[0-9]{4,}\.com$',      # Lots of numbers
                r'.*secure.*bank.*\.com$', # Fake banking
                r'.*paypal.*\.tk$',        # Paypal + suspicious TLD
                r'.*amazon.*\.ml$',        # Amazon + suspicious TLD
                r'.*[0-9]+[a-z]+[0-9]+.*\.com$',  # Number-letter-number pattern
            ]
            
            self.blacklist_patterns.extend([p for p in default_suspicious_patterns if p not in self.blacklist_patterns])
            
            logger.info(f"✅ Initialized with {len(self.whitelist_domains)} safe domains")
            
        except Exception as e:
            logger.error(f"❌ Initialize default lists error: {e}")
    
    def check_url(self, url: str) -> Optional[Dict]:
        """
        URL'yi whitelist/blacklist'te kontrol et
        
        Returns:
            None: Liste'de yok, ML analizi gerekli
            Dict: Liste'de var, sonuç döndür
        """
        try:
            # Cache kontrol et
            domain = self._extract_domain(url)
            cache_key = domain.lower()
            
            if cache_key in self.cache:
                cache_entry = self.cache[cache_key]
                if datetime.now() - cache_entry['timestamp'] < self.cache_ttl:
                    return cache_entry['result']
            
            # Whitelist kontrol
            whitelist_result = self._check_whitelist(domain, url)
            if whitelist_result:
                self._cache_result(cache_key, whitelist_result)
                return whitelist_result
            
            # Blacklist kontrol
            blacklist_result = self._check_blacklist(domain, url)
            if blacklist_result:
                self._cache_result(cache_key, blacklist_result)
                return blacklist_result
            
            # Liste'de yok
            return None
            
        except Exception as e:
            logger.error(f"❌ Check URL error: {e}")
            return None
    
    def _extract_domain(self, url: str) -> str:
        """URL'den domain çıkar"""
        try:
            # Basic parsing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            if not hostname:
                return ""
            
            # TLD extraction ile daha iyi parsing
            extracted = tldextract.extract(hostname)
            
            # Alt domain varsa tam domain, yoksa sadece domain+suffix
            if extracted.subdomain:
                return f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}"
            else:
                return f"{extracted.domain}.{extracted.suffix}"
                
        except Exception as e:
            logger.error(f"❌ Extract domain error: {e}")
            return ""
    
    def _check_whitelist(self, domain: str, url: str) -> Optional[Dict]:
        """Whitelist kontrolü"""
        try:
            domain_lower = domain.lower()
            
            # Exact domain match
            if domain_lower in self.whitelist_domains:
                return {
                    "prediction": "safe",
                    "confidence": 1.0,
                    "source": "whitelist_exact",
                    "reason": f"Domain {domain} is in whitelist",
                    "bypass_ml": True
                }
            
            # Parent domain match (subdomain kontrolü)
            extracted = tldextract.extract(domain)
            parent_domain = f"{extracted.domain}.{extracted.suffix}"
            
            if parent_domain.lower() in self.whitelist_domains:
                return {
                    "prediction": "safe",
                    "confidence": 0.95,
                    "source": "whitelist_parent",
                    "reason": f"Parent domain {parent_domain} is in whitelist",
                    "bypass_ml": True
                }
            
            # Pattern match
            for pattern in self.whitelist_patterns:
                if re.match(pattern, domain_lower):
                    return {
                        "prediction": "safe",
                        "confidence": 0.9,
                        "source": "whitelist_pattern",
                        "reason": f"Domain matches whitelist pattern",
                        "bypass_ml": True
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Check whitelist error: {e}")
            return None
    
    def _check_blacklist(self, domain: str, url: str) -> Optional[Dict]:
        """Blacklist kontrolü"""
        try:
            domain_lower = domain.lower()
            
            # Exact domain match
            if domain_lower in self.blacklist_domains:
                return {
                    "prediction": "phishing",
                    "confidence": 1.0,
                    "source": "blacklist_exact",
                    "reason": f"Domain {domain} is in blacklist",
                    "bypass_ml": True
                }
            
            # Pattern match
            for pattern in self.blacklist_patterns:
                if re.match(pattern, domain_lower):
                    return {
                        "prediction": "phishing",
                        "confidence": 0.95,
                        "source": "blacklist_pattern",
                        "reason": f"Domain matches suspicious pattern",
                        "bypass_ml": True
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Check blacklist error: {e}")
            return None
    
    def _cache_result(self, cache_key: str, result: Dict):
        """Sonucu cache'le"""
        self.cache[cache_key] = {
            'result': result,
            'timestamp': datetime.now()
        }
        
        # Cache temizliği
        if len(self.cache) > 10000:  # Max 10k entries
            self._cleanup_cache()
    
    def _cleanup_cache(self):
        """Eski cache entry'leri temizle"""
        try:
            current_time = datetime.now()
            expired_keys = []
            
            for key, entry in self.cache.items():
                if current_time - entry['timestamp'] > self.cache_ttl:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.cache[key]
                
            logger.info(f"🧹 Cache cleanup: removed {len(expired_keys)} expired entries")
            
        except Exception as e:
            logger.error(f"❌ Cache cleanup error: {e}")
    
    def add_to_whitelist(self, domain: str, source: str = "manual"):
        """Domain'i whitelist'e ekle"""
        try:
            domain_clean = self._extract_domain(domain)
            if domain_clean:
                self.whitelist_domains.add(domain_clean.lower())
                self._save_lists()
                logger.info(f"✅ Added to whitelist: {domain_clean} (source: {source})")
                
        except Exception as e:
            logger.error(f"❌ Add to whitelist error: {e}")
    
    def add_to_blacklist(self, domain: str, source: str = "manual"):
        """Domain'i blacklist'e ekle"""
        try:
            domain_clean = self._extract_domain(domain)
            if domain_clean:
                self.blacklist_domains.add(domain_clean.lower())
                self._save_lists()
                logger.info(f"🚨 Added to blacklist: {domain_clean} (source: {source})")
                
        except Exception as e:
            logger.error(f"❌ Add to blacklist error: {e}")
    
    def remove_from_whitelist(self, domain: str):
        """Domain'i whitelist'ten çıkar"""
        try:
            domain_clean = self._extract_domain(domain).lower()
            if domain_clean in self.whitelist_domains:
                self.whitelist_domains.remove(domain_clean)
                self._save_lists()
                logger.info(f"🗑️ Removed from whitelist: {domain_clean}")
                
        except Exception as e:
            logger.error(f"❌ Remove from whitelist error: {e}")
    
    def remove_from_blacklist(self, domain: str):
        """Domain'i blacklist'ten çıkar"""
        try:
            domain_clean = self._extract_domain(domain).lower()
            if domain_clean in self.blacklist_domains:
                self.blacklist_domains.remove(domain_clean)
                self._save_lists()
                logger.info(f"🗑️ Removed from blacklist: {domain_clean}")
                
        except Exception as e:
            logger.error(f"❌ Remove from blacklist error: {e}")
    
    def bulk_update_from_threat_feeds(self):
        """Threat feed'lerden bulk güncelleme (gelecek implementasyon)"""
        # TODO: PhishTank, OpenPhish gibi feed'lerden otomatik güncelleme
        pass
    
    def get_statistics(self) -> Dict:
        """İstatistikleri döndür"""
        return {
            'whitelist_domains': len(self.whitelist_domains),
            'blacklist_domains': len(self.blacklist_domains),
            'whitelist_patterns': len(self.whitelist_patterns),
            'blacklist_patterns': len(self.blacklist_patterns),
            'cache_entries': len(self.cache),
            'last_update': datetime.now().isoformat()
        }
    
    def _save_lists(self):
        """Listeleri dosyaya kaydet"""
        try:
            # Whitelist kaydet
            whitelist_data = {
                'domains': list(self.whitelist_domains),
                'last_updated': datetime.now().isoformat(),
                'total_count': len(self.whitelist_domains)
            }
            
            with open(self.whitelist_file, 'w', encoding='utf-8') as f:
                json.dump(whitelist_data, f, indent=2, ensure_ascii=False)
            
            # Blacklist kaydet
            blacklist_data = {
                'domains': list(self.blacklist_domains),
                'last_updated': datetime.now().isoformat(),
                'total_count': len(self.blacklist_domains)
            }
            
            with open(self.blacklist_file, 'w', encoding='utf-8') as f:
                json.dump(blacklist_data, f, indent=2, ensure_ascii=False)
            
            # Patterns kaydet
            patterns_data = {
                'whitelist_patterns': self.whitelist_patterns,
                'blacklist_patterns': self.blacklist_patterns,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.patterns_file, 'w', encoding='utf-8') as f:
                json.dump(patterns_data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.error(f"❌ Save lists error: {e}")

    def bulk_update_from_threat_feeds(self):
        """Threat intelligence feedlerinden toplu güncelleme"""
        try:
            logger.info("🔄 Updating from threat intelligence feeds...")
            
            # Known malicious domains from threat feeds  
            threat_feeds = [
                {
                    'url': 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
                    'type': 'phishing'
                }
            ]
            
            new_domains = set()
            
            for feed in threat_feeds:
                try:
                    response = requests.get(feed['url'], timeout=10)
                    if response.status_code == 200:
                        domains = response.text.strip().split('\n')
                        for domain in domains:
                            domain = domain.strip().lower()
                            if domain and not domain.startswith('#') and '.' in domain:
                                # Basic domain validation
                                if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
                                    new_domains.add(domain)
                    
                    logger.info(f"✅ Retrieved domains from {feed['type']} feed")
                    
                except Exception as e:
                    logger.error(f"❌ Failed to fetch from {feed['url']}: {e}")
                    continue
            
            # Add to blacklist
            initial_size = len(self.blacklist_domains)
            self.blacklist_domains.update(new_domains)
            added_count = len(self.blacklist_domains) - initial_size
            
            if added_count > 0:
                self._save_lists()
                logger.info(f"📝 Added {added_count} new domains to blacklist")
            else:
                logger.info("ℹ️ No new domains to add from threat feeds")
                
        except Exception as e:
            logger.error(f"❌ Bulk update from threat feeds error: {e}")
    
    def analyze_url_reputation(self, url: str) -> Dict[str, Any]:
        """URL reputation analizi"""
        try:
            domain = self._extract_domain(url)
            
            reputation_result = {
                'domain': domain,
                'reputation_score': 0.5,  # Neutral
                'reputation_sources': [],
                'risk_indicators': [],
                'trust_indicators': [],
                'analysis_details': {},
                'recommendation': 'unknown'
            }
            
            # 1. Whitelist/Blacklist check
            list_check = self.check_url(url)
            if list_check:
                if list_check['prediction'] == 'safe':
                    reputation_result['reputation_score'] = 0.9
                    reputation_result['trust_indicators'].append(f"Listed in {list_check['source']}")
                    reputation_result['recommendation'] = 'trusted'
                elif list_check['prediction'] == 'phishing':
                    reputation_result['reputation_score'] = 0.1
                    reputation_result['risk_indicators'].append(f"Listed in {list_check['source']}")
                    reputation_result['recommendation'] = 'block'
                
                reputation_result['reputation_sources'].append(list_check['source'])
                return reputation_result
            
            # 2. Domain characteristics
            domain_analysis = self._analyze_domain_characteristics(domain)
            reputation_result['analysis_details']['domain_characteristics'] = domain_analysis
            
            # Adjust score based on domain characteristics
            if domain_analysis['is_suspicious']:
                reputation_result['reputation_score'] -= 0.3
                reputation_result['risk_indicators'].extend(domain_analysis['risk_factors'])
            
            if domain_analysis['is_trustworthy']:
                reputation_result['reputation_score'] += 0.3
                reputation_result['trust_indicators'].extend(domain_analysis['trust_factors'])
            
            # 3. Pattern-based analysis
            pattern_analysis = self._analyze_domain_patterns(domain)
            reputation_result['analysis_details']['pattern_analysis'] = pattern_analysis
            
            if pattern_analysis['suspicious_patterns']:
                reputation_result['reputation_score'] -= 0.2
                reputation_result['risk_indicators'].extend(pattern_analysis['suspicious_patterns'])
            
            # 4. Generate final recommendation
            score = reputation_result['reputation_score']
            if score >= 0.8:
                reputation_result['recommendation'] = 'trusted'
            elif score >= 0.6:
                reputation_result['recommendation'] = 'likely_safe'
            elif score >= 0.4:
                reputation_result['recommendation'] = 'neutral'
            elif score >= 0.2:
                reputation_result['recommendation'] = 'suspicious'
            else:
                reputation_result['recommendation'] = 'block'
            
            # Normalize score
            reputation_result['reputation_score'] = max(0.0, min(1.0, reputation_result['reputation_score']))
            
            return reputation_result
            
        except Exception as e:
            logger.error(f"❌ Analyze URL reputation error: {e}")
            return {
                'domain': domain,
                'reputation_score': 0.5,
                'error': str(e),
                'recommendation': 'unknown'
            }
    
    def _analyze_domain_characteristics(self, domain: str) -> Dict:
        """Domain karakteristik analizi"""
        try:
            analysis = {
                'is_suspicious': False,
                'is_trustworthy': False,
                'risk_factors': [],
                'trust_factors': [],
                'domain_length': len(domain),
                'subdomain_count': 0,
                'has_numbers': bool(re.search(r'\d', domain)),
                'has_hyphens': '-' in domain
            }
            
            extracted = tldextract.extract(domain)
            
            # Subdomain analysis
            if extracted.subdomain:
                subdomains = extracted.subdomain.split('.')
                analysis['subdomain_count'] = len(subdomains)
                
                if len(subdomains) > 2:
                    analysis['is_suspicious'] = True
                    analysis['risk_factors'].append(f"Multiple subdomains: {len(subdomains)}")
            
            # Domain length analysis
            if len(extracted.domain) > 20:
                analysis['is_suspicious'] = True
                analysis['risk_factors'].append("Very long domain name")
            elif len(extracted.domain) < 4:
                # EXCEPTION: Gov.tr domains are always trustworthy regardless of length
                if not extracted.suffix.endswith('gov.tr'):
                    analysis['is_suspicious'] = True
                    analysis['risk_factors'].append("Very short domain name")
            
            # TRUSTED HOSTING PLATFORMS - Special handling
            trusted_hosting_platforms = {
                'netlify.app': 'Netlify hosting platform',
                'github.io': 'GitHub Pages',
                'vercel.app': 'Vercel hosting',
                'herokuapp.com': 'Heroku platform',
                'firebase.app': 'Firebase hosting',
                'surge.sh': 'Surge hosting',
                'pages.dev': 'Cloudflare Pages'
            }
            
            # Check if it's a trusted hosting platform
            for platform, description in trusted_hosting_platforms.items():
                if domain.endswith(platform):
                    analysis['is_trustworthy'] = True
                    analysis['trust_factors'].append(f"Trusted hosting platform: {description}")
                    break
            
            # TLD analysis
            trusted_tlds = {'.com', '.org', '.net', '.edu', '.gov', '.com.tr', '.org.tr', '.net.tr', '.edu.tr', '.gov.tr'}
            suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download'}
            
            tld = f".{extracted.suffix}"
            if tld in trusted_tlds:
                analysis['trust_factors'].append(f"Trusted TLD: {tld}")
                # SPECIAL: Gov.tr domains are highly trustworthy
                if tld == '.gov.tr':
                    analysis['is_trustworthy'] = True
                    analysis['trust_factors'].append("Government domain - highly trusted")
            elif tld in suspicious_tlds:
                analysis['is_suspicious'] = True
                analysis['risk_factors'].append(f"Suspicious TLD: {tld}")
            
            return analysis
            
        except Exception as e:
            logger.error(f"❌ Analyze domain characteristics error: {e}")
            return {'is_suspicious': False, 'is_trustworthy': False, 'risk_factors': [], 'trust_factors': []}
    
    def _analyze_domain_patterns(self, domain: str) -> Dict:
        """Domain pattern analizi"""
        try:
            analysis = {
                'suspicious_patterns': [],
                'legitimate_patterns': [],
                'pattern_score': 0.0
            }
            
            # Suspicious patterns
            suspicious_patterns = [
                (r'[a-z0-9]{20,}', "Very long random string"),
                (r'[0-9]+[a-z]+[0-9]+', "Number-letter-number pattern"),
                (r'(secure|login|auth|verify|account|update)', "Suspicious keywords"),
                (r'(paypal|amazon|microsoft|google|apple).*[0-9]', "Brand impersonation with numbers"),
                (r'[a-z]+-[a-z]+-[a-z]+', "Multiple hyphen pattern")
            ]
            
            for pattern, description in suspicious_patterns:
                if re.search(pattern, domain, re.IGNORECASE):
                    analysis['suspicious_patterns'].append(description)
                    analysis['pattern_score'] -= 0.2
            
            return analysis
            
        except Exception as e:
            logger.error(f"❌ Analyze domain patterns error: {e}")
            return {'suspicious_patterns': [], 'legitimate_patterns': [], 'pattern_score': 0.0}


# Global instance
whitelist_blacklist_manager = WhitelistBlacklistManager()

