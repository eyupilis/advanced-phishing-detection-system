import re
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict
import logging

logger = logging.getLogger(__name__)

class FeatureExtractor:
    """URL'den özellik çıkarma sınıfı"""
    
    def extract_features(self, url: str) -> Dict[str, float]:
        """URL'den tüm özellikleri çıkar"""
        try:
            parsed = urlparse(url)
            features = {}
            
            # Temel URL özellikleri
            features['url_length'] = len(url)
            features['domain_length'] = len(parsed.netloc)
            features['hostname_length'] = len(parsed.hostname) if parsed.hostname else 0
            features['path_length'] = len(parsed.path)
            features['query_length'] = len(parsed.query) if parsed.query else 0
            
            # Subdomain analizi
            if parsed.hostname:
                domain_parts = parsed.hostname.split('.')
                features['subdomain_level'] = len(domain_parts) - 2 if len(domain_parts) > 2 else 0
            else:
                features['subdomain_level'] = 0
            
            # Path analizi
            features['path_level'] = len([p for p in parsed.path.split('/') if p])
            
            # Karakter sayıları
            features['num_dots'] = url.count('.')
            features['num_hyphens'] = url.count('-')
            features['num_underscores'] = url.count('_')
            features['num_slashes'] = url.count('/')
            features['num_at_symbols'] = url.count('@')
            features['num_question_marks'] = url.count('?')
            features['num_ampersands'] = url.count('&')
            features['num_equals'] = url.count('=')
            features['num_percent'] = url.count('%')
            features['num_hash'] = url.count('#')
            features['num_digits'] = sum(c.isdigit() for c in url)
            
            # Özel karakterler
            special_chars = '!@#$%^&*()_+-=[]{}|;:,.<>?'
            features['num_special_chars'] = sum(c in special_chars for c in url)
            
            # Oranlar
            if len(url) > 0:
                features['digit_ratio'] = features['num_digits'] / len(url)
                features['special_char_ratio'] = features['num_special_chars'] / len(url)
            else:
                features['digit_ratio'] = 0
                features['special_char_ratio'] = 0
            
            # Karakter devam oranı
            features['char_continuation_rate'] = self._calculate_char_continuation(url)
            
            # IP adresi kontrolü
            features['is_ip_address'] = self._is_ip_address(parsed.hostname) if parsed.hostname else 0
            
            # Punycode kontrolü
            features['has_punycode'] = 1 if 'xn--' in url else 0
            
            # TLD analizi
            tld_info = self._analyze_tld(parsed.hostname) if parsed.hostname else {}
            features.update(tld_info)
            
            # Domain analizi
            domain_info = self._analyze_domain(parsed.hostname) if parsed.hostname else {}
            features.update(domain_info)
            
            # HTTPS kontrolü
            features['is_https'] = 1 if parsed.scheme == 'https' else 0
            features['https_token_in_domain'] = 1 if 'https' in parsed.netloc else 0
            
            # Port kontrolü
            features['has_port'] = 1 if parsed.port else 0
            
            # URL kısaltma servisi kontrolü
            features['uses_shortening'] = self._check_url_shortening(parsed.hostname) if parsed.hostname else 0
            
            # Diğer özellikleri varsayılan değerlerle doldur
            self._fill_default_features(features)
            
            return features
            
        except Exception as e:
            logger.error(f"Feature extraction error: {e}")
            return self._get_default_features()
    
    def _calculate_char_continuation(self, url: str) -> float:
        """Karakterlerin devam etme oranını hesapla"""
        if len(url) < 2:
            return 0.0
        
        consecutive_count = 0
        for i in range(len(url) - 1):
            if url[i] == url[i + 1]:
                consecutive_count += 1
        
        return consecutive_count / (len(url) - 1) if len(url) > 1 else 0
    
    def _is_ip_address(self, hostname: str) -> int:
        """IP adresi olup olmadığını kontrol et"""
        if not hostname:
            return 0
        
        import socket
        try:
            socket.inet_aton(hostname)
            return 1
        except socket.error:
            return 0
    
    def _analyze_tld(self, hostname: str) -> Dict[str, float]:
        """TLD analizi"""
        if not hostname:
            return {'has_tld': 0, 'tld_length': 0, 'is_suspicious_tld': 0}
        
        parts = hostname.split('.')
        if len(parts) < 2:
            return {'has_tld': 0, 'tld_length': 0, 'is_suspicious_tld': 0}
        
        tld = parts[-1].lower()
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'top', 'click', 'download']
        
        return {
            'has_tld': 1,
            'tld_length': len(tld),
            'is_suspicious_tld': 1 if tld in suspicious_tlds else 0
        }
    
    def _analyze_domain(self, hostname: str) -> Dict[str, float]:
        """Domain analizi"""
        if not hostname:
            return {
                'domain_has_numbers': 0,
                'domain_has_hyphens': 0,
                'is_homograph': 0,
                'domain_entropy': 0
            }
        
        return {
            'domain_has_numbers': 1 if any(c.isdigit() for c in hostname) else 0,
            'domain_has_hyphens': 1 if '-' in hostname else 0,
            'is_homograph': self._check_homograph(hostname),
            'domain_entropy': self._calculate_entropy(hostname)
        }
    
    def _check_homograph(self, hostname: str) -> int:
        """Homograph saldırısı kontrolü"""
        suspicious_chars = ['а', 'о', 'р', 'е', 'х', 'с', 'у', 'k', 'ρ', 'α', 'ο']
        return 1 if any(char in hostname for char in suspicious_chars) else 0
    
    def _calculate_entropy(self, text: str) -> float:
        """Shannon entropisi hesapla"""
        if not text:
            return 0
        
        import math
        from collections import Counter
        
        counter = Counter(text)
        length = len(text)
        entropy = 0
        
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _check_url_shortening(self, hostname: str) -> int:
        """URL kısaltma servisi kontrolü"""
        if not hostname:
            return 0
        
        shortening_services = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'short.link', 'tiny.cc', 'is.gd', 'buff.ly'
        ]
        
        return 1 if hostname in shortening_services else 0
    
    def _fill_default_features(self, features: Dict[str, float]):
        """Eksik özellikleri varsayılan değerlerle doldur"""
        default_features = self._get_default_features()
        
        for key, value in default_features.items():
            if key not in features:
                features[key] = value
    
    def _get_default_features(self) -> Dict[str, float]:
        """Varsayılan feature seti"""
        return {
            'url_length': 0,
            'domain_length': 0,
            'hostname_length': 0,
            'path_length': 0,
            'query_length': 0,
            'subdomain_level': 0,
            'path_level': 0,
            'num_dots': 0,
            'num_hyphens': 0,
            'num_underscores': 0,
            'num_slashes': 0,
            'num_at_symbols': 0,
            'num_question_marks': 0,
            'num_ampersands': 0,
            'num_equals': 0,
            'num_percent': 0,
            'num_hash': 0,
            'num_digits': 0,
            'num_special_chars': 0,
            'digit_ratio': 0,
            'special_char_ratio': 0,
            'char_continuation_rate': 0,
            'is_ip_address': 0,
            'has_punycode': 0,
            'has_tld': 0,
            'tld_length': 0,
            'is_suspicious_tld': 0,
            'domain_has_numbers': 0,
            'domain_has_hyphens': 0,
            'is_homograph': 0,
            'domain_entropy': 0,
            'is_https': 0,
            'https_token_in_domain': 0,
            'has_port': 0,
            'uses_shortening': 0
        }

class RuleBasedAnalyzer:
    """Kural tabanlı analiz sınıfı"""
    
    def __init__(self):
        # Bilinen kötü amaçlı domain pattern'leri
        self.suspicious_patterns = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP adresi
            r'.*-.*-.*-.*',  # Çok fazla tire
            r'.*\.(tk|ml|ga|cf)$',  # Şüpheli TLD'ler
            r'.*[а-я].*',  # Kiril karakterleri
            r'.*\.exe$',  # Yürütülebilir dosya
            r'.*\.(zip|rar|exe|scr)$'  # Şüpheli dosya uzantıları
        ]
    
    def analyze(self, url: str, features: Dict[str, float]) -> list[str]:
        """Kural tabanlı analiz yap"""
        flags = []
        
        try:
            # URL uzunluğu kontrolü
            if features.get('url_length', 0) > 100:
                flags.append('Very long URL')
            
            # Şüpheli pattern kontrolü
            for pattern in self.suspicious_patterns:
                if re.match(pattern, url, re.IGNORECASE):
                    flags.append(f'Suspicious pattern: {pattern}')
            
            # Domain analizi
            if features.get('subdomain_level', 0) > 3:
                flags.append('Too many subdomains')
            
            if features.get('is_ip_address', 0) == 1:
                flags.append('IP address instead of domain')
            
            if features.get('has_punycode', 0) == 1:
                flags.append('Contains punycode')
            
            # Güvenlik kontrolü
            if features.get('is_https', 0) == 0:
                flags.append('Not using HTTPS')
            
            # Şüpheli karakterler
            if features.get('special_char_ratio', 0) > 0.3:
                flags.append('High special character ratio')
            
            return flags
            
        except Exception as e:
            logger.error(f"Rule-based analysis error: {e}")
            return ['Analysis error'] 