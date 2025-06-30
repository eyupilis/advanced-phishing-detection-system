from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, List, Dict, Any, Set
import joblib
import pandas as pd
import numpy as np
import requests
import socket
import ssl
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs
import time
import logging
from contextlib import asynccontextmanager
import uuid
import asyncio
import aiohttp
import hashlib
import whois
import dns.resolver
import geoip2.database
import yara
import psutil
import json
from collections import defaultdict
import threading
from queue import Queue
import pickle
import sqlite3
import schedule
import base64
import mimetypes
from urllib.robotparser import RobotFileParser
# Advanced imports - only load when needed
try:
    import textstat
    TEXTSTAT_AVAILABLE = True
except ImportError:
    TEXTSTAT_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Import feature extraction classes
from feature_extractor import FeatureExtractor, RuleBasedAnalyzer
import time

# Yeni advanced feature imports
try:
    from advanced_behavioral_analyzer import AdvancedBehavioralAnalyzer
    BEHAVIORAL_ANALYZER_ENABLED = True
    print("✅ Advanced Behavioral Analyzer enabled")
except ImportError as e:
    BEHAVIORAL_ANALYZER_ENABLED = False
    print(f"⚠️ Advanced Behavioral Analyzer disabled: {e}")

try:
    from real_time_threat_monitor import RealTimeThreatMonitor
    THREAT_MONITOR_ENABLED = True
    print("✅ Real-time Threat Monitor enabled")
except ImportError as e:
    THREAT_MONITOR_ENABLED = False
    print(f"⚠️ Real-time Threat Monitor disabled: {e}")

try:
    from content_security_analyzer import ContentSecurityAnalyzer
    CONTENT_ANALYZER_ENABLED = True
    print("✅ Content Security Analyzer enabled")
except ImportError as e:
    CONTENT_ANALYZER_ENABLED = False
    print(f"⚠️ Content Security Analyzer disabled: {e}")

try:
    from network_intelligence_engine import NetworkIntelligenceEngine
    NETWORK_INTEL_ENABLED = True
    print("✅ Network Intelligence Engine enabled")
except ImportError as e:
    NETWORK_INTEL_ENABLED = False
    print(f"⚠️ Network Intelligence Engine disabled: {e}")

try:
    from ml_feedback_optimizer import MLFeedbackOptimizer
    ML_OPTIMIZER_ENABLED = True
    print("✅ ML Feedback Optimizer enabled")
except ImportError as e:
    ML_OPTIMIZER_ENABLED = False
    print(f"⚠️ ML Feedback Optimizer disabled: {e}")

try:
    from visual_phishing_detector import VisualPhishingDetector
    VISUAL_DETECTOR_ENABLED = True
    print("✅ Visual Phishing Detector enabled")
except ImportError as e:
    VISUAL_DETECTOR_ENABLED = False
    print(f"⚠️ Visual Phishing Detector disabled: {e}")

try:
    from threat_intelligence_aggregator import ThreatIntelligenceAggregator
    THREAT_AGGREGATOR_ENABLED = True
    print("✅ Threat Intelligence Aggregator enabled")
except ImportError as e:
    THREAT_AGGREGATOR_ENABLED = False
    print(f"⚠️ Threat Intelligence Aggregator disabled: {e}")

try:
    from advanced_reporting_engine import AdvancedReportingEngine
    REPORTING_ENGINE_ENABLED = True
    print("✅ Advanced Reporting Engine enabled")
except ImportError as e:
    REPORTING_ENGINE_ENABLED = False
    print(f"⚠️ Advanced Reporting Engine disabled: {e}")

# Supabase entegrasyonu
try:
    from supabase_client import supabase_client
    SUPABASE_ENABLED = True
    print("✅ Supabase integration enabled")
except ImportError as e:
    SUPABASE_ENABLED = False
    print(f"⚠️ Supabase integration disabled: {e}")

# False Positive Tracker entegrasyonu
try:
    from false_positive_tracker import false_positive_tracker
    FP_TRACKER_ENABLED = True
    print("✅ False Positive Tracker enabled")
except ImportError as e:
    FP_TRACKER_ENABLED = False
    print(f"⚠️ False Positive Tracker disabled: {e}")

# Enhanced Ensemble Analyzer entegrasyonu
try:
    from enhanced_ensemble_analyzer import enhanced_ensemble_analyzer
    ENHANCED_ANALYZER_ENABLED = True
    print("✅ Enhanced Ensemble Analyzer enabled")
except ImportError as e:
    ENHANCED_ANALYZER_ENABLED = False
    print(f"⚠️ Enhanced Ensemble Analyzer disabled: {e}")

# Real Behavioral Analyzer entegrasyonu
try:
    from real_behavioral_analyzer import real_behavioral_analyzer
    REAL_BEHAVIORAL_ENABLED = True
    print("✅ Real Behavioral Analyzer enabled")
except ImportError as e:
    REAL_BEHAVIORAL_ENABLED = False
    print(f"⚠️ Real Behavioral Analyzer disabled: {e}")

import asyncio

# Logging ayarları
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global değişkenler
model = None
selected_features = None
feature_importance = None

# Yeni global yapılar
threat_monitor = None
behavioral_analyzer = None
content_analyzer = None
network_intel = None
ml_optimizer = None
visual_detector = None
threat_aggregator = None
reporting_engine = None

# Real-time monitoring structures
active_sessions = {}
suspicious_patterns = defaultdict(list)
threat_alerts = Queue()
system_metrics = {
    'cpu_usage': 0,
    'memory_usage': 0,
    'active_connections': 0,
    'threat_level': 'LOW'
}

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global model, selected_features, feature_importance
    global threat_monitor, behavioral_analyzer, content_analyzer, network_intel
    global ml_optimizer, visual_detector, threat_aggregator, reporting_engine
    
    try:
        # Model ve feature'ları yükle
        model = joblib.load('best_phishing_model.pkl')
        selected_features = joblib.load('selected_features.pkl')
        feature_importance = pd.read_csv('feature_importance.csv')
        
        # Yeni advanced feature'ları initialize et
        if THREAT_MONITOR_ENABLED:
            threat_monitor = RealTimeThreatMonitor()
            await threat_monitor.start_monitoring()
            
        if BEHAVIORAL_ANALYZER_ENABLED:
            behavioral_analyzer = AdvancedBehavioralAnalyzer()
            
        if CONTENT_ANALYZER_ENABLED:
            content_analyzer = ContentSecurityAnalyzer()
            
        if NETWORK_INTEL_ENABLED:
            network_intel = NetworkIntelligenceEngine()
            
        if ML_OPTIMIZER_ENABLED:
            ml_optimizer = MLFeedbackOptimizer()
            
        if VISUAL_DETECTOR_ENABLED:
            visual_detector = VisualPhishingDetector()
            
        if THREAT_AGGREGATOR_ENABLED:
            threat_aggregator = ThreatIntelligenceAggregator()
            
        if REPORTING_ENGINE_ENABLED:
            reporting_engine = AdvancedReportingEngine()
        
        # Start background tasks
        asyncio.create_task(background_threat_monitoring())
        asyncio.create_task(system_health_monitoring())
        asyncio.create_task(ml_model_optimization())
        
        logger.info("✅ Gelişmiş phishing detector sistemi başarıyla başlatıldı")
        
    except Exception as e:
        logger.error(f"❌ Başlatma hatası: {e}")
    
    yield
    
    # Shutdown
    logger.info("🔄 Gelişmiş sistem kapatılıyor...")
    
    # Cleanup advanced features
    if threat_monitor:
        await threat_monitor.stop_monitoring()

app = FastAPI(
    title="🔒 Phishing Detector API",
    description="AI tabanlı phishing URL tespit sistemi",
    version="1.0.0",
    lifespan=lifespan
)

# CORS ayarları
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic modelleri
class URLRequest(BaseModel):
    url: str
    user_agent: Optional[str] = None
    source_ip: Optional[str] = None
    referrer: Optional[str] = None
    session_id: Optional[str] = None

class AdvancedURLRequest(BaseModel):
    url: str
    analyze_content: bool = Field(default=True, description="İçerik analizi yap")
    analyze_visual: bool = Field(default=True, description="Görsel analiz yap")
    analyze_network: bool = Field(default=True, description="Ağ analizi yap")
    analyze_behavior: bool = Field(default=True, description="Davranış analizi yap")
    deep_scan: bool = Field(default=False, description="Derin tarama yap")
    capture_screenshot: bool = Field(default=False, description="Ekran görüntüsü al")
    user_agent: Optional[str] = None
    source_ip: Optional[str] = None
    referrer: Optional[str] = None
    session_id: Optional[str] = None

class PredictionResponse(BaseModel):
    url: str
    prediction: str  # "safe" veya "phishing"
    confidence: float
    risk_score: float
    analysis: Dict[str, Any]
    features: Dict[str, float]
    rule_based_flags: List[str]
    timestamp: str

class AdvancedPredictionResponse(BaseModel):
    url: str
    prediction: str
    confidence: float
    risk_score: float
    threat_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    analysis: Dict[str, Any]
    features: Dict[str, float]
    rule_based_flags: List[str]
    behavioral_analysis: Optional[Dict[str, Any]] = None
    content_analysis: Optional[Dict[str, Any]] = None
    visual_analysis: Optional[Dict[str, Any]] = None
    network_analysis: Optional[Dict[str, Any]] = None
    threat_intelligence: Optional[Dict[str, Any]] = None
    recommendations: List[str]
    timestamp: str
    analysis_duration_ms: float
    session_id: Optional[str] = None

class FeedbackRequest(BaseModel):
    url: str
    feedback: str  # "correct" or "incorrect"
    prediction: str
    confidence: float
    timestamp: str
    user_comment: Optional[str] = None
    false_positive_type: Optional[str] = None

class ThreatAlert(BaseModel):
    alert_id: str
    threat_type: str
    severity: str
    url: str
    description: str
    timestamp: str
    indicators: Dict[str, Any]
    recommended_actions: List[str]

class SystemStatus(BaseModel):
    status: str
    version: str
    uptime: str
    total_analyses: int
    threat_level: str
    active_threats: int
    system_health: Dict[str, Any]
    component_status: Dict[str, str]
    performance_metrics: Dict[str, float]

class BulkAnalysisRequest(BaseModel):
    urls: List[str] = Field(..., max_items=100)
    analysis_type: str = Field(default="standard", pattern="^(standard|advanced|deep)$")
    priority: str = Field(default="normal", pattern="^(low|normal|high|urgent)$")
    notify_on_completion: bool = Field(default=False)
    callback_url: Optional[str] = None

class ThreatHuntingRequest(BaseModel):
    indicators: List[str]
    hunt_type: str = Field(..., pattern="^(domain|ip|url|hash|pattern)$")
    time_range: str = Field(default="24h", pattern="^(1h|6h|24h|7d|30d)$")
    confidence_threshold: float = Field(default=0.7, ge=0.0, le=1.0)

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
        """Aynı karakterlerin devam etme oranını hesapla"""
        if len(url) <= 1:
            return 0
        
        continuation_count = 0
        for i in range(1, len(url)):
            if url[i] == url[i-1]:
                continuation_count += 1
        
        return continuation_count / len(url)
    
    def _is_ip_address(self, hostname: str) -> int:
        """IP adresi olup olmadığını kontrol et"""
        if not hostname:
            return 0
        
        try:
            socket.inet_aton(hostname)
            return 1
        except:
            return 0
    
    def _analyze_tld(self, hostname: str) -> Dict[str, float]:
        """TLD analizini yap"""
        if not hostname:
            return {'tld_legitimacy_prob': 0, 'known_tld': 0, 'tld_in_subdomain': 0, 'tld_in_path': 0}
        
        common_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.mil', '.int']
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        
        tld = '.' + hostname.split('.')[-1] if '.' in hostname else ''
        
        return {
            'tld_legitimacy_prob': 0.9 if tld in common_tlds else 0.3 if tld in suspicious_tlds else 0.5,
            'known_tld': 1 if tld in common_tlds else 0,
            'tld_in_subdomain': 1 if any(tld_name in hostname for tld_name in common_tlds) else 0,
            'tld_in_path': 0
        }
    
    def _analyze_domain(self, hostname: str) -> Dict[str, float]:
        """Domain analizini yap"""
        if not hostname:
            return {'prefix_suffix_domain': 0, 'random_domain': 0, 'domain_in_brand_list': 0, 
                   'brand_in_subdomain': 0, 'brand_in_path': 0, 'target_brand_count': 0, 
                   'similarity_to_brands': 0}
        
        # Prefix-suffix kontrolü
        prefix_suffix = 1 if '-' in hostname else 0
        
        # Rastgele domain kontrolü
        vowels = 'aeiou'
        domain_base = hostname.split('.')[0]
        
        vowel_ratio = sum(c in vowels for c in domain_base.lower()) / len(domain_base) if domain_base else 0
        random_score = 1 if vowel_ratio < 0.2 or vowel_ratio > 0.6 else 0
        
        # Brand kontrolü
        brands = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'ebay']
        brand_count = sum(brand in hostname.lower() for brand in brands)
        
        return {
            'prefix_suffix_domain': prefix_suffix,
            'random_domain': random_score,
            'domain_in_brand_list': 1 if any(brand in hostname.lower() for brand in brands) else 0,
            'brand_in_subdomain': 1 if brand_count > 0 else 0,
            'brand_in_path': 0,
            'target_brand_count': brand_count,
            'similarity_to_brands': min(brand_count / len(brands), 1.0)
        }
    
    def _check_url_shortening(self, hostname: str) -> int:
        """URL kısaltma servisi kontrolü"""
        if not hostname:
            return 0
        
        shortening_services = [
            'bit.ly', 'tinyurl.com', 'short.link', 't.co', 'goo.gl',
            'ow.ly', 'buff.ly', 'tiny.cc', 'is.gd', 'v.gd'
        ]
        
        return 1 if any(service in hostname for service in shortening_services) else 0
    
    def _fill_default_features(self, features: Dict[str, float]):
        """Eksik özellikleri varsayılan değerlerle doldur"""
        default_features = self._get_default_features()
        
        for key, value in default_features.items():
            if key not in features:
                features[key] = value
    
    def _get_default_features(self) -> Dict[str, float]:
        """Varsayılan feature değerlerini döndür"""
        return {
            'url_length': 0, 'domain_length': 0, 'subdomain_level': 0, 'path_level': 0,
            'hostname_length': 0, 'path_length': 0, 'query_length': 0, 'num_dots': 0,
            'num_hyphens': 0, 'num_underscores': 0, 'num_slashes': 0, 'num_at_symbols': 0,
            'num_question_marks': 0, 'num_ampersands': 0, 'num_equals': 0, 'num_percent': 0,
            'num_hash': 0, 'num_digits': 0, 'num_special_chars': 0, 'digit_ratio': 0,
            'special_char_ratio': 0, 'char_continuation_rate': 0, 'is_ip_address': 0,
            'has_punycode': 0, 'tld_legitimacy_prob': 0.5, 'known_tld': 0, 'tld_in_subdomain': 0,
            'tld_in_path': 0, 'prefix_suffix_domain': 0, 'random_domain': 0, 'domain_in_brand_list': 0,
            'brand_in_subdomain': 0, 'brand_in_path': 0, 'target_brand_count': 0,
            'similarity_to_brands': 0, 'is_https': 0, 'https_token_in_domain': 0, 'has_port': 0,
            'ssl_certificate_valid': -1, 'ssl_certificate_age': -1, 'uses_shortening': 0,
            'num_redirects': 0, 'double_slash_redirect': 0, 'external_redirect': 0,
            'domain_age_days': -1, 'domain_registration_length': -1, 'whois_privacy_enabled': 0,
            'domain_renewal_date': -1, 'has_dns_record': -1, 'num_name_servers': -1,
            'num_mx_servers': -1, 'ttl_hostname': -1, 'asn_reputation': 0, 'page_title_exists': -1,
            'title_domain_match': -1, 'has_favicon': -1, 'external_favicon': -1,
            'has_meta_description': -1, 'line_of_code': -1, 'largest_line_length': -1,
            'has_login_form': -1, 'has_external_form_submit': -1, 'submit_to_email': -1,
            'has_hidden_fields': -1, 'has_password_field': -1, 'server_form_handler_suspicious': -1,
            'num_external_js': -1, 'num_external_css': -1, 'obfuscated_js_count': -1,
            'has_iframe': -1, 'num_popups': -1, 'right_click_disabled': -1, 'on_mouseover': -1,
            'total_hyperlinks': -1, 'external_hyperlinks_ratio': -1, 'internal_hyperlinks_ratio': -1,
            'null_hyperlinks_ratio': -1, 'suspicious_anchor_ratio': -1, 'links_in_meta_script_tags': -1,
            'num_images': -1, 'external_resources_ratio': -1, 'external_media_ratio': -1,
            'suspicious_keywords_count': 0, 'financial_keywords_count': 0, 'security_keywords_count': 0,
            'crypto_keywords_count': 0, 'phishing_hints_score': 0, 'alexa_rank': -1,
            'google_indexed': -1, 'google_page_rank': -1, 'web_traffic_rank': -1,
            'links_pointing_to_page': -1, 'statistical_report_flagged': -1, 'response_time_ms': -1,
            'is_responsive_design': -1, 'page_load_complete': -1
        }

class RuleBasedAnalyzer:
    """Kural tabanlı analiz sınıfı"""
    
    def __init__(self):
        self.suspicious_patterns = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP adresi
            r'https?://[^/]*\d{5,}',  # Uzun sayı içeren domain
            r'[a-z]{20,}',  # Çok uzun kelimeler
            r'[0-9a-f]{32,}',  # Hash benzeri stringler
        ]
        
        self.blacklisted_domains = [
            'example-phishing.com',
            'fake-bank.net',
        ]
    
    def analyze(self, url: str, features: Dict[str, float]) -> List[str]:
        """Kural tabanlı analiz yap"""
        flags = []
        
        # URL uzunluğu kontrolü
        if features.get('url_length', 0) > 100:
            flags.append("Çok uzun URL")
        
        # IP adresi kontrolü
        if features.get('is_ip_address', 0) == 1:
            flags.append("IP adresi kullanılıyor")
        
        # Subdomain fazlalığı
        if features.get('subdomain_level', 0) > 3:
            flags.append("Fazla subdomain")
        
        # HTTPS eksikliği
        if features.get('is_https', 0) == 0:
            flags.append("HTTPS kullanılmıyor")
        
        # URL kısaltma servisi
        if features.get('uses_shortening', 0) == 1:
            flags.append("URL kısaltma servisi")
        
        # Şüpheli pattern kontrolü
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url):
                flags.append(f"Şüpheli pattern bulundu")
        
        # Blacklist kontrolü
        parsed = urlparse(url)
        if parsed.hostname and any(domain in parsed.hostname for domain in self.blacklisted_domains):
            flags.append("Blacklist'te bulunan domain")
        
        return flags

# Background monitoring functions
async def background_threat_monitoring():
    """Arka planda sürekli tehdit izleme"""
    global threat_monitor, system_metrics
    
    while True:
        try:
            if threat_monitor:
                # Gerçek zamanlı tehdit taraması
                threats = await threat_monitor.scan_for_threats()
                
                # Yeni tehditler varsa uyarı oluştur
                for threat in threats:
                    threat_alerts.put({
                        'alert_id': str(uuid.uuid4()),
                        'threat_type': threat.get('type', 'unknown'),
                        'severity': threat.get('severity', 'medium'),
                        'description': threat.get('description', ''),
                        'timestamp': datetime.now().isoformat(),
                        'indicators': threat.get('indicators', {}),
                        'url': threat.get('url', ''),
                        'recommended_actions': threat.get('actions', [])
                    })
                
                # Sistem metriklerini güncelle
                system_metrics['threat_level'] = await threat_monitor.get_current_threat_level()
                
            await asyncio.sleep(30)  # Her 30 saniyede bir kontrol
            
        except Exception as e:
            logger.error(f"❌ Background threat monitoring error: {e}")
            await asyncio.sleep(60)

async def system_health_monitoring():
    """Sistem sağlığı izleme"""
    global system_metrics
    
    while True:
        try:
            # CPU ve memory kullanımı
            system_metrics['cpu_usage'] = psutil.cpu_percent(interval=1)
            system_metrics['memory_usage'] = psutil.virtual_memory().percent
            
            # Aktif bağlantı sayısı
            system_metrics['active_connections'] = len(active_sessions)
            
            # Disk kullanımı kontrolü
            disk_usage = psutil.disk_usage('/').percent
            if disk_usage > 90:
                logger.warning(f"⚠️ Disk usage critical: {disk_usage}%")
            
            # Memory kullanımı kontrolü
            if system_metrics['memory_usage'] > 90:
                logger.warning(f"⚠️ Memory usage critical: {system_metrics['memory_usage']}%")
            
            await asyncio.sleep(10)  # Her 10 saniyede bir kontrol
            
        except Exception as e:
            logger.error(f"❌ System health monitoring error: {e}")
            await asyncio.sleep(30)

async def ml_model_optimization():
    """ML model optimizasyon ve güncelleme"""
    global ml_optimizer
    
    while True:
        try:
            if ml_optimizer:
                # Model performansını değerlendir
                performance_stats = await ml_optimizer.evaluate_model_performance()
                
                # Gerekirse model parametrelerini optimize et
                if performance_stats.get('needs_optimization', False):
                    logger.info("🔄 Optimizing ML models...")
                    await ml_optimizer.optimize_models()
                
                # Feature importance güncelle
                await ml_optimizer.update_feature_importance()
                
            await asyncio.sleep(3600)  # Her saatte bir kontrol
            
        except Exception as e:
            logger.error(f"❌ ML model optimization error: {e}")
            await asyncio.sleep(1800)

def get_threat_level(confidence: float, risk_score: float, external_threats: int = 0) -> str:
    """Tehdit seviyesi hesapla"""
    if external_threats > 0 or (confidence > 0.9 and risk_score > 0.8):
        return "CRITICAL"
    elif confidence > 0.8 and risk_score > 0.6:
        return "HIGH"
    elif confidence > 0.6 and risk_score > 0.4:
        return "MEDIUM"
    else:
        return "LOW"

def generate_recommendations(analysis_result: Dict) -> List[str]:
    """Analiz sonucuna göre öneriler oluştur"""
    recommendations = []
    
    prediction = analysis_result.get('prediction', '')
    confidence = analysis_result.get('confidence', 0)
    risk_score = analysis_result.get('risk_score', 0)
    
    if prediction == 'phishing':
        recommendations.append("🚨 Bu URL'yi ziyaret etmeyin")
        recommendations.append("🔒 Kişisel bilgilerinizi bu sitede paylaşmayın")
        recommendations.append("📧 Bu URL'yi aldığınız e-postayı spam olarak işaretleyin")
        
        if confidence > 0.8:
            recommendations.append("⚠️ Yüksek güvenilirlikle phishing tespit edildi")
            recommendations.append("🛡️ Antivirüs yazılımınızı güncelleyin")
        
        if risk_score > 0.7:
            recommendations.append("💻 Bilgisayarınızı tam tarama yapın")
            recommendations.append("🔑 Parolalarınızı değiştirin")
    
    elif prediction == 'safe' and confidence < 0.8:
        recommendations.append("⚠️ Düşük güven seviyesi - dikkatli olun")
        recommendations.append("🔍 URL'yi manuel olarak kontrol edin")
        recommendations.append("🌐 Tanınmış arama motorları kullanın")
    
    return recommendations

def enhance_comprehensive_analysis(comprehensive_data: Dict) -> Dict:
    """Comprehensive analysis data'sını web arayüzü için optimize et"""
    if not comprehensive_data:
        return {}
    
    # analysis_duration -> analysis_duration_ms dönüştür
    if 'analysis_duration' in comprehensive_data:
        comprehensive_data['analysis_duration_ms'] = comprehensive_data['analysis_duration'] * 1000
    
    # Analysis engines bilgilerini arayüz formatına çevir
    analysis_engines = comprehensive_data.get('analysis_engines', {})
    enhanced_engines = {}
    
    # Her engine için arayüz uyumlu formata çevir
    for engine_name, engine_result in analysis_engines.items():
        if not engine_result:
            continue
        
        # Status kontrolü - yoksa "completed" say
        status = engine_result.get('status', 'completed')
        if status != 'completed':
            continue
            
        risk_score = engine_result.get('risk_score', 0.0)
        
        # Engine type'a göre arayüz formatını belirle
        if engine_name == 'visual_detection':
            enhanced_engines['visual_detection'] = {
                'risk_score': risk_score,
                'confidence': engine_result.get('confidence', 0.0),
                'brand_impersonation': engine_result.get('brand_impersonation'),
                'visual_flags': engine_result.get('visual_flags', []),
                'forms_analysis': engine_result.get('forms_analysis', {}),
                'ui_manipulation_detected': engine_result.get('ui_manipulation_detected', False),
                'status': 'completed'
            }
        elif engine_name == 'url_truncation':
            enhanced_engines['url_truncation'] = {
                'risk_score': risk_score,
                'manipulation_detected': engine_result.get('manipulation_detected', False),
                'manipulation_types': engine_result.get('manipulation_types', []),
                'truncation_flags': engine_result.get('truncation_flags', []),
                'subdomain_analysis': engine_result.get('subdomain_analysis', {}),
                'path_analysis': engine_result.get('path_analysis', {}),
                'status': 'completed'
            }
        elif engine_name == 'whitelist_blacklist':
            enhanced_engines['whitelist_blacklist'] = {
                'risk_score': risk_score,
                'is_whitelisted': engine_result.get('is_whitelisted', False),
                'is_blacklisted': engine_result.get('is_blacklisted', False),
                'source': engine_result.get('source', 'unknown'),
                'confidence': engine_result.get('confidence', 0.0),
                'reason': engine_result.get('reason', ''),
                'reputation_analysis': engine_result.get('reputation_analysis', {}),
                'status': 'completed'
            }
        elif engine_name == 'false_positive':
            enhanced_engines['false_positive'] = {
                'risk_score': risk_score,
                'is_false_positive': engine_result.get('is_false_positive', False),
                'confidence': engine_result.get('confidence', 0.0),
                'reasons': engine_result.get('reasons', []),
                'pattern_matches': engine_result.get('pattern_matches', []),
                'historical_analysis': engine_result.get('historical_analysis', {}),
                'status': 'completed'
            }
        elif engine_name == 'behavioral_analysis':
            enhanced_engines['behavioral_analysis'] = {
                'risk_score': risk_score,
                'status': engine_result.get('status', 'completed'),
                'tracking_type': engine_result.get('tracking_type', 'unknown'),
                'behavioral_flags': engine_result.get('behavioral_flags', []),
                'session_analysis': engine_result.get('session_analysis', {}),
                'automation_detected': engine_result.get('automation_detected', False),
                'session_quality': engine_result.get('session_quality', 'unknown')
            }
        elif engine_name == 'content_security':
            enhanced_engines['content_security'] = {
                'risk_score': risk_score,
                'status': engine_result.get('status', 'completed'),
                'content_flags': engine_result.get('content_flags', []),
                'security_analysis': engine_result.get('security_analysis', {}),
                'phishing_indicators': engine_result.get('phishing_indicators', {})
            }
        elif engine_name == 'network_analysis':
            enhanced_engines['network_analysis'] = {
                'risk_score': risk_score,
                'status': engine_result.get('status', 'completed'),
                'network_accessible': engine_result.get('network_accessible', False),
                'ssl_analysis': engine_result.get('ssl_analysis', {}),
                'dns_analysis': engine_result.get('dns_analysis', {}),
                'network_flags': engine_result.get('network_flags', [])
            }
        elif engine_name == 'external_threat_intel':
            enhanced_engines['external_threat_intel'] = {
                'risk_score': risk_score,
                'status': engine_result.get('status', 'completed'),
                'is_phishing': engine_result.get('is_phishing', False),
                'confidence_score': engine_result.get('confidence_score', 0.0),
                'threat_level': engine_result.get('threat_level', 'unknown'),
                'sources': engine_result.get('sources', [])
            }
        elif engine_name == 'ml_ensemble':
            enhanced_engines['ml_ensemble'] = {
                'risk_score': risk_score,
                'status': engine_result.get('status', 'completed'),
                'ensemble_prediction': engine_result.get('ensemble_prediction', 'unknown'),
                'ensemble_confidence': engine_result.get('ensemble_confidence', 0.0),
                'total_models': engine_result.get('total_models', 0),
                'active_models': engine_result.get('active_models', 0),
                'individual_models': engine_result.get('individual_models', {})
            }
        else:
            # Diğer engine'ler için genel format
            enhanced_engines[engine_name] = {
                'risk_score': risk_score,
                'status': engine_result.get('status', 'completed'),
                **{k: v for k, v in engine_result.items() if k not in ['status']}
            }
    
    # Enhanced engines bilgisini comprehensive data'ya ekle
    comprehensive_data['enhanced_engines'] = enhanced_engines
    
    return comprehensive_data

# Global objeler
feature_extractor = FeatureExtractor()
rule_analyzer = RuleBasedAnalyzer()

@app.get("/", response_class=HTMLResponse)
async def root():
    """Ana sayfa - Web arayüzü"""
    try:
        with open("templates/index.html", "r", encoding="utf-8") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content, status_code=200)
    except FileNotFoundError:
        return HTMLResponse(content="""
            <h1>🔒 Phishing Detector API</h1>
            <p>Web arayüzü yükleniyor...</p>
            <p>API endpoint'leri:</p>
            <ul>
                <li><a href="/health">/health</a> - Sistem durumu</li>
                <li><a href="/model-stats">/model-stats</a> - Model istatistikleri</li>
                <li>POST /analyze - URL analizi</li>
            </ul>
        """, status_code=200)

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "features_loaded": selected_features is not None
    }

@app.post("/analyze", response_model=PredictionResponse)
async def analyze_url(request: URLRequest):
    """🚀 ENHANCED URL ANALİZİ - Tüm akıllı özelliklerle!"""
    try:
        url = request.url.strip()
        analysis_id = None
        
        # URL formatını kontrol et
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # 🎯 ENHANCED ENSEMBLE ANALYZER - NEW GENERATION!
        if ENHANCED_ANALYZER_ENABLED:
            try:
                from enhanced_ensemble_analyzer import enhanced_ensemble_analyzer
                logger.info(f"🔥 Starting ENHANCED analysis for: {url}")
                logger.info(f"🎯 ENTERING FIRST CODE PATH - Enhanced analyzer starting")
                
                # Request metadata hazırla
                request_metadata = {
                    'timestamp': datetime.now().isoformat(),
                    'session_id': str(uuid.uuid4()),
                    'ip_address': '127.0.0.1',
                    'user_agent': 'API_CLIENT'
                }
                
                # 🚀 ENHANCED ANALYSIS - ALL FEATURES ACTIVATED
                enhanced_result = await enhanced_ensemble_analyzer.comprehensive_analyze(
                    url=url,
                    session_id=request_metadata['session_id'],
                    user_agent=request_metadata['user_agent'],
                    deep_scan=True
                )
                
                # Enhanced result yapısını düzelt
                logger.info(f"🔍 ENHANCED RESULT PROCESSING: enhanced_result keys: {list(enhanced_result.keys())}")
                final_decision = {
                    'prediction': enhanced_result.get('final_decision', 'unknown'),
                    'confidence': enhanced_result.get('confidence', 0.0),  # ✅ DOĞRU FIELD
                    'source': 'enhanced_comprehensive'
                }
                logger.info(f"🔍 FINAL DECISION: {final_decision}")
                pipeline_results = enhanced_result.get('analysis_engines', {})
                performance_metrics = {
                    'total_time_ms': enhanced_result.get('analysis_duration', 0) * 1000 if enhanced_result.get('analysis_duration') else 0
                }
                
                # Response formatına çevir
                prediction_label = final_decision.get('prediction', 'unknown')
                confidence = final_decision.get('confidence', 0.0)
                
                # Ensure prediction_label is string
                if isinstance(prediction_label, (int, float)):
                    prediction_label = "phishing" if prediction_label > 0.5 else "safe"
                elif not isinstance(prediction_label, str):
                    prediction_label = str(prediction_label)
                    
                risk_score = confidence if prediction_label == 'phishing' else (1 - confidence)
                
                # Feature extraction (compatibility için)
                feature_extractor = FeatureExtractor()
                features = feature_extractor.extract_features(url)
                
                # Rule-based analysis
                rule_analyzer = RuleBasedAnalyzer()
                rule_flags = rule_analyzer.analyze(url, features)
                
                # ✅ KRİTİK DÜZELTİ: Enhanced analyzer'dan DOĞRU voting bilgisini al
                # Enhanced analyzer'ın comprehensive result'ından al
                comprehensive_ml = enhanced_result.get('analysis_engines', {}).get('ml_ensemble', {})
                
                # Voting bilgilerini doğru kaynaktan al
                total_models = 7  # Sabit 7 model
                active_models = comprehensive_ml.get('active_models', 0)
                phishing_votes = comprehensive_ml.get('threat_votes', 0)
                safe_votes = comprehensive_ml.get('safe_votes', 0)
                individual_models = comprehensive_ml.get('individual_models', {})
                
                # Fallback: pipeline_results'tan al (eski format için)
                if active_models == 0:
                    ml_result = pipeline_results.get('ml_ensemble', {})
                    individual_models = ml_result.get('individual_models', {}) if ml_result and not ml_result.get('error') else {}
                    active_models = ml_result.get('active_models', len(individual_models))
                    phishing_votes = ml_result.get('threat_votes', 0)
                    safe_votes = ml_result.get('safe_votes', 0)
                
                # ✅ Debug log - DETAYLI ANALIZ
                logger.info(f"🔍 ENHANCED RESULT KEYS: {list(enhanced_result.keys())}")
                logger.info(f"🔍 ANALYSIS ENGINES: {list(enhanced_result.get('analysis_engines', {}).keys())}")
                comprehensive_ml_debug = enhanced_result.get('analysis_engines', {}).get('ml_ensemble', {})
                logger.info(f"🔍 ML_ENSEMBLE KEYS: {list(comprehensive_ml_debug.keys())}")
                logger.info(f"🔍 VOTING RESULT: active_models={active_models}, phishing_votes={phishing_votes}, safe_votes={safe_votes}")
                
                # Eğer whitelist bypass oldu ve gerçek model bilgisi yok ise, gerçek ML analizi yap
                decision_source = final_decision.get('source', '')
                if active_models == 0 and ('whitelist' in decision_source or 'blacklist' in decision_source):
                    logger.info(f"🔄 Whitelist bypass detected for {url}, running real ML analysis for UI display")
                    
                    try:
                        # Import ve gerçek ensemble analizi çalıştır
                        from ensemble_phishing_detector import api_analyze_url_7_models
                        real_ml_result = api_analyze_url_7_models(url)
                        
                        if 'error' not in real_ml_result:
                            # Gerçek model sonuçlarını kullan
                            individual_models = real_ml_result.get('individual_models', {})
                            active_models = len(individual_models)
                            phishing_votes = real_ml_result.get('phishing_votes', 0)
                            safe_votes = real_ml_result.get('safe_votes', 0)
                            
                            logger.info(f"✅ Real ML analysis: {active_models} models, {phishing_votes} phishing, {safe_votes} safe")
                        else:
                            logger.error(f"❌ Real ML analysis failed: {real_ml_result.get('error')}")
                            # Fallback to original whitelist decision
                            active_models = 0
                            
                    except Exception as e:
                        logger.error(f"❌ Failed to run real ML analysis: {e}")
                        # Fallback to original whitelist decision
                        active_models = 0
                
                # Enhanced analysis details - ARAYÜZ COMPATİBLE FORMAT
                analysis = {
                    "🚀_enhanced_analysis": True,
                    "🎯_decision_source": final_decision.get('source', 'enhanced_ensemble'),
                    "⚡_pipeline_phases": list(pipeline_results.keys()),
                    "🚫_bypassed_phases": pipeline_results.get('bypassed_phases', []),
                    "📊_processing_time_ms": performance_metrics.get('total_time_ms', 0),
                    "ensemble_prediction": prediction_label,
                    "ensemble_confidence": confidence,
                    "hybrid_risk_score": risk_score,
                    "ensemble_status": "success_enhanced",
                    # ARAYÜZ İÇİN GEREKLİ ALANLAR
                    "total_models": total_models,
                    "active_models": active_models,
                    "phishing_votes": phishing_votes,
                    "safe_votes": safe_votes,
                    "voting_ratio": f"{phishing_votes}:{safe_votes}",
                    "individual_models": individual_models,
                    "model_weights": ml_result.get('model_weights', {}) if ml_result else {}
                }
                
                # Whitelist/Blacklist bypass info
                whitelist_result = pipeline_results.get('whitelist_blacklist', {})
                if whitelist_result.get('bypass_ml', False):
                    analysis['🎯_bypass_reason'] = whitelist_result.get('reason', '')
                    analysis['📋_bypass_source'] = whitelist_result.get('source', '')
                
                # External API bilgileri
                external_result = pipeline_results.get('external_apis', {})
                # Her zaman external API bilgilerini göster
                if external_result:
                    analysis['🌐_external_apis'] = {
                        'api_count': external_result.get('apis_checked', 0),
                        'threat_sources': external_result.get('sources', []) if external_result.get('is_phishing') else [],
                        'safe_sources': external_result.get('sources', []) if not external_result.get('is_phishing') else [],
                        'consensus_confidence': external_result.get('confidence_score', 0),
                        'threat_level': external_result.get('threat_level', 'unknown'),
                        'sources_available': external_result.get('apis_available', 0)
                    }
                else:
                    # Fallback - eğer external API bilgisi yoksa boş göster
                    analysis['🌐_external_apis'] = {
                        'api_count': 0,
                        'threat_sources': [],
                        'safe_sources': [],
                        'consensus_confidence': 0,
                        'threat_level': 'not_checked',
                        'sources_available': 0
                    }
                
                # ML Ensemble details
                ml_result = pipeline_results.get('ml_ensemble', {})
                if ml_result and not ml_result.get('error'):
                    analysis['🤖_ml_ensemble'] = {
                        'total_models': 7,
                        'dynamic_weights_applied': ml_result.get('dynamic_weights_applied', False),
                        'individual_models': ml_result.get('individual_models', {}),
                        'model_weights': ml_result.get('model_weights', {})
                    }
                
                # Truncation analysis
                truncation_result = pipeline_results.get('truncation', {})
                if truncation_result and not truncation_result.get('error'):
                    trunc_decision = truncation_result.get('final_decision', {})
                    analysis['🔧_truncation_analysis'] = {
                        'performed': True,
                        'decision': trunc_decision.get('decision', ''),
                        'confidence': trunc_decision.get('confidence', 0),
                        'recommendation': trunc_decision.get('recommendation', '')
                    }
                
                # Comprehensive analysis format'ını da enhanced result'a ekle
                # enhanced_result ZATen comprehensive_analysis formatında
                analysis['comprehensive_analysis'] = enhance_comprehensive_analysis(enhanced_result)
                
                response = PredictionResponse(
                    url=url,
                    prediction=prediction_label,
                    confidence=round(confidence, 4),
                    risk_score=round(risk_score, 4),
                    analysis=analysis,
                    features=features,
                    rule_based_flags=rule_flags,
                    timestamp=datetime.now().isoformat()
                )
                
                # 🗄️ SUPABASE ENHANCED KAYDI
                if SUPABASE_ENABLED:
                    try:
                        analysis_id = await asyncio.create_task(
                            asyncio.to_thread(supabase_client.save_url_analysis, enhanced_result, request_metadata)
                        )
                        
                        if analysis_id:
                            response.analysis['🗄️_analysis_id'] = analysis_id
                            logger.info(f"✅ Enhanced analysis saved to Supabase: {analysis_id}")
                        
                    except Exception as e:
                        logger.error(f"❌ Supabase save error: {e}")
                
                logger.info(f"🎯 ENHANCED analysis completed: {prediction_label} "
                           f"(conf: {confidence:.3f}) in {performance_metrics.get('total_time_ms', 0):.1f}ms")
                
                # 🔍 DEBUG: Final voting bilgilerini logla
                final_voting = response.analysis
                logger.info(f"🔍 FINAL UI VOTING: total={final_voting.get('total_models')}, "
                           f"active={final_voting.get('active_models')}, "
                           f"phishing={final_voting.get('phishing_votes')}, "
                           f"safe={final_voting.get('safe_votes')}")
                
                return response
                
            except Exception as e:
                logger.error(f"❌ Enhanced analyzer error: {e}")
                import traceback
                logger.error(f"❌ Enhanced analyzer traceback: {traceback.format_exc()}")
                logger.info("🔄 Falling back to ensemble analysis...")
        
        # 🚀 KAPSAMLI ANALİZ SİSTEMİ (Tüm Motorlar) - Import moved to top
        from enhanced_ensemble_analyzer import enhanced_ensemble_analyzer
        
        logger.info(f"🚀 KAPSAMLI ANALİZ başlıyor: {url}")
        
        # Session ID oluştur
        session_id = f"session_{hash(url)}_{int(time.time())}"
        user_agent = 'API_CLIENT'
        
        # Kapsamlı analiz yap
        comprehensive_result = await enhanced_ensemble_analyzer.comprehensive_analyze(
            url=url,
            session_id=session_id,
            user_agent=user_agent,
            deep_scan=True
        )
        
        # Enhanced result'ı ensemble formatına çevir
        if 'error' not in comprehensive_result:
            ml_engine = comprehensive_result.get('analysis_engines', {}).get('ml_ensemble', {})
            ensemble_result = {
                "final_label": ml_engine.get('ensemble_prediction', 'Unknown'),
                "confidence": ml_engine.get('ensemble_confidence', 0.0),
                "total_models": ml_engine.get('total_models', 7),
                "active_models": ml_engine.get('active_models', 0),
                "phishing_votes": ml_engine.get('threat_votes', 0),
                "safe_votes": ml_engine.get('safe_votes', 0),
                "voting_ratio": f"{ml_engine.get('threat_votes', 0)}:{ml_engine.get('safe_votes', 0)}",
                "model_weights": {},
                "probability_phishing": comprehensive_result.get('final_risk_score', 0.0),
                "model_predictions": ml_engine.get('individual_models', {}),
                "rule_analysis": {"flags": []},
                "timestamp": comprehensive_result.get('timestamp', datetime.now().isoformat()),
                "optimization": "comprehensive_analysis",
                
                # 🆕 ENHANCED DATA
                "comprehensive_analysis": comprehensive_result
            }
        else:
            ensemble_result = comprehensive_result
        
        # API format'ına çevir
        if 'error' not in ensemble_result:
            ensemble_result = {
                "ensemble_prediction": ensemble_result['final_label'],
                "ensemble_confidence": ensemble_result['confidence'],
                "total_models": ensemble_result['total_models'],
                "active_models": ensemble_result['active_models'],
                "phishing_votes": ensemble_result['phishing_votes'],
                "safe_votes": ensemble_result['safe_votes'],
                "voting_ratio": ensemble_result['voting_ratio'],
                "model_weights": ensemble_result['model_weights'],
                "rule_based_flags_count": len(ensemble_result['rule_analysis'].get('flags', [])),
                "hybrid_risk_score": ensemble_result['probability_phishing'],
                "ensemble_status": "success_7_models_optimized",
                "individual_models": ensemble_result.get('individual_models', {}),
                "rule_analysis": ensemble_result['rule_analysis'],
                "timestamp": ensemble_result['timestamp'],
                "optimization": ensemble_result.get('optimization', 'features_cached'),
                
                # 🆕 KAPSAMLI ANALİZ VERİSİNİ KORU
                "comprehensive_analysis": ensemble_result.get('comprehensive_analysis', {})
            }
        
        if 'error' in ensemble_result:
            # Fallback to single model
            feature_extractor = FeatureExtractor()
            features = feature_extractor.extract_features(url)
            selected_feature_values = []
            for feature_name in selected_features:
                selected_feature_values.append(features.get(feature_name, 0))
            
            prediction_prob = model.predict_proba([selected_feature_values])[0]
            prediction = model.predict([selected_feature_values])[0]
            
            confidence = max(prediction_prob)
            risk_score = prediction_prob[1]
            prediction_label = "phishing" if prediction == 1 else "safe"
            rule_flags = rule_analyzer.analyze(url, features)
            
            if rule_flags:
                risk_score = min(risk_score + 0.2, 1.0)
            
            response = PredictionResponse(
                url=url,
                prediction=prediction_label,
                confidence=confidence,
                risk_score=risk_score,
                analysis={
                    "ml_prediction": prediction_label,
                    "ml_confidence": confidence,
                    "rule_based_flags_count": len(rule_flags),
                    "hybrid_risk_score": risk_score,
                    "ensemble_status": "fallback_single_model"
                },
                features={name: features.get(name, 0) for name in selected_features[:10]},
                rule_based_flags=rule_flags,
                timestamp=datetime.now().isoformat()
            )
        else:
            # Ensemble başarılı
            # Final decision'ı comprehensive analysis'ten al (en doğru sonuç)
            final_decision = ensemble_result.get('comprehensive_analysis', {}).get('final_decision', 'Unknown')
            if final_decision == 'Unknown':
                final_decision = ensemble_result['ensemble_prediction']  # Fallback
            
            # Ensure final_decision is string
            if isinstance(final_decision, (int, float)):
                final_decision = "phishing" if final_decision > 0.5 else "safe"
            elif not isinstance(final_decision, str):
                final_decision = str(final_decision)
            
            response = PredictionResponse(
                url=url,
                prediction=final_decision.lower(),
                confidence=ensemble_result['ensemble_confidence'],
                risk_score=ensemble_result['hybrid_risk_score'],
                analysis={
                    "ensemble_prediction": ensemble_result['ensemble_prediction'],
                    "ensemble_confidence": ensemble_result['ensemble_confidence'],
                    "total_models": ensemble_result['total_models'],
                    "active_models": ensemble_result['active_models'],
                    "phishing_votes": ensemble_result['phishing_votes'],
                    "safe_votes": ensemble_result['safe_votes'],
                    "voting_ratio": ensemble_result['voting_ratio'],
                    "model_weights": ensemble_result['model_weights'],
                    "rule_based_flags_count": ensemble_result['rule_based_flags_count'],
                    "hybrid_risk_score": ensemble_result['hybrid_risk_score'],
                    "ensemble_status": ensemble_result['ensemble_status'],
                    "individual_models": ensemble_result['individual_models'],
                    
                    # 🆕 KAPSAMLI ANALİZ VERİSİ (Web arayüzü için)
                    "comprehensive_analysis": enhance_comprehensive_analysis(ensemble_result.get('comprehensive_analysis', {}))
                },
                features=FeatureExtractor().extract_features(url),
                rule_based_flags=ensemble_result['rule_analysis'].get('flags', []),
                timestamp=ensemble_result['timestamp']
            )
        
        # 🗄️ SUPABASE DATABASE KAYDI
        if SUPABASE_ENABLED:
            try:
                # Request info topla
                request_info = {
                    'session_id': str(uuid.uuid4()),
                    'ip_address': '127.0.0.1',  # FastAPI'de gerçek IP almak için başka yöntem gerekli
                    'user_agent': 'API_CLIENT'
                }
                
                # Analysis result'ı Supabase format'ına çevir
                analysis_data = {
                    'url': url,
                    'prediction': response.prediction,
                    'confidence': response.confidence,
                    'risk_score': response.risk_score,
                    'analysis': response.analysis,
                    'features': response.features,
                    'rule_based_flags': response.rule_based_flags
                }
                
                # Veritabanına kaydet
                analysis_id = supabase_client.save_url_analysis(analysis_data, request_info)
                
                if analysis_id:
                    logger.info(f"✅ Analysis saved to Supabase: {analysis_id}")
                    # Response'a analysis_id ekle
                    response.analysis['analysis_id'] = analysis_id
                else:
                    logger.warning("⚠️ Failed to save analysis to Supabase")
                    
            except Exception as e:
                logger.error(f"❌ Supabase save error: {e}")
        
        return response
        
    except Exception as e:
        logger.error(f"Analiz hatası: {e}")
        raise HTTPException(status_code=500, detail=f"Analiz hatası: {str(e)}")

@app.post("/feedback")
async def submit_feedback(feedback: FeedbackRequest):
    """🔄 ENHANCED FEEDBACK - Dynamic learning & system improvement"""
    try:
        # Feedback data preparation
        feedback_data = {
            "url": feedback.url,
            "feedback_type": feedback.feedback,  # "correct" or "incorrect"
            "prediction": feedback.prediction,
            "confidence": feedback.confidence,
            "timestamp": feedback.timestamp,
            "processed_at": datetime.now().isoformat()
        }
        
        logger.info(f"📝 Processing feedback: {feedback.feedback} for {feedback.url}")
        
        # 🎯 ENHANCED FEEDBACK PROCESSING
        if ENHANCED_ANALYZER_ENABLED:
            try:
                # Enhanced feedback processing ile sistem öğrenmesi
                # Bu feedback'i enhanced analyzer'a göndererek dynamic weights güncelle
                
                # Mock analysis result (gerçek implementation'da analysis_id ile orijinal sonucu bulacağız)
                mock_analysis_result = {
                    'url': feedback.url,
                    'pipeline_results': {
                        'ml_ensemble': {
                            'ensemble_prediction': feedback.prediction,
                            'ensemble_confidence': feedback.confidence,
                            'individual_models': {}  # Gerçek data gerekli
                        }
                    },
                    'final_decision': {
                        'prediction': feedback.prediction,
                        'confidence': feedback.confidence
                    }
                }
                
                # Enhanced Analyzer'ın feedback öğrenme sistemi
                await enhanced_ensemble_analyzer.save_feedback_and_update(
                    mock_analysis_result, feedback.feedback
                )
                
                logger.info(f"🧠 Enhanced analyzer updated with feedback: {feedback.feedback}")
                
            except Exception as e:
                logger.error(f"❌ Enhanced feedback processing error: {e}")
        
        feedback_data['enhanced_processed'] = ENHANCED_ANALYZER_ENABLED
        
        # Save to CSV file (existing behavior)
        feedback_df = pd.DataFrame([feedback_data])
        try:
            existing_feedback = pd.read_csv('feedback.csv')
            feedback_df = pd.concat([existing_feedback, feedback_df], ignore_index=True)
        except:
            pass
        
        feedback_df.to_csv('feedback.csv', index=False)
        
        # 🗄️ SUPABASE FEEDBACK KAYDI
        feedback_id = None
        if SUPABASE_ENABLED:
            try:
                # Request info topla
                request_info = {
                    'session_id': str(uuid.uuid4()),
                    'ip_address': '127.0.0.1',
                    'user_agent': 'API_CLIENT'
                }
                
                # Feedback formatını düzenle
                supabase_feedback = {
                    'url': feedback.url,
                    'prediction': feedback.prediction,
                    'feedback': feedback.feedback,
                    'confidence': feedback.confidence
                }
                
                # Veritabanına kaydet
                feedback_id = supabase_client.save_user_feedback(
                    supabase_feedback, 
                    analysis_id=None,  # Analysis ID'yi bulabilsek daha iyi olur
                    request_info=request_info
                )
                
                if feedback_id:
                    logger.info(f"✅ Feedback saved to Supabase: {feedback_id}")
                else:
                    logger.warning("⚠️ Failed to save feedback to Supabase")
                    
            except Exception as e:
                logger.error(f"❌ Supabase feedback save error: {e}")
        
        # 🚨 FALSE POSITIVE/NEGATIVE TRACKING
        if FP_TRACKER_ENABLED and feedback.feedback == "incorrect":
            try:
                # Analysis data'yı temsil etmek için mock data oluştur
                # Gerçek uygulamada bu data analysis endpoint'inden gelecek
                analysis_data = {
                    "url": feedback.url,
                    "prediction": feedback.prediction,
                    "confidence": feedback.confidence,
                    "analysis": {
                        "ensemble_status": "success_7_models",
                        "individual_models": {},  # Gerçek data gerekli
                        "phishing_votes": 0,  # Gerçek data gerekli
                        "safe_votes": 0,  # Gerçek data gerekli
                        "voting_ratio": 0  # Gerçek data gerekli
                    },
                    "rule_based_flags": [],
                    "features": {}
                }
                
                # False prediction type'ını belirle
                prediction_type = "false_positive" if feedback.prediction.lower() == "phishing" else "false_negative"
                
                # False Positive Tracker'a kaydet
                false_positive_tracker.add_false_prediction(
                    url=feedback.url,
                    prediction_type=prediction_type,
                    analysis_data=analysis_data,
                    feedback_data={
                        "feedback": feedback.feedback,
                        "timestamp": feedback.timestamp
                    }
                )
                
                logger.info(f"🚨 False prediction tracked: {prediction_type} for {feedback.url}")
                
            except Exception as e:
                logger.error(f"❌ False Positive Tracker error: {e}")
        
        logger.info(f"📊 Cyber Intelligence Feedback Received: {feedback.feedback} for {feedback.url}")
        
        return {
            "status": "success",
            "message": "OPERATOR FEEDBACK SUCCESSFULLY LOGGED",
            "feedback_id": feedback_id or len(feedback_df),
            "supabase_id": feedback_id,
            "csv_id": len(feedback_df),
            "processed_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"🚨 Feedback Processing Error: {e}")
        raise HTTPException(status_code=500, detail=f"FEEDBACK SYSTEM ERROR: {str(e)}")

@app.get("/model-stats")
async def get_model_stats():
    """Model istatistiklerini getir"""
    try:
        model_info = joblib.load('model_info.pkl')
        
        stats = {
            "model_name": model_info['model_name'],
            "accuracy": model_info['accuracy'],
            "auc_score": model_info['auc_score'],
            "feature_count": len(selected_features),
            "top_features": feature_importance.head(10).to_dict('records') if feature_importance is not None else []
        }
        
        return stats
        
    except Exception as e:
        logger.error(f"Model stats hatası: {e}")
        raise HTTPException(status_code=500, detail="Model istatistikleri alınamadı")

# 🎛️ DASHBOARD API ENDPOINTS
@app.get("/dashboard/analytics")
async def get_dashboard_analytics(days: int = 30):
    """Dashboard için analytics verilerini getir"""
    if not SUPABASE_ENABLED:
        return {"error": "Supabase not configured", "data": []}
    
    try:
        analytics_data = supabase_client.get_daily_analytics(days)
        return {
            "status": "success",
            "data": analytics_data,
            "days": days,
            "total_records": len(analytics_data)
        }
    except Exception as e:
        logger.error(f"❌ Dashboard analytics error: {e}")
        raise HTTPException(status_code=500, detail=f"Analytics error: {str(e)}")

@app.get("/dashboard/model-performance")
async def get_model_performance():
    """Model performance verilerini getir"""
    if not SUPABASE_ENABLED:
        return {"error": "Supabase not configured", "data": []}
    
    try:
        performance_data = supabase_client.get_model_performance()
        return {
            "status": "success",
            "data": performance_data,
            "total_models": len(performance_data)
        }
    except Exception as e:
        logger.error(f"❌ Model performance error: {e}")
        raise HTTPException(status_code=500, detail=f"Model performance error: {str(e)}")

@app.get("/dashboard/false-positives")
async def get_false_positive_hotspots(limit: int = 20):
    """False positive hotspot'ları getir"""
    if not SUPABASE_ENABLED:
        return {"error": "Supabase not configured", "data": []}
    
    try:
        hotspots = supabase_client.get_false_positive_hotspots(limit)
        return {
            "status": "success",
            "data": hotspots,
            "limit": limit,
            "total_hotspots": len(hotspots)
        }
    except Exception as e:
        logger.error(f"❌ False positive hotspots error: {e}")
        raise HTTPException(status_code=500, detail=f"False positive error: {str(e)}")

@app.get("/dashboard/recent-analyses")
async def get_recent_analyses(limit: int = 50):
    """Son analizleri getir"""
    if not SUPABASE_ENABLED:
        return {"error": "Supabase not configured", "data": []}
    
    try:
        # Bu endpoint için yeni method eklemeli
        result = supabase_client._make_request('GET', f'url_analyses?order=analysis_timestamp.desc&limit={limit}')
        
        if 'error' in result:
            return {"error": result['error'], "data": []}
            
        return {
            "status": "success",
            "data": result,
            "limit": limit,
            "total_records": len(result)
        }
    except Exception as e:
        logger.error(f"❌ Recent analyses error: {e}")
        raise HTTPException(status_code=500, detail=f"Recent analyses error: {str(e)}")

@app.post("/dashboard/update-model-stats")
async def update_model_performance_stats():
    """Model performance istatistiklerini manuel güncelle"""
    if not SUPABASE_ENABLED:
        return {"error": "Supabase not configured"}
    
    try:
        supabase_client.update_model_performance_stats()
        return {
            "status": "success",
            "message": "Model performance stats updated",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"❌ Update model stats error: {e}")
        raise HTTPException(status_code=500, detail=f"Update error: {str(e)}")

# 🚨 FALSE POSITIVE TRACKING ENDPOINTS
@app.get("/tracking/summary")
async def get_false_positive_summary():
    """False positive/negative tracking özeti"""
    if not FP_TRACKER_ENABLED:
        return {"error": "False Positive Tracker not configured", "data": {}}
    
    try:
        summary = false_positive_tracker.get_summary_report()
        return {
            "status": "success",
            "data": summary,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"❌ False positive summary error: {e}")
        raise HTTPException(status_code=500, detail=f"Tracking summary error: {str(e)}")

@app.get("/tracking/export-ml-data")
async def export_false_predictions_for_ml():
    """False prediction verilerini ML training için export et"""
    if not FP_TRACKER_ENABLED:
        return {"error": "False Positive Tracker not configured"}
    
    try:
        df = false_positive_tracker.export_for_ml_training()
        
        if len(df) == 0:
            return {
                "status": "warning",
                "message": "No false predictions found for export",
                "records": 0
            }
        
        # CSV dosya adını belirle
        filename = f"false_predictions_for_training_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        return {
            "status": "success",
            "message": "False predictions exported for ML training",
            "filename": filename,
            "records": len(df),
            "false_positives": len(df[df['error_type'] == 'false_positive']),
            "false_negatives": len(df[df['error_type'] == 'false_negative']),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"❌ Export ML data error: {e}")
        raise HTTPException(status_code=500, detail=f"Export error: {str(e)}")

@app.get("/tracking/improvements")
async def get_system_improvements():
    """Sistem geliştirme önerilerini getir"""
    if not FP_TRACKER_ENABLED:
        return {"error": "False Positive Tracker not configured", "data": []}
    
    try:
        summary = false_positive_tracker.get_summary_report()
        improvements = summary.get("improvement_recommendations", [])
        
        return {
            "status": "success",
            "data": improvements,
            "total_recommendations": len(improvements),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"❌ System improvements error: {e}")
        raise HTTPException(status_code=500, detail=f"Improvements error: {str(e)}")

@app.get("/tracking/patterns")
async def get_error_patterns():
    """Error pattern analizini getir"""
    if not FP_TRACKER_ENABLED:
        return {"error": "False Positive Tracker not configured", "data": {}}
    
    try:
        patterns = false_positive_tracker.error_patterns
        return {
            "status": "success",
            "data": patterns,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"❌ Error patterns error: {e}")
        raise HTTPException(status_code=500, detail=f"Patterns error: {str(e)}")

# 🚀 ENHANCED SYSTEM ENDPOINTS
@app.get("/enhanced/statistics")
async def get_enhanced_system_statistics():
    """🎯 Enhanced system istatistiklerini al"""
    try:
        if not ENHANCED_ANALYZER_ENABLED:
            raise HTTPException(
                status_code=503, 
                detail="Enhanced analyzer not available"
            )
        
        # Enhanced analyzer'dan comprehensive stats al
        stats = enhanced_ensemble_analyzer.get_system_statistics()
        
        return {
            "message": "Enhanced system statistics retrieved",
            "timestamp": datetime.now().isoformat(),
            "enhanced_analyzer_enabled": True,
            "statistics": stats
        }
        
    except Exception as e:
        logger.error(f"❌ Enhanced statistics error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/enhanced/model-weights")
async def get_current_model_weights():
    """🏋️ Dynamic model weights'i al"""
    try:
        if not ENHANCED_ANALYZER_ENABLED:
            raise HTTPException(
                status_code=503, 
                detail="Enhanced analyzer not available"
            )
        
        from dynamic_model_weighting import dynamic_weighting
        
        weights_summary = dynamic_weighting.get_performance_summary()
        
        return {
            "message": "Current model weights retrieved", 
            "timestamp": datetime.now().isoformat(),
            "weights": weights_summary
        }
        
    except Exception as e:
        logger.error(f"❌ Model weights error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/enhanced/whitelist-blacklist")
async def get_whitelist_blacklist_status():
    """📋 Whitelist/Blacklist durumunu al"""
    try:
        if not ENHANCED_ANALYZER_ENABLED:
            raise HTTPException(
                status_code=503, 
                detail="Enhanced analyzer not available"
            )
        
        from whitelist_blacklist_manager import whitelist_blacklist_manager
        
        stats = whitelist_blacklist_manager.get_statistics()
        
        return {
            "message": "Whitelist/Blacklist status retrieved",
            "timestamp": datetime.now().isoformat(),
            "statistics": stats
        }
        
    except Exception as e:
        logger.error(f"❌ Whitelist/Blacklist error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/enhanced/reset-weights")
async def reset_model_weights():
    """🔄 Model weights'i sıfırla"""
    try:
        if not ENHANCED_ANALYZER_ENABLED:
            raise HTTPException(
                status_code=503, 
                detail="Enhanced analyzer not available"
            )
        
        from dynamic_model_weighting import dynamic_weighting
        
        dynamic_weighting.reset_weights()
        
        return {
            "message": "Model weights reset to default",
            "timestamp": datetime.now().isoformat(),
            "success": True
        }
        
    except Exception as e:
        logger.error(f"❌ Reset weights error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/enhanced/add-to-whitelist")
async def add_domain_to_whitelist(domain: str):
    """➕ Domain'i whitelist'e ekle"""
    try:
        if not ENHANCED_ANALYZER_ENABLED:
            raise HTTPException(
                status_code=503, 
                detail="Enhanced analyzer not available"
            )
        
        from whitelist_blacklist_manager import whitelist_blacklist_manager
        
        whitelist_blacklist_manager.add_to_whitelist(domain, "manual_api")
        
        return {
            "message": f"Domain added to whitelist: {domain}",
            "timestamp": datetime.now().isoformat(),
            "success": True
        }
        
    except Exception as e:
        logger.error(f"❌ Add to whitelist error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/enhanced/add-to-blacklist")
async def add_domain_to_blacklist(domain: str):
    """🚫 Domain'i blacklist'e ekle"""
    try:
        if not ENHANCED_ANALYZER_ENABLED:
            raise HTTPException(
                status_code=503, 
                detail="Enhanced analyzer not available"
            )
        
        from whitelist_blacklist_manager import whitelist_blacklist_manager
        
        whitelist_blacklist_manager.add_to_blacklist(domain, "manual_api")
        
        return {
            "message": f"Domain added to blacklist: {domain}",
            "timestamp": datetime.now().isoformat(),
            "success": True
        }
        
    except Exception as e:
        logger.error(f"❌ Add to blacklist error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# YENİ GELİŞMİŞ ENDPOINT'LER

@app.post("/advanced/analyze", response_model=AdvancedPredictionResponse)
async def advanced_analyze_url(request: AdvancedURLRequest):
    """🚀 Gelişmiş URL analizi - Comprehensive Analysis System"""
    start_time = datetime.now()
    session_id = request.session_id or str(uuid.uuid4())
    
    try:
        url = request.url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        logger.info(f"🚀 ADVANCED ANALYSIS başlıyor: {url}")

        # Use Enhanced Ensemble Analyzer for comprehensive analysis
        from enhanced_ensemble_analyzer import enhanced_ensemble_analyzer

        comprehensive_result = await enhanced_ensemble_analyzer.comprehensive_analyze(
            url=url,
            session_id=session_id,
            user_agent=request.user_agent or 'ADVANCED_API_CLIENT',
            deep_scan=request.deep_scan
        )

        if 'error' not in comprehensive_result:
            # Get ML ensemble results
            ml_engine = comprehensive_result.get('analysis_engines', {}).get('ml_ensemble', {})

            # Get individual engine results
            behavioral_analysis = comprehensive_result.get('analysis_engines', {}).get('behavioral_analysis', {})
            content_analysis = comprehensive_result.get('analysis_engines', {}).get('content_security', {})
            visual_analysis = comprehensive_result.get('analysis_engines', {}).get('visual_detection', {})
            network_analysis = comprehensive_result.get('analysis_engines', {}).get('network_analysis', {})
            threat_intelligence = comprehensive_result.get('analysis_engines', {}).get('external_threat_intel', {})

            final_prediction = comprehensive_result.get('final_decision', 'unknown').lower()
            final_confidence = comprehensive_result.get('final_confidence', 0.0)
            final_risk_score = comprehensive_result.get('final_risk_score', 0.0)

            # Threat level hesapla
            threat_level = get_threat_level(
                final_confidence,
                final_risk_score,
                len([t for t in [threat_intelligence] if t and t.get('is_threat', False)])
            )

            # Get ensemble analysis for backward compatibility
            ensemble_analysis = {
                "ensemble_prediction": ml_engine.get('ensemble_prediction', 'Unknown'),
                "ensemble_confidence": ml_engine.get('ensemble_confidence', 0.0),
                "total_models": ml_engine.get('total_models', 7),
                "active_models": ml_engine.get('active_models', 0),
                "phishing_votes": ml_engine.get('threat_votes', 0),
                "safe_votes": ml_engine.get('safe_votes', 0),
                "voting_ratio": ml_engine.get('voting_ratio', '0/7'),
                "model_weights": ml_engine.get('model_weights', {}),
                "individual_models": ml_engine.get('individual_models', {}),
                "comprehensive_analysis": comprehensive_result
            }

            # Get features from ML engine or fallback
            features = ml_engine.get('features', {})
            if not features:
                # Fallback to feature extraction
                feature_extractor = FeatureExtractor()
                features = feature_extractor.extract_features(url)

            # Get recommendations
            recommendations = comprehensive_result.get('recommendations', [])
            if not recommendations:
                recommendations = generate_recommendations({
                    'prediction': final_prediction,
                    'confidence': final_confidence,
                    'risk_score': final_risk_score
                })
        else:
            # Fallback to basic analysis if comprehensive fails
            logger.warning("⚠️ Comprehensive analysis failed, falling back to basic analysis")
            from ensemble_phishing_detector import api_analyze_url_7_models
            ensemble_result = api_analyze_url_7_models(url)

            final_prediction = ensemble_result.get('final_label', 'unknown').lower()
            final_confidence = ensemble_result.get('confidence', 0.0)
            final_risk_score = ensemble_result.get('confidence', 0.0)
            threat_level = get_threat_level(final_confidence, final_risk_score)

            ensemble_analysis = ensemble_result
            features = ensemble_result.get('features', {})
            recommendations = generate_recommendations({
                'prediction': final_prediction,
                'confidence': final_confidence,
                'risk_score': final_risk_score
            })

            # Set empty analysis for individual engines
            behavioral_analysis = None
            content_analysis = None
            visual_analysis = None
            network_analysis = None
            threat_intelligence = None

        end_time = datetime.now()
        analysis_duration = (end_time - start_time).total_seconds() * 1000

        return AdvancedPredictionResponse(
            url=url,
            prediction=final_prediction,
            confidence=round(final_confidence, 4),
            risk_score=round(final_risk_score, 4),
            threat_level=threat_level,
            analysis=ensemble_analysis,
            features=features,
            rule_based_flags=comprehensive_result.get('rule_based_flags', []) if 'error' not in comprehensive_result else [],
            behavioral_analysis=behavioral_analysis,
            content_analysis=content_analysis,
            visual_analysis=visual_analysis,
            network_analysis=network_analysis,
            threat_intelligence=threat_intelligence,
            recommendations=recommendations,
            timestamp=end_time.isoformat(),
            analysis_duration_ms=round(analysis_duration, 2),
            session_id=session_id
        )
    except Exception as e:
        logger.error(f"Advanced analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/system/status", response_model=SystemStatus)
async def get_system_status():
    """Sistem durumu ve sağlık bilgileri"""
    try:
        # Component status kontrol et
        component_status = {
            "ml_models": "operational" if model is not None else "error",
            "enhanced_analyzer": "operational" if ENHANCED_ANALYZER_ENABLED else "disabled",
            "threat_monitor": "operational" if THREAT_MONITOR_ENABLED else "disabled",
            "behavioral_analyzer": "operational" if BEHAVIORAL_ANALYZER_ENABLED else "disabled",
            "content_analyzer": "operational" if CONTENT_ANALYZER_ENABLED else "disabled",
            "network_intel": "operational" if NETWORK_INTEL_ENABLED else "disabled",
            "visual_detector": "operational" if VISUAL_DETECTOR_ENABLED else "disabled",
            "supabase": "operational" if SUPABASE_ENABLED else "disabled"
        }
        
        # Active threats say
        active_threats_count = 0
        try:
            active_threats_count = threat_alerts.qsize()
        except:
            pass
        
        return SystemStatus(
            status="operational",
            version="2.0.0-advanced",
            uptime="0d 0h 0m",  # TODO: Implement proper uptime tracking
            total_analyses=system_metrics.get('total_analyses', 0),
            threat_level=system_metrics.get('threat_level', 'LOW'),
            active_threats=active_threats_count,
            system_health={
                "cpu_usage": system_metrics.get('cpu_usage', 0),
                "memory_usage": system_metrics.get('memory_usage', 0),
                "disk_usage": psutil.disk_usage('/').percent if psutil else 0,
                "active_connections": system_metrics.get('active_connections', 0)
            },
            component_status=component_status,
            performance_metrics={
                "avg_response_time_ms": 0,  # TODO: Implement proper metrics
                "requests_per_minute": 0,   # TODO: Implement proper metrics
                "success_rate": 0.99        # TODO: Implement proper metrics
            }
        )
        
    except Exception as e:
        logger.error(f"System status error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/bulk/analyze")
async def bulk_analyze_urls(request: BulkAnalysisRequest, background_tasks: BackgroundTasks):
    """Toplu URL analizi"""
    try:
        if len(request.urls) > 100:
            raise HTTPException(status_code=400, detail="Maximum 100 URLs allowed")
        
        job_id = str(uuid.uuid4())
        
        # Background task olarak çalıştır
        background_tasks.add_task(
            process_bulk_analysis,
            job_id,
            request.urls,
            request.analysis_type,
            request.priority,
            request.callback_url
        )
        
        return {
            "job_id": job_id,
            "status": "queued",
            "total_urls": len(request.urls),
            "analysis_type": request.analysis_type,
            "priority": request.priority,
            "estimated_completion": (datetime.now() + timedelta(minutes=len(request.urls) * 2)).isoformat(),
            "check_status_url": f"/bulk/status/{job_id}"
        }
        
    except Exception as e:
        logger.error(f"Bulk analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def process_bulk_analysis(job_id: str, urls: List[str], analysis_type: str, 
                               priority: str, callback_url: Optional[str]):
    """Toplu analiz işlemini gerçekleştir"""
    try:
        results = []
        
        for url in urls:
            try:
                if analysis_type == "advanced":
                    # Advanced analiz kullan
                    request = AdvancedURLRequest(url=url)
                    result = await advanced_analyze_url(request)
                    results.append(result.dict())
                else:
                    # Standard analiz kullan
                    request = URLRequest(url=url)
                    result = await analyze_url(request)
                    results.append(result.dict())
                    
            except Exception as e:
                results.append({
                    "url": url,
                    "error": str(e),
                    "prediction": "error",
                    "confidence": 0.0
                })
        
        # Sonuçları kaydet (database veya cache)
        # TODO: Implement bulk results storage
        
        # Callback URL varsa bildir
        if callback_url:
            try:
                async with aiohttp.ClientSession() as session:
                    await session.post(callback_url, json={
                        "job_id": job_id,
                        "status": "completed",
                        "results": results
                    })
            except Exception as e:
                logger.error(f"Callback notification error: {e}")
                
    except Exception as e:
        logger.error(f"Bulk analysis processing error: {e}")

@app.get("/threats/alerts")
async def get_threat_alerts(limit: int = 50):
    """Aktif tehdit uyarılarını getir"""
    try:
        alerts = []
        
        # Queue'dan alert'leri al
        while not threat_alerts.empty() and len(alerts) < limit:
            alert = threat_alerts.get()
            alerts.append(alert)
        
        return {
            "alerts": alerts,
            "total_alerts": len(alerts),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Get threat alerts error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/threats/hunt")
async def threat_hunting(request: ThreatHuntingRequest):
    """Proaktif tehdit avcılığı"""
    try:
        hunt_results = {
            "matches_found": 0,
            "indicators_analyzed": len(request.indicators),
            "threat_score": 0.0,
            "details": []
        }
        
        # TODO: Implement actual threat hunting logic
        # This would integrate with threat intelligence feeds
        
        return {
            "hunt_id": str(uuid.uuid4()),
            "hunt_type": request.hunt_type,
            "indicators_searched": len(request.indicators),
            "time_range": request.time_range,
            "results": hunt_results,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Threat hunting error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analytics/realtime")
async def get_realtime_analytics():
    """Gerçek zamanlı analitik veriler"""
    try:
        return {
            "system_metrics": system_metrics,
            "active_sessions": len(active_sessions),
            "threat_level": system_metrics.get('threat_level', 'LOW'),
            "performance": {
                "cpu_usage": system_metrics.get('cpu_usage', 0),
                "memory_usage": system_metrics.get('memory_usage', 0),
                "active_connections": system_metrics.get('active_connections', 0)
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Realtime analytics error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reports/generate/{report_type}")
async def generate_report(report_type: str, days: int = 7):
    """Gelişmiş raporlar oluştur"""
    try:
        report_data = {
            "summary": {
                "total_analyses": 0,
                "phishing_detected": 0,
                "false_positives": 0,
                "accuracy_rate": 0.0
            },
            "trends": [],
            "top_threats": [],
            "recommendations": []
        }
        
        # TODO: Implement actual report generation
        
        return {
            "report_id": str(uuid.uuid4()),
            "report_type": report_type,
            "time_range": f"{days} days",
            "data": report_data,
            "generated_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# YENİ GELİŞMİŞ ENDPOINT'LER - DEVAMI

@app.get("/security/dashboard")
async def get_security_dashboard():
    """🔒 Güvenlik dashboard verileri"""
    try:
        # Import security manager
        from security_manager import security_manager
        
        dashboard_data = security_manager.get_security_dashboard()
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "security_dashboard": dashboard_data
        }
        
    except Exception as e:
        logger.error(f"❌ Security dashboard error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/security/generate-api-key")
async def generate_new_api_key(permissions: List[str] = ["read"], rate_limit: int = 1000):
    """🔑 Yeni API anahtarı oluştur"""
    try:
        from security_manager import security_manager
        
        api_key = security_manager.generate_api_key(
            permissions=permissions,
            rate_limit=rate_limit
        )
        
        if api_key:
            return {
                "status": "success",
                "api_key": api_key,
                "permissions": permissions,
                "rate_limit": rate_limit,
                "created_at": datetime.now().isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to generate API key")
            
    except Exception as e:
        logger.error(f"❌ API key generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/system/dashboard")
async def get_system_dashboard():
    """📊 Sistem dashboard verileri"""
    try:
        from system_dashboard import system_dashboard
        
        dashboard_data = await system_dashboard.get_dashboard_data()
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "dashboard": dashboard_data
        }
        
    except Exception as e:
        logger.error(f"❌ System dashboard error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/ml/performance")
async def get_ml_performance():
    """🤖 ML model performans analizi"""
    try:
        from advanced_ml_features import advanced_ml_features
        
        performance_summary = advanced_ml_features.get_model_performance_summary()
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "model_performance": performance_summary,
            "ensemble_weights": advanced_ml_features.dynamic_weights
        }
        
    except Exception as e:
        logger.error(f"❌ ML performance error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/ml/optimize-ensemble")
async def optimize_ensemble_weights():
    """⚙️ Ensemble ağırlıklarını optimize et"""
    try:
        from advanced_ml_features import advanced_ml_features
        
        # Load models for optimization
        models = {}
        model_names = [
            'phishing_model', 'cybersecurity_model', 'phishing_urls_model',
            'website_model', 'crypto_scam_model', 'link_phishing_model', 'malicious_urls_model'
        ]
        
        for model_name in model_names:
            try:
                models[model_name] = joblib.load(f'{model_name}.pkl')
            except FileNotFoundError:
                logger.warning(f"Model file not found: {model_name}.pkl")
                continue
        
        # Use recent feedback as validation data (simplified example)
        validation_data = []  # In production, load from database
        
        optimized_weights = await advanced_ml_features.optimize_ensemble_weights(
            models, validation_data
        )
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "message": "Ensemble weights optimized",
            "optimized_weights": optimized_weights
        }
        
    except Exception as e:
        logger.error(f"❌ Ensemble optimization error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/behavioral/feedback")
async def submit_behavioral_feedback(url: str, predicted_label: str, 
                                  correct_label: str, confidence: float):
    """🧠 Davranışsal feedback gönder"""
    try:
        from advanced_ml_features import advanced_ml_features
        
        # Extract features for the URL (simplified)
        features = feature_extractor.extract_features(url)
        
        await advanced_ml_features.add_feedback(
            url, predicted_label, correct_label, features, confidence
        )
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "message": "Behavioral feedback recorded"
        }
        
    except Exception as e:
        logger.error(f"❌ Behavioral feedback error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/network/analyze/{domain}")
async def analyze_domain_network(domain: str, deep_scan: bool = False):
    """🌐 Domain network analizi"""
    try:
        from network_analyzer import network_analyzer
        
        # Construct URL for network analysis
        url = f"https://{domain}"
        
        network_analysis = await network_analyzer.analyze_url_network(url, deep_scan)
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "domain": domain,
            "network_analysis": network_analysis
        }
        
    except Exception as e:
        logger.error(f"❌ Network analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/content/analyze")
async def analyze_url_content(url: str, deep_scan: bool = False):
    """📄 URL içerik analizi"""
    try:
        from content_analyzer import content_analyzer
        
        content_analysis = await content_analyzer.analyze_url_content(url, deep_scan)
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "url": url,
            "content_analysis": content_analysis
        }
        
    except Exception as e:
        logger.error(f"❌ Content analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/behavioral/session/{session_id}")
async def get_session_behavior(session_id: str):
    """👤 Session davranış analizi"""
    try:
        from behavioral_analyzer import behavioral_analyzer
        
        session_analysis = behavioral_analyzer.get_session_analysis(session_id)
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "session_id": session_id,
            "behavioral_analysis": session_analysis
        }
        
    except Exception as e:
        logger.error(f"❌ Session behavior analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/threats/monitor")
async def get_threat_monitoring_status():
    """⚠️ Tehdit izleme durumu"""
    try:
        try:
            from real_time_threat_monitor import real_time_threat_monitor
            monitoring_status = real_time_threat_monitor.get_metrics()
        except ImportError:
            # real_time_threat_monitor instance'ı yoksa, RealTimeThreatMonitor class'ından instance oluştur
            from real_time_threat_monitor import RealTimeThreatMonitor
            temp_monitor = RealTimeThreatMonitor()
            monitoring_status = temp_monitor.get_metrics()
            
            return {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "threat_monitoring": monitoring_status
            }
        
    except Exception as e:
        logger.error(f"❌ Threat monitoring status error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/system/restart-monitoring")
async def restart_system_monitoring():
    """🔄 Sistem izlemeyi yeniden başlat"""
    try:
        from system_dashboard import system_dashboard
        
        # Stop and restart monitoring
        system_dashboard.stop_monitoring()
        await asyncio.sleep(2)  # Brief pause
        system_dashboard.start_monitoring()
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "message": "System monitoring restarted"
        }
        
    except Exception as e:
        logger.error(f"❌ Restart monitoring error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/usage-stats")
async def get_api_usage_statistics():
    """📈 API kullanım istatistikleri"""
    try:
        from security_manager import security_manager
        
        # Get API usage stats from security manager
        usage_stats = {
            "total_api_keys": len(security_manager.api_keys),
            "rate_limited_requests": len(security_manager.rate_limits),
            "security_incidents": len(security_manager.security_incidents),
            "blocked_ips": len(security_manager.blocked_ips),
            "api_key_usage": {}
        }
        
        # API key usage details
        for api_key, usage_data in security_manager.api_key_usage.items():
            masked_key = api_key[:8] + "..."
            usage_stats["api_key_usage"][masked_key] = {
                "request_count": len(usage_data["requests"]),
                "last_used": usage_data["last_used"].isoformat() if usage_data["last_used"] else None,
                "rate_limit": usage_data["rate_limit"]
            }
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "usage_statistics": usage_stats
        }
        
    except Exception as e:
        logger.error(f"❌ Usage statistics error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health/advanced")
async def advanced_health_check():
    """🏥 Gelişmiş sistem sağlık kontrolü"""
    try:
        health_data = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "components": {},
            "performance": {},
            "resources": {}
        }
        
        # Component health checks
        try:
            from system_dashboard import system_dashboard
            dashboard_data = await system_dashboard.get_dashboard_data()
            health_data["components"]["system_dashboard"] = "operational"
            health_data["performance"] = dashboard_data.get("performance_summary", {})
        except Exception as e:
            health_data["components"]["system_dashboard"] = f"error: {str(e)}"
        
        try:
            from security_manager import security_manager
            security_dashboard = security_manager.get_security_dashboard()
            health_data["components"]["security_manager"] = "operational"
        except Exception as e:
            health_data["components"]["security_manager"] = f"error: {str(e)}"
        
        try:
            from advanced_ml_features import advanced_ml_features
            ml_performance = advanced_ml_features.get_model_performance_summary()
            health_data["components"]["ml_features"] = "operational"
        except Exception as e:
            health_data["components"]["ml_features"] = f"error: {str(e)}"
        
        # Resource usage
        import psutil
        health_data["resources"] = {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent if psutil.disk_usage('/') else 0
        }
        
        # Determine overall status
        component_errors = [comp for comp in health_data["components"].values() if "error" in str(comp)]
        if component_errors:
            health_data["status"] = "degraded"
        
        if health_data["resources"]["cpu_percent"] > 90 or health_data["resources"]["memory_percent"] > 90:
            health_data["status"] = "warning"
        
        return health_data
        
    except Exception as e:
        logger.error(f"❌ Advanced health check error: {e}")
        return {
            "status": "error",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }

@app.post("/behavioral/track")
async def track_behavioral_data(behavioral_data: Dict[str, Any]):
    """🎯 Gerçek behavioral tracking endpoint"""
    try:
        if not REAL_BEHAVIORAL_ENABLED:
            return {
                "status": "disabled",
                "message": "Real behavioral tracking is not enabled"
            }
        
        session_id = behavioral_data.get('sessionId')
        if not session_id:
            return {
                "status": "error",
                "message": "Session ID is required"
            }
        
        logger.info(f"🎯 Received behavioral data for session: {session_id}")
        
        # Analyze behavioral data
        analysis_result = await real_behavioral_analyzer.analyze_behavioral_data(
            session_id, behavioral_data
        )
        
        return {
            "status": "success",
            "session_id": session_id,
            "analysis": analysis_result,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"❌ Behavioral tracking error: {e}")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }

@app.get("/behavioral/session/{session_id}/summary")
async def get_behavioral_session_summary(session_id: str):
    """📊 Get behavioral session summary"""
    try:
        if not REAL_BEHAVIORAL_ENABLED:
            return {
                "status": "disabled",
                "message": "Real behavioral tracking is not enabled"
            }
        
        summary = real_behavioral_analyzer.get_session_summary(session_id)
        return {
            "status": "success",
            "summary": summary,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"❌ Session summary error: {e}")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }

@app.get("/analysis/log/{session_id}")
async def get_analysis_log(session_id: str):
    """📋 Get detailed analysis log for a session"""
    try:
        logger.info(f"📋 Getting analysis log for session: {session_id}")
        
        # Bu endpoint real-time analysis log'ları döndürecek
        # Şimdilik placeholder response döndürüyoruz
        return {
            "status": "success",
            "session_id": session_id,
            "message": "Analysis log endpoint ready - will return detailed step-by-step analysis logs",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"❌ Analysis log error: {e}")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }

@app.get("/analysis/stream/{session_id}")
async def stream_analysis_log(session_id: str):
    """📡 Real-time analysis log streaming (SSE)"""
    try:
        from fastapi.responses import StreamingResponse
        import asyncio
        import json
        
        async def event_stream():
            # Bu SSE (Server-Sent Events) stream'i analysis süresince
            # gerçek zamanlı güncellemeler gönderecek
            yield f"data: {json.dumps({'status': 'connected', 'session_id': session_id})}\n\n"
            
            # Demo stream - gerçek implementation için analysis_logger'dan
            # gerçek zamanlı event'ler gönderilecek
            for i in range(5):
                await asyncio.sleep(1)
                demo_step = {
                    "step_number": i + 1,
                    "phase_name": f"Demo Phase {i + 1}",
                    "step_name": f"Demo Step {i + 1}",
                    "status": "completed" if i < 4 else "processing",
                    "timestamp": datetime.now().isoformat(),
                    "duration_ms": 500 + (i * 100),
                    "details": {"message": f"Demo message for step {i + 1}"}
                }
                yield f"data: {json.dumps(demo_step)}\n\n"
            
            # Final completion
            yield f"data: {json.dumps({'status': 'completed', 'session_id': session_id})}\n\n"
        
        return StreamingResponse(
            event_stream(),
            media_type="text/plain",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Content-Type": "text/event-stream"
            }
        )
        
    except Exception as e:
        logger.error(f"❌ Analysis stream error: {e}")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081) 