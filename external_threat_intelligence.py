"""
EXTERNAL THREAT INTELLIGENCE
Google Safe Browsing ve VirusTotal API'leri kullanarak URL güvenlik kontrolü
"""

import os
import logging
import asyncio
import aiohttp
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Logging configuration
logger = logging.getLogger(__name__)

class ExternalThreatIntelligence:
    """
    Gelişmiş Harici Tehdit İstihbaratı
    Google Safe Browsing ve VirusTotal API'leri kullanarak URL güvenlik kontrolü
    """
    
    def __init__(self):
        # API Keys (environment variables'dan al)
        self.google_safe_browsing_api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        
        # API URLs
        self.google_safe_browsing_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.virustotal_url = "https://www.virustotal.com/vtapi/v2/url/report"
        
        # Cache sistemi
        self.cache = {}
        self.cache_ttl = timedelta(hours=6)  # 6 saat cache
        
        # Rate limiting
        self.rate_limits = {
            'google': {'requests': [], 'limit': 10000, 'window': timedelta(hours=24)},
            'virustotal': {'requests': [], 'limit': 1000, 'window': timedelta(minutes=1)}
        }
        
        # Request timeouts
        self.timeout = 5  # 5 saniye timeout
    
    async def check_all_apis(self, url: str) -> Dict:
        """Google Safe Browsing ve VirusTotal API'leri paralel olarak kontrol et"""
        try:
            # Cache kontrolü
            cache_key = hashlib.md5(url.encode()).hexdigest()
            if cache_key in self.cache:
                cache_entry = self.cache[cache_key]
                if datetime.now() - cache_entry['timestamp'] < self.cache_ttl:
                    logger.info(f"🎯 Cache hit for: {url}")
                    return cache_entry['result']
            
            # Paralel API çağrıları
            tasks = []
            
            if self.google_safe_browsing_api_key:
                tasks.append(self._check_google_safe_browsing(url))
            
            if self.virustotal_api_key:
                tasks.append(self._check_virustotal(url))
            
            # Eğer API key yok ise empty result
            if not tasks:
                return self._create_empty_result("No API keys configured")
            
            # API çağrılarını paralel çalıştır
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Sonuçları aggregate et
            aggregated_result = self._aggregate_api_results(url, results)
            
            # Cache'e kaydet
            self.cache[cache_key] = {
                'result': aggregated_result,
                'timestamp': datetime.now()
            }
            
            return aggregated_result
            
        except Exception as e:
            logger.error(f"❌ Check all APIs error: {e}")
            return self._create_empty_result(f"API check failed: {str(e)}")

    async def _check_google_safe_browsing(self, url: str) -> Dict:
        """Google Safe Browsing API kontrolü"""
        try:
            # Rate limit kontrolü
            if not self._check_rate_limit('google', 10000, timedelta(hours=24)):  # 10k/day
                return {'source': 'google_safe_browsing', 'error': 'Rate limit exceeded'}
            
            payload = {
                "client": {
                    "clientId": "phishing-detector",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ALL_PLATFORMS"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            headers = {
                'Content-Type': 'application/json'
            }
            
            api_url = f"{self.google_safe_browsing_url}?key={self.google_safe_browsing_api_key}"
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.post(api_url, json=payload, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        result = {
                            'source': 'google_safe_browsing',
                            'status': 'success',
                            'is_phishing': False,
                            'confidence': 0.0,
                            'details': {}
                        }
                        
                        # Google Safe Browsing response
                        if 'matches' in data and data['matches']:
                            result['is_phishing'] = True
                            result['confidence'] = 0.95  # Google güvenilir
                            result['details'] = {
                                'threat_types': [match.get('threatType') for match in data['matches']],
                                'platform_types': [match.get('platformType') for match in data['matches']],
                                'cache_duration': data['matches'][0].get('cacheDuration', '300s')
                            }
                        
                        return result
                    else:
                        return {'source': 'google_safe_browsing', 'error': f'HTTP {response.status}'}
                        
        except asyncio.TimeoutError:
            logger.warning("⏱️ Google Safe Browsing API timeout")
            return {'source': 'google_safe_browsing', 'error': 'Timeout'}
        except Exception as e:
            logger.error(f"❌ Google Safe Browsing API error: {e}")
            return {'source': 'google_safe_browsing', 'error': str(e)}
    
    async def _check_virustotal(self, url: str) -> Dict:
        """VirusTotal API kontrolü"""
        try:
            # Rate limit kontrolü  
            if not self._check_rate_limit('virustotal', 1000, timedelta(minutes=1)):  # 1000/min for premium
                return {'source': 'virustotal', 'error': 'Rate limit exceeded'}
            
            params = {
                'apikey': self.virustotal_api_key,
                'resource': url,
                'scan': 0  # Sadece rapor al, yeni scan başlatma
            }
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.get(self.virustotal_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        result = {
                            'source': 'virustotal',
                            'status': 'success',
                            'is_phishing': False,
                            'confidence': 0.0,
                            'details': {}
                        }
                        
                        # VirusTotal response
                        if data.get('response_code') == 1:  # URL found
                            positives = data.get('positives', 0)
                            total = data.get('total', 0)
                            
                            if total > 0:
                                threat_ratio = positives / total
                                
                                # Threat seviyesine göre confidence
                                if threat_ratio >= 0.3:  # %30+ detection = yüksek risk
                                    result['is_phishing'] = True
                                    result['confidence'] = min(0.9, 0.5 + threat_ratio)
                                elif threat_ratio >= 0.1:  # %10-30 = orta risk
                                    result['confidence'] = threat_ratio * 0.5
                                
                                result['details'] = {
                                    'positives': positives,
                                    'total': total,
                                    'threat_ratio': threat_ratio,
                                    'scan_date': data.get('scan_date'),
                                    'permalink': data.get('permalink')
                                }
                        
                        return result
                    else:
                        return {'source': 'virustotal', 'error': f'HTTP {response.status}'}
                        
        except asyncio.TimeoutError:
            logger.warning("⏱️ VirusTotal API timeout")
            return {'source': 'virustotal', 'error': 'Timeout'}
        except Exception as e:
            logger.error(f"❌ VirusTotal API error: {e}")
            return {'source': 'virustotal', 'error': str(e)}

    def _check_rate_limit(self, api_name: str, limit: int, time_window: timedelta) -> bool:
        """Rate limit kontrolü"""
        try:
            now = datetime.now()
            
            if api_name not in self.rate_limits:
                self.rate_limits[api_name] = {'requests': [], 'limit': limit, 'window': time_window}
            
            # Eski istekleri temizle
            cutoff_time = now - time_window
            self.rate_limits[api_name]['requests'] = [
                req_time for req_time in self.rate_limits[api_name]['requests'] 
                if req_time > cutoff_time
            ]
            
            # Limit kontrolü
            if len(self.rate_limits[api_name]['requests']) >= limit:
                return False
            
            # Yeni isteği kaydet
            self.rate_limits[api_name]['requests'].append(now)
            return True
            
        except Exception as e:
            logger.error(f"❌ Rate limit check error: {e}")
            return True  # Hata durumunda allow et

    def _aggregate_api_results(self, url: str, results: List) -> Dict:
        """API sonuçlarını birleştir ve final karar ver"""
        try:
            aggregated = {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'apis_checked': 0,
                'apis_available': 0,
                'is_phishing': False,
                'confidence_score': 0.0,
                'threat_level': 'safe',
                'sources': [],
                'errors': []
            }
            
            valid_results = []
            
            for result in results:
                if isinstance(result, Exception):
                    aggregated['errors'].append(str(result))
                    continue
                
                if isinstance(result, dict):
                    if 'error' in result:
                        aggregated['errors'].append(f"{result.get('source', 'unknown')}: {result['error']}")
                    else:
                        valid_results.append(result)
                        aggregated['sources'].append(result.get('source', 'unknown'))
            
            aggregated['apis_checked'] = len(valid_results)
            aggregated['apis_available'] = len([r for r in results if not isinstance(r, Exception)])
            
            if not valid_results:
                aggregated['threat_level'] = 'unknown'
                return aggregated
            
            # Weighted voting system
            phishing_votes = 0
            total_confidence = 0
            high_confidence_sources = []
            
            for result in valid_results:
                confidence = result.get('confidence', 0.0)
                is_phishing = result.get('is_phishing', False)
                source = result.get('source', 'unknown')
                
                # Source-based weighting
                source_weight = 1.0
                if source == 'google_safe_browsing':
                    source_weight = 1.5  # Google daha güvenilir
                elif source == 'virustotal':
                    source_weight = 1.2
                
                weighted_confidence = confidence * source_weight
                total_confidence += weighted_confidence
                
                if is_phishing:
                    phishing_votes += weighted_confidence
                    if confidence >= 0.7:
                        high_confidence_sources.append(source)
            
            # Final decision
            if valid_results:
                avg_confidence = total_confidence / len(valid_results)
                phishing_probability = phishing_votes / max(total_confidence, 0.1)
                
                # Threat level belirleme
                if phishing_probability >= 0.7 or high_confidence_sources:
                    aggregated['is_phishing'] = True
                    aggregated['threat_level'] = 'high'
                    aggregated['confidence_score'] = min(0.95, avg_confidence)
                elif phishing_probability >= 0.3:
                    aggregated['threat_level'] = 'medium'
                    aggregated['confidence_score'] = avg_confidence * 0.7
                else:
                    aggregated['threat_level'] = 'safe'
                    aggregated['confidence_score'] = max(0.1, 1.0 - avg_confidence)
            
            logger.info(f"🔍 External API analysis: {url} → {aggregated['threat_level']} (confidence: {aggregated['confidence_score']:.3f})")
            return aggregated
            
        except Exception as e:
            logger.error(f"❌ Aggregate results error: {e}")
            return self._create_empty_result(f"Aggregation failed: {str(e)}")

    def _create_empty_result(self, reason: str) -> Dict:
        """Boş/hata sonucu oluştur"""
        return {
            'url': '',
            'timestamp': datetime.now().isoformat(),
            'apis_checked': 0,
            'apis_available': 0,
            'is_phishing': False,
            'confidence_score': 0.0,
            'threat_level': 'unknown',
            'sources': [],
            'errors': [reason]
        }

    def clear_cache(self):
        """Cache'i temizle"""
        self.cache.clear()
        logger.info("🧹 External API cache cleared")

    def get_cache_stats(self) -> Dict:
        """Cache istatistikleri"""
        return {
            'total_entries': len(self.cache),
            'cache_ttl_hours': self.cache_ttl.total_seconds() / 3600,
            'rate_limits': {
                api: {
                    'requests_in_window': len(data['requests']),
                    'limit': data['limit'],
                    'window_minutes': data['window'].total_seconds() / 60
                }
                for api, data in self.rate_limits.items()
            }
        }

# Global instance
external_intel = ExternalThreatIntelligence()

# Async helper function for non-async contexts
def check_url_external_apis(url: str) -> Dict:
    """Sync wrapper for async API checks"""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Eğer zaten bir event loop çalışıyorsa, task oluştur
            task = asyncio.create_task(external_intel.check_all_apis(url))
            return asyncio.run_coroutine_threadsafe(task, loop).result(timeout=10)
        else:
            # Yeni event loop oluştur
            return asyncio.run(external_intel.check_all_apis(url))
    except Exception as e:
        logger.error(f"❌ Sync wrapper error: {e}")
        return external_intel._create_empty_result(f"Sync wrapper failed: {str(e)}") 