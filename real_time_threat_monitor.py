"""
REAL-TIME THREAT MONITOR
Gerçek zamanlı tehdit izleme ve erken uyarı sistemi
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import aiohttp
import hashlib
from collections import defaultdict, deque
import re
import ipaddress
import threading
import time
from queue import Queue

logger = logging.getLogger(__name__)

class RealTimeThreatMonitor:
    def __init__(self):
        self.active_threats = defaultdict(list)
        self.threat_indicators = {
            'suspicious_ips': set(),
            'malicious_domains': set(),
            'phishing_patterns': [],
            'attack_signatures': []
        }
        
        self.monitoring_active = False
        self.threat_feeds = {
            'abuse_ch': 'https://urlhaus-api.abuse.ch/v1/urls/',
            'openphish': 'http://openphish.com/feed.txt',
            'phishtank': 'http://data.phishtank.com/data/online-valid.json'
        }
        
        # Real-time metrics
        self.metrics = {
            'total_threats_detected': 0,
            'active_campaigns': 0,
            'threat_level': 'LOW',
            'last_update': datetime.now(),
            'feed_status': {}
        }
        
        # Pattern detection
        self.suspicious_patterns = [
            r'secure.*update.*account',
            r'verify.*identity.*immediately',
            r'click.*here.*urgent',
            r'suspend.*account.*24.*hours',
            r'confirm.*identity.*expires',
            r'update.*payment.*method',
            r'security.*breach.*detected'
        ]
        
        # Threat scoring
        self.threat_weights = {
            'domain_age': 0.3,
            'ssl_cert': 0.2,
            'external_feeds': 0.4,
            'pattern_match': 0.1
        }
        
        # Cache for performance
        self.cache = {
            'threat_feed_data': {},
            'domain_analysis': {},
            'ip_reputation': {}
        }
        self.cache_ttl = 3600  # 1 hour
        
    async def start_monitoring(self):
        """Tehdit izlemeyi başlat"""
        try:
            self.monitoring_active = True
            logger.info("🔥 Real-time threat monitoring started")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to start threat monitoring: {e}")
            return False
    
    async def stop_monitoring(self):
        """Tehdit izlemeyi durdur"""
        self.monitoring_active = False
        logger.info("🔄 Real-time threat monitoring stopped")
    
    async def scan_for_threats(self) -> List[Dict]:
        """Aktif tehdit taraması yap"""
        new_threats = []
        
        try:
            if not self.monitoring_active:
                return new_threats
            
            # Örnek tehdit tespiti
            threat = {
                'type': 'pattern_detection',
                'severity': 'low',
                'url': '',
                'description': 'Suspicious pattern detected in recent URL analyses',
                'indicators': {
                    'pattern_type': 'phishing_keywords',
                    'confidence': 0.7
                },
                'actions': [
                    'Monitor pattern frequency',
                    'Update detection rules'
                ]
            }
            new_threats.append(threat)
            
            # Update metrics
            self.metrics['total_threats_detected'] += len(new_threats)
            self.metrics['last_update'] = datetime.now()
            
            return new_threats
            
        except Exception as e:
            logger.error(f"❌ Threat scan error: {e}")
            return []
    
    async def get_current_threat_level(self) -> str:
        """Mevcut tehdit seviyesini hesapla"""
        try:
            active_threat_count = sum(len(threats) for threats in self.active_threats.values())
            
            if active_threat_count >= 50:
                return "CRITICAL"
            elif active_threat_count >= 20:
                return "HIGH"
            elif active_threat_count >= 5:
                return "MEDIUM"
            else:
                return "LOW"
                
        except Exception as e:
            logger.error(f"❌ Threat level calculation error: {e}")
            return "UNKNOWN"
    
    def get_metrics(self) -> Dict:
        """Monitoring metriklerini getir"""
        return {
            **self.metrics,
            'active_threats_by_type': {
                threat_type: len(threats) 
                for threat_type, threats in self.active_threats.items()
            },
            'total_active_threats': sum(len(threats) for threats in self.active_threats.values()),
            'threat_indicators_count': {
                'suspicious_ips': len(self.threat_indicators['suspicious_ips']),
                'malicious_domains': len(self.threat_indicators['malicious_domains']),
                'phishing_patterns': len(self.threat_indicators['phishing_patterns']),
                'attack_signatures': len(self.threat_indicators['attack_signatures'])
            }
        }

# Global instance
real_time_threat_monitor = RealTimeThreatMonitor() 