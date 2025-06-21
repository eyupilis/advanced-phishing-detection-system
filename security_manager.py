"""
SECURITY MANAGER
Gelişmiş güvenlik özellikleri: rate limiting, authentication, encryption
"""

import asyncio
import logging
import hashlib
import hmac
import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
import secrets
import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import ipaddress
import re
import threading

logger = logging.getLogger(__name__)

class SecurityManager:
    def __init__(self):
        # Rate limiting storage
        self.rate_limits = defaultdict(lambda: {
            'requests': deque(maxlen=1000),
            'blocked_until': None,
            'violation_count': 0
        })
        
        # API Key management
        self.api_keys = {}
        self.api_key_usage = defaultdict(lambda: {
            'requests': deque(maxlen=10000),
            'last_used': None,
            'rate_limit': 1000  # requests per hour
        })
        
        # Security incidents tracking
        self.security_incidents = deque(maxlen=1000)
        
        # Blocked IPs and domains
        self.blocked_ips = set()
        self.blocked_domains = set()
        
        # Rate limiting configuration
        self.rate_limit_config = {
            'default': {'requests': 100, 'window': 3600},  # 100 req/hour
            'premium': {'requests': 1000, 'window': 3600}, # 1000 req/hour
            'analyze_endpoint': {'requests': 50, 'window': 300},  # 50 req/5min
            'feedback_endpoint': {'requests': 20, 'window': 3600} # 20 req/hour
        }
        
        # Suspicious patterns
        self.suspicious_patterns = {
            'user_agents': [
                r'bot|crawler|spider|scraper',
                r'automated|script|tool',
                r'python|curl|wget|postman',
                r'scanner|exploit|attack'
            ],
            'ips': [
                r'^10\.',      # Private IP
                r'^192\.168\.', # Private IP
                r'^172\.(1[6-9]|2[0-9]|3[01])\.',  # Private IP
                r'^127\.',     # Localhost
                r'^0\.',       # Invalid
            ],
            'urls': [
                r'\.exe$',     # Executable files
                r'\.zip$',     # Archives
                r'\.rar$',
                r'admin',      # Admin panels
                r'wp-admin',   # WordPress admin
                r'phpmyadmin', # Database admin
            ]
        }
        
        # Encryption setup
        self.encryption_key = self._generate_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # Security monitoring
        self.security_metrics = {
            'total_requests': 0,
            'blocked_requests': 0,
            'security_incidents': 0,
            'rate_limited_ips': set(),
            'last_attack_attempt': None,
            'attack_patterns': defaultdict(int)
        }
        
        # Thread safety
        self.security_lock = threading.Lock()
        
    def _generate_encryption_key(self) -> bytes:
        """Encryption key oluştur"""
        try:
            # In production, this should be loaded from secure storage
            password = b"phishing_detector_secure_key_2024"
            salt = b"phishing_salt_unique_value"
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            return key
            
        except Exception as e:
            logger.error(f"❌ Encryption key generation error: {e}")
            return Fernet.generate_key()
    
    async def check_rate_limit(self, identifier: str, endpoint: str = 'default', 
                             api_key: Optional[str] = None) -> Dict:
        """Rate limiting kontrolü"""
        try:
            with self.security_lock:
                current_time = time.time()
                
                # Determine rate limit config
                config = self.rate_limit_config.get(endpoint, self.rate_limit_config['default'])
                
                # API key based limits
                if api_key and api_key in self.api_key_usage:
                    api_usage = self.api_key_usage[api_key]
                    config = {'requests': api_usage['rate_limit'], 'window': 3600}
                
                # Check if currently blocked
                limit_data = self.rate_limits[identifier]
                if limit_data['blocked_until'] and current_time < limit_data['blocked_until']:
                    time_left = int(limit_data['blocked_until'] - current_time)
                    return {
                        'allowed': False,
                        'reason': 'rate_limited',
                        'retry_after': time_left,
                        'message': f'Rate limited. Try again in {time_left} seconds.'
                    }
                
                # Clean old requests
                window_start = current_time - config['window']
                requests = limit_data['requests']
                while requests and requests[0] < window_start:
                    requests.popleft()
                
                # Check current rate
                current_requests = len(requests)
                
                if current_requests >= config['requests']:
                    # Rate limit exceeded
                    block_duration = min(300 * (limit_data['violation_count'] + 1), 3600)  # Max 1 hour
                    limit_data['blocked_until'] = current_time + block_duration
                    limit_data['violation_count'] += 1
                    
                    # Log security incident
                    self._log_security_incident('rate_limit_exceeded', {
                        'identifier': identifier,
                        'endpoint': endpoint,
                        'requests_count': current_requests,
                        'limit': config['requests'],
                        'block_duration': block_duration
                    })
                    
                    return {
                        'allowed': False,
                        'reason': 'rate_limit_exceeded',
                        'retry_after': block_duration,
                        'requests_remaining': 0,
                        'reset_time': current_time + config['window']
                    }
                
                # Allow request and track it
                requests.append(current_time)
                
                # Track API key usage
                if api_key:
                    self.api_key_usage[api_key]['requests'].append(current_time)
                    self.api_key_usage[api_key]['last_used'] = datetime.now()
                
                return {
                    'allowed': True,
                    'requests_remaining': config['requests'] - current_requests - 1,
                    'reset_time': current_time + config['window'],
                    'limit': config['requests']
                }
                
        except Exception as e:
            logger.error(f"❌ Rate limit check error: {e}")
            return {
                'allowed': True,  # Fail open for availability
                'error': str(e)
            }
    
    async def validate_api_key(self, api_key: str) -> Dict:
        """API key doğrulama"""
        try:
            if not api_key:
                return {
                    'valid': False,
                    'reason': 'missing_api_key',
                    'message': 'API key is required'
                }
            
            # Check if API key exists and is valid
            if api_key in self.api_keys:
                key_info = self.api_keys[api_key]
                
                # Check expiration
                if 'expires_at' in key_info:
                    if datetime.now() > datetime.fromisoformat(key_info['expires_at']):
                        return {
                            'valid': False,
                            'reason': 'expired_api_key',
                            'message': 'API key has expired'
                        }
                
                # Check if key is active
                if not key_info.get('active', True):
                    return {
                        'valid': False,
                        'reason': 'inactive_api_key',
                        'message': 'API key is inactive'
                    }
                
                return {
                    'valid': True,
                    'key_info': key_info,
                    'permissions': key_info.get('permissions', ['read']),
                    'rate_limit': key_info.get('rate_limit', 1000)
                }
            
            # Invalid API key
            self._log_security_incident('invalid_api_key', {
                'api_key': api_key[:8] + '...',  # Log only first 8 chars
                'timestamp': datetime.now().isoformat()
            })
            
            return {
                'valid': False,
                'reason': 'invalid_api_key',
                'message': 'Invalid API key'
            }
            
        except Exception as e:
            logger.error(f"❌ API key validation error: {e}")
            return {
                'valid': False,
                'reason': 'validation_error',
                'message': 'API key validation failed'
            }
    
    async def analyze_request_security(self, request_data: Dict) -> Dict:
        """Request güvenlik analizi"""
        try:
            security_analysis = {
                'risk_score': 0.0,
                'security_flags': [],
                'recommendations': [],
                'block_request': False
            }
            
            # Analyze IP address
            ip_analysis = await self._analyze_ip_security(request_data.get('client_ip'))
            security_analysis['risk_score'] += ip_analysis['risk_score'] * 0.3
            security_analysis['security_flags'].extend(ip_analysis['flags'])
            
            # Analyze User Agent
            ua_analysis = await self._analyze_user_agent(request_data.get('user_agent'))
            security_analysis['risk_score'] += ua_analysis['risk_score'] * 0.2
            security_analysis['security_flags'].extend(ua_analysis['flags'])
            
            # Analyze request patterns
            pattern_analysis = await self._analyze_request_patterns(request_data)
            security_analysis['risk_score'] += pattern_analysis['risk_score'] * 0.3
            security_analysis['security_flags'].extend(pattern_analysis['flags'])
            
            # Analyze payload
            if 'payload' in request_data:
                payload_analysis = await self._analyze_payload_security(request_data['payload'])
                security_analysis['risk_score'] += payload_analysis['risk_score'] * 0.2
                security_analysis['security_flags'].extend(payload_analysis['flags'])
            
            # Determine if request should be blocked
            if security_analysis['risk_score'] > 0.8:
                security_analysis['block_request'] = True
                security_analysis['recommendations'].append('Block this request immediately')
                
                # Log high-risk request
                self._log_security_incident('high_risk_request', {
                    'risk_score': security_analysis['risk_score'],
                    'flags': security_analysis['security_flags'],
                    'client_ip': request_data.get('client_ip'),
                    'user_agent': request_data.get('user_agent')
                })
            
            # Generate recommendations
            recommendations = self._generate_security_recommendations(security_analysis)
            security_analysis['recommendations'].extend(recommendations)
            
            return security_analysis
            
        except Exception as e:
            logger.error(f"❌ Request security analysis error: {e}")
            return {
                'risk_score': 0.5,
                'security_flags': ['analysis_error'],
                'block_request': False,
                'error': str(e)
            }
    
    async def _analyze_ip_security(self, ip_address: Optional[str]) -> Dict:
        """IP güvenlik analizi"""
        try:
            analysis = {
                'risk_score': 0.0,
                'flags': []
            }
            
            if not ip_address:
                analysis['flags'].append('missing_ip')
                analysis['risk_score'] = 0.3
                return analysis
            
            # Check if IP is blocked
            if ip_address in self.blocked_ips:
                analysis['flags'].append('blocked_ip')
                analysis['risk_score'] = 1.0
                return analysis
            
            # Check suspicious IP patterns
            for pattern in self.suspicious_patterns['ips']:
                if re.match(pattern, ip_address):
                    analysis['flags'].append('suspicious_ip_pattern')
                    analysis['risk_score'] += 0.4
                    break
            
            # Check if private IP used publicly
            try:
                ip_obj = ipaddress.ip_address(ip_address)
                if ip_obj.is_private:
                    analysis['flags'].append('private_ip_public_request')
                    analysis['risk_score'] += 0.5
                elif ip_obj.is_loopback:
                    analysis['flags'].append('loopback_ip')
                    analysis['risk_score'] += 0.7
            except ValueError:
                analysis['flags'].append('invalid_ip_format')
                analysis['risk_score'] += 0.3
            
            # Check IP reputation (simplified)
            if self._is_known_malicious_ip(ip_address):
                analysis['flags'].append('known_malicious_ip')
                analysis['risk_score'] += 0.8
            
            return analysis
            
        except Exception as e:
            logger.error(f"❌ IP security analysis error: {e}")
            return {'risk_score': 0.3, 'flags': ['ip_analysis_error']}
    
    def _is_known_malicious_ip(self, ip_address: str) -> bool:
        """Bilinen kötü niyetli IP kontrolü"""
        try:
            # In production, this would check against threat intelligence feeds
            # For now, simple check against common attack IPs
            malicious_ranges = [
                '185.220.',  # Example Tor exit nodes
                '198.96.',   # Example malicious range
                '46.166.'    # Example malicious range
            ]
            
            return any(ip_address.startswith(range_prefix) for range_prefix in malicious_ranges)
            
        except:
            return False
    
    async def _analyze_user_agent(self, user_agent: Optional[str]) -> Dict:
        """User Agent güvenlik analizi"""
        try:
            analysis = {
                'risk_score': 0.0,
                'flags': []
            }
            
            if not user_agent:
                analysis['flags'].append('missing_user_agent')
                analysis['risk_score'] = 0.4
                return analysis
            
            # Check suspicious patterns
            for pattern in self.suspicious_patterns['user_agents']:
                if re.search(pattern, user_agent, re.IGNORECASE):
                    analysis['flags'].append('suspicious_user_agent')
                    analysis['risk_score'] += 0.5
                    break
            
            # Check for very short or very long user agents
            if len(user_agent) < 10:
                analysis['flags'].append('too_short_user_agent')
                analysis['risk_score'] += 0.3
            elif len(user_agent) > 500:
                analysis['flags'].append('too_long_user_agent')
                analysis['risk_score'] += 0.2
            
            # Check for common attack tools
            attack_tools = ['sqlmap', 'nikto', 'nmap', 'masscan', 'zap']
            if any(tool in user_agent.lower() for tool in attack_tools):
                analysis['flags'].append('attack_tool_user_agent')
                analysis['risk_score'] += 0.8
            
            return analysis
            
        except Exception as e:
            logger.error(f"❌ User agent analysis error: {e}")
            return {'risk_score': 0.2, 'flags': ['user_agent_analysis_error']}
    
    async def _analyze_request_patterns(self, request_data: Dict) -> Dict:
        """Request pattern analizi"""
        try:
            analysis = {
                'risk_score': 0.0,
                'flags': []
            }
            
            # Check request frequency from same IP
            ip = request_data.get('client_ip')
            if ip and ip in self.rate_limits:
                recent_requests = len(self.rate_limits[ip]['requests'])
                if recent_requests > 50:  # Very high frequency
                    analysis['flags'].append('high_frequency_requests')
                    analysis['risk_score'] += 0.4
            
            # Check URL patterns
            url = request_data.get('url', '')
            for pattern in self.suspicious_patterns['urls']:
                if re.search(pattern, url, re.IGNORECASE):
                    analysis['flags'].append('suspicious_url_pattern')
                    analysis['risk_score'] += 0.3
                    break
            
            # Check request timing patterns
            current_hour = datetime.now().hour
            if 2 <= current_hour <= 6:  # Late night activity
                analysis['flags'].append('unusual_timing')
                analysis['risk_score'] += 0.1
            
            return analysis
            
        except Exception as e:
            logger.error(f"❌ Request pattern analysis error: {e}")
            return {'risk_score': 0.2, 'flags': ['pattern_analysis_error']}
    
    async def _analyze_payload_security(self, payload: Dict) -> Dict:
        """Payload güvenlik analizi"""
        try:
            analysis = {
                'risk_score': 0.0,
                'flags': []
            }
            
            # Check payload size
            payload_str = json.dumps(payload)
            if len(payload_str) > 10000:  # Very large payload
                analysis['flags'].append('large_payload')
                analysis['risk_score'] += 0.2
            
            # Check for injection patterns
            injection_patterns = [
                r'<script.*?>.*?</script>',  # XSS
                r'union.*select',            # SQL injection
                r'../.*/',                   # Path traversal
                r'eval\s*\(',               # Code injection
            ]
            
            for pattern in injection_patterns:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    analysis['flags'].append('injection_attempt')
                    analysis['risk_score'] += 0.7
                    break
            
            # Check for suspicious keywords
            suspicious_keywords = [
                'admin', 'root', 'password', 'passwd', 'shadow',
                'config', 'database', 'db_password', 'api_key'
            ]
            
            for keyword in suspicious_keywords:
                if keyword in payload_str.lower():
                    analysis['flags'].append('suspicious_keyword')
                    analysis['risk_score'] += 0.2
                    break
            
            return analysis
            
        except Exception as e:
            logger.error(f"❌ Payload security analysis error: {e}")
            return {'risk_score': 0.2, 'flags': ['payload_analysis_error']}
    
    def _generate_security_recommendations(self, security_analysis: Dict) -> List[str]:
        """Güvenlik önerileri oluştur"""
        recommendations = []
        flags = security_analysis.get('security_flags', [])
        risk_score = security_analysis.get('risk_score', 0)
        
        if risk_score > 0.6:
            recommendations.append("🚨 High security risk detected")
        
        if 'blocked_ip' in flags or 'known_malicious_ip' in flags:
            recommendations.append("🚫 Block this IP address immediately")
        
        if 'suspicious_user_agent' in flags or 'attack_tool_user_agent' in flags:
            recommendations.append("🤖 Potential automated attack tool detected")
        
        if 'injection_attempt' in flags:
            recommendations.append("💉 Injection attack attempt detected")
        
        if 'high_frequency_requests' in flags:
            recommendations.append("⚡ Implement stricter rate limiting")
        
        if 'private_ip_public_request' in flags:
            recommendations.append("🏠 Private IP making public request - investigate")
        
        return recommendations
    
    def _log_security_incident(self, incident_type: str, details: Dict) -> None:
        """Güvenlik olayını kaydet"""
        try:
            incident = {
                'timestamp': datetime.now().isoformat(),
                'type': incident_type,
                'details': details,
                'severity': self._calculate_incident_severity(incident_type, details)
            }
            
            self.security_incidents.append(incident)
            
            # Update security metrics
            self.security_metrics['security_incidents'] += 1
            self.security_metrics['attack_patterns'][incident_type] += 1
            
            if incident['severity'] == 'high':
                self.security_metrics['last_attack_attempt'] = datetime.now()
            
            logger.warning(f"🔒 Security incident: {incident_type} - {details}")
            
        except Exception as e:
            logger.error(f"❌ Security incident logging error: {e}")
    
    def _calculate_incident_severity(self, incident_type: str, details: Dict) -> str:
        """Olay ciddiyetini hesapla"""
        try:
            high_severity_types = [
                'injection_attempt', 'known_malicious_ip', 'attack_tool_user_agent'
            ]
            
            medium_severity_types = [
                'rate_limit_exceeded', 'suspicious_user_agent', 'high_risk_request'
            ]
            
            if incident_type in high_severity_types:
                return 'high'
            elif incident_type in medium_severity_types:
                return 'medium'
            else:
                return 'low'
                
        except:
            return 'medium'
    
    def encrypt_data(self, data: str) -> str:
        """Veriyi şifrele"""
        try:
            encrypted_data = self.cipher_suite.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            logger.error(f"❌ Data encryption error: {e}")
            return data  # Return original data if encryption fails
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Veriyi çöz"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = self.cipher_suite.decrypt(encrypted_bytes)
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"❌ Data decryption error: {e}")
            return encrypted_data  # Return encrypted data if decryption fails
    
    def generate_api_key(self, permissions: List[str] = None, 
                        rate_limit: int = 1000, expires_days: int = 365) -> str:
        """Yeni API key oluştur"""
        try:
            api_key = secrets.token_urlsafe(32)
            
            key_info = {
                'created_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(days=expires_days)).isoformat(),
                'permissions': permissions or ['read'],
                'rate_limit': rate_limit,
                'active': True,
                'created_by': 'system'
            }
            
            self.api_keys[api_key] = key_info
            
            logger.info(f"✅ New API key generated with permissions: {permissions}")
            
            return api_key
            
        except Exception as e:
            logger.error(f"❌ API key generation error: {e}")
            return None
    
    def get_security_dashboard(self) -> Dict:
        """Güvenlik dashboard verileri"""
        try:
            current_time = datetime.now()
            
            # Recent incidents (last 24 hours)
            recent_incidents = [
                incident for incident in self.security_incidents
                if datetime.fromisoformat(incident['timestamp']) > current_time - timedelta(hours=24)
            ]
            
            # Active rate limits
            active_rate_limits = 0
            for limit_data in self.rate_limits.values():
                if limit_data['blocked_until'] and time.time() < limit_data['blocked_until']:
                    active_rate_limits += 1
            
            dashboard = {
                'total_security_incidents': len(self.security_incidents),
                'recent_incidents_24h': len(recent_incidents),
                'active_rate_limits': active_rate_limits,
                'blocked_ips_count': len(self.blocked_ips),
                'total_api_keys': len(self.api_keys),
                'attack_patterns': dict(self.security_metrics['attack_patterns']),
                'last_attack_attempt': self.security_metrics['last_attack_attempt'],
                'security_status': self._calculate_security_status(),
                'recent_incidents': recent_incidents[-10:],  # Last 10 incidents
                'top_attack_sources': self._get_top_attack_sources()
            }
            
            return dashboard
            
        except Exception as e:
            logger.error(f"❌ Security dashboard error: {e}")
            return {'error': str(e)}
    
    def _calculate_security_status(self) -> str:
        """Genel güvenlik durumunu hesapla"""
        try:
            current_time = datetime.now()
            
            # Recent high-severity incidents
            recent_high_incidents = [
                incident for incident in self.security_incidents
                if (incident['severity'] == 'high' and 
                    datetime.fromisoformat(incident['timestamp']) > current_time - timedelta(hours=1))
            ]
            
            if len(recent_high_incidents) >= 5:
                return 'critical'
            elif len(recent_high_incidents) >= 2:
                return 'high'
            elif len(self.blocked_ips) > 10:
                return 'elevated'
            else:
                return 'normal'
                
        except:
            return 'unknown'
    
    def _get_top_attack_sources(self) -> List[Dict]:
        """En sık saldırı kaynaklarını getir"""
        try:
            ip_incidents = defaultdict(int)
            
            for incident in self.security_incidents:
                ip = incident['details'].get('client_ip')
                if ip:
                    ip_incidents[ip] += 1
            
            # Sort by incident count
            top_sources = sorted(ip_incidents.items(), key=lambda x: x[1], reverse=True)[:10]
            
            return [
                {'ip': ip, 'incident_count': count}
                for ip, count in top_sources
            ]
            
        except Exception as e:
            logger.error(f"❌ Top attack sources error: {e}")
            return []

# Global instance
security_manager = SecurityManager() 