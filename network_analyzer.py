"""
NETWORK ANALYZER
SSL, DNS, IP ve ağ güvenlik analizi
"""

import asyncio
import logging
import socket
import ssl
import dns.resolver
import aiohttp
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import re
import geoip2.database
import geoip2.errors
import subprocess
import time

logger = logging.getLogger(__name__)

class NetworkAnalyzer:
    def __init__(self):
        # Network analysis configurations
        self.suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5432, 6667]
        self.malicious_asns = []  # Known malicious ASN numbers
        self.legitimate_dns_servers = [
            '8.8.8.8', '8.8.4.4',  # Google
            '1.1.1.1', '1.0.0.1',  # Cloudflare
            '208.67.222.222', '208.67.220.220'  # OpenDNS
        ]
        
        # SSL/TLS analysis patterns
        self.weak_cipher_suites = [
            'NULL', 'aNULL', 'eNULL', 'EXPORT', 'DES', 'RC4', 'MD5', 'PSK', 'SRP'
        ]
        
        # Suspicious IP ranges (examples)
        self.suspicious_ip_ranges = [
            '10.0.0.0/8',     # Private networks being used publicly
            '192.168.0.0/16', # Private networks
            '172.16.0.0/12'   # Private networks
        ]
        
        # Trusted Certificate Authorities
        self.trusted_cas = [
            'Let\'s Encrypt', 'DigiCert', 'GlobalSign', 'Sectigo', 'GeoTrust',
            'Comodo', 'VeriSign', 'Symantec', 'GoDaddy', 'Entrust', 'Amazon',
            'Google Trust Services', 'Microsoft', 'Apple'
        ]
        
        # Network scoring weights
        self.network_weights = {
            'ssl_security': 0.3,
            'dns_analysis': 0.2,
            'ip_reputation': 0.25,
            'geolocation': 0.1,
            'port_scan': 0.1,
            'network_timing': 0.05
        }
        
    async def analyze_url_network(self, url: str, deep_scan: bool = False) -> Dict:
        """URL için kapsamlı network analizi"""
        try:
            analysis_result = {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'network_accessible': False,
                'risk_score': 0.0,
                'network_flags': [],
                'ssl_analysis': {},
                'dns_analysis': {},
                'ip_analysis': {},
                'geolocation_analysis': {},
                'port_analysis': {},
                'timing_analysis': {},
                'recommendations': []
            }
            
            # URL parsing
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            if not domain:
                analysis_result['error'] = 'Invalid URL - no domain found'
                return analysis_result
            
            # Basic connectivity check
            connectivity = await self._check_connectivity(domain, port)
            analysis_result['network_accessible'] = connectivity.get('accessible', False)
            
            if not analysis_result['network_accessible']:
                analysis_result['error'] = connectivity.get('error', 'Network not accessible')
                analysis_result['risk_score'] = 0.3  # Moderate risk for inaccessible
                return analysis_result
            
            # DNS Analysis
            dns_risk = await self._analyze_dns(domain)
            analysis_result['dns_analysis'] = dns_risk
            
            # SSL/TLS Analysis (if HTTPS)
            ssl_risk = 0.0
            if parsed_url.scheme == 'https':
                ssl_analysis = await self._analyze_ssl(domain, port)
                analysis_result['ssl_analysis'] = ssl_analysis
                ssl_risk = ssl_analysis.get('risk_score', 0)
            
            # IP Analysis
            ip_analysis = await self._analyze_ip(domain)
            analysis_result['ip_analysis'] = ip_analysis
            ip_risk = ip_analysis.get('risk_score', 0)
            
            # Geolocation Analysis
            geo_analysis = await self._analyze_geolocation(domain)
            analysis_result['geolocation_analysis'] = geo_analysis
            geo_risk = geo_analysis.get('risk_score', 0)
            
            # Timing Analysis
            timing_analysis = await self._analyze_network_timing(domain, port)
            analysis_result['timing_analysis'] = timing_analysis
            timing_risk = timing_analysis.get('risk_score', 0)
            
            # Port Analysis (if deep scan)
            port_risk = 0.0
            if deep_scan:
                port_analysis = await self._analyze_ports(domain)
                analysis_result['port_analysis'] = port_analysis
                port_risk = port_analysis.get('risk_score', 0)
            
            # Calculate total network risk score
            total_risk = (
                ssl_risk * self.network_weights['ssl_security'] +
                dns_risk.get('risk_score', 0) * self.network_weights['dns_analysis'] +
                ip_risk * self.network_weights['ip_reputation'] +
                geo_risk * self.network_weights['geolocation'] +
                port_risk * self.network_weights['port_scan'] +
                timing_risk * self.network_weights['network_timing']
            )
            
            analysis_result['risk_score'] = round(total_risk, 3)
            
            # Network flags
            flags = []
            if ssl_risk > 0.6:
                flags.append('ssl_security_issues')
            if dns_risk.get('risk_score', 0) > 0.7:
                flags.append('dns_suspicious')
            if ip_risk > 0.8:
                flags.append('ip_reputation_poor')
            if geo_risk > 0.7:
                flags.append('suspicious_geolocation')
            if port_risk > 0.6:
                flags.append('suspicious_ports_open')
            if timing_risk > 0.8:
                flags.append('network_timing_anomaly')
            
            analysis_result['network_flags'] = flags
            
            # Generate recommendations
            recommendations = self._generate_network_recommendations(analysis_result)
            analysis_result['recommendations'] = recommendations
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"❌ Network analysis error: {e}")
            return {
                'url': url,
                'error': str(e),
                'risk_score': 0.5,
                'network_flags': ['analysis_error']
            }
    
    async def _check_connectivity(self, domain: str, port: int, timeout: int = 5) -> Dict:
        """Temel bağlantı kontrolü"""
        try:
            # TCP connectivity check
            future = asyncio.open_connection(domain, port)
            reader, writer = await asyncio.wait_for(future, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            
            return {
                'accessible': True,
                'response_time': timeout,  # Simplified
                'tcp_connection': 'successful'
            }
            
        except asyncio.TimeoutError:
            return {
                'accessible': False,
                'error': 'Connection timeout',
                'tcp_connection': 'timeout'
            }
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e),
                'tcp_connection': 'failed'
            }
    
    async def _analyze_dns(self, domain: str) -> Dict:
        """DNS analizi"""
        try:
            dns_result = {
                'domain': domain,
                'risk_score': 0.0,
                'dns_records': {},
                'dns_flags': [],
                'analysis_details': {}
            }
            
            # A Record lookup
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                dns_result['dns_records']['A'] = [str(r) for r in a_records]
            except:
                dns_result['dns_flags'].append('no_a_record')
                dns_result['risk_score'] += 0.3
            
            # MX Record lookup
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                dns_result['dns_records']['MX'] = [str(r) for r in mx_records]
            except:
                dns_result['dns_flags'].append('no_mx_record')
                dns_result['risk_score'] += 0.1
            
            # NS Record lookup
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                dns_result['dns_records']['NS'] = [str(r) for r in ns_records]
            except:
                dns_result['dns_flags'].append('no_ns_record')
                dns_result['risk_score'] += 0.2
            
            # TXT Record lookup (SPF, DMARC check)
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                txt_strings = [str(r) for r in txt_records]
                dns_result['dns_records']['TXT'] = txt_strings
                
                # Check for security records
                has_spf = any('spf' in txt.lower() for txt in txt_strings)
                has_dmarc = any('dmarc' in txt.lower() for txt in txt_strings)
                
                if not has_spf:
                    dns_result['dns_flags'].append('no_spf_record')
                    dns_result['risk_score'] += 0.05  # Reduced penalty
                if not has_dmarc:
                    dns_result['dns_flags'].append('no_dmarc_record')
                    dns_result['risk_score'] += 0.05  # Reduced penalty
                
                # Positive points for having security records
                if has_spf:
                    dns_result['dns_flags'].append('has_spf_record')
                if has_dmarc:
                    dns_result['dns_flags'].append('has_dmarc_record')
                    
            except:
                dns_result['dns_flags'].append('no_txt_record')
                dns_result['risk_score'] += 0.1
            
            # Domain age analysis (simplified)
            dns_result['analysis_details']['domain_analysis'] = {
                'suspicious_pattern': self._check_suspicious_domain_pattern(domain),
                'punycode_domain': domain.startswith('xn--')
            }
            
            if dns_result['analysis_details']['domain_analysis']['suspicious_pattern']:
                dns_result['risk_score'] += 0.3
                dns_result['dns_flags'].append('suspicious_domain_pattern')
            
            if dns_result['analysis_details']['domain_analysis']['punycode_domain']:
                dns_result['risk_score'] += 0.2
                dns_result['dns_flags'].append('punycode_domain')
            
            dns_result['risk_score'] = min(dns_result['risk_score'], 1.0)
            
            return dns_result
            
        except Exception as e:
            logger.error(f"❌ DNS analysis error: {e}")
            return {
                'domain': domain,
                'error': str(e),
                'risk_score': 0.5,
                'dns_flags': ['dns_lookup_failed']
            }
    
    def _check_suspicious_domain_pattern(self, domain: str) -> bool:
        """Şüpheli domain pattern kontrolü"""
        try:
            # Very long domain
            if len(domain) > 50:
                return True
            
            # Too many subdomains
            if domain.count('.') > 4:
                return True
            
            # Numbers in domain (potential DGA)
            if len(re.findall(r'\d', domain)) > len(domain) * 0.3:
                return True
            
            # Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                return True
            
            # Random character patterns
            if re.search(r'[a-z]{10,}', domain):  # Very long sequences
                return True
            
            return False
            
        except:
            return False
    
    async def _analyze_ssl(self, domain: str, port: int) -> Dict:
        """SSL/TLS güvenlik analizi"""
        try:
            ssl_result = {
                'domain': domain,
                'port': port,
                'risk_score': 0.0,
                'ssl_flags': [],
                'certificate_info': {},
                'security_analysis': {}
            }
            
            # SSL Certificate check
            context = ssl.create_default_context()
            
            try:
                with socket.create_connection((domain, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        
                        # Certificate analysis
                        issuer_cn = ''
                        if 'issuer' in cert:
                            issuer_dict = dict(x[0] for x in cert['issuer'])
                            issuer_cn = issuer_dict.get('commonName', '')
                        
                        ssl_result['certificate_info'] = {
                            'subject': cert.get('subject', []),
                            'issuer': cert.get('issuer', []),
                            'issuer_cn': issuer_cn,
                            'version': cert.get('version'),
                            'serial_number': cert.get('serialNumber'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter')
                        }
                        
                        # Check if issuer is trusted
                        is_trusted_ca = any(trusted_ca in issuer_cn for trusted_ca in self.trusted_cas)
                        ssl_result['certificate_info']['trusted_ca'] = is_trusted_ca
                        
                        if not is_trusted_ca:
                            ssl_result['ssl_flags'].append('untrusted_ca')
                            ssl_result['risk_score'] += 0.4
                        
                        # Certificate validity check
                        if 'notAfter' in cert:
                            try:
                                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                                days_until_expiry = (expiry_date - datetime.now()).days
                                
                                if days_until_expiry < 0:
                                    ssl_result['ssl_flags'].append('certificate_expired')
                                    ssl_result['risk_score'] += 0.8
                                elif days_until_expiry < 30:
                                    ssl_result['ssl_flags'].append('certificate_expiring_soon')
                                    ssl_result['risk_score'] += 0.3
                                    
                                ssl_result['certificate_info']['days_until_expiry'] = days_until_expiry
                            except:
                                ssl_result['ssl_flags'].append('invalid_certificate_date')
                                ssl_result['risk_score'] += 0.4
                        
                        # Cipher analysis
                        if cipher:
                            ssl_result['security_analysis']['cipher_suite'] = cipher[0]
                            ssl_result['security_analysis']['ssl_version'] = cipher[1]
                            ssl_result['security_analysis']['key_length'] = cipher[2]
                            
                            # Check for weak ciphers
                            cipher_name = cipher[0]
                            for weak_cipher in self.weak_cipher_suites:
                                if weak_cipher in cipher_name:
                                    ssl_result['ssl_flags'].append('weak_cipher')
                                    ssl_result['risk_score'] += 0.5
                                    break
                            
                            # Check SSL/TLS version
                            ssl_version = cipher[1]
                            if ssl_version in ['SSLv2', 'SSLv3']:
                                ssl_result['ssl_flags'].append('critically_outdated_ssl')
                                ssl_result['risk_score'] += 0.8
                            elif ssl_version in ['TLSv1', 'TLSv1.1']:
                                ssl_result['ssl_flags'].append('outdated_ssl_version')
                                ssl_result['risk_score'] += 0.3
                            elif ssl_version in ['TLSv1.2']:
                                ssl_result['ssl_flags'].append('acceptable_ssl_version')
                                # TLS 1.2 is still acceptable, no penalty
                            elif ssl_version in ['TLSv1.3']:
                                ssl_result['ssl_flags'].append('modern_ssl_version')
                                # TLS 1.3 is excellent, reduce risk score
                                ssl_result['risk_score'] = max(0, ssl_result['risk_score'] - 0.1)
                            
                            # Check key length
                            key_length = cipher[2]
                            if key_length < 1024:
                                ssl_result['ssl_flags'].append('very_weak_key')
                                ssl_result['risk_score'] += 0.6
                            elif key_length < 2048:
                                ssl_result['ssl_flags'].append('weak_key_length')
                                ssl_result['risk_score'] += 0.2
                            elif key_length >= 2048:
                                ssl_result['ssl_flags'].append('strong_key_length')
                                # Strong key length, slight risk reduction
                                ssl_result['risk_score'] = max(0, ssl_result['risk_score'] - 0.05)
                        
                        # Subject Alternative Names check
                        san_list = []
                        if 'subjectAltName' in cert:
                            san_list = [name[1] for name in cert['subjectAltName']]
                            ssl_result['certificate_info']['subject_alt_names'] = san_list
                        
                        # Check if domain matches certificate
                        domain_match = False
                        if san_list:
                            domain_match = domain in san_list or any(
                                domain.endswith(san.replace('*.', '.')) for san in san_list if san.startswith('*.')
                            )
                        
                        if not domain_match:
                            # Check subject CN
                            subject_dict = dict(x[0] for x in cert.get('subject', []))
                            cn = subject_dict.get('commonName', '')
                            if cn != domain and not (cn.startswith('*.') and domain.endswith(cn[2:])):
                                ssl_result['ssl_flags'].append('domain_mismatch')
                                ssl_result['risk_score'] += 0.6
            
            except ssl.SSLError as e:
                ssl_result['ssl_flags'].append('ssl_connection_failed')
                ssl_result['risk_score'] += 0.7
                ssl_result['error'] = f"SSL Error: {str(e)}"
            
            except socket.timeout:
                ssl_result['ssl_flags'].append('ssl_timeout')
                ssl_result['risk_score'] += 0.4
                ssl_result['error'] = "SSL connection timeout"
            
            ssl_result['risk_score'] = min(ssl_result['risk_score'], 1.0)
            
            return ssl_result
            
        except Exception as e:
            logger.error(f"❌ SSL analysis error: {e}")
            return {
                'domain': domain,
                'port': port,
                'error': str(e),
                'risk_score': 0.5,
                'ssl_flags': ['ssl_analysis_failed']
            }
    
    async def _analyze_ip(self, domain: str) -> Dict:
        """IP adresi analizi"""
        try:
            ip_result = {
                'domain': domain,
                'risk_score': 0.0,
                'ip_flags': [],
                'ip_addresses': [],
                'ip_analysis': {}
            }
            
            # Resolve IP addresses
            try:
                ip_addresses = socket.gethostbyname_ex(domain)[2]
                ip_result['ip_addresses'] = ip_addresses
            except socket.gaierror:
                ip_result['ip_flags'].append('dns_resolution_failed')
                ip_result['risk_score'] += 0.5
                return ip_result
            
            for ip in ip_addresses:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    
                    # Check for private IP addresses
                    if ip_obj.is_private:
                        ip_result['ip_flags'].append('private_ip_address')
                        ip_result['risk_score'] += 0.6
                    
                    # Check for localhost
                    if ip_obj.is_loopback:
                        ip_result['ip_flags'].append('localhost_ip')
                        ip_result['risk_score'] += 0.8
                    
                    # Check for suspicious IP ranges
                    for suspicious_range in self.suspicious_ip_ranges:
                        if ip_obj in ipaddress.ip_network(suspicious_range):
                            ip_result['ip_flags'].append('suspicious_ip_range')
                            ip_result['risk_score'] += 0.4
                            break
                    
                except ValueError:
                    ip_result['ip_flags'].append('invalid_ip_address')
                    ip_result['risk_score'] += 0.3
            
            # Multiple IP analysis
            if len(ip_addresses) > 10:
                ip_result['ip_flags'].append('too_many_ip_addresses')
                ip_result['risk_score'] += 0.2
            
            ip_result['ip_analysis']['ip_count'] = len(ip_addresses)
            ip_result['risk_score'] = min(ip_result['risk_score'], 1.0)
            
            return ip_result
            
        except Exception as e:
            logger.error(f"❌ IP analysis error: {e}")
            return {
                'domain': domain,
                'error': str(e),
                'risk_score': 0.5,
                'ip_flags': ['ip_analysis_failed']
            }
    
    async def _analyze_geolocation(self, domain: str) -> Dict:
        """Coğrafi konum analizi"""
        try:
            geo_result = {
                'domain': domain,
                'risk_score': 0.0,
                'geo_flags': [],
                'geolocation_info': {}
            }
            
            # Get IP addresses
            try:
                ip_addresses = socket.gethostbyname_ex(domain)[2]
            except socket.gaierror:
                geo_result['geo_flags'].append('dns_resolution_failed')
                geo_result['risk_score'] += 0.3
                return geo_result
            
            # Simplified geolocation analysis (without external database)
            suspicious_countries = ['CN', 'RU', 'KP', 'IR']  # Example
            
            for ip in ip_addresses:
                try:
                    # In real implementation, you would use GeoIP database
                    # For now, we'll do basic analysis
                    
                    # Check for IP ranges known to be in suspicious countries
                    # This is a simplified example
                    if ip.startswith(('61.', '125.', '114.')):  # Example Chinese IP ranges
                        geo_result['geo_flags'].append('suspicious_country')
                        geo_result['risk_score'] += 0.3
                    
                    # Check for hosting providers vs residential
                    if ip.startswith(('104.', '172.', '192.')):  # Example hosting ranges
                        geo_result['geolocation_info']['hosting_provider'] = True
                    else:
                        geo_result['geolocation_info']['residential'] = True
                        
                except Exception:
                    continue
            
            geo_result['risk_score'] = min(geo_result['risk_score'], 1.0)
            
            return geo_result
            
        except Exception as e:
            logger.error(f"❌ Geolocation analysis error: {e}")
            return {
                'domain': domain,
                'error': str(e),
                'risk_score': 0.3,
                'geo_flags': ['geolocation_analysis_failed']
            }
    
    async def _analyze_network_timing(self, domain: str, port: int) -> Dict:
        """Network timing analizi"""
        try:
            timing_result = {
                'domain': domain,
                'port': port,
                'risk_score': 0.0,
                'timing_flags': [],
                'timing_measurements': {}
            }
            
            # Measure connection times
            start_time = time.time()
            try:
                future = asyncio.open_connection(domain, port)
                reader, writer = await asyncio.wait_for(future, timeout=10)
                connection_time = time.time() - start_time
                writer.close()
                await writer.wait_closed()
                
                timing_result['timing_measurements']['connection_time'] = connection_time
                
                # Analyze timing anomalies
                if connection_time > 10:  # Very slow connection
                    timing_result['timing_flags'].append('slow_connection')
                    timing_result['risk_score'] += 0.3
                elif connection_time > 5:
                    timing_result['timing_flags'].append('moderately_slow_connection')
                    timing_result['risk_score'] += 0.1
                
            except asyncio.TimeoutError:
                timing_result['timing_flags'].append('connection_timeout')
                timing_result['risk_score'] += 0.5
            except Exception:
                timing_result['timing_flags'].append('connection_failed')
                timing_result['risk_score'] += 0.4
            
            timing_result['risk_score'] = min(timing_result['risk_score'], 1.0)
            
            return timing_result
            
        except Exception as e:
            logger.error(f"❌ Network timing analysis error: {e}")
            return {
                'domain': domain,
                'port': port,
                'error': str(e),
                'risk_score': 0.3,
                'timing_flags': ['timing_analysis_failed']
            }
    
    async def _analyze_ports(self, domain: str) -> Dict:
        """Port tarama analizi (deep scan)"""
        try:
            port_result = {
                'domain': domain,
                'risk_score': 0.0,
                'port_flags': [],
                'open_ports': [],
                'suspicious_services': []
            }
            
            # Scan suspicious ports
            for port in self.suspicious_ports:
                try:
                    future = asyncio.open_connection(domain, port)
                    reader, writer = await asyncio.wait_for(future, timeout=3)
                    writer.close()
                    await writer.wait_closed()
                    
                    port_result['open_ports'].append(port)
                    
                    # Identify suspicious services
                    if port in [22, 23]:  # SSH, Telnet
                        port_result['suspicious_services'].append(f'Remote access (port {port})')
                        port_result['risk_score'] += 0.2
                    elif port in [135, 139, 445]:  # Windows networking
                        port_result['suspicious_services'].append(f'Windows networking (port {port})')
                        port_result['risk_score'] += 0.3
                    elif port in [1433, 3389, 5432]:  # Database/RDP
                        port_result['suspicious_services'].append(f'Database/RDP (port {port})')
                        port_result['risk_score'] += 0.4
                        
                except (asyncio.TimeoutError, Exception):
                    continue
            
            if len(port_result['open_ports']) > 3:
                port_result['port_flags'].append('multiple_suspicious_ports')
                port_result['risk_score'] += 0.3
            
            port_result['risk_score'] = min(port_result['risk_score'], 1.0)
            
            return port_result
            
        except Exception as e:
            logger.error(f"❌ Port analysis error: {e}")
            return {
                'domain': domain,
                'error': str(e),
                'risk_score': 0.2,
                'port_flags': ['port_analysis_failed']
            }
    
    def _generate_network_recommendations(self, analysis_result: Dict) -> List[str]:
        """Network analizi sonucuna göre öneriler"""
        recommendations = []
        
        risk_score = analysis_result.get('risk_score', 0)
        flags = analysis_result.get('network_flags', [])
        
        if risk_score > 0.8:
            recommendations.append("🚨 Yüksek network riski tespit edildi")
            recommendations.append("🚫 Bu siteye bağlantıyı engelleyin")
        
        if 'ssl_security_issues' in flags:
            recommendations.append("🔒 SSL güvenlik sorunları var")
            recommendations.append("⚠️ Hassas bilgi girmeyin")
        
        if 'dns_suspicious' in flags:
            recommendations.append("🔍 DNS yapılandırması şüpheli")
        
        if 'ip_reputation_poor' in flags:
            recommendations.append("📍 IP adresi kötü reputasyona sahip")
        
        if 'suspicious_geolocation' in flags:
            recommendations.append("🌍 Şüpheli coğrafi konum")
        
        if 'suspicious_ports_open' in flags:
            recommendations.append("🚪 Şüpheli network portları açık")
        
        if 'network_timing_anomaly' in flags:
            recommendations.append("⏱️ Network timing anomalisi")
        
        return recommendations

# Global instance
network_analyzer = NetworkAnalyzer() 