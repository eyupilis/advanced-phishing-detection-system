"""
ADVANCED FALSE POSITIVE TRACKER
Production-level false positive detection and tracking system
"""

import json
import hashlib
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse
import tldextract
import logging
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)

@dataclass
class FalsePositivePattern:
    """False positive pattern definition"""
    pattern_type: str  # domain, path, parameter, content
    pattern: str
    confidence: float
    source: str
    created_at: str
    usage_count: int = 0
    accuracy_score: float = 0.0

@dataclass 
class FalsePositiveRecord:
    """Individual false positive record"""
    url: str
    domain: str
    prediction: str
    actual_label: str
    confidence: float
    reasons: List[str]
    timestamp: str
    user_feedback: Optional[str] = None
    verified: bool = False
    pattern_id: Optional[str] = None

class AdvancedFalsePositiveTracker:
    """Production-level false positive detection and tracking"""
    
    def __init__(self):
        # Storage
        self.false_positive_records: List[Dict] = []
        self.fp_patterns: Dict[str, Dict] = {}
        self.domain_reputation: Dict[str, Dict] = {}
        
        # Configuration
        self.confidence_threshold = 0.7
        self.pattern_min_occurrences = 3
        self.max_records = 10000
        
        # Files
        self.fp_records_file = "false_positive_records.json"
        self.fp_patterns_file = "false_positive_patterns.json" 
        self.domain_reputation_file = "domain_reputation.json"
        
        # Analytics
        self.analytics = {
            'total_fps': 0,
            'patterns_detected': 0,
            'accuracy_improvement': 0.0,
            'common_fp_types': Counter(),
            'false_positive_rate': 0.0
        }
        
        # Load existing data
        self._load_data()
        self._initialize_known_patterns()
        
        logger.info(f"🔍 Advanced False Positive Tracker initialized")
        logger.info(f"📊 Loaded {len(self.false_positive_records)} FP records")
        logger.info(f"🎯 Loaded {len(self.fp_patterns)} FP patterns")
        
    def _load_data(self):
        """Load existing false positive data"""
        try:
            # Load FP records
            try:
                with open(self.fp_records_file, 'r', encoding='utf-8') as f:
                    self.false_positive_records = json.load(f)
                logger.info(f"✅ Loaded {len(self.false_positive_records)} FP records")
            except FileNotFoundError:
                logger.info("📁 No FP records file found, starting fresh")
            
            # Load FP patterns
            try:
                with open(self.fp_patterns_file, 'r', encoding='utf-8') as f:
                    self.fp_patterns = json.load(f)
                logger.info(f"✅ Loaded {len(self.fp_patterns)} FP patterns")
            except FileNotFoundError:
                logger.info("📁 No FP patterns file found, starting fresh")
                
            # Load domain reputation
            try:
                with open(self.domain_reputation_file, 'r', encoding='utf-8') as f:
                    self.domain_reputation = json.load(f)
                logger.info(f"✅ Loaded {len(self.domain_reputation)} domain reputations")
            except FileNotFoundError:
                logger.info("📁 No domain reputation file found, starting fresh")
                
        except Exception as e:
            logger.error(f"❌ Load FP data error: {e}")
    
    def _initialize_known_patterns(self):
        """Initialize known false positive patterns"""
        try:
            known_patterns = [
                # Legitimate domains mistakenly flagged
                {
                    'pattern_type': 'domain',
                    'pattern': r'.*\.edu(\.[a-z]{2})?$',
                    'confidence': 0.9,
                    'source': 'system',
                    'description': 'Educational institutions'
                },
                {
                    'pattern_type': 'domain', 
                    'pattern': r'.*\.gov(\.[a-z]{2})?$',
                    'confidence': 0.95,
                    'source': 'system',
                    'description': 'Government domains'
                },
                {
                    'pattern_type': 'domain',
                    'pattern': r'.*(github|gitlab|bitbucket)\.com$',
                    'confidence': 0.85,
                    'source': 'system',
                    'description': 'Code repositories'
                },
                {
                    'pattern_type': 'path',
                    'pattern': r'/api/v[0-9]+/',
                    'confidence': 0.7,
                    'source': 'system',
                    'description': 'Legitimate API endpoints'
                },
                # Turkish specific patterns
                {
                    'pattern_type': 'domain',
                    'pattern': r'.*\.(com\.tr|gov\.tr|edu\.tr|org\.tr)$',
                    'confidence': 0.8,
                    'source': 'system',
                    'description': 'Turkish legitimate domains'
                }
            ]
            
            for i, pattern_data in enumerate(known_patterns):
                pattern_id = f"system_pattern_{i}"
                if pattern_id not in self.fp_patterns:
                    self.fp_patterns[pattern_id] = {
                        'pattern_type': pattern_data['pattern_type'],
                        'pattern': pattern_data['pattern'],
                        'confidence': pattern_data['confidence'],
                        'source': pattern_data['source'],
                        'created_at': datetime.now().isoformat(),
                        'usage_count': 0,
                        'accuracy_score': 0.0
                    }
                    
        except Exception as e:
            logger.error(f"❌ Initialize known patterns error: {e}")
    
    def check_false_positive(self, url: str, prediction_confidence: float = 0.0, 
                           analysis_context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Advanced false positive detection
        """
        try:
            start_time = time.time()
            
            # Extract URL components
            parsed = urlparse(url)
            domain = self._extract_domain(url)
            
            fp_result = {
                'is_false_positive': False,
                'confidence': 0.0,
                'reasons': [],
                'pattern_matches': [],
                'domain_reputation': None,
                'historical_accuracy': 0.0,
                'recommendation': 'proceed_with_analysis',
                'analysis_time_ms': 0.0
            }
            
            # 1. Pattern-based detection
            pattern_confidence = self._check_fp_patterns(url, parsed, domain)
            if pattern_confidence > 0:
                fp_result['pattern_matches'] = self._get_matching_patterns(url, parsed, domain)
                fp_result['confidence'] = max(fp_result['confidence'], pattern_confidence)
                fp_result['reasons'].append(f"Pattern match (conf: {pattern_confidence:.3f})")
            
            # 2. Domain reputation check
            domain_rep = self._check_domain_reputation(domain)
            if domain_rep:
                fp_result['domain_reputation'] = domain_rep
                if domain_rep.get('is_legitimate', False):
                    rep_confidence = domain_rep.get('confidence', 0.0)
                    fp_result['confidence'] = max(fp_result['confidence'], rep_confidence)
                    fp_result['reasons'].append(f"Legitimate domain reputation (conf: {rep_confidence:.3f})")
            
            # 3. Historical analysis
            historical_analysis = self._analyze_historical_data(url, domain)
            if historical_analysis['has_history']:
                fp_result['historical_accuracy'] = historical_analysis['accuracy']
                if historical_analysis['likely_fp']:
                    hist_conf = historical_analysis['confidence']
                    fp_result['confidence'] = max(fp_result['confidence'], hist_conf)
                    fp_result['reasons'].append(f"Historical false positive pattern (conf: {hist_conf:.3f})")
            
            # Final decision
            if fp_result['confidence'] >= self.confidence_threshold:
                fp_result['is_false_positive'] = True
                fp_result['recommendation'] = 'likely_false_positive'
            elif fp_result['confidence'] >= 0.4:
                fp_result['recommendation'] = 'review_required'
            
            # Performance tracking
            fp_result['analysis_time_ms'] = round((time.time() - start_time) * 1000, 2)
            
            return fp_result
            
        except Exception as e:
            logger.error(f"❌ Check false positive error: {e}")
            return {
                'is_false_positive': False,
                'confidence': 0.0,
                'reasons': [f"Analysis error: {str(e)}"],
                'error': str(e)
            }
    
    def _check_fp_patterns(self, url: str, parsed: urlparse, domain: str) -> float:
        """Check URL against known false positive patterns"""
        try:
            max_confidence = 0.0
            
            for pattern_id, pattern in self.fp_patterns.items():
                confidence = 0.0
                
                if pattern['pattern_type'] == 'domain':
                    if re.search(pattern['pattern'], domain, re.IGNORECASE):
                        confidence = pattern['confidence']
                        
                elif pattern['pattern_type'] == 'path':
                    if re.search(pattern['pattern'], parsed.path, re.IGNORECASE):
                        confidence = pattern['confidence']
                        
                elif pattern['pattern_type'] == 'parameter':
                    if re.search(pattern['pattern'], parsed.query, re.IGNORECASE):
                        confidence = pattern['confidence']
                
                if confidence > 0:
                    # Update pattern usage
                    pattern['usage_count'] += 1
                    max_confidence = max(max_confidence, confidence)
            
            return max_confidence
            
        except Exception as e:
            logger.error(f"❌ Check FP patterns error: {e}")
            return 0.0
    
    def _get_matching_patterns(self, url: str, parsed: urlparse, domain: str) -> List[Dict]:
        """Get detailed information about matching patterns"""
        matching_patterns = []
        
        for pattern_id, pattern in self.fp_patterns.items():
            matches = False
            match_type = ""
            
            if pattern['pattern_type'] == 'domain' and re.search(pattern['pattern'], domain, re.IGNORECASE):
                matches = True
                match_type = f"Domain matches: {pattern['pattern']}"
                
            elif pattern['pattern_type'] == 'path' and re.search(pattern['pattern'], parsed.path, re.IGNORECASE):
                matches = True
                match_type = f"Path matches: {pattern['pattern']}"
                
            if matches:
                matching_patterns.append({
                    'pattern_id': pattern_id,
                    'pattern_type': pattern['pattern_type'],
                    'pattern': pattern['pattern'],
                    'confidence': pattern['confidence'],
                    'match_type': match_type,
                    'usage_count': pattern['usage_count']
                })
        
        return matching_patterns
    
    def _check_domain_reputation(self, domain: str) -> Optional[Dict]:
        """Check domain reputation data"""
        try:
            if domain in self.domain_reputation:
                return self.domain_reputation[domain]
            
            # Basic heuristics for unknown domains
            try:
                extracted = tldextract.extract(domain)
            except:
                return None
            
            # Check for known legitimate TLDs
            legitimate_tlds = {'.edu', '.gov', '.org', '.com.tr', '.gov.tr', '.edu.tr'}
            tld = f".{extracted.suffix}"
            
            if tld in legitimate_tlds:
                reputation = {
                    'is_legitimate': True,
                    'confidence': 0.6,
                    'source': 'tld_heuristic',
                    'last_updated': datetime.now().isoformat()
                }
                # Cache this result
                self.domain_reputation[domain] = reputation
                return reputation
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Check domain reputation error: {e}")
            return None
    
    def _analyze_historical_data(self, url: str, domain: str) -> Dict:
        """Analyze historical false positive data"""
        try:
            # Check exact URL matches
            url_history = [fp for fp in self.false_positive_records if fp.get('url') == url]
            domain_history = [fp for fp in self.false_positive_records if fp.get('domain') == domain]
            
            analysis = {
                'has_history': len(url_history) > 0 or len(domain_history) > 0,
                'url_fps': len(url_history),
                'domain_fps': len(domain_history),
                'accuracy': 0.0,
                'likely_fp': False,
                'confidence': 0.0
            }
            
            if url_history:
                # Exact URL has FP history
                verified_fps = sum(1 for fp in url_history if fp.get('verified', False))
                if verified_fps > 0:
                    analysis['likely_fp'] = True
                    analysis['confidence'] = min(0.9, 0.7 + (verified_fps * 0.1))
                    analysis['accuracy'] = verified_fps / len(url_history)
            
            elif len(domain_history) >= 3:
                # Domain has multiple FP records
                recent_fps = []
                for fp in domain_history:
                    try:
                        fp_time = datetime.fromisoformat(fp.get('timestamp', ''))
                        if (datetime.now() - fp_time).days <= 30:
                            recent_fps.append(fp)
                    except:
                        continue
                
                if len(recent_fps) >= 2:
                    analysis['likely_fp'] = True
                    analysis['confidence'] = 0.6
                    analysis['accuracy'] = len(recent_fps) / len(domain_history)
            
            return analysis
            
        except Exception as e:
            logger.error(f"❌ Analyze historical data error: {e}")
            return {'has_history': False, 'likely_fp': False, 'confidence': 0.0, 'accuracy': 0.0}
    
    def track_false_positive(self, url: str, prediction: str, actual_label: str, 
                           confidence: float, user_feedback: Optional[str] = None,
                           verified: bool = False) -> str:
        """Track a new false positive"""
        try:
            domain = self._extract_domain(url)
            
            # Create FP record
            fp_record = {
                'url': url,
                'domain': domain, 
                'prediction': prediction,
                'actual_label': actual_label,
                'confidence': confidence,
                'reasons': [],
                'timestamp': datetime.now().isoformat(),
                'user_feedback': user_feedback,
                'verified': verified,
                'pattern_id': None
            }
            
            # Add to records
            self.false_positive_records.append(fp_record)
            
            # Cleanup old records if needed
            if len(self.false_positive_records) > self.max_records:
                self.false_positive_records = self.false_positive_records[-self.max_records:]
            
            # Update analytics
            self.analytics['total_fps'] += 1
            self.analytics['common_fp_types'][prediction] = self.analytics['common_fp_types'].get(prediction, 0) + 1
            
            # Save data
            self._save_data()
            
            logger.info(f"📝 Tracked false positive: {url} (predicted: {prediction}, actual: {actual_label})")
            
            return fp_record['timestamp']
            
        except Exception as e:
            logger.error(f"❌ Track false positive error: {e}")
            return ""
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urlparse(url)
            return parsed.netloc.lower()
            
        except Exception as e:
            logger.error(f"❌ Extract domain error: {e}")
            return ""
    
    def _save_data(self):
        """Save false positive data to files"""
        try:
            # Save FP records
            with open(self.fp_records_file, 'w', encoding='utf-8') as f:
                json.dump(self.false_positive_records, f, indent=2, ensure_ascii=False)
            
            # Save patterns
            with open(self.fp_patterns_file, 'w', encoding='utf-8') as f:
                json.dump(self.fp_patterns, f, indent=2, ensure_ascii=False)
            
            # Save domain reputation  
            with open(self.domain_reputation_file, 'w', encoding='utf-8') as f:
                json.dump(self.domain_reputation, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.error(f"❌ Save FP data error: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive false positive statistics"""
        try:
            recent_fps = []
            for fp in self.false_positive_records:
                try:
                    fp_time = datetime.fromisoformat(fp.get('timestamp', ''))
                    if (datetime.now() - fp_time).days <= 30:
                        recent_fps.append(fp)
                except:
                    continue
            
            stats = {
                'total_false_positives': len(self.false_positive_records),
                'recent_false_positives': len(recent_fps),
                'total_patterns': len(self.fp_patterns),
                'auto_detected_patterns': len([p for p in self.fp_patterns.values() if p.get('source') == 'auto_detected']),
                'most_common_fp_types': dict(self.analytics['common_fp_types']),
                'pattern_accuracy': self._calculate_pattern_accuracy(),
                'domain_coverage': len(set(fp.get('domain', '') for fp in self.false_positive_records)),
                'verified_fps': len([fp for fp in self.false_positive_records if fp.get('verified', False)]),
                'accuracy_improvement': self.analytics.get('accuracy_improvement', 0.0)
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"❌ Get FP statistics error: {e}")
            return {}
    
    def _calculate_pattern_accuracy(self) -> float:
        """Calculate overall pattern accuracy"""
        try:
            if not self.fp_patterns:
                return 0.0
            
            total_accuracy = sum(p.get('accuracy_score', 0.0) for p in self.fp_patterns.values())
            return total_accuracy / len(self.fp_patterns)
            
        except Exception:
            return 0.0

# Global instance
false_positive_tracker = AdvancedFalsePositiveTracker()
