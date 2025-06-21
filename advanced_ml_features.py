"""
ADVANCED MACHINE LEARNING FEATURES
Gelişmiş ML özellikleri: ensemble optimization, feature engineering, adaptive learning
"""

import asyncio
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from sklearn.ensemble import VotingClassifier, BaggingClassifier, AdaBoostClassifier
from sklearn.model_selection import cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.feature_selection import SelectKBest, chi2, mutual_info_classif
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib
import json
from collections import defaultdict, deque
import threading
import time

logger = logging.getLogger(__name__)

class AdvancedMLFeatures:
    def __init__(self):
        # Model performance tracking
        self.model_performance = defaultdict(lambda: {
            'accuracy': deque(maxlen=100),
            'precision': deque(maxlen=100),
            'recall': deque(maxlen=100),
            'f1_score': deque(maxlen=100),
            'prediction_times': deque(maxlen=100),
            'last_updated': None,
            'total_predictions': 0,
            'correct_predictions': 0
        })
        
        # Feature importance tracking
        self.feature_importance = defaultdict(list)
        self.feature_correlation_matrix = None
        
        # Adaptive learning parameters
        self.learning_rate = 0.01
        self.adaptation_threshold = 0.1
        self.min_samples_for_adaptation = 50
        
        # Ensemble configuration
        self.ensemble_methods = {
            'voting': 'majority',
            'stacking': True,
            'boosting': True,
            'bagging': True
        }
        
        # Feature engineering patterns
        self.url_patterns = [
            r'https?://',
            r'www\.',
            r'\d+\.\d+\.\d+\.\d+',  # IP pattern
            r'[a-zA-Z0-9]+-[a-zA-Z0-9]+',  # Hyphenated domains
            r'\d{3,}',  # Long number sequences
            r'[bcdfghjklmnpqrstvwxyz]{5,}',  # Consonant clusters
            r'[aeiou]{3,}',  # Vowel clusters
        ]
        
        # Real-time feedback storage
        self.feedback_buffer = deque(maxlen=1000)
        self.feedback_lock = threading.Lock()
        
        # Model ensemble weights (dynamic)
        self.dynamic_weights = {
            'phishing_model': 1.0,
            'cybersecurity_model': 1.0,
            'phishing_urls_model': 1.0,
            'website_model': 1.0,
            'crypto_scam_model': 1.0,
            'link_phishing_model': 1.0,
            'malicious_urls_model': 1.0
        }
        
    async def optimize_ensemble_weights(self, models: Dict, validation_data: List[Dict]) -> Dict:
        """Ensemble ağırlıklarını optimize et"""
        try:
            if not validation_data or len(validation_data) < 10:
                logger.warning("Insufficient validation data for ensemble optimization")
                return self.dynamic_weights
            
            logger.info("🔧 Optimizing ensemble weights...")
            
            # Prepare validation dataset
            X_val, y_val = self._prepare_validation_data(validation_data)
            
            if X_val is None or len(X_val) == 0:
                return self.dynamic_weights
            
            # Get individual model predictions
            model_predictions = {}
            model_scores = {}
            
            for model_name, model in models.items():
                try:
                    if hasattr(model, 'predict_proba'):
                        predictions = model.predict_proba(X_val)[:, 1]  # Get positive class probability
                    else:
                        predictions = model.predict(X_val)
                    
                    model_predictions[model_name] = predictions
                    
                    # Calculate individual model performance
                    binary_predictions = (predictions > 0.5).astype(int)
                    accuracy = accuracy_score(y_val, binary_predictions)
                    precision = precision_score(y_val, binary_predictions, zero_division=0)
                    recall = recall_score(y_val, binary_predictions, zero_division=0)
                    f1 = f1_score(y_val, binary_predictions, zero_division=0)
                    
                    # Combined score for weight calculation
                    combined_score = (accuracy + precision + recall + f1) / 4
                    model_scores[model_name] = combined_score
                    
                except Exception as e:
                    logger.error(f"❌ Error evaluating model {model_name}: {e}")
                    model_scores[model_name] = 0.5  # Default score
            
            # Calculate optimal weights using performance-based weighting
            total_score = sum(model_scores.values())
            if total_score > 0:
                optimized_weights = {
                    model_name: score / total_score 
                    for model_name, score in model_scores.items()
                }
                
                # Apply smoothing to prevent extreme weights
                min_weight = 0.1
                max_weight = 0.4
                
                for model_name in optimized_weights:
                    weight = optimized_weights[model_name]
                    weight = max(min_weight, min(max_weight, weight))
                    optimized_weights[model_name] = weight
                
                # Normalize weights to sum to 1
                weight_sum = sum(optimized_weights.values())
                optimized_weights = {
                    model_name: weight / weight_sum 
                    for model_name, weight in optimized_weights.items()
                }
                
                self.dynamic_weights.update(optimized_weights)
                
                logger.info(f"✅ Ensemble weights optimized: {optimized_weights}")
                
                # Save optimization results
                optimization_result = {
                    'timestamp': datetime.now().isoformat(),
                    'validation_samples': len(validation_data),
                    'model_scores': model_scores,
                    'optimized_weights': optimized_weights,
                    'previous_weights': dict(self.dynamic_weights)
                }
                
                # Store results (in production, save to database)
                self._save_optimization_results(optimization_result)
                
            return self.dynamic_weights
            
        except Exception as e:
            logger.error(f"❌ Ensemble optimization error: {e}")
            return self.dynamic_weights
    
    def _prepare_validation_data(self, validation_data: List[Dict]) -> Tuple[Optional[np.ndarray], Optional[np.ndarray]]:
        """Validation verisi hazırla"""
        try:
            features_list = []
            labels_list = []
            
            for sample in validation_data:
                if 'features' in sample and 'label' in sample:
                    features = sample['features']
                    label = sample['label']
                    
                    # Convert features dict to array
                    if isinstance(features, dict):
                        feature_array = self._extract_feature_vector(features)
                        features_list.append(feature_array)
                        labels_list.append(1 if label == 'phishing' else 0)
            
            if features_list and labels_list:
                return np.array(features_list), np.array(labels_list)
            
            return None, None
            
        except Exception as e:
            logger.error(f"❌ Validation data preparation error: {e}")
            return None, None
    
    def _extract_feature_vector(self, features: Dict) -> np.ndarray:
        """Feature dictionary'den vector çıkar"""
        try:
            # Standard feature keys (should match your existing feature extraction)
            standard_features = [
                'url_length', 'num_dots', 'num_hyphens', 'num_underscores',
                'num_percent', 'num_question', 'num_equal', 'num_at',
                'num_and', 'num_exclamation', 'num_space', 'num_tilde',
                'num_comma', 'num_plus', 'num_asterisk', 'num_hash',
                'num_dollar', 'has_ip', 'has_port', 'domain_length',
                'path_length', 'query_length', 'fragment_length',
                'num_subdomains', 'entropy', 'vowel_ratio', 'digit_ratio'
            ]
            
            feature_vector = []
            for feature_name in standard_features:
                value = features.get(feature_name, 0)
                if isinstance(value, (int, float)):
                    feature_vector.append(value)
                else:
                    feature_vector.append(0)
            
            return np.array(feature_vector)
            
        except Exception as e:
            logger.error(f"❌ Feature vector extraction error: {e}")
            return np.zeros(27)  # Default vector size
    
    async def engineer_advanced_features(self, url: str, content: Optional[str] = None) -> Dict:
        """Gelişmiş feature engineering"""
        try:
            advanced_features = {}
            
            # URL-based features
            url_features = self._extract_url_features(url)
            advanced_features.update(url_features)
            
            # Content-based features (if available)
            if content:
                content_features = self._extract_content_features(content)
                advanced_features.update(content_features)
            
            # Pattern-based features
            pattern_features = self._extract_pattern_features(url)
            advanced_features.update(pattern_features)
            
            # N-gram features
            ngram_features = self._extract_ngram_features(url)
            advanced_features.update(ngram_features)
            
            # Temporal features
            temporal_features = self._extract_temporal_features()
            advanced_features.update(temporal_features)
            
            return advanced_features
            
        except Exception as e:
            logger.error(f"❌ Advanced feature engineering error: {e}")
            return {}
    
    def _extract_url_features(self, url: str) -> Dict:
        """URL-based özellikler"""
        try:
            features = {}
            
            # Length-based features
            features['url_total_length'] = len(url)
            features['url_domain_length'] = len(url.split('/')[2]) if '/' in url else len(url)
            features['url_path_length'] = len('/'.join(url.split('/')[3:])) if '/' in url else 0
            
            # Character frequency features
            for char in '.-_~!@#$%^&*()+=[]{}|;:,<>?/':
                features[f'char_freq_{char}'] = url.count(char) / len(url) if len(url) > 0 else 0
            
            # Digit and letter ratios
            digits = sum(c.isdigit() for c in url)
            letters = sum(c.isalpha() for c in url)
            features['digit_letter_ratio'] = digits / (letters + 1)
            features['digit_percentage'] = digits / len(url) if len(url) > 0 else 0
            features['letter_percentage'] = letters / len(url) if len(url) > 0 else 0
            
            # Case features
            uppercase = sum(c.isupper() for c in url)
            lowercase = sum(c.islower() for c in url)
            features['case_ratio'] = uppercase / (lowercase + 1)
            
            # Entropy calculation
            features['url_entropy'] = self._calculate_entropy(url)
            
            return features
            
        except Exception as e:
            logger.error(f"❌ URL feature extraction error: {e}")
            return {}
    
    def _extract_content_features(self, content: str) -> Dict:
        """Content-based özellikler"""
        try:
            features = {}
            
            if not content:
                return features
            
            # Content length features
            features['content_length'] = len(content)
            features['content_word_count'] = len(content.split())
            features['content_line_count'] = len(content.split('\n'))
            
            # HTML tag analysis
            import re
            html_tags = re.findall(r'<[^>]+>', content)
            features['html_tag_count'] = len(html_tags)
            features['html_tag_ratio'] = len(html_tags) / len(content) if len(content) > 0 else 0
            
            # Form analysis
            forms = re.findall(r'<form[^>]*>', content, re.IGNORECASE)
            features['form_count'] = len(forms)
            
            # Input field analysis
            inputs = re.findall(r'<input[^>]*>', content, re.IGNORECASE)
            features['input_count'] = len(inputs)
            
            # JavaScript analysis
            scripts = re.findall(r'<script[^>]*>.*?</script>', content, re.IGNORECASE | re.DOTALL)
            features['script_count'] = len(scripts)
            features['script_content_length'] = sum(len(script) for script in scripts)
            
            # Link analysis
            links = re.findall(r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>', content, re.IGNORECASE)
            features['link_count'] = len(links)
            external_links = [link for link in links if link.startswith(('http://', 'https://'))]
            features['external_link_count'] = len(external_links)
            features['external_link_ratio'] = len(external_links) / (len(links) + 1)
            
            return features
            
        except Exception as e:
            logger.error(f"❌ Content feature extraction error: {e}")
            return {}
    
    def _extract_pattern_features(self, url: str) -> Dict:
        """Pattern-based özellikler"""
        try:
            features = {}
            
            # URL pattern matching
            for i, pattern in enumerate(self.url_patterns):
                import re
                matches = re.findall(pattern, url, re.IGNORECASE)
                features[f'pattern_{i}_count'] = len(matches)
                features[f'pattern_{i}_present'] = 1 if matches else 0
            
            # Suspicious character sequences
            features['consecutive_dots'] = self._count_consecutive_chars(url, '.')
            features['consecutive_hyphens'] = self._count_consecutive_chars(url, '-')
            features['consecutive_numbers'] = self._count_consecutive_numbers(url)
            
            # Brand impersonation features
            brands = ['paypal', 'amazon', 'google', 'facebook', 'microsoft', 'apple']
            for brand in brands:
                features[f'contains_{brand}'] = 1 if brand in url.lower() else 0
            
            return features
            
        except Exception as e:
            logger.error(f"❌ Pattern feature extraction error: {e}")
            return {}
    
    def _extract_ngram_features(self, url: str, n: int = 3) -> Dict:
        """N-gram özellikler"""
        try:
            features = {}
            
            # Character n-grams
            ngrams = [url[i:i+n] for i in range(len(url)-n+1)]
            ngram_freq = {}
            for ngram in ngrams:
                ngram_freq[ngram] = ngram_freq.get(ngram, 0) + 1
            
            # Top frequent n-grams
            top_ngrams = sorted(ngram_freq.items(), key=lambda x: x[1], reverse=True)[:10]
            for i, (ngram, freq) in enumerate(top_ngrams):
                features[f'top_ngram_{i}_freq'] = freq / len(ngrams) if ngrams else 0
            
            # N-gram diversity
            features['ngram_diversity'] = len(set(ngrams)) / len(ngrams) if ngrams else 0
            
            return features
            
        except Exception as e:
            logger.error(f"❌ N-gram feature extraction error: {e}")
            return {}
    
    def _extract_temporal_features(self) -> Dict:
        """Temporal özellikler"""
        try:
            features = {}
            current_time = datetime.now()
            
            # Time-based features
            features['hour_of_day'] = current_time.hour
            features['day_of_week'] = current_time.weekday()
            features['is_weekend'] = 1 if current_time.weekday() >= 5 else 0
            features['is_business_hours'] = 1 if 9 <= current_time.hour <= 17 else 0
            
            # Seasonal features
            features['month'] = current_time.month
            features['quarter'] = (current_time.month - 1) // 3 + 1
            
            return features
            
        except Exception as e:
            logger.error(f"❌ Temporal feature extraction error: {e}")
            return {}
    
    def _calculate_entropy(self, text: str) -> float:
        """Shannon entropy hesapla"""
        try:
            if not text:
                return 0.0
            
            # Character frequency
            char_freq = {}
            for char in text:
                char_freq[char] = char_freq.get(char, 0) + 1
            
            # Calculate entropy
            entropy = 0.0
            text_length = len(text)
            for freq in char_freq.values():
                prob = freq / text_length
                entropy -= prob * np.log2(prob)
            
            return entropy
            
        except Exception as e:
            logger.error(f"❌ Entropy calculation error: {e}")
            return 0.0
    
    def _count_consecutive_chars(self, text: str, char: str) -> int:
        """Ardışık karakter sayısı"""
        try:
            import re
            pattern = re.escape(char) + r'{2,}'
            matches = re.findall(pattern, text)
            return max(len(match) for match in matches) if matches else 0
        except:
            return 0
    
    def _count_consecutive_numbers(self, text: str) -> int:
        """Ardışık rakam sayısı"""
        try:
            import re
            matches = re.findall(r'\d{2,}', text)
            return max(len(match) for match in matches) if matches else 0
        except:
            return 0
    
    async def adaptive_model_update(self, model_name: str, feedback_data: List[Dict]) -> bool:
        """Adaptive model güncelleme"""
        try:
            if len(feedback_data) < self.min_samples_for_adaptation:
                logger.info(f"Insufficient feedback data for {model_name} adaptation")
                return False
            
            logger.info(f"🔄 Starting adaptive update for {model_name}")
            
            # Prepare training data from feedback
            X_feedback, y_feedback = self._prepare_feedback_data(feedback_data)
            
            if X_feedback is None or len(X_feedback) == 0:
                return False
            
            # Load existing model
            try:
                model = joblib.load(f'{model_name}.pkl')
            except FileNotFoundError:
                logger.error(f"Model file not found: {model_name}.pkl")
                return False
            
            # Check if model supports partial_fit (online learning)
            if hasattr(model, 'partial_fit'):
                # Online learning
                model.partial_fit(X_feedback, y_feedback)
                logger.info(f"✅ Online learning update applied to {model_name}")
            else:
                # Batch learning with existing data
                # In production, you would combine with existing training data
                logger.info(f"Model {model_name} requires batch retraining")
                # For now, skip batch retraining to avoid overwriting
                return False
            
            # Save updated model
            joblib.dump(model, f'{model_name}.pkl')
            
            # Update performance tracking
            self._update_model_performance(model_name, X_feedback, y_feedback, model)
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Adaptive model update error for {model_name}: {e}")
            return False
    
    def _prepare_feedback_data(self, feedback_data: List[Dict]) -> Tuple[Optional[np.ndarray], Optional[np.ndarray]]:
        """Feedback verisini ML formatına çevir"""
        try:
            features_list = []
            labels_list = []
            
            for feedback in feedback_data:
                if 'features' in feedback and 'correct_label' in feedback:
                    features = feedback['features']
                    correct_label = feedback['correct_label']
                    
                    feature_array = self._extract_feature_vector(features)
                    features_list.append(feature_array)
                    labels_list.append(1 if correct_label == 'phishing' else 0)
            
            if features_list and labels_list:
                return np.array(features_list), np.array(labels_list)
            
            return None, None
            
        except Exception as e:
            logger.error(f"❌ Feedback data preparation error: {e}")
            return None, None
    
    def _update_model_performance(self, model_name: str, X_test: np.ndarray, 
                                y_test: np.ndarray, model) -> None:
        """Model performans metriklerini güncelle"""
        try:
            # Make predictions
            y_pred = model.predict(X_test)
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            
            # Update performance tracking
            perf = self.model_performance[model_name]
            perf['accuracy'].append(accuracy)
            perf['precision'].append(precision)
            perf['recall'].append(recall)
            perf['f1_score'].append(f1)
            perf['last_updated'] = datetime.now()
            perf['total_predictions'] += len(y_test)
            perf['correct_predictions'] += accuracy_score(y_test, y_pred, normalize=False)
            
            logger.info(f"📊 Updated performance for {model_name}: "
                       f"Acc={accuracy:.3f}, Prec={precision:.3f}, "
                       f"Rec={recall:.3f}, F1={f1:.3f}")
            
        except Exception as e:
            logger.error(f"❌ Performance update error for {model_name}: {e}")
    
    def get_model_performance_summary(self) -> Dict:
        """Model performans özetini getir"""
        try:
            summary = {}
            
            for model_name, perf in self.model_performance.items():
                if perf['accuracy']:
                    summary[model_name] = {
                        'avg_accuracy': np.mean(perf['accuracy']),
                        'avg_precision': np.mean(perf['precision']),
                        'avg_recall': np.mean(perf['recall']),
                        'avg_f1_score': np.mean(perf['f1_score']),
                        'total_predictions': perf['total_predictions'],
                        'overall_accuracy': perf['correct_predictions'] / perf['total_predictions'] 
                                          if perf['total_predictions'] > 0 else 0,
                        'last_updated': perf['last_updated'].isoformat() if perf['last_updated'] else None,
                        'recent_performance_trend': self._calculate_performance_trend(perf['accuracy'])
                    }
            
            return summary
            
        except Exception as e:
            logger.error(f"❌ Performance summary error: {e}")
            return {}
    
    def _calculate_performance_trend(self, accuracy_history: deque) -> str:
        """Performans trendini hesapla"""
        try:
            if len(accuracy_history) < 10:
                return 'insufficient_data'
            
            recent = list(accuracy_history)[-10:]
            older = list(accuracy_history)[-20:-10] if len(accuracy_history) >= 20 else recent
            
            recent_avg = np.mean(recent)
            older_avg = np.mean(older)
            
            diff = recent_avg - older_avg
            
            if diff > 0.05:
                return 'improving'
            elif diff < -0.05:
                return 'declining'
            else:
                return 'stable'
                
        except Exception as e:
            logger.error(f"❌ Trend calculation error: {e}")
            return 'unknown'
    
    def _save_optimization_results(self, results: Dict) -> None:
        """Optimizasyon sonuçlarını kaydet"""
        try:
            # In production, save to database
            # For now, save to file
            filename = f"ensemble_optimization_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            logger.info(f"💾 Optimization results saved to {filename}")
            
        except Exception as e:
            logger.error(f"❌ Save optimization results error: {e}")
    
    async def add_feedback(self, url: str, predicted_label: str, correct_label: str, 
                          features: Dict, confidence: float) -> None:
        """Gerçek zamanlı feedback ekle"""
        try:
            feedback_entry = {
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'predicted_label': predicted_label,
                'correct_label': correct_label,
                'features': features,
                'confidence': confidence,
                'was_correct': predicted_label == correct_label
            }
            
            with self.feedback_lock:
                self.feedback_buffer.append(feedback_entry)
            
            # Trigger adaptive learning if enough feedback accumulated
            if len(self.feedback_buffer) >= self.min_samples_for_adaptation:
                # Process feedback in background
                asyncio.create_task(self._process_feedback_batch())
            
        except Exception as e:
            logger.error(f"❌ Add feedback error: {e}")
    
    async def _process_feedback_batch(self) -> None:
        """Feedback batch'ini işle"""
        try:
            with self.feedback_lock:
                feedback_batch = list(self.feedback_buffer)
                self.feedback_buffer.clear()
            
            if not feedback_batch:
                return
            
            logger.info(f"🔄 Processing feedback batch of {len(feedback_batch)} samples")
            
            # Group feedback by prediction accuracy
            incorrect_predictions = [
                fb for fb in feedback_batch if not fb['was_correct']
            ]
            
            # If too many incorrect predictions, trigger ensemble rebalancing
            accuracy_rate = 1 - (len(incorrect_predictions) / len(feedback_batch))
            
            if accuracy_rate < 0.8:  # Less than 80% accuracy
                logger.warning(f"⚠️ Low accuracy detected ({accuracy_rate:.2f}), "
                             "triggering ensemble rebalancing")
                # Trigger ensemble optimization with recent data
                # This would be implemented with your existing models
            
            # Store feedback for future model updates
            self._store_feedback_for_training(feedback_batch)
            
        except Exception as e:
            logger.error(f"❌ Process feedback batch error: {e}")
    
    def _store_feedback_for_training(self, feedback_batch: List[Dict]) -> None:
        """Feedback'i gelecekteki training için sakla"""
        try:
            # In production, store in database
            # For now, append to file
            filename = 'training_feedback.jsonl'
            
            with open(filename, 'a') as f:
                for feedback in feedback_batch:
                    f.write(json.dumps(feedback, default=str) + '\n')
            
            logger.info(f"💾 Stored {len(feedback_batch)} feedback samples for training")
            
        except Exception as e:
            logger.error(f"❌ Store feedback error: {e}")

# Global instance
advanced_ml_features = AdvancedMLFeatures() 