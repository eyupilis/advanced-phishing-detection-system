"""
DYNAMIC MODEL WEIGHTING SYSTEM
Kullanıcı feedback'lerine göre model ağırlıklarını dinamik olarak ayarlama
"""

import json
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
import logging
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

class DynamicModelWeighting:
    def __init__(self, update_threshold: int = 10, learning_rate: float = 0.02):
        """
        Args:
            update_threshold: Her kaç feedback'te bir ağırlıkları güncelle
            learning_rate: Öğrenme hızı (0.01-0.05 arası önerilen)
        """
        self.update_threshold = update_threshold
        self.learning_rate = learning_rate
        
        # Model isimleri (7-model ensemble)
        self.model_names = [
            'phishing_model', 'cybersecurity_model', 'phishing_urls_model',
            'website_model', 'crypto_scam_model', 'link_phishing_model',
            'malicious_urls_model'
        ]
        
        # Model ağırlıkları (başlangıçta eşit)
        self.model_weights = {model: 1.0 for model in self.model_names}
        
        # Feedback buffer (son N feedback'i sakla)
        self.feedback_buffer = deque(maxlen=1000)  # Son 1000 feedback
        
        # Performance tracking
        self.model_performance = {
            model: {
                'correct_predictions': 0,
                'total_predictions': 0,
                'accuracy': 1.0,
                'confidence_sum': 0.0,
                'avg_confidence': 0.5
            } for model in self.model_names
        }
        
        # Weighting history (analiz için)
        self.weight_history = []
        
        # Dosya adları
        self.weights_file = "dynamic_model_weights.json"
        self.performance_file = "model_performance_history.json"
        
        # Mevcut weights'i yükle
        self._load_weights()
    
    def add_feedback(self, analysis_result: Dict, user_feedback: str):
        """
        Yeni kullanıcı feedback'i ekle ve gerekirse ağırlıkları güncelle
        
        Args:
            analysis_result: 7-model ensemble analiz sonucu
            user_feedback: 'correct' veya 'incorrect'
        """
        try:
            # Feedback'i buffer'a ekle
            feedback_entry = {
                'timestamp': datetime.now().isoformat(),
                'user_feedback': user_feedback,
                'ensemble_prediction': analysis_result.get('ensemble_prediction', ''),
                'ensemble_confidence': analysis_result.get('ensemble_confidence', 0),
                'individual_models': analysis_result.get('individual_models', {}),
                'url': analysis_result.get('url', '')
            }
            
            self.feedback_buffer.append(feedback_entry)
            
            # Her model için performance güncelle
            self._update_model_performance(feedback_entry)
            
            # Threshold'a ulaştıysak ağırlıkları güncelle
            if len(self.feedback_buffer) % self.update_threshold == 0:
                self._update_weights()
                logger.info(f"🔄 Model weights updated after {len(self.feedback_buffer)} feedbacks")
            
        except Exception as e:
            logger.error(f"❌ Add feedback error: {e}")
    
    def _update_model_performance(self, feedback_entry: Dict):
        """Her model için performance metriklerini güncelle"""
        try:
            user_feedback = feedback_entry['user_feedback']
            individual_models = feedback_entry['individual_models']
            ensemble_prediction = feedback_entry['ensemble_prediction'].lower()
            
            # Kullanıcının doğru cevabını belirle
            if user_feedback == 'correct':
                # Ensemble doğru tahmin etti, user correct dedi
                correct_label = ensemble_prediction
            else:
                # Ensemble yanlış tahmin etti, tersini al
                correct_label = 'safe' if ensemble_prediction == 'phishing' else 'phishing'
            
            # Her model için doğruluk kontrol et
            for model_name, model_result in individual_models.items():
                if model_name in self.model_performance:
                    model_prediction = model_result.get('prediction', '').lower()
                    model_confidence = model_result.get('confidence', 0)
                    
                    # Performance metrics güncelle
                    self.model_performance[model_name]['total_predictions'] += 1
                    self.model_performance[model_name]['confidence_sum'] += model_confidence
                    
                    # Doğru tahmin mi?
                    if model_prediction == correct_label:
                        self.model_performance[model_name]['correct_predictions'] += 1
                    
                    # Accuracy hesapla
                    total = self.model_performance[model_name]['total_predictions']
                    correct = self.model_performance[model_name]['correct_predictions']
                    self.model_performance[model_name]['accuracy'] = correct / total if total > 0 else 1.0
                    
                    # Average confidence hesapla
                    conf_sum = self.model_performance[model_name]['confidence_sum']
                    self.model_performance[model_name]['avg_confidence'] = conf_sum / total if total > 0 else 0.5
            
        except Exception as e:
            logger.error(f"❌ Update model performance error: {e}")
    
    def _update_weights(self):
        """Model ağırlıklarını performance'a göre güncelle"""
        try:
            # Son N feedback'e göre ağırlık hesapla
            recent_feedbacks = list(self.feedback_buffer)[-self.update_threshold:]
            
            # Her model için success rate hesapla
            model_success_rates = {}
            
            for model_name in self.model_names:
                correct_count = 0
                total_count = 0
                
                for feedback in recent_feedbacks:
                    individual_models = feedback.get('individual_models', {})
                    if model_name in individual_models:
                        total_count += 1
                        
                        # Model'in tahminini kontrol et
                        model_pred = individual_models[model_name].get('prediction', '').lower()
                        ensemble_pred = feedback.get('ensemble_prediction', '').lower()
                        user_feedback = feedback.get('user_feedback', '')
                        
                        # Doğru tahmin mi?
                        if user_feedback == 'correct':
                            # Ensemble doğruysa, model de doğru mu?
                            if model_pred == ensemble_pred:
                                correct_count += 1
                        else:
                            # Ensemble yanlışsa, model doğru mu?
                            correct_label = 'safe' if ensemble_pred == 'phishing' else 'phishing'
                            if model_pred == correct_label:
                                correct_count += 1
                
                # Success rate hesapla
                success_rate = correct_count / total_count if total_count > 0 else 0.5
                model_success_rates[model_name] = success_rate
            
            # Ağırlıkları güncelle (exponential moving average)
            for model_name in self.model_names:
                success_rate = model_success_rates.get(model_name, 0.5)
                
                # Learning rate ile ağırlık güncelle
                if success_rate > 0.5:
                    # Başarılı model → ağırlığı artır
                    weight_multiplier = 1 + (success_rate - 0.5) * self.learning_rate * 2
                else:
                    # Başarısız model → ağırlığı azalt
                    weight_multiplier = 1 - (0.5 - success_rate) * self.learning_rate * 2
                
                # Ağırlığı güncelle (minimum 0.1, maksimum 2.0)
                new_weight = self.model_weights[model_name] * weight_multiplier
                self.model_weights[model_name] = max(0.1, min(2.0, new_weight))
            
            # Normalize weights (toplamı model sayısına eşit olsun)
            total_weight = sum(self.model_weights.values())
            normalization_factor = len(self.model_names) / total_weight
            
            for model_name in self.model_names:
                self.model_weights[model_name] *= normalization_factor
            
            # History'e kaydet
            self.weight_history.append({
                'timestamp': datetime.now().isoformat(),
                'weights': self.model_weights.copy(),
                'success_rates': model_success_rates,
                'feedback_count': len(self.feedback_buffer)
            })
            
            # Dosyaya kaydet
            self._save_weights()
            
            logger.info(f"✅ Model weights updated: {self.model_weights}")
            
        except Exception as e:
            logger.error(f"❌ Update weights error: {e}")
    
    def get_current_weights(self) -> Dict[str, float]:
        """Mevcut model ağırlıklarını döndür"""
        return self.model_weights.copy()
    
    def get_performance_summary(self) -> Dict:
        """Model performance özetini döndür"""
        return {
            'model_performance': self.model_performance.copy(),
            'current_weights': self.model_weights.copy(),
            'total_feedbacks': len(self.feedback_buffer),
            'last_update': self.weight_history[-1] if self.weight_history else None
        }
    
    def reset_weights(self):
        """Ağırlıkları başlangıç değerlerine döndür"""
        self.model_weights = {model: 1.0 for model in self.model_names}
        self.feedback_buffer.clear()
        self.weight_history.clear()
        self._save_weights()
        logger.info("🔄 Model weights reset to default")
    
    def _save_weights(self):
        """Ağırlıkları dosyaya kaydet"""
        try:
            data = {
                'model_weights': self.model_weights,
                'model_performance': self.model_performance,
                'weight_history': self.weight_history[-100:],  # Son 100 değişiklik
                'last_updated': datetime.now().isoformat(),
                'total_feedbacks': len(self.feedback_buffer)
            }
            
            with open(self.weights_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.error(f"❌ Save weights error: {e}")
    
    def _load_weights(self):
        """Kayıtlı ağırlıkları yükle"""
        try:
            with open(self.weights_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            self.model_weights = data.get('model_weights', {model: 1.0 for model in self.model_names})
            self.model_performance = data.get('model_performance', {
                model: {
                    'correct_predictions': 0,
                    'total_predictions': 0,
                    'accuracy': 1.0,
                    'confidence_sum': 0.0,
                    'avg_confidence': 0.5
                } for model in self.model_names
            })
            self.weight_history = data.get('weight_history', [])
            
            logger.info(f"✅ Model weights loaded: {self.model_weights}")
            
        except FileNotFoundError:
            logger.info("📁 No saved weights found, using default weights")
        except Exception as e:
            logger.error(f"❌ Load weights error: {e}")
    
    def export_performance_data(self) -> Dict:
        """Performance verilerini analiz için export et"""
        return {
            'model_weights': self.model_weights,
            'model_performance': self.model_performance,
            'weight_history': self.weight_history,
            'recent_feedbacks': list(self.feedback_buffer)[-50:],  # Son 50 feedback
            'statistics': {
                'total_feedbacks': len(self.feedback_buffer),
                'updates_count': len(self.weight_history),
                'avg_accuracy': np.mean([perf['accuracy'] for perf in self.model_performance.values()]),
                'weight_variance': np.var(list(self.model_weights.values()))
            }
        }

# Global instance
dynamic_weighting = DynamicModelWeighting() 