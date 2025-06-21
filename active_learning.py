import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, roc_auc_score
import joblib
import logging
from datetime import datetime
import shap
from ml_pipeline import PhishingDetectorPipeline, FeatureExtractor
import warnings
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)

class ActiveLearningSystem:
    """Active Learning ve Incremental Model Güncelleme Sistemi"""
    
    def __init__(self):
        self.pipeline = PhishingDetectorPipeline()
        self.feature_extractor = FeatureExtractor()
        self.uncertainty_threshold = 0.7  # Belirsizlik eşiği
        self.feedback_threshold = 50  # Yeniden eğitim için minimum feedback sayısı
        self.model_version = 1
        
    def load_current_model(self):
        """Mevcut modeli yükle"""
        try:
            self.pipeline.load_model()
            selected_features = joblib.load('selected_features.pkl')
            return True, selected_features
        except:
            logger.error("Model yüklenemedi")
            return False, None
    
    def calculate_prediction_uncertainty(self, prediction_proba):
        """Tahmin belirsizliğini hesapla"""
        # Entropy tabanlı belirsizlik
        entropy = -np.sum(prediction_proba * np.log2(prediction_proba + 1e-10))
        
        # Marjin tabanlı belirsizlik (en yüksek iki tahmin arasındaki fark)
        sorted_proba = np.sort(prediction_proba)[::-1]
        margin = sorted_proba[0] - sorted_proba[1]
        
        # Normalize edilmiş belirsizlik skoru (0-1 arası)
        uncertainty_score = 1 - margin
        
        return uncertainty_score, entropy
    
    def identify_uncertain_predictions(self, feedback_data):
        """Belirsiz tahminleri tespit et"""
        uncertain_samples = []
        
        for _, row in feedback_data.iterrows():
            # URL'den feature'ları çıkar
            features = self.feature_extractor.extract_features(row['url'])
            
            # Model tahmini yap
            selected_features = joblib.load('selected_features.pkl')
            feature_values = [features.get(fname, 0) for fname in selected_features]
            
            prediction_proba = self.pipeline.best_model.predict_proba([feature_values])[0]
            uncertainty, entropy = self.calculate_prediction_uncertainty(prediction_proba)
            
            if uncertainty > self.uncertainty_threshold:
                uncertain_samples.append({
                    'url': row['url'],
                    'features': feature_values,
                    'uncertainty': uncertainty,
                    'entropy': entropy,
                    'actual_label': row['actual_label'],
                    'predicted_label': row['predicted_label'],
                    'feedback_time': row['timestamp']
                })
        
        return uncertain_samples
    
    def prepare_incremental_training_data(self, feedback_file='feedback.csv'):
        """Incremental eğitim için veri hazırla"""
        try:
            # Feedback verilerini oku
            feedback_df = pd.read_csv(feedback_file)
            
            if len(feedback_df) < self.feedback_threshold:
                logger.info(f"Yeterli feedback yok: {len(feedback_df)}/{self.feedback_threshold}")
                return None, None
            
            # Belirsiz örnekleri tespit et
            uncertain_samples = self.identify_uncertain_predictions(feedback_df)
            
            # Yanlış tahminleri de ekle
            wrong_predictions = feedback_df[
                feedback_df['predicted_label'] != feedback_df['actual_label']
            ]
            
            # Eğitim verisi hazırla
            training_data = []
            training_labels = []
            
            # Belirsiz örnekleri ekle
            for sample in uncertain_samples:
                training_data.append(sample['features'])
                training_labels.append(1 if sample['actual_label'] == 'phishing' else 0)
            
            # Yanlış tahminleri ekle
            for _, row in wrong_predictions.iterrows():
                features = self.feature_extractor.extract_features(row['url'])
                selected_features = joblib.load('selected_features.pkl')
                feature_values = [features.get(fname, 0) for fname in selected_features]
                
                training_data.append(feature_values)
                training_labels.append(1 if row['actual_label'] == 'phishing' else 0)
            
            if len(training_data) == 0:
                logger.info("Eğitim için uygun veri bulunamadı")
                return None, None
            
            return np.array(training_data), np.array(training_labels)
            
        except Exception as e:
            logger.error(f"Incremental veri hazırlama hatası: {e}")
            return None, None
    
    def incremental_update(self, new_X, new_y):
        """Modeli incremental olarak güncelle"""
        try:
            # Mevcut modeli yükle
            success, selected_features = self.load_current_model()
            if not success:
                logger.error("Model güncellenemedi - mevcut model yok")
                return False
            
            # Orijinal eğitim verisi yükle (cache'lenmiş olmalı)
            try:
                original_X = joblib.load('original_training_X.pkl')
                original_y = joblib.load('original_training_y.pkl')
            except:
                logger.warning("Orijinal eğitim verisi bulunamadı, sadece yeni veri kullanılacak")
                original_X = new_X
                original_y = new_y
            
            # Verileri birleştir
            combined_X = np.vstack([original_X, new_X])
            combined_y = np.hstack([original_y, new_y])
            
            # Train-validation split
            X_train, X_val, y_train, y_val = train_test_split(
                combined_X, combined_y, test_size=0.2, random_state=42, stratify=combined_y
            )
            
            # Yeni model eğit
            new_model = RandomForestClassifier(
                n_estimators=300,  # Daha fazla ağaç
                max_depth=20,
                random_state=42,
                n_jobs=-1
            )
            
            new_model.fit(X_train, y_train)
            
            # Performansı değerlendir
            val_pred = new_model.predict(X_val)
            val_pred_proba = new_model.predict_proba(X_val)[:, 1]
            
            new_accuracy = accuracy_score(y_val, val_pred)
            new_auc = roc_auc_score(y_val, val_pred_proba)
            
            # Eski model performansı
            old_val_pred = self.pipeline.best_model.predict(X_val)
            old_val_pred_proba = self.pipeline.best_model.predict_proba(X_val)[:, 1]
            
            old_accuracy = accuracy_score(y_val, old_val_pred)
            old_auc = roc_auc_score(y_val, old_val_pred_proba)
            
            logger.info(f"Eski model - Accuracy: {old_accuracy:.4f}, AUC: {old_auc:.4f}")
            logger.info(f"Yeni model - Accuracy: {new_accuracy:.4f}, AUC: {new_auc:.4f}")
            
            # Yeni model daha iyiyse güncelle
            if new_auc > old_auc:
                # Modeli kaydet
                self.model_version += 1
                model_backup_name = f'model_v{self.model_version}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pkl'
                
                # Eski modeli yedekle
                joblib.dump(self.pipeline.best_model, f'backup_{model_backup_name}')
                
                # Yeni modeli kaydet
                joblib.dump(new_model, 'best_phishing_model.pkl')
                
                # Model bilgilerini güncelle
                model_info = {
                    'model_name': 'RandomForest_Updated',
                    'accuracy': new_accuracy,
                    'auc_score': new_auc,
                    'version': self.model_version,
                    'update_time': datetime.now().isoformat(),
                    'training_samples': len(combined_X)
                }
                joblib.dump(model_info, 'model_info.pkl')
                
                # Güncellenmiş eğitim verisini kaydet
                joblib.dump(combined_X, 'original_training_X.pkl')
                joblib.dump(combined_y, 'original_training_y.pkl')
                
                # Pipeline'ı güncelle
                self.pipeline.best_model = new_model
                self.pipeline.best_model_name = 'RandomForest_Updated'
                
                logger.info(f"✅ Model başarıyla güncellendi! v{self.model_version}")
                logger.info(f"📈 Performans artışı - AUC: {old_auc:.4f} → {new_auc:.4f}")
                
                return True
            else:
                logger.info("❌ Yeni model eski modelden daha iyi değil, güncelleme yapılmadı")
                return False
                
        except Exception as e:
            logger.error(f"Incremental update hatası: {e}")
            return False
    
    def semi_supervised_learning(self, unlabeled_urls, confidence_threshold=0.9):
        """Semi-supervised learning - yüksek güvenli tahminleri pseudo-label olarak kullan"""
        try:
            success, selected_features = self.load_current_model()
            if not success:
                return []
            
            pseudo_labeled_data = []
            
            for url in unlabeled_urls:
                # Feature'ları çıkar
                features = self.feature_extractor.extract_features(url)
                feature_values = [features.get(fname, 0) for fname in selected_features]
                
                # Tahmin yap
                prediction_proba = self.pipeline.best_model.predict_proba([feature_values])[0]
                confidence = np.max(prediction_proba)
                
                # Yüksek güvenli tahminleri pseudo-label olarak ekle
                if confidence > confidence_threshold:
                    prediction = np.argmax(prediction_proba)
                    pseudo_labeled_data.append({
                        'url': url,
                        'features': feature_values,
                        'pseudo_label': prediction,
                        'confidence': confidence
                    })
                    
                    logger.info(f"Pseudo-labeled: {url} -> {'phishing' if prediction == 1 else 'safe'} (conf: {confidence:.3f})")
            
            return pseudo_labeled_data
            
        except Exception as e:
            logger.error(f"Semi-supervised learning hatası: {e}")
            return []
    
    def run_active_learning_cycle(self):
        """Tam active learning döngüsünü çalıştır"""
        logger.info("🔄 Active Learning döngüsü başlatılıyor...")
        
        # 1. Incremental training data hazırla
        new_X, new_y = self.prepare_incremental_training_data()
        
        if new_X is not None and len(new_X) > 0:
            logger.info(f"📊 {len(new_X)} yeni eğitim örneği bulundu")
            
            # 2. Modeli incremental olarak güncelle
            update_success = self.incremental_update(new_X, new_y)
            
            if update_success:
                # 3. SHAP analizi güncelle
                try:
                    self.update_shap_analysis()
                    logger.info("✅ SHAP analizi güncellendi")
                except Exception as e:
                    logger.error(f"SHAP analizi hatası: {e}")
                
                # 4. Model performans raporu
                self.generate_performance_report()
                
                return True
        else:
            logger.info("❌ Yeterli yeni eğitim verisi bulunamadı")
            return False
    
    def update_shap_analysis(self):
        """SHAP analizini güncelle"""
        try:
            # Test verisi yükle
            original_X = joblib.load('original_training_X.pkl')
            sample_size = min(100, len(original_X))
            sample_indices = np.random.choice(len(original_X), sample_size, replace=False)
            X_sample = original_X[sample_indices]
            
            # SHAP explainer oluştur
            explainer = shap.TreeExplainer(self.pipeline.best_model)
            shap_values = explainer.shap_values(X_sample)
            
            # SHAP plot kaydet
            import matplotlib.pyplot as plt
            plt.figure(figsize=(12, 8))
            if isinstance(shap_values, list):
                shap.summary_plot(shap_values[1], X_sample, show=False)
            else:
                shap.summary_plot(shap_values, X_sample, show=False)
            plt.title(f'SHAP Analysis - Model v{self.model_version}')
            plt.tight_layout()
            plt.savefig(f'shap_analysis_v{self.model_version}.png', dpi=300, bbox_inches='tight')
            plt.close()
            
        except Exception as e:
            logger.error(f"SHAP güncelleme hatası: {e}")
    
    def generate_performance_report(self):
        """Performans raporu oluştur"""
        try:
            # Model bilgilerini oku
            model_info = joblib.load('model_info.pkl')
            
            report = f"""
🤖 PHISHING DETECTOR MODEL RAPORU
{'='*50}
📅 Güncelleme Zamanı: {model_info.get('update_time', 'N/A')}
🔢 Model Versiyonu: v{model_info.get('version', 1)}
📈 Doğruluk Oranı: {model_info.get('accuracy', 0):.4f}
🎯 AUC Skoru: {model_info.get('auc_score', 0):.4f}
📊 Eğitim Örnek Sayısı: {model_info.get('training_samples', 'N/A')}
🧠 Model Tipi: {model_info.get('model_name', 'N/A')}

🔄 Active Learning Döngüsü Tamamlandı!
📁 Güncellenmiş dosyalar:
   - best_phishing_model.pkl
   - model_info.pkl
   - shap_analysis_v{model_info.get('version', 1)}.png
            """
            
            print(report)
            
            # Raporu dosyaya kaydet
            with open(f'performance_report_v{model_info.get("version", 1)}.txt', 'w', encoding='utf-8') as f:
                f.write(report)
                
        except Exception as e:
            logger.error(f"Rapor oluşturma hatası: {e}")

def run_active_learning_scheduler():
    """Active learning zamanlayıcısı - belirli aralıklarla çalışır"""
    import time
    
    al_system = ActiveLearningSystem()
    
    while True:
        try:
            logger.info("🕐 Active learning döngüsü kontrol ediliyor...")
            al_system.run_active_learning_cycle()
            
            # 1 saat bekle (üretimde daha uzun olabilir)
            time.sleep(3600)
            
        except KeyboardInterrupt:
            logger.info("⏹️ Active learning zamanlayıcısı durduruldu")
            break
        except Exception as e:
            logger.error(f"Zamanlayıcı hatası: {e}")
            time.sleep(300)  # 5 dakika bekle ve tekrar dene

if __name__ == "__main__":
    # Logging ayarları
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Active learning sistemini test et
    al_system = ActiveLearningSystem()
    
    print("🚀 Active Learning Sistemi Test Ediliyor...")
    print("="*50)
    
    # Tek döngü çalıştır
    success = al_system.run_active_learning_cycle()
    
    if success:
        print("✅ Active learning döngüsü başarıyla tamamlandı!")
    else:
        print("ℹ️ Güncelleme için yeterli veri yok veya model zaten optimal")
    
    print("\n💡 Sürekli çalıştırmak için 'run_active_learning_scheduler()' fonksiyonunu kullanın") 