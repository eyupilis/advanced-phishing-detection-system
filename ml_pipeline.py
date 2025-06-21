import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score
import xgboost as xgb
import lightgbm as lgb
import shap
import joblib
import warnings
warnings.filterwarnings('ignore')

class PhishingDetectorPipeline:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_importance = {}
        self.shap_explainer = None
        self.best_model = None
        self.best_model_name = None
        
    def load_and_prepare_data(self, csv_path):
        """Veriyi yükle ve hazırla"""
        print("🔄 Veri yükleniyor...")
        df = pd.read_csv(csv_path)
        
        # URL sütununu kaldır (model için gerekli değil)
        if 'url' in df.columns:
            df = df.drop('url', axis=1)
        
        # Hedef değişkeni encode et
        le = LabelEncoder()
        df['label_encoded'] = le.fit_transform(df['label'])
        
        # Features ve target ayır
        X = df.drop(['label', 'label_encoded'], axis=1)
        y = df['label_encoded']  # 0: good, 1: bad
        
        print(f"✅ Veri hazırlandı: {X.shape[0]} örnek, {X.shape[1]} özellik")
        return X, y, le
    
    def feature_selection(self, X, y, top_k=50):
        """En önemli özellikleri seç"""
        print(f"🔍 En önemli {top_k} özellik seçiliyor...")
        
        # Random Forest ile feature importance
        rf_selector = RandomForestClassifier(n_estimators=100, random_state=42)
        rf_selector.fit(X, y)
        
        # Feature importance'ları al
        feature_importance = pd.DataFrame({
            'feature': X.columns,
            'importance': rf_selector.feature_importances_
        }).sort_values('importance', ascending=False)
        
        # En önemli özellikleri seç
        top_features = feature_importance.head(top_k)['feature'].tolist()
        
        print(f"✅ Seçilen özellikler: {len(top_features)}")
        return X[top_features], top_features, feature_importance
    
    def train_models(self, X_train, X_test, y_train, y_test):
        """Birden fazla model eğit"""
        print("🚀 Modeller eğitiliyor...")
        
        # Model tanımları
        models_config = {
            'RandomForest': RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                random_state=42,
                n_jobs=-1
            ),
            'XGBoost': xgb.XGBClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                eval_metric='logloss'
            ),
            'LightGBM': lgb.LGBMClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                verbose=-1
            )
        }
        
        results = {}
        best_score = 0
        
        for name, model in models_config.items():
            print(f"📊 {name} eğitiliyor...")
            
            # Model eğit
            model.fit(X_train, y_train)
            
            # Tahmin yap
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1]
            
            # Metrikleri hesapla
            accuracy = accuracy_score(y_test, y_pred)
            auc_score = roc_auc_score(y_test, y_pred_proba)
            
            # Cross validation
            cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')
            
            results[name] = {
                'model': model,
                'accuracy': accuracy,
                'auc_score': auc_score,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'classification_report': classification_report(y_test, y_pred)
            }
            
            print(f"✅ {name} - Accuracy: {accuracy:.4f}, AUC: {auc_score:.4f}")
            
            # En iyi modeli belirle
            if auc_score > best_score:
                best_score = auc_score
                self.best_model = model
                self.best_model_name = name
        
        self.models = results
        print(f"🏆 En iyi model: {self.best_model_name} (AUC: {best_score:.4f})")
        return results
    
    def explain_model_with_shap(self, X_train, X_test):
        """SHAP ile model açıklanabilirlik analizi"""
        print("🧠 SHAP analizi yapılıyor...")
        
        # SHAP explainer oluştur
        if self.best_model_name == 'XGBoost':
            self.shap_explainer = shap.TreeExplainer(self.best_model)
        elif self.best_model_name == 'LightGBM':
            self.shap_explainer = shap.TreeExplainer(self.best_model)
        else:  # RandomForest
            self.shap_explainer = shap.TreeExplainer(self.best_model)
        
        # SHAP değerlerini hesapla
        shap_values = self.shap_explainer.shap_values(X_test)
        
        # SHAP summary plot
        plt.figure(figsize=(12, 8))
        if isinstance(shap_values, list):
            shap.summary_plot(shap_values[1], X_test, show=False)
        else:
            shap.summary_plot(shap_values, X_test, show=False)
        plt.title('SHAP Feature Importance Analysis')
        plt.tight_layout()
        plt.savefig('shap_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        print("✅ SHAP analizi tamamlandı (shap_analysis.png dosyasına kaydedildi)")
        return shap_values
    
    def save_models(self):
        """Modeli ve scaler'ı kaydet"""
        print("💾 Model kaydediliyor...")
        
        # En iyi modeli kaydet
        joblib.dump(self.best_model, 'best_phishing_model.pkl')
        
        # Model bilgilerini kaydet
        model_info = {
            'model_name': self.best_model_name,
            'accuracy': self.models[self.best_model_name]['accuracy'],
            'auc_score': self.models[self.best_model_name]['auc_score']
        }
        joblib.dump(model_info, 'model_info.pkl')
        
        print(f"✅ Model kaydedildi: {self.best_model_name}")
    
    def load_model(self):
        """Kaydedilen modeli yükle"""
        try:
            self.best_model = joblib.load('best_phishing_model.pkl')
            model_info = joblib.load('model_info.pkl')
            self.best_model_name = model_info['model_name']
            print(f"✅ Model yüklendi: {self.best_model_name}")
            return True
        except:
            print("❌ Model yüklenemedi")
            return False
    
    def predict_single_url(self, features):
        """Tek bir URL için tahmin yap"""
        if self.best_model is None:
            if not self.load_model():
                return None, None
        
        # Tahmin yap
        prediction = self.best_model.predict([features])[0]
        probability = self.best_model.predict_proba([features])[0]
        
        return prediction, probability
    
    def run_full_pipeline(self, csv_path, test_size=0.2, top_features=50):
        """Tam pipeline'ı çalıştır"""
        print("🚀 Phishing Detector Pipeline Başlatılıyor...")
        print("="*50)
        
        # 1. Veriyi yükle
        X, y, label_encoder = self.load_and_prepare_data(csv_path)
        
        # 2. Feature selection
        X_selected, selected_features, feature_importance = self.feature_selection(X, y, top_features)
        
        # 3. Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_selected, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # 4. Modelleri eğit
        results = self.train_models(X_train, X_test, y_train, y_test)
        
        # 5. SHAP analizi
        shap_values = self.explain_model_with_shap(X_train, X_test[:100])  # İlk 100 örnek için
        
        # 6. Modeli kaydet
        self.save_models()
        
        # 7. Sonuçları göster
        print("\n" + "="*50)
        print("📊 MODEL PERFORMANS RAPORU")
        print("="*50)
        
        for name, result in results.items():
            print(f"\n🔸 {name}:")
            print(f"   Accuracy: {result['accuracy']:.4f}")
            print(f"   AUC Score: {result['auc_score']:.4f}")
            print(f"   CV Mean ± Std: {result['cv_mean']:.4f} ± {result['cv_std']:.4f}")
        
        # Feature importance'ları kaydet
        feature_importance.to_csv('feature_importance.csv', index=False)
        joblib.dump(selected_features, 'selected_features.pkl')
        
        print(f"\n✅ Pipeline tamamlandı!")
        print(f"📁 Kaydedilen dosyalar:")
        print(f"   - best_phishing_model.pkl")
        print(f"   - model_info.pkl")
        print(f"   - selected_features.pkl")
        print(f"   - feature_importance.csv")
        print(f"   - shap_analysis.png")
        
        return results, selected_features, feature_importance

# Ana çalıştırma
if __name__ == "__main__":
    # Pipeline'ı başlat
    pipeline = PhishingDetectorPipeline()
    
    # Tam pipeline'ı çalıştır
    results, features, importance = pipeline.run_full_pipeline(
        csv_path='mega_phishing_dataset_20k.csv',
        test_size=0.2,
        top_features=50
    ) 