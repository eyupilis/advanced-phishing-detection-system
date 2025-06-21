#!/usr/bin/env python3
"""
6. Model Pipeline: Link Phishing Detection
Dataset: Link Phishing Detection with 87 comprehensive features
Target: status (phishing, legitimate)
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif, RFECV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, classification_report, confusion_matrix
from sklearn.linear_model import LogisticRegression
import xgboost as xgb
import lightgbm as lgb
from catboost import CatBoostClassifier
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import shap
from typing import Dict, Any, Tuple
import warnings
warnings.filterwarnings('ignore')

class LinkPhishingDetectorPipeline:
    """Link Phishing Detection Pipeline with 87 Features"""
    
    def __init__(self):
        self.model = None
        self.label_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.feature_selector = None
        self.selected_features = None
        self.feature_names = []
        self.feature_importance = None
        self.model_info = {}
        
    def load_and_preprocess_data(self, filepath: str) -> Tuple[pd.DataFrame, pd.Series]:
        """Veri setini yükle ve ön işleme yap"""
        print("📂 Link Phishing veri seti yükleniyor...")
        
        df = pd.read_csv(filepath, low_memory=False)
        print(f"   📏 Boyut: {df.shape[0]} örneklem, {df.shape[1]} sütun")
        
        # Gereksiz sütunları kaldır
        if 'Unnamed: 0' in df.columns:
            df = df.drop('Unnamed: 0', axis=1)
        
        # URL sütununu kaldır (feature extraction için sakla ama modelde kullanma)
        if 'url' in df.columns:
            df = df.drop('url', axis=1)
        
        # Target değişkeni ayır
        target_col = 'status'
        X = df.drop(target_col, axis=1)
        y = df[target_col]
        
        print(f"   🎯 Target dağılımı:")
        value_counts = y.value_counts()
        for label, count in value_counts.items():
            percentage = (count / len(y)) * 100
            print(f"     {label}: {count} ({percentage:.1f}%)")
        
        # Mixed type sütunları düzelt
        for col in X.columns:
            if X[col].dtype == 'object':
                # String değerleri sayısal değerlere çevir
                X[col] = X[col].replace({'one': 1, 'zero': 0, 'One': 1, 'Zero': 0, '1': 1, '0': 0})
                X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)
        
        print(f"   🔢 Özellikler ({len(X.columns)}):")
        print(f"     İlk 10: {list(X.columns[:10])}")
        print(f"     Son 10: {list(X.columns[-10:])}")
        
        return X, y
    
    def feature_analysis(self, X: pd.DataFrame, y: pd.Series) -> pd.DataFrame:
        """Özellik analizi ve mühendisliği"""
        print("🔍 Özellik analizi yapılıyor...")
        
        X_processed = X.copy()
        
        # Temel istatistikler
        print(f"   📊 Null değerler: {X_processed.isnull().sum().sum()}")
        print(f"   📊 Duplicate satırlar: {X_processed.duplicated().sum()}")
        
        # Composite features oluştur
        print("   🔧 Composite özellikler oluşturuluyor...")
        
        # URL complexity score
        complexity_features = ['url_length', 'hostname_length', 'nb_subdomains', 'total_of.', 'total_of-', 'total_of@']
        if all(col in X_processed.columns for col in complexity_features):
            X_processed['url_complexity_score'] = X_processed[complexity_features].sum(axis=1)
        
        # Security indicators
        security_features = ['https_token', 'dns_record', 'google_index', 'whois_registered_domain']
        if all(col in X_processed.columns for col in security_features):
            X_processed['security_score'] = X_processed[security_features].sum(axis=1)
        
        # Suspicious patterns
        suspicious_features = ['ip', 'punycode', 'abnormal_subdomain', 'prefix_suffix', 'shortening_service']
        if all(col in X_processed.columns for col in suspicious_features):
            X_processed['suspicious_pattern_score'] = X_processed[suspicious_features].sum(axis=1)
        
        # Brand mimicking score
        brand_features = ['domain_in_brand', 'brand_in_subdomain', 'brand_in_path']
        if all(col in X_processed.columns for col in brand_features):
            X_processed['brand_mimicking_score'] = X_processed[brand_features].sum(axis=1)
        
        # Web content analysis
        content_features = ['login_form', 'external_favicon', 'iframe', 'popup_window', 'onmouseover', 'right_clic']
        if all(col in X_processed.columns for col in content_features):
            X_processed['malicious_content_score'] = X_processed[content_features].sum(axis=1)
        
        print(f"   ✅ {X_processed.shape[1]} özellik hazırlandı (orijinal: {X.shape[1]})")
        print(f"   🆕 Yeni özellikler: {X_processed.shape[1] - X.shape[1]} adet")
        
        return X_processed
    
    def feature_selection(self, X: pd.DataFrame, y: pd.Series, k: int = 50) -> Tuple[pd.DataFrame, list]:
        """En önemli özellikleri seç"""
        print(f"🎯 Özellik seçimi (en iyi {k} özellik)...")
        
        # Label encoding for target
        y_encoded = self.label_encoder.fit_transform(y)
        
        # İlk olarak univariate selection
        selector_univariate = SelectKBest(score_func=f_classif, k=min(k, X.shape[1]))
        X_selected = selector_univariate.fit_transform(X, y_encoded)
        
        # Seçilen özellik isimlerini al
        selected_indices = selector_univariate.get_support(indices=True)
        selected_features = X.columns[selected_indices].tolist()
        
        # Random Forest ile feature importance doğrula
        rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        rf.fit(X_selected, y_encoded)
        
        # Feature importance'a göre sırala
        feature_importance = pd.DataFrame({
            'feature': selected_features,
            'importance': rf.feature_importances_,
            'f_score': selector_univariate.scores_[selected_indices]
        }).sort_values('importance', ascending=False)
        
        print("   📊 En önemli 15 özellik:")
        for idx, row in feature_importance.head(15).iterrows():
            print(f"     {row['feature']:30s}: importance={row['importance']:.4f}, f_score={row['f_score']:.2f}")
        
        self.selected_features = selected_features
        self.feature_selector = selector_univariate
        self.feature_importance = feature_importance
        self.feature_names = selected_features
        
        return pd.DataFrame(X_selected, columns=selected_features, index=X.index), selected_features
    
    def train_models(self, X: pd.DataFrame, y: pd.Series) -> Dict[str, Any]:
        """Farklı algoritmaları eğit ve karşılaştır"""
        print("🚀 Model eğitimi başlıyor...")
        
        # Label encoding
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
        
        # Modeller
        models = {
            'RandomForest': RandomForestClassifier(
                n_estimators=300, 
                max_depth=20, 
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42, 
                n_jobs=-1
            ),
            'ExtraTrees': ExtraTreesClassifier(
                n_estimators=300, 
                max_depth=20, 
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42, 
                n_jobs=-1
            ),
            'XGBoost': xgb.XGBClassifier(
                n_estimators=300, 
                max_depth=12, 
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42, 
                n_jobs=-1
            ),
            'LightGBM': lgb.LGBMClassifier(
                n_estimators=300, 
                max_depth=12, 
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42, 
                verbose=-1,
                n_jobs=-1
            ),
            'CatBoost': CatBoostClassifier(
                iterations=300, 
                depth=10,
                learning_rate=0.1,
                random_state=42, 
                verbose=False
            )
        }
        
        results = {}
        
        for name, model in models.items():
            print(f"\n🔄 {name} eğitiliyor...")
            
            # Model eğitimi
            model.fit(X_train, y_train)
            
            # Tahminler
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None
            
            # Metrikler
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred)
            recall = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            auc = roc_auc_score(y_test, y_pred_proba) if y_pred_proba is not None else 0
            
            results[name] = {
                'model': model,
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'auc_score': auc
            }
            
            print(f"   📈 Accuracy: {accuracy:.4f}")
            print(f"   📈 Precision: {precision:.4f}")
            print(f"   📈 Recall: {recall:.4f}")
            print(f"   📈 F1-Score: {f1:.4f}")
            print(f"   📈 AUC: {auc:.4f}")
        
        # En iyi modeli seç
        best_model_name = max(results.keys(), key=lambda x: results[x]['auc_score'])
        best_model = results[best_model_name]['model']
        
        print(f"\n🏆 En iyi model: {best_model_name}")
        print(f"   📊 AUC Score: {results[best_model_name]['auc_score']:.4f}")
        print(f"   📊 Accuracy: {results[best_model_name]['accuracy']:.4f}")
        
        self.model = best_model
        self.model_info = {
            'model_name': best_model_name,
            'accuracy': results[best_model_name]['accuracy'],
            'precision': results[best_model_name]['precision'],
            'recall': results[best_model_name]['recall'],
            'f1_score': results[best_model_name]['f1_score'],
            'auc_score': results[best_model_name]['auc_score'],
            'feature_count': len(self.selected_features),
            'dataset_size': len(X)
        }
        
        return results
    
    def save_model(self, prefix: str = "link_phishing_model"):
        """Modeli ve bileşenleri kaydet"""
        print("💾 Model kaydediliyor...")
        
        # Model
        joblib.dump(self.model, f'{prefix}_best.pkl')
        print(f"   ✅ Model: {prefix}_best.pkl")
        
        # Label encoder
        joblib.dump(self.label_encoder, f'{prefix}_best_label_encoder.pkl')
        print(f"   ✅ Label encoder: {prefix}_best_label_encoder.pkl")
        
        # Scaler
        joblib.dump(self.scaler, f'{prefix}_best_scaler.pkl')
        print(f"   ✅ Scaler: {prefix}_best_scaler.pkl")
        
        # Feature selector
        joblib.dump(self.feature_selector, f'{prefix}_best_feature_selector.pkl')
        print(f"   ✅ Feature selector: {prefix}_best_feature_selector.pkl")
        
        # Selected features
        joblib.dump(self.selected_features, f'{prefix}_best_selected_features.pkl')
        print(f"   ✅ Selected features: {prefix}_best_selected_features.pkl")
        
        # Feature names
        joblib.dump(self.feature_names, f'{prefix}_best_feature_names.pkl')
        print(f"   ✅ Feature names: {prefix}_best_feature_names.pkl")
        
        # Model info
        joblib.dump(self.model_info, f'{prefix}_best_info.pkl')
        print(f"   ✅ Model info: {prefix}_best_info.pkl")
        
        # Feature importance
        if self.feature_importance is not None:
            self.feature_importance.to_csv(f'{prefix}_feature_importance.csv', index=False)
            print(f"   ✅ Feature importance: {prefix}_feature_importance.csv")
    
    def load_model(self, prefix: str = "link_phishing_model") -> bool:
        """Kaydedilmiş modeli yükle"""
        try:
            self.model = joblib.load(f'{prefix}_best.pkl')
            self.label_encoder = joblib.load(f'{prefix}_best_label_encoder.pkl')
            self.scaler = joblib.load(f'{prefix}_best_scaler.pkl')
            self.feature_selector = joblib.load(f'{prefix}_best_feature_selector.pkl')
            self.selected_features = joblib.load(f'{prefix}_best_selected_features.pkl')
            self.feature_names = joblib.load(f'{prefix}_best_feature_names.pkl')
            self.model_info = joblib.load(f'{prefix}_best_info.pkl')
            
            print(f"✅ Model başarıyla yüklendi: {self.model.__class__.__name__}")
            return True
        except Exception as e:
            print(f"❌ Model yüklenemedi: {e}")
            return False
    
    def run_full_pipeline(self, filepath: str):
        """Tam pipeline'ı çalıştır"""
        print("🚀 Link Phishing Detection Model Pipeline Başlıyor")
        print("=" * 60)
        
        # 1. Veri yükleme
        X, y = self.load_and_preprocess_data(filepath)
        
        # 2. Özellik analizi ve mühendisliği
        X_processed = self.feature_analysis(X, y)
        
        # 3. Özellik seçimi
        X_selected, selected_features = self.feature_selection(X_processed, y, k=50)
        
        # 4. Model eğitimi
        results = self.train_models(X_selected, y)
        
        # 5. Model kaydetme
        self.save_model()
        
        print("\n✅ Pipeline tamamlandı!")
        print(f"🎯 En iyi model: {self.model_info['model_name']}")
        print(f"📊 Accuracy: {self.model_info['accuracy']:.4f}")
        print(f"📊 AUC Score: {self.model_info['auc_score']:.4f}")
        print(f"🔢 Seçilen özellik sayısı: {len(selected_features)}")
        
        return results

def main():
    """Ana fonksiyon"""
    pipeline = LinkPhishingDetectorPipeline()
    
    # Pipeline'ı çalıştır
    results = pipeline.run_full_pipeline('link_phishing_dataset.csv')
    
    print("\n🏁 6. Model hazır! Ensemble sistemine entegre edilebilir.")

if __name__ == "__main__":
    main() 