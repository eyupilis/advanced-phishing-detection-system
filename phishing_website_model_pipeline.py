#!/usr/bin/env python3
"""
4. Model: Phishing Website Detector Model Pipeline
Dataset: 11K website features, 31 özellik
Algoritma: Feature-based classification
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif, RFE
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, classification_report, confusion_matrix
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

class PhishingWebsiteDetectorPipeline:
    """Phishing Website Feature-based Detection Pipeline"""
    
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_selector = None
        self.selected_features = None
        self.feature_importance = None
        self.model_info = {}
    
    def extract_website_features(self, url: str) -> Dict[str, float]:
        """URL'den website özellikleri çıkar (simülasyon)"""
        try:
            from urllib.parse import urlparse
            import re
            
            parsed = urlparse(url)
            
            # 31 temel özellik (orijinal dataset'deki gibi)
            features = {
                'UsingIP': int(bool(re.match(r'^\d+\.\d+\.\d+\.\d+', parsed.netloc))),
                'LongURL': int(len(url) > 75),
                'ShortURL': int(len(url) < 30),
                'Symbol@': int('@' in url),
                'Redirecting//': int('//' in parsed.path),
                'PrefixSuffix-': int('-' in parsed.netloc),
                'SubDomains': parsed.netloc.count('.') - 1 if '.' in parsed.netloc else 0,
                'HTTPS': int(parsed.scheme == 'https'),
                'DomainRegLen': len(parsed.netloc) if parsed.netloc else 0,
                'Favicon': 0,  # Simülasyon
                'NonStdPort': int(parsed.port is not None and parsed.port not in [80, 443]),
                'HTTPSDomainURL': int('https' in url.lower()),
                'RequestURL': len([x for x in parsed.path.split('/') if x]),
                'AnchorURL': 0,  # Simülasyon
                'LinksInScriptTags': 0,  # Simülasyon
                'ServerFormHandler': 0,  # Simülasyon
                'InfoEmail': 0,  # Simülasyon
                'AbnormalURL': int(bool(re.search(r'redirect|forward', url.lower()))),
                'WebsiteForwarding': 0,  # Simülasyon
                'StatusBarCust': 0,  # Simülasyon
                'DisableRightClick': 0,  # Simülasyon
                'UsingPopupWindow': 0,  # Simülasyon
                'IframeRedirection': 0,  # Simülasyon
                'AgeofDomain': 100,  # Simülasyon (gün)
                'DNSRecording': 1,  # Simülasyon
                'WebsiteTraffic': 50,  # Simülasyon
                'PageRank': 0.5,  # Simülasyon
                'GoogleIndex': 1,  # Simülasyon
                'LinksPointingToPage': 10,  # Simülasyon
                'StatsReport': 0,  # Simülasyon
                'class': 1  # Dummy (kullanılmayacak)
            }
            
            return features
            
        except Exception as e:
            print(f"Website özellik çıkarımında hata: {e}")
            # Default safe features
            return {col: 0 for col in ['UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 
                                     'PrefixSuffix-', 'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon',
                                     'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL', 'LinksInScriptTags',
                                     'ServerFormHandler', 'InfoEmail', 'AbnormalURL', 'WebsiteForwarding', 'StatusBarCust',
                                     'DisableRightClick', 'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
                                     'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'StatsReport', 'class']}
        
    def load_and_preprocess_data(self, filepath: str) -> Tuple[pd.DataFrame, pd.Series]:
        """Veri setini yükle ve ön işleme yap"""
        print("📂 Veri seti yükleniyor...")
        
        df = pd.read_csv(filepath)
        print(f"   📏 Boyut: {df.shape[0]} örneklem, {df.shape[1]} sütun")
        
        # Index sütununu kaldır
        if 'Index' in df.columns:
            df = df.drop('Index', axis=1)
        
        # Target değişkeni ayır
        target_col = 'class'
        X = df.drop(target_col, axis=1)
        y = df[target_col]
        
        # Target'ı binary'ye çevir: -1 (phishing) -> 1, 1 (safe) -> 0
        y = (y == -1).astype(int)  # -1 (phishing) = 1, 1 (safe) = 0
        
        print(f"   🎯 Target dağılımı:")
        value_counts = y.value_counts()
        for label, count in value_counts.items():
            label_name = "Phishing" if label == 1 else "Safe"
            percentage = (count / len(y)) * 100
            print(f"     {label_name}: {count} ({percentage:.1f}%)")
        
        # Özellik isimleri
        print(f"   🔢 Özellikler ({len(X.columns)}):")
        for i, col in enumerate(X.columns):
            if i < 10:  # İlk 10'u göster
                print(f"     - {col}")
            elif i == 10:
                print(f"     ... ve {len(X.columns) - 10} tane daha")
                break
        
        return X, y
    
    def feature_engineering(self, X: pd.DataFrame) -> pd.DataFrame:
        """Özellik mühendisliği yap"""
        print("🔧 Özellik mühendisliği...")
        
        X_processed = X.copy()
        
        # Tüm özellikler zaten sayısal ve temizlenmiş durumda
        # Sadece özellik kombinasyonları ekliyoruz
        
        # URL güvenlik skoru
        security_features = ['HTTPS', 'HTTPSDomainURL', 'NonStdPort']
        if all(col in X_processed.columns for col in security_features):
            X_processed['security_score'] = X_processed[security_features].sum(axis=1)
        
        # Domain güvenilirlik skoru  
        domain_features = ['DomainRegLen', 'AgeofDomain', 'DNSRecording']
        if all(col in X_processed.columns for col in domain_features):
            X_processed['domain_trust_score'] = X_processed[domain_features].sum(axis=1)
        
        # URL şüphe skoru
        suspicious_features = ['UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//']
        if all(col in X_processed.columns for col in suspicious_features):
            X_processed['suspicious_url_score'] = X_processed[suspicious_features].sum(axis=1)
        
        # Web trafiği ve popülerlik skoru
        traffic_features = ['WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage']
        if all(col in X_processed.columns for col in traffic_features):
            X_processed['popularity_score'] = X_processed[traffic_features].sum(axis=1)
        
        # JavaScript ve form manipülasyon skoru
        js_features = ['LinksInScriptTags', 'ServerFormHandler', 'StatusBarCust', 'DisableRightClick', 'UsingPopupWindow', 'IframeRedirection']
        if all(col in X_processed.columns for col in js_features):
            X_processed['js_manipulation_score'] = X_processed[js_features].sum(axis=1)
        
        print(f"   ✅ {X_processed.shape[1]} özellik hazırlandı (orijinal: {X.shape[1]})")
        print(f"   🆕 Yeni özellikler: {X_processed.shape[1] - X.shape[1]} adet")
        
        return X_processed
    
    def feature_selection(self, X: pd.DataFrame, y: pd.Series, k: int = 25) -> pd.DataFrame:
        """En önemli özellikleri seç"""
        print(f"🎯 Özellik seçimi (en iyi {k} özellik)...")
        
        # İlk olarak univariate selection
        selector_univariate = SelectKBest(score_func=f_classif, k=min(k, X.shape[1]))
        X_selected = selector_univariate.fit_transform(X, y)
        
        # Seçilen özellik isimlerini al
        selected_indices = selector_univariate.get_support(indices=True)
        selected_features = X.columns[selected_indices].tolist()
        
        # Random Forest ile feature importance
        rf = RandomForestClassifier(n_estimators=100, random_state=42)
        rf.fit(X_selected, y)
        
        # Feature importance'a göre sırala
        feature_importance = pd.DataFrame({
            'feature': selected_features,
            'importance': rf.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("   📊 En önemli 10 özellik:")
        for idx, row in feature_importance.head(10).iterrows():
            print(f"     {row['feature']}: {row['importance']:.4f}")
        
        self.selected_features = selected_features
        self.feature_selector = selector_univariate
        self.feature_importance = feature_importance
        
        return pd.DataFrame(X_selected, columns=selected_features, index=X.index)
    
    def train_models(self, X: pd.DataFrame, y: pd.Series) -> Dict[str, Any]:
        """Farklı algoritmaları eğit ve karşılaştır"""
        print("🚀 Model eğitimi başlıyor...")
        
        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Modeller
        models = {
            'RandomForest': RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42),
            'ExtraTrees': ExtraTreesClassifier(n_estimators=200, max_depth=15, random_state=42),
            'XGBoost': xgb.XGBClassifier(n_estimators=200, max_depth=8, random_state=42),
            'LightGBM': lgb.LGBMClassifier(n_estimators=200, max_depth=8, random_state=42, verbose=-1),
            'CatBoost': CatBoostClassifier(iterations=200, depth=8, random_state=42, verbose=False),
            'LogisticRegression': LogisticRegression(random_state=42, max_iter=1000)
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
    
    def save_model(self, prefix: str = "phishing_website_model"):
        """Modeli ve bileşenleri kaydet"""
        print("💾 Model kaydediliyor...")
        
        # Model
        joblib.dump(self.model, f'{prefix}_best.pkl')
        print(f"   ✅ Model: {prefix}_best.pkl")
        
        # Feature selector
        joblib.dump(self.feature_selector, f'{prefix}_best_feature_selector.pkl')
        print(f"   ✅ Feature selector: {prefix}_best_feature_selector.pkl")
        
        # Selected features
        joblib.dump(self.selected_features, f'{prefix}_best_selected_features.pkl')
        print(f"   ✅ Selected features: {prefix}_best_selected_features.pkl")
        
        # Model info
        joblib.dump(self.model_info, f'{prefix}_best_info.pkl')
        print(f"   ✅ Model info: {prefix}_best_info.pkl")
        
        # Feature importance
        if self.feature_importance is not None:
            self.feature_importance.to_csv(f'{prefix}_feature_importance.csv', index=False)
            print(f"   ✅ Feature importance: {prefix}_feature_importance.csv")
    
    def run_full_pipeline(self, filepath: str):
        """Tam pipeline'ı çalıştır"""
        print("🚀 Phishing Website Detector Model Pipeline Başlıyor")
        print("=" * 60)
        
        # 1. Veri yükleme
        X, y = self.load_and_preprocess_data(filepath)
        
        # 2. Özellik mühendisliği
        X_engineered = self.feature_engineering(X)
        
        # 3. Özellik seçimi
        X_selected = self.feature_selection(X_engineered, y, k=25)
        
        # 4. Model eğitimi
        results = self.train_models(X_selected, y)
        
        # 5. Model kaydetme
        self.save_model()
        
        print("\n✅ Pipeline tamamlandı!")
        print(f"🎯 En iyi model: {self.model_info['model_name']}")
        print(f"📊 Accuracy: {self.model_info['accuracy']:.4f}")
        print(f"📊 AUC Score: {self.model_info['auc_score']:.4f}")
        
        return results

def main():
    """Ana fonksiyon"""
    pipeline = PhishingWebsiteDetectorPipeline()
    
    # Pipeline'ı çalıştır
    results = pipeline.run_full_pipeline('phishing_website_detector_dataset.csv')
    
    print("\n🏁 4. Model hazır! Ensemble sistemine entegre edilebilir.")

if __name__ == "__main__":
    main() 