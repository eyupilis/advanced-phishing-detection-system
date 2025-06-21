#!/usr/bin/env python3
"""
Malicious URLs Model Pipeline
7. Model için kapsamlı ML pipeline'ı

Dataset: 651,191 URLs, 4 sınıf (benign, phishing, defacement, malware)
Hedef: Multi-class -> Binary classification (threat vs benign)
"""

import pandas as pd
import numpy as np
import joblib
import time
import warnings
from datetime import datetime
from pathlib import Path

# ML Libraries
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.metrics import classification_report, confusion_matrix

# ML Models
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, GradientBoostingClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from catboost import CatBoostClassifier

# Feature Engineering
import re
import math
from urllib.parse import urlparse
from collections import Counter

warnings.filterwarnings('ignore')

class MaliciousURLsDetectorPipeline:
    """Malicious URLs Detection Pipeline for 7th Model"""
    
    def __init__(self):
        self.name = "Malicious URLs Detector"
        self.version = "1.0"
        self.model = None
        self.scaler = None
        self.feature_selector = None
        self.label_encoder = None
        self.selected_features = None
        self.feature_names = None
        
    def extract_url_features(self, url):
        """Gelişmiş URL özellik çıkarımı"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            query = parsed.query
            
            features = {}
            
            # 1. Temel URL özellikleri
            features['url_length'] = len(url)
            features['domain_length'] = len(domain)
            features['path_length'] = len(path)
            features['query_length'] = len(query) if query else 0
            features['fragment_length'] = len(parsed.fragment) if parsed.fragment else 0
            
            # 2. Domain analizi
            if domain:
                domain_parts = domain.split('.')
                features['subdomain_count'] = max(0, len(domain_parts) - 2)
                features['domain_parts_count'] = len(domain_parts)
                
                # TLD analizi
                features['tld_length'] = len(domain_parts[-1]) if domain_parts else 0
                features['has_suspicious_tld'] = int(domain_parts[-1] in ['tk', 'ml', 'ga', 'cf', 'xyz', 'top', 'click'] if domain_parts else False)
                
                # Domain karakteristikleri
                features['domain_entropy'] = self._calculate_entropy(domain)
                features['domain_has_numbers'] = int(any(c.isdigit() for c in domain))
                features['domain_digit_ratio'] = sum(c.isdigit() for c in domain) / len(domain) if domain else 0
                features['domain_hyphen_count'] = domain.count('-')
                features['domain_underscore_count'] = domain.count('_')
            else:
                for key in ['subdomain_count', 'domain_parts_count', 'tld_length', 'has_suspicious_tld', 
                           'domain_entropy', 'domain_has_numbers', 'domain_digit_ratio', 'domain_hyphen_count', 'domain_underscore_count']:
                    features[key] = 0
            
            # 3. Path analizi
            features['path_depth'] = len([x for x in path.split('/') if x])
            features['path_has_extension'] = int('.' in path.split('/')[-1] if path.split('/') else False)
            features['path_entropy'] = self._calculate_entropy(path)
            
            # 4. Query analizi
            if query:
                features['query_params_count'] = len(query.split('&'))
                features['query_entropy'] = self._calculate_entropy(query)
                features['query_has_suspicious_params'] = int(any(param in query.lower() for param in ['exec', 'eval', 'cmd', 'shell']))
            else:
                features['query_params_count'] = 0
                features['query_entropy'] = 0
                features['query_has_suspicious_params'] = 0
            
            # 5. Protokol ve port
            features['is_https'] = int(parsed.scheme == 'https')
            features['has_port'] = int(parsed.port is not None)
            features['port_number'] = parsed.port if parsed.port else 0
            
            # 6. Özel karakter analizi
            special_chars = '@$%&*()+=[]{}|\\:";\'<>?,./'
            features['special_char_count'] = sum(c in special_chars for c in url)
            features['special_char_ratio'] = features['special_char_count'] / len(url) if url else 0
            
            # 7. Digit analizi
            features['total_digits'] = sum(c.isdigit() for c in url)
            features['digit_ratio'] = features['total_digits'] / len(url) if url else 0
            
            # 8. Karakter frekans analizi
            features['url_entropy'] = self._calculate_entropy(url)
            features['longest_word_length'] = max([len(word) for word in re.findall(r'[a-zA-Z]+', url)] + [0])
            features['shortest_word_length'] = min([len(word) for word in re.findall(r'[a-zA-Z]+', url)] + [100])
            
            # 9. Şüpheli pattern'ler
            suspicious_patterns = [
                r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP adresi
                r'localhost',
                r'file://',
                r'data:',
                r'%[0-9a-fA-F]{2}',  # URL encoding
                r'[a-zA-Z0-9]{20,}',  # Uzun random string
            ]
            
            for i, pattern in enumerate(suspicious_patterns):
                features[f'suspicious_pattern_{i}'] = int(bool(re.search(pattern, url)))
            
            # 10. Phishing keyword'leri
            phishing_keywords = ['secure', 'account', 'verify', 'login', 'signin', 'confirm', 'update', 'suspended', 'billing']
            features['phishing_keywords_count'] = sum(keyword in url.lower() for keyword in phishing_keywords)
            
            # 11. Defacement keyword'leri
            defacement_keywords = ['hacked', 'defaced', 'owned', 'pwned', 'team', 'crew']
            features['defacement_keywords_count'] = sum(keyword in url.lower() for keyword in defacement_keywords)
            
            # 12. Malware keyword'leri
            malware_keywords = ['download', 'exe', 'payload', 'exploit', 'shell', 'backdoor']
            features['malware_keywords_count'] = sum(keyword in url.lower() for keyword in malware_keywords)
            
            # 13. Brand impersonation
            brands = ['google', 'microsoft', 'apple', 'amazon', 'paypal', 'ebay', 'facebook', 'instagram', 'twitter']
            features['brand_impersonation_count'] = sum(brand in url.lower() for brand in brands)
            
            # 14. Homograph attack
            features['has_punycode'] = int('xn--' in url.lower())
            features['mixed_charset'] = int(any(ord(c) > 127 for c in url))
            
            # 15. URL shortener
            shorteners = ['bit.ly', 'tinyurl', 't.co', 'short.link', 'is.gd', 'ow.ly']
            features['is_shortened'] = int(any(shortener in domain.lower() for shortener in shorteners) if domain else False)
            
            return features
            
        except Exception as e:
            print(f"Feature extraction error for {url}: {e}")
            return self._get_default_features()
    
    def _calculate_entropy(self, text):
        """String entropy hesapla"""
        if not text:
            return 0
        
        frequencies = Counter(text)
        length = len(text)
        entropy = 0
        
        for freq in frequencies.values():
            prob = freq / length
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    def _get_default_features(self):
        """Default feature değerleri"""
        return {f'feature_{i}': 0 for i in range(50)}  # 50 default features
    
    def create_features(self, df):
        """DataFrame'den features oluştur"""
        print("📊 Özellik çıkarımı başlıyor...")
        print(f"   📈 Toplam URL: {len(df):,}")
        
        features_list = []
        batch_size = 10000
        
        for i in range(0, len(df), batch_size):
            batch = df.iloc[i:i+batch_size]
            batch_features = []
            
            for idx, row in batch.iterrows():
                url_features = self.extract_url_features(row['url'])
                batch_features.append(url_features)
                
                if (idx + 1) % 5000 == 0:
                    print(f"   İşlenen: {idx + 1:,}/{len(df):,}")
            
            features_list.extend(batch_features)
        
        print("✅ Özellik çıkarımı tamamlandı!")
        
        # DataFrame'e çevir
        features_df = pd.DataFrame(features_list)
        
        # Feature names kaydet
        self.feature_names = list(features_df.columns)
        
        return features_df
    
    def prepare_labels(self, df):
        """Labels'ı binary classification için hazırla"""
        print("🏷️ Label preprocessing...")
        
        # Multi-class -> Binary: benign=0, diğerleri=1 (threat)
        binary_labels = df['type'].apply(lambda x: 0 if x == 'benign' else 1)
        
        print(f"   📊 Binary Label Dağılımı:")
        print(f"      Safe (benign): {(binary_labels == 0).sum():,}")
        print(f"      Threat (others): {(binary_labels == 1).sum():,}")
        
        return binary_labels
    
    def train_model(self, X, y):
        """Model eğitimi"""
        print(f"\n🤖 Model Eğitimi Başlıyor...")
        print(f"   📊 Dataset: {X.shape[0]:,} samples, {X.shape[1]} features")
        
        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"   📈 Train: {X_train.shape[0]:,}, Test: {X_test.shape[0]:,}")
        
        # Feature scaling
        print("⚖️ Feature scaling...")
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Feature selection
        print("🎯 Feature selection...")
        self.feature_selector = SelectKBest(score_func=f_classif, k=min(40, X.shape[1]))
        X_train_selected = self.feature_selector.fit_transform(X_train_scaled, y_train)
        X_test_selected = self.feature_selector.transform(X_test_scaled)
        
        # Selected feature names
        selected_indices = self.feature_selector.get_support(indices=True)
        self.selected_features = [self.feature_names[i] for i in selected_indices]
        
        print(f"   ✅ {len(self.selected_features)} özellik seçildi")
        
        # Model seçimi ve eğitimi
        models = {
            'RandomForest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
            'ExtraTrees': ExtraTreesClassifier(n_estimators=100, random_state=42, n_jobs=-1),
            'XGBoost': XGBClassifier(random_state=42, eval_metric='logloss'),
            'LightGBM': LGBMClassifier(random_state=42, verbose=-1),
            'CatBoost': CatBoostClassifier(random_state=42, verbose=False)
        }
        
        best_model = None
        best_score = 0
        best_name = ""
        results = {}
        
        print(f"\n🔬 Model Karşılaştırması:")
        
        for name, model in models.items():
            start_time = time.time()
            
            # Model eğitimi
            model.fit(X_train_selected, y_train)
            
            # Tahmin
            y_pred = model.predict(X_test_selected)
            y_pred_proba = model.predict_proba(X_test_selected)[:, 1]
            
            # Metrikler
            accuracy = accuracy_score(y_test, y_pred)
            auc_score = roc_auc_score(y_test, y_pred_proba)
            f1 = f1_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred)
            recall = recall_score(y_test, y_pred)
            
            train_time = time.time() - start_time
            
            results[name] = {
                'accuracy': accuracy,
                'auc_score': auc_score,
                'f1_score': f1,
                'precision': precision,
                'recall': recall,
                'train_time': train_time
            }
            
            print(f"   {name:12s}: Acc={accuracy:.4f}, AUC={auc_score:.4f}, F1={f1:.4f} ({train_time:.2f}s)")
            
            # En iyi model seçimi (AUC'a göre)
            if auc_score > best_score:
                best_score = auc_score
                best_model = model
                best_name = name
        
        self.model = best_model
        
        print(f"\n🏆 En İyi Model: {best_name}")
        print(f"   🎯 AUC Score: {best_score:.4f}")
        
        # Final evaluation
        final_pred = self.model.predict(X_test_selected)
        final_proba = self.model.predict_proba(X_test_selected)[:, 1]
        
        print(f"\n📊 Final Model Performansı:")
        print(f"   Accuracy: {accuracy_score(y_test, final_pred):.4f}")
        print(f"   AUC Score: {roc_auc_score(y_test, final_proba):.4f}")
        print(f"   Precision: {precision_score(y_test, final_pred):.4f}")
        print(f"   Recall: {recall_score(y_test, final_pred):.4f}")
        print(f"   F1-Score: {f1_score(y_test, final_pred):.4f}")
        
        return {
            'model_name': best_name,
            'model': self.model,
            'results': results,
            'best_score': best_score,
            'feature_count': len(self.selected_features)
        }
    
    def save_model(self, model_info, prefix="malicious_urls_model_best"):
        """Model ve bileşenleri kaydet"""
        print(f"\n💾 Model kaydediliyor...")
        
        # Model kaydet
        joblib.dump(self.model, f"{prefix}.pkl")
        joblib.dump(self.scaler, f"{prefix}_scaler.pkl")
        joblib.dump(self.feature_selector, f"{prefix}_feature_selector.pkl")
        joblib.dump(self.selected_features, f"{prefix}_selected_features.pkl")
        joblib.dump(self.feature_names, f"{prefix}_feature_names.pkl")
        
        # Model bilgileri
        model_details = {
            'model_name': model_info['model_name'],
            'accuracy': model_info['results'][model_info['model_name']]['accuracy'],
            'auc_score': model_info['best_score'],
            'f1_score': model_info['results'][model_info['model_name']]['f1_score'],
            'precision': model_info['results'][model_info['model_name']]['precision'],
            'recall': model_info['results'][model_info['model_name']]['recall'],
            'feature_count': model_info['feature_count'],
            'selected_features': self.selected_features,
            'training_date': datetime.now().isoformat(),
            'pipeline_version': self.version
        }
        
        joblib.dump(model_details, f"{prefix}_info.pkl")
        
        # Feature importance (if available)
        if hasattr(self.model, 'feature_importances_'):
            feature_importance_df = pd.DataFrame({
                'feature': self.selected_features,
                'importance': self.model.feature_importances_
            }).sort_values('importance', ascending=False)
            
            feature_importance_df.to_csv(f"{prefix}_feature_importance.csv", index=False)
            print(f"   📊 Feature importance kaydedildi")
        
        print(f"✅ Model başarıyla kaydedildi: {prefix}")
        return model_details

def main():
    """Ana eğitim scripti"""
    print("🚀 Malicious URLs Detector - 7. Model Eğitimi")
    print("=" * 60)
    
    # Dataset yükle
    print("📁 Dataset yükleniyor...")
    df = pd.read_csv("malicious_urls_dataset.csv")
    print(f"   📊 Dataset: {len(df):,} kayıt")
    
    # Sampling (büyük dataset için)
    if len(df) > 100000:
        print(f"⚡ Dataset sampling yapılıyor (100K)...")
        df_sampled = df.groupby('type').apply(
            lambda x: x.sample(min(25000, len(x)), random_state=42)
        ).reset_index(drop=True)
        df = df_sampled
        print(f"   📊 Sampled dataset: {len(df):,} kayıt")
    
    # Pipeline oluştur
    pipeline = MaliciousURLsDetectorPipeline()
    
    # Features oluştur
    features_df = pipeline.create_features(df)
    
    # Labels hazırla
    labels = pipeline.prepare_labels(df)
    
    # Model eğit
    model_info = pipeline.train_model(features_df, labels)
    
    # Model kaydet
    saved_info = pipeline.save_model(model_info)
    
    print(f"\n🎉 7. Model Başarıyla Eğitildi!")
    print(f"   🏆 Model: {saved_info['model_name']}")
    print(f"   🎯 AUC Score: {saved_info['auc_score']:.4f}")
    print(f"   📊 Feature Count: {saved_info['feature_count']}")

if __name__ == "__main__":
    main() 