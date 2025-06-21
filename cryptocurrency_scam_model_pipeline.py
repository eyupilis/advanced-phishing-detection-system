#!/usr/bin/env python3
"""
5. Model Pipeline: Cryptocurrency Scam Detection
Dataset: Cryptocurrency Scam URLs and Blockchain Addresses
Target: category (Phishing, Scamming, Malware, Hacked)
"""

import pandas as pd
import numpy as np
import re
import tldextract
from urllib.parse import urlparse, parse_qs
import pickle
import json
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score
from sklearn.linear_model import LogisticRegression
import xgboost as xgb
import lightgbm as lgb
from catboost import CatBoostClassifier
import matplotlib.pyplot as plt
import seaborn as sns

class CryptocurrencyScamDetectorPipeline:
    """Cryptocurrency Scam URL Detection Pipeline"""
    
    def __init__(self):
        self.model = None
        self.label_encoder = None
        self.scaler = StandardScaler()
        self.feature_selector = None
        self.selected_features = None
        self.feature_names = []
        
    def extract_url_features(self, url):
        """URL'den cryptocurrency scam detection özelliklerini çıkar"""
        features = {}
        
        if pd.isna(url) or url == '':
            return {f'url_{i}': 0 for i in range(25)}
        
        try:
            # URL parsing
            parsed = urlparse(url)
            ext = tldextract.extract(url)
            
            # 1. Temel URL özellikleri
            features['url_length'] = len(url)
            features['domain_length'] = len(parsed.netloc) if parsed.netloc else 0
            features['path_length'] = len(parsed.path) if parsed.path else 0
            features['query_length'] = len(parsed.query) if parsed.query else 0
            
            # 2. Domain özellikleri
            features['subdomain_count'] = len(ext.subdomain.split('.')) if ext.subdomain else 0
            features['domain_has_numbers'] = int(bool(re.search(r'\d', ext.domain or '')))
            features['domain_hyphen_count'] = (ext.domain or '').count('-')
            
            # 3. Cryptocurrency scam keywords
            crypto_keywords = ['wallet', 'ether', 'bitcoin', 'btc', 'eth', 'crypto', 'coin', 
                             'blockchain', 'binance', 'coinbase', 'metamask', 'trust']
            features['crypto_keywords_count'] = sum(1 for kw in crypto_keywords if kw in url.lower())
            
            # 4. Phishing indicators  
            phishing_words = ['secure', 'verify', 'update', 'confirm', 'login', 'account', 
                            'support', 'official', 'limited', 'urgent']
            features['phishing_keywords_count'] = sum(1 for kw in phishing_words if kw in url.lower())
            
            # 5. Suspicious characters
            features['special_char_count'] = sum(1 for c in url if c in '!@#$%^&*()+=[]{}|;:,<>?')
            features['uppercase_count'] = sum(1 for c in url if c.isupper())
            features['digit_count'] = sum(1 for c in url if c.isdigit())
            
            # 6. URL structure analysis
            features['has_ip'] = int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc or '')))
            features['has_port'] = int(':' in (parsed.netloc or ''))
            features['tld_suspicious'] = int((ext.suffix or '') in ['tk', 'ml', 'ga', 'cf', 'click', 'download'])
            
            # 7. Brand impersonation detection
            brands = ['myetherwallet', 'metamask', 'binance', 'coinbase', 'blockchain', 'trust', 
                     'uniswap', 'ethereum', 'bitcoin']
            features['brand_impersonation'] = 0
            for brand in brands:
                if brand in url.lower() and ext.domain and brand not in ext.domain.lower():
                    features['brand_impersonation'] = 1
                    break
                    
            # 8. Homograph attack detection
            suspicious_chars = ['xn--', 'ğ', 'ş', 'ı', 'ç', 'ö', 'ü']
            features['homograph_attack'] = int(any(char in url.lower() for char in suspicious_chars))
            
            # 9. International domain
            features['is_international'] = int(bool(re.search(r'xn--', url)))
            
            # 10. URL complexity
            features['url_complexity'] = (
                features['special_char_count'] + 
                features['subdomain_count'] + 
                features['domain_hyphen_count'] +
                features['crypto_keywords_count']
            )
            
            # 11. Path analysis
            features['path_depth'] = len([p for p in parsed.path.split('/') if p]) if parsed.path else 0
            features['has_parameters'] = int(bool(parsed.query))
            features['suspicious_extensions'] = int(any(ext in (parsed.path or '') for ext in ['.php', '.asp', '.jsp']))
            
            # 12. Domain reputation indicators
            features['short_domain'] = int(len(ext.domain or '') < 5)
            features['long_domain'] = int(len(ext.domain or '') > 20)
            
        except Exception as e:
            print(f"URL parsing error for {url}: {e}")
            features = {f'url_{i}': 0 for i in range(25)}
            
        return features
    
    def extract_name_features(self, name):
        """Domain name'den özellik çıkar"""
        features = {}
        
        if pd.isna(name) or name == '':
            return {f'name_{i}': 0 for i in range(10)}
        
        try:
            # 1. Basic name features
            features['name_length'] = len(name)
            features['name_dots'] = name.count('.')
            features['name_hyphens'] = name.count('-')
            features['name_numbers'] = sum(1 for c in name if c.isdigit())
            
            # 2. Cryptocurrency terms
            crypto_terms = ['wallet', 'ether', 'bitcoin', 'crypto', 'coin', 'btc', 'eth']
            features['name_crypto_terms'] = sum(1 for term in crypto_terms if term in name.lower())
            
            # 3. Suspicious patterns
            features['name_multiple_tld'] = int(name.count('.') > 2)
            features['name_suspicious_tld'] = int(any(tld in name.lower() for tld in ['tk', 'ml', 'ga', 'cf']))
            features['name_long_subdomain'] = int(any(len(part) > 15 for part in name.split('.')))
            
            # 4. Brand similarity
            popular_brands = ['myetherwallet', 'metamask', 'binance', 'coinbase']
            features['name_brand_similarity'] = 0
            for brand in popular_brands:
                if brand in name.lower():
                    features['name_brand_similarity'] = 1
                    break
                    
            # 5. Character analysis
            features['name_vowel_ratio'] = len([c for c in name.lower() if c in 'aeiou']) / len(name) if name else 0
            
        except Exception as e:
            print(f"Name parsing error for {name}: {e}")
            features = {f'name_{i}': 0 for i in range(10)}
        
        return features
    
    def extract_description_features(self, description):
        """Description'dan özellik çıkar"""
        features = {}
        
        if pd.isna(description) or description == '':
            return {'desc_length': 0, 'desc_scam_words': 0, 'desc_urgency': 0, 'desc_trust_words': 0}
        
        try:
            features['desc_length'] = len(description)
            
            # Scam keywords
            scam_words = ['scam', 'phishing', 'malicious', 'fake', 'fraud', 'suspicious', 'hack']
            features['desc_scam_words'] = sum(1 for word in scam_words if word in description.lower())
            
            # Urgency indicators
            urgency_words = ['urgent', 'limited', 'expire', 'verify', 'confirm', 'update', 'secure']
            features['desc_urgency'] = sum(1 for word in urgency_words if word in description.lower())
            
            # Trust indicators
            trust_words = ['official', 'verified', 'secure', 'trusted', 'legitimate']
            features['desc_trust_words'] = sum(1 for word in trust_words if word in description.lower())
            
        except:
            features = {'desc_length': 0, 'desc_scam_words': 0, 'desc_urgency': 0, 'desc_trust_words': 0}
        
        return features
    
    def extract_address_features(self, addresses):
        """Blockchain addresses'den özellik çıkar"""
        features = {
            'has_addresses': 0,
            'eth_address_count': 0,
            'btc_address_count': 0,
            'other_address_count': 0,
            'total_addresses': 0
        }
        
        if pd.isna(addresses) or addresses == '':
            return features
        
        try:
            # JSON parse et
            if isinstance(addresses, str):
                addr_data = eval(addresses)  # Safe eval for controlled data
            else:
                addr_data = addresses
            
            features['has_addresses'] = 1
            
            if isinstance(addr_data, dict):
                for crypto, addr_list in addr_data.items():
                    if isinstance(addr_list, list):
                        count = len(addr_list)
                        features['total_addresses'] += count
                        
                        if crypto.upper() == 'ETH':
                            features['eth_address_count'] = count
                        elif crypto.upper() == 'BTC':
                            features['btc_address_count'] = count
                        else:
                            features['other_address_count'] += count
                            
        except:
            pass
        
        return features
    
    def create_features(self, df):
        """Tam feature set oluştur"""
        features_list = []
        
        print("📊 Özellik çıkarımı başlıyor...")
        
        for idx, row in df.iterrows():
            if idx % 1000 == 0:
                print(f"   İşlenen: {idx}/{len(df)}")
            
            # Her kategoriden özellik çıkar
            url_features = self.extract_url_features(row.get('url', ''))
            name_features = self.extract_name_features(row.get('name', ''))
            desc_features = self.extract_description_features(row.get('description', ''))
            addr_features = self.extract_address_features(row.get('addresses', ''))
            
            # Subcategory özelliği
            subcategory_features = {
                'subcategory_is_wallet': int('wallet' in str(row.get('subcategory', '')).lower()),
                'subcategory_is_exchange': int('exchange' in str(row.get('subcategory', '')).lower()),
                'subcategory_is_trading': int('trading' in str(row.get('subcategory', '')).lower())
            }
            
            # Tüm özellikleri birleştir
            all_features = {**url_features, **name_features, **desc_features, **addr_features, **subcategory_features}
            features_list.append(all_features)
        
        print("✅ Özellik çıkarımı tamamlandı!")
        
        # DataFrame'e çevir
        features_df = pd.DataFrame(features_list)
        
        # Feature names kaydet
        self.feature_names = list(features_df.columns)
        
        return features_df
    
    def train_model(self, df, target_column='category'):
        """Model eğitimi"""
        print("🚀 Cryptocurrency Scam Model Eğitimi Başlıyor...")
        print("=" * 60)
        
        # Özellik çıkarımı
        X = self.create_features(df)
        y = df[target_column].copy()
        
        print(f"📊 Dataset Bilgileri:")
        print(f"   📏 Örneklem sayısı: {len(X)}")
        print(f"   🎯 Özellik sayısı: {len(X.columns)}")
        print(f"   📋 Target dağılımı:")
        for category, count in y.value_counts().items():
            print(f"     {category}: {count} ({count/len(y)*100:.1f}%)")
        
        # Az örnek olan kategorileri filtrele (min 10 örnek)
        value_counts = y.value_counts()
        categories_to_keep = value_counts[value_counts >= 10].index
        mask = y.isin(categories_to_keep)
        
        X = X[mask].reset_index(drop=True)
        y = y[mask].reset_index(drop=True)
        
        print(f"\n🔍 Filtrelenmeden sonra:")
        print(f"   📏 Örneklem sayısı: {len(X)}")
        print(f"   📋 Target dağılımı:")
        for category, count in y.value_counts().items():
            print(f"     {category}: {count} ({count/len(y)*100:.1f}%)")
        
        # Target encoding
        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
        
        # Feature scaling
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Feature selection - en iyi 30 özelliği seç
        print("\n🔍 Özellik seçimi yapılıyor...")
        self.feature_selector = SelectKBest(score_func=f_classif, k=min(30, len(X.columns)))
        X_train_selected = self.feature_selector.fit_transform(X_train_scaled, y_train)
        X_test_selected = self.feature_selector.transform(X_test_scaled)
        
        # Seçilen özellik isimlerini kaydet
        selected_indices = self.feature_selector.get_support(indices=True)
        self.selected_features = [self.feature_names[i] for i in selected_indices]
        
        print(f"✅ {len(self.selected_features)} özellik seçildi")
        print("En önemli 10 özellik:")
        for i, feature in enumerate(self.selected_features[:10]):
            print(f"   {i+1}. {feature}")
        
        # Model test etme
        models = {
            'RandomForest': RandomForestClassifier(n_estimators=100, random_state=42),
            'ExtraTrees': ExtraTreesClassifier(n_estimators=100, random_state=42),
            'XGBoost': xgb.XGBClassifier(random_state=42, eval_metric='mlogloss'),
            'LightGBM': lgb.LGBMClassifier(random_state=42, verbosity=-1),
            'CatBoost': CatBoostClassifier(random_state=42, verbose=False),
            'LogisticRegression': LogisticRegression(random_state=42, max_iter=1000)
        }
        
        print(f"\n🧪 Model Karşılaştırması:")
        best_score = 0
        best_model_name = None
        
        results = {}
        for name, model in models.items():
            print(f"   🔄 {name} eğitiliyor...")
            model.fit(X_train_selected, y_train)
            
            # Cross validation
            cv_scores = cross_val_score(model, X_train_selected, y_train, cv=5, scoring='accuracy')
            
            # Test accuracy
            test_pred = model.predict(X_test_selected)
            test_accuracy = accuracy_score(y_test, test_pred)
            
            results[name] = {
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'test_accuracy': test_accuracy,
                'model': model
            }
            
            print(f"     CV: {cv_scores.mean():.4f} (±{cv_scores.std():.4f})")
            print(f"     Test: {test_accuracy:.4f}")
            
            if test_accuracy > best_score:
                best_score = test_accuracy
                best_model_name = name
        
        # En iyi modeli seç
        self.model = results[best_model_name]['model']
        
        print(f"\n🏆 En İyi Model: {best_model_name}")
        print(f"   🎯 Test Accuracy: {best_score:.4f}")
        
        # Detailed classification report
        print(f"\n📊 Detaylı Sınıflandırma Raporu ({best_model_name}):")
        test_pred = self.model.predict(X_test_selected)
        target_names = self.label_encoder.classes_
        print(classification_report(y_test, test_pred, target_names=target_names))
        
        # Feature importance
        if hasattr(self.model, 'feature_importances_'):
            importance_df = pd.DataFrame({
                'feature': self.selected_features,
                'importance': self.model.feature_importances_
            }).sort_values('importance', ascending=False)
            
            print(f"\n🔍 En Önemli 10 Özellik:")
            for i, row in importance_df.head(10).iterrows():
                print(f"   {row['feature']}: {row['importance']:.4f}")
            
            # Feature importance'ı kaydet
            importance_df.to_csv('cryptocurrency_scam_model_feature_importance.csv', index=False)
        
        return {
            'model_name': best_model_name,
            'accuracy': best_score,
            'cv_mean': results[best_model_name]['cv_mean'],
            'cv_std': results[best_model_name]['cv_std'],
            'feature_count': len(self.selected_features)
        }
    
    def predict(self, urls, names=None, descriptions=None, addresses=None):
        """Tek veya çoklu URL prediction"""
        if isinstance(urls, str):
            urls = [urls]
        
        # Ensure all inputs are lists of same length
        if names is None:
            names = [''] * len(urls)
        if descriptions is None:
            descriptions = [''] * len(urls)
        if addresses is None:
            addresses = [''] * len(urls)
        
        # Create temporary dataframe
        temp_df = pd.DataFrame({
            'url': urls,
            'name': names,
            'description': descriptions,
            'addresses': addresses
        })
        
        # Extract features
        X = self.create_features(temp_df)
        
        # Apply scaling and feature selection
        X_scaled = self.scaler.transform(X)
        X_selected = self.feature_selector.transform(X_scaled)
        
        # Predict
        predictions = self.model.predict(X_selected)
        probabilities = self.model.predict_proba(X_selected)
        
        # Convert back to original labels
        predicted_categories = self.label_encoder.inverse_transform(predictions)
        
        results = []
        for i, url in enumerate(urls):
            result = {
                'url': url,
                'predicted_category': predicted_categories[i],
                'confidence': max(probabilities[i]),
                'all_probabilities': {
                    category: prob for category, prob in 
                    zip(self.label_encoder.classes_, probabilities[i])
                }
            }
            results.append(result)
        
        return results[0] if len(results) == 1 else results
    
    def save_model(self, prefix='cryptocurrency_scam_model'):
        """Model ve pipeline'ı kaydet"""
        model_files = []
        
        # Ana model
        model_file = f"{prefix}_best.pkl"
        with open(model_file, 'wb') as f:
            pickle.dump(self.model, f)
        model_files.append(model_file)
        
        # Label encoder
        le_file = f"{prefix}_best_label_encoder.pkl"
        with open(le_file, 'wb') as f:
            pickle.dump(self.label_encoder, f)
        model_files.append(le_file)
        
        # Scaler
        scaler_file = f"{prefix}_best_scaler.pkl"
        with open(scaler_file, 'wb') as f:
            pickle.dump(self.scaler, f)
        model_files.append(scaler_file)
        
        # Feature selector
        fs_file = f"{prefix}_best_feature_selector.pkl"
        with open(fs_file, 'wb') as f:
            pickle.dump(self.feature_selector, f)
        model_files.append(fs_file)
        
        # Selected features
        features_file = f"{prefix}_best_selected_features.pkl"
        with open(features_file, 'wb') as f:
            pickle.dump(self.selected_features, f)
        model_files.append(features_file)
        
        # Model info
        info = {
            'model_type': type(self.model).__name__,
            'feature_count': len(self.selected_features),
            'classes': self.label_encoder.classes_.tolist(),
            'feature_names': self.feature_names,
            'selected_features': self.selected_features
        }
        
        info_file = f"{prefix}_best_info.pkl"
        with open(info_file, 'wb') as f:
            pickle.dump(info, f)
        model_files.append(info_file)
        
        print(f"✅ Model dosyaları kaydedildi:")
        for file in model_files:
            print(f"   📄 {file}")
        
        return model_files
    
    def load_model(self, prefix='cryptocurrency_scam_model'):
        """Kaydedilmiş modeli yükle"""
        try:
            # Ana model
            with open(f"{prefix}_best.pkl", 'rb') as f:
                self.model = pickle.load(f)
            
            # Label encoder
            with open(f"{prefix}_best_label_encoder.pkl", 'rb') as f:
                self.label_encoder = pickle.load(f)
            
            # Scaler
            with open(f"{prefix}_best_scaler.pkl", 'rb') as f:
                self.scaler = pickle.load(f)
            
            # Feature selector
            with open(f"{prefix}_best_feature_selector.pkl", 'rb') as f:
                self.feature_selector = pickle.load(f)
            
            # Selected features
            with open(f"{prefix}_best_selected_features.pkl", 'rb') as f:
                self.selected_features = pickle.load(f)
            
            # Model info
            with open(f"{prefix}_best_info.pkl", 'rb') as f:
                info = pickle.load(f)
                self.feature_names = info['feature_names']
            
            print(f"✅ Model başarıyla yüklendi: {info['model_type']}")
            return True
            
        except Exception as e:
            print(f"❌ Model yükleme hatası: {e}")
            return False

def main():
    """Ana pipeline fonksiyonu"""
    print("🚀 Cryptocurrency Scam Detection Pipeline")
    print("=" * 60)
    
    # Veri setini yükle
    print("📂 Veri seti yükleniyor...")
    df = pd.read_csv('cryptocurrency_scam_dataset.csv')
    
    print(f"📊 Dataset: {len(df)} örneklem, {len(df.columns)} sütun")
    
    # Pipeline oluştur
    pipeline = CryptocurrencyScamDetectorPipeline()
    
    # Model eğit
    results = pipeline.train_model(df, target_column='category')
    
    # Model kaydet
    pipeline.save_model()
    
    print(f"\n✅ Cryptocurrency Scam Model Pipeline Tamamlandı!")
    print(f"🎯 En İyi Model: {results['model_name']}")
    print(f"📊 Test Accuracy: {results['accuracy']:.4f}")
    print(f"🔍 Özellik Sayısı: {results['feature_count']}")
    
    # Test örnekleri
    print(f"\n🧪 Test Örnekleri:")
    test_cases = [
        ("https://myetherwallet.com", "MyEtherWallet Official", "", ""),  # Gerçek site (muhtemelen safe)
        ("http://myetherwallett.com", "Fake MyEtherWallet", "Phishing site copying MEW", ""),  # Phishing
        ("http://crypto-scam-exchange.tk", "Fake Exchange", "Give us your crypto for guaranteed returns!", "")  # Scam
    ]
    
    for url, name, desc, addr in test_cases:
        try:
            result = pipeline.predict(url, [name], [desc], [addr])
            print(f"   🔍 {url}")
            print(f"     Kategori: {result['predicted_category']} ({result['confidence']:.3f})")
        except Exception as e:
            print(f"   ❌ Test hatası: {e}")

if __name__ == "__main__":
    main() 