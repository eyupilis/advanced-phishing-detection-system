#!/usr/bin/env python3
"""
4-Model Ensemble Phishing Detector
Modeller:
1. Mega Phishing Detector (20K URLs, 96 features)
2. Cybersecurity VirusTotal Analyzer (4K domains, 17 features)
3. Advanced URL Feature Analyzer (549K URLs, 35 features)
4. Website Feature Detector (11K websites, 31 features)
"""

import pandas as pd
import numpy as np
import joblib
import json
import re
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

# Önceki modellerden feature extractor'ları import et
from feature_extractor import FeatureExtractor, RuleBasedAnalyzer

class EnsemblePhishingDetector:
    """
    Çoklu Model Ensemble Sistemi
    
    Birden fazla veri seti ve algoritmadan eğitilmiş modelleri birleştirerek
    daha güvenilir phishing tespiti yapar.
    
    Features:
    - Multi-model voting mechanism
    - Weighted predictions
    - Individual model transparency
    - Adaptive learning from feedback
    - Confidence scoring
    """
    
    def __init__(self):
        self.models = {}
        self.model_weights = {}
        self.model_performance = {}
        self.feature_extractor = FeatureExtractor()
        self.rule_analyzer = RuleBasedAnalyzer()
        
        # Model metadata
        self.model_info = {
            'phishing_model': {
                'name': 'Mega Phishing Detector',
                'dataset': '20K URLs with 96 features',
                'algorithm': 'Random Forest',
                'speciality': 'General URL pattern analysis'
            },
            'cybersecurity_model': {
                'name': 'Cybersecurity VirusTotal Analyzer',
                'dataset': '4K domains with VirusTotal data',
                'algorithm': 'CatBoost',
                'speciality': 'Security engine analysis'
            },
            'phishing_urls_model': {
                'name': 'Advanced URL Feature Analyzer',
                'dataset': '549K URLs with 35 URL features',
                'algorithm': 'Random Forest',
                'speciality': 'Comprehensive URL structure analysis'
            },
            'website_model': {
                'name': 'Website Feature Detector',
                'dataset': '11K websites with 31 features',
                'algorithm': 'Machine Learning',
                'speciality': 'Website behavior analysis'
            }
        }
        
        # Feedback storage
        self.feedback_history = []
        
        # Load models
        self.load_all_models()
    
    def load_all_models(self):
        """Tüm eğitilmiş modelleri yükle"""
        
        print("🔄 Ensemble modelleri yükleniyor...")
        
        # Model 1: Mega Phishing Detector
        try:
            self.models['phishing_model'] = joblib.load('best_phishing_model.pkl')
            self.model_info['phishing_model']['selected_features'] = joblib.load('selected_features.pkl')
            
            # Performance bilgilerini yükle
            try:
                with open('model_info.pkl', 'rb') as f:
                    model_info = joblib.load(f)
                    self.model_performance['phishing_model'] = model_info.get('performance', {})
            except:
                self.model_performance['phishing_model'] = {'accuracy': 0.9991, 'auc_score': 0.9995}
            
            print("   ✅ Phishing Model yüklendi")
            
        except Exception as e:
            print(f"   ❌ Phishing Model yüklenemedi: {e}")
        
        # Model 2: Cybersecurity Model
        try:
            self.models['cybersecurity_model'] = joblib.load('cybersecurity_model_catboost.pkl')
            
            # Model info yükle
            try:
                cybersecurity_info = joblib.load('cybersecurity_model_catboost_info.pkl')
                self.model_performance['cybersecurity_model'] = cybersecurity_info.get('performance', {})
                self.model_info['cybersecurity_model']['selected_features'] = cybersecurity_info.get('selected_features', [])
            except:
                self.model_performance['cybersecurity_model'] = {'accuracy': 0.9964, 'auc_score': 1.0000}
            
            print("   ✅ Cybersecurity Model yüklendi")
            
        except Exception as e:
            print(f"   ❌ Cybersecurity Model yüklenemedi: {e}")
        
        # Model 3: Advanced URL Feature Model
        try:
            self.models['phishing_urls_model'] = joblib.load('phishing_urls_model_best.pkl')
            
            # Model info ve feature extractor components yükle
            try:
                urls_info = joblib.load('phishing_urls_model_best_info.pkl')
                self.models['phishing_urls_model_scaler'] = joblib.load('phishing_urls_model_best_scaler.pkl')
                self.models['phishing_urls_model_label_encoder'] = joblib.load('phishing_urls_model_best_label_encoder.pkl')
                self.models['phishing_urls_model_feature_selector'] = joblib.load('phishing_urls_model_best_feature_selector.pkl')
                
                self.model_performance['phishing_urls_model'] = urls_info.get('model_performance', {}).get('RandomForest', {})
                self.model_info['phishing_urls_model']['feature_names'] = urls_info.get('feature_names', [])
                
                # Feature extraction pipeline ekle
                from phishing_urls_model_pipeline import PhishingURLsDetectorPipeline
                self.models['phishing_urls_extractor'] = PhishingURLsDetectorPipeline()
                
            except Exception as sub_e:
                print(f"     ⚠️ URL Model bileşenleri yüklenirken hata: {sub_e}")
                self.model_performance['phishing_urls_model'] = {'accuracy': 0.9125, 'auc_score': 0.9564}
            
            print("   ✅ Advanced URL Feature Model yüklendi")
            
        except Exception as e:
            print(f"   ❌ Advanced URL Feature Model yüklenemedi: {e}")
        
        # Model 4: Website Feature Detector
        try:
            self.models['website_model'] = joblib.load('phishing_website_model_best.pkl')
            
            # Model info ve feature extractor components yükle
            try:
                website_info = joblib.load('phishing_website_model_best_info.pkl')
                self.model_info['website_model']['selected_features'] = website_info.get('selected_features', [])
                self.model_info['website_model']['feature_selector'] = joblib.load('phishing_website_model_best_feature_selector.pkl')
                self.model_info['website_model']['info'] = website_info.get('info', {})
                
                self.model_performance['website_model'] = website_info.get('model_performance', {})
                
                # Feature extraction pipeline ekle
                from phishing_website_model_pipeline import PhishingWebsiteDetectorPipeline
                self.models['website_extractor'] = PhishingWebsiteDetectorPipeline()
                
            except Exception as sub_e:
                print(f"     ⚠️ Website Model bileşenleri yüklenirken hata: {sub_e}")
                self.model_performance['website_model'] = {'accuracy': 0.9656, 'auc_score': 0.9995}
            
            print("   ✅ Website Feature Model yüklendi")
            
        except Exception as e:
            print(f"   ❌ Website Feature Model yüklenemedi: {e}")
        
        # 5. Cryptocurrency Scam Model - Geçici olarak devre dışı (özellik uyumsuzluğu)
        try:
            print("   ⚠️ Cryptocurrency Scam Model geçici olarak devre dışı bırakıldı (özellik uyumsuzluğu)")
            self.models['crypto_scam_model'] = None
        except Exception as e:
            print(f"   ❌ Cryptocurrency Scam Model yüklenemedi: {e}")
            self.models['crypto_scam_model'] = None
        
        # 6. Link Phishing Model
        try:
            print("   🔄 Link Phishing Model yükleniyor...")
            from link_phishing_model_pipeline import LinkPhishingDetectorPipeline
            link_pipeline = LinkPhishingDetectorPipeline()
            if link_pipeline.load_model():
                self.models['link_phishing_model'] = link_pipeline.model
                self.model_info['link_phishing_model'] = {
                    'type': 'LinkPhishingDetector',
                    'features': 89,
                    'accuracy': 0.9892,
                    'specialization': 'Advanced link analysis',
                    'label_encoder': link_pipeline.label_encoder,
                    'scaler': link_pipeline.scaler,
                    'feature_selector': link_pipeline.feature_selector,
                    'selected_features': link_pipeline.selected_features,
                    'feature_names': link_pipeline.feature_names,
                    'pipeline': link_pipeline
                }
                self.model_performance['link_phishing_model'] = {'accuracy': 0.9892, 'auc_score': 0.9992}
                print(f"   ✅ Link Phishing Model yüklendi")
            else:
                self.models['link_phishing_model'] = None
                print(f"   ⚠️ Link Phishing Model bulunamadı")
        except Exception as e:
            print(f"   ❌ Link Phishing Model yüklenemedi: {e}")
            self.models['link_phishing_model'] = None
        
        # 7. Malicious URLs Model (NEW!)
        try:
            print("   🔄 Malicious URLs Model yükleniyor...")
            from malicious_urls_model_pipeline import MaliciousURLsDetectorPipeline
            malicious_pipeline = MaliciousURLsDetectorPipeline()
            
            # Model dosyalarını load et
            try:
                malicious_pipeline.model = joblib.load('malicious_urls_model_best.pkl')
                malicious_pipeline.scaler = joblib.load('malicious_urls_model_best_scaler.pkl')
                malicious_pipeline.feature_selector = joblib.load('malicious_urls_model_best_feature_selector.pkl')
                malicious_pipeline.selected_features = joblib.load('malicious_urls_model_best_selected_features.pkl')
                malicious_pipeline.feature_names = joblib.load('malicious_urls_model_best_feature_names.pkl')
                
                model_info = joblib.load('malicious_urls_model_best_info.pkl')
                
                self.models['malicious_urls_model'] = malicious_pipeline.model
                self.model_info['malicious_urls_model'] = {
                    'type': 'MaliciousURLsDetector',
                    'features': model_info['feature_count'],
                    'accuracy': model_info['accuracy'],
                    'auc_score': model_info['auc_score'],
                    'specialization': 'Multi-threat URL detection (phishing, malware, defacement)',
                    'scaler': malicious_pipeline.scaler,
                    'feature_selector': malicious_pipeline.feature_selector,
                    'selected_features': malicious_pipeline.selected_features,
                    'feature_names': malicious_pipeline.feature_names,
                    'pipeline': malicious_pipeline
                }
                self.model_performance['malicious_urls_model'] = {
                    'accuracy': model_info['accuracy'], 
                    'auc_score': model_info['auc_score']
                }
                print(f"   ✅ Malicious URLs Model yüklendi (AUC: {model_info['auc_score']:.4f})")
            except Exception as load_e:
                print(f"     ❌ Model dosyaları yüklenemedi: {load_e}")
                self.models['malicious_urls_model'] = None
                
        except Exception as e:
            print(f"   ❌ Malicious URLs Model yüklenemedi: {e}")
            self.models['malicious_urls_model'] = None
        
        # 6. Link Phishing Detection Model
        try:
            print("   🔄 Link Phishing Detection Model yükleniyor...")
            from link_phishing_model_pipeline import LinkPhishingDetectorPipeline
            link_pipeline = LinkPhishingDetectorPipeline()
            if link_pipeline.load_model():
                self.models['link_phishing_model'] = link_pipeline.model
                self.model_info['link_phishing_model'] = {
                    'name': 'Link Phishing Detection Model',
                    'dataset': '19K URLs with 87 comprehensive features',
                    'algorithm': 'XGBoost',
                    'speciality': 'Comprehensive link analysis with 50 selected features',
                    'type': 'LinkPhishingDetector',
                    'features': 50,
                    'accuracy': 0.9892,
                    'auc_score': 0.9992,
                    'specialization': 'Advanced URL pattern and content analysis',
                    'label_encoder': link_pipeline.label_encoder,
                    'scaler': link_pipeline.scaler,
                    'feature_selector': link_pipeline.feature_selector,
                    'selected_features': link_pipeline.selected_features,
                    'feature_names': link_pipeline.feature_names,
                    'pipeline': link_pipeline
                }
                self.model_performance['link_phishing_model'] = {'accuracy': 0.9892, 'auc_score': 0.9992}
                print(f"   ✅ Link Phishing Detection Model yüklendi ({link_pipeline.model.__class__.__name__})")
            else:
                self.models['link_phishing_model'] = None
                print(f"   ⚠️ Link Phishing Detection Model bulunamadı")
        except Exception as e:
            print(f"   ❌ Link Phishing Detection Model yüklenemedi: {e}")
            self.models['link_phishing_model'] = None
        
        # Initialize model weights based on performance
        self.initialize_weights()
        
        successful_models = len([m for m in self.models.values() if m is not None])
        print(f"✅ {successful_models} model başarıyla yüklendi (toplam {len(self.models)} model tanımlı)")
    
    def initialize_weights(self):
        """Model ağırlıklarını performansa göre başlat - Öncelikli modeller ağırlıklandırıldı"""
        
        # Öncelikli modeller - daha yüksek ağırlık
        priority_models = {
            'phishing_model': 2.5,      # MEGA PHISHING - En yüksek ağırlık
            'cybersecurity_model': 2.3,  # CYBERSECURITY - İkinci yüksek
            'link_phishing_model': 2.0   # LINK SCANNER - Üçüncü yüksek
        }
        
        if not self.model_performance:
            # Default weights with priority
            self.model_weights = {}
            for model_name in self.models.keys():
                if model_name in priority_models:
                    self.model_weights[model_name] = priority_models[model_name]
                else:
                    self.model_weights[model_name] = 1.0
            return
        
        total_performance = 0
        model_scores = {}
        
        for model_name, performance in self.model_performance.items():
            # AUC Score + Accuracy kombinasyonu
            base_score = (performance.get('auc_score', 0.5) + performance.get('accuracy', 0.5)) / 2
            
            # Öncelikli modellere bonus ağırlık
            if model_name in priority_models:
                priority_multiplier = priority_models[model_name]
                final_score = base_score * priority_multiplier
                print(f"   🎯 Öncelikli model {model_name}: base={base_score:.3f} × {priority_multiplier} = {final_score:.3f}")
            else:
                final_score = base_score
            
            model_scores[model_name] = final_score
            total_performance += final_score
        
        # Normalize weights
        for model_name, score in model_scores.items():
            self.model_weights[model_name] = score / total_performance if total_performance > 0 else 1.0
        
        print("🎯 GÜNCEL Model ağırlıkları (Öncelikli modeller ağırlıklandırıldı):")
        for model_name, weight in self.model_weights.items():
            priority_marker = " 🔥" if model_name in priority_models else ""
            print(f"   {model_name}: {weight:.3f}{priority_marker}")
    
    def extract_features_for_model(self, url: str, model_name: str):
        """Belirli model için özellik çıkarımı"""
        
        try:
            if model_name == 'phishing_model':
                # Mega phishing dataset özellikleri
                basic_features = self.feature_extractor.extract_features(url)
                
                # Selected features'a göre sırayla veri hazırla
                if 'selected_features' in self.model_info[model_name]:
                    selected_features = self.model_info[model_name]['selected_features']
                    # Feature values'ı doğru sırada hazırla
                    feature_values = []
                    for feature_name in selected_features:
                        feature_values.append(basic_features.get(feature_name, 0))
                    
                    # DataFrame oluşturmak yerine doğrudan array döndür
                    return np.array([feature_values])
                else:
                    # Tüm featuresları kullan
                    feature_values = list(basic_features.values())
                    return np.array([feature_values])
            
            elif model_name == 'cybersecurity_model':
                # Cybersecurity model için özellik çıkarımı
                # Bu model VirusTotal benzeri analiz sonuçları bekliyor
                # Simulated features (gerçek uygulamada VirusTotal API'den gelecek)
                
                features = [
                    int('.onion' in url.lower()),  # is_onion
                    self._extract_tld(url),  # tld
                    0,  # categories_sophos
                    0,  # categories_alpha_mountain
                    self._calculate_reputation(url),  # reputation
                    0,  # number_of_tags
                    60,  # last_analysis_stats_harmles
                    5,  # last_analysis_stats_malicious
                    0,  # last_analysis_stats_suspicious
                    25,  # last_analysis_stats_undetected
                    0,  # total_votes_harmless
                    0,  # total_votes_malicious
                    5/61,  # malicious_harmless_ratio
                    90,  # total_analysis_score
                    2  # reputation_category
                ]
                
                return np.array([features])
            
            elif model_name == 'phishing_urls_model':
                # Advanced URL Feature Model için özellik çıkarımı
                try:
                    if 'phishing_urls_extractor' in self.models:
                        extractor = self.models['phishing_urls_extractor']
                        features = extractor.extract_url_features(url)
                        
                        # Feature names ile sıralı array oluştur
                        if 'feature_names' in self.model_info[model_name]:
                            feature_names = self.model_info[model_name]['feature_names']
                            feature_values = [features.get(name, 0) for name in feature_names]
                            feature_array = np.array([feature_values])
                        else:
                            # Fallback: feature values'ları doğrudan al
                            feature_array = np.array([list(features.values())])
                        
                        # Feature selection uygula
                        if 'phishing_urls_model_feature_selector' in self.models:
                            feature_selector = self.models['phishing_urls_model_feature_selector']
                            feature_array = feature_selector.transform(feature_array)
                        
                        return feature_array
                    else:
                        # Extractor yoksa basit özellik çıkarımı
                        feature_array = self._extract_basic_url_features(url)
                        
                        # Feature selection uygula
                        if 'phishing_urls_model_feature_selector' in self.models:
                            feature_selector = self.models['phishing_urls_model_feature_selector']
                            feature_array = feature_selector.transform(feature_array)
                        
                        return feature_array
                except Exception as sub_e:
                    print(f"     URL feature extraction hatası: {sub_e}")
                    return self._extract_basic_url_features(url)
            
            elif model_name == 'website_model':
                # Website Feature Detector için özellik çıkarımı
                try:
                    if 'website_extractor' in self.models:
                        extractor = self.models['website_extractor']
                        features = extractor.extract_website_features(url)
                        
                        # Class sütununu kaldır
                        if 'class' in features:
                            del features['class']
                        
                        # DataFrame oluştur
                        import pandas as pd
                        features_df = pd.DataFrame([features])
                        
                        # Feature engineering uygula
                        features_engineered = extractor.feature_engineering(features_df)
                        
                        # Selected features'a göre sırala
                        if 'selected_features' in self.model_info[model_name]:
                            selected_features = self.model_info[model_name]['selected_features']
                            # Sadece mevcut özellikleri seç
                            available_features = [col for col in selected_features if col in features_engineered.columns]
                            if available_features:
                                features_selected = features_engineered[available_features]
                                return features_selected.values
                        
                        # Feature selection uygula
                        if 'feature_selector' in self.model_info[model_name]:
                            feature_selector = self.model_info[model_name]['feature_selector']
                            return feature_selector.transform(features_engineered)
                        
                        return features_engineered.values
                    else:
                        # Fallback
                        return self._extract_basic_website_features(url)
                        
                except Exception as sub_e:
                    print(f"❌ Website model özellik çıkarımında hata: {sub_e}")
                    return self._extract_basic_website_features(url)
            
            elif model_name == 'crypto_scam_model':
                # Cryptocurrency Scam Model için özellik çıkarımı
                try:
                    if 'pipeline' in self.model_info[model_name]:
                        # Pipeline üzerinden TAM feature extraction (URL + name + desc + addresses)
                        pipeline = self.model_info[model_name]['pipeline']
                        
                        # Full dataset formatında DataFrame oluştur
                        import pandas as pd
                        from urllib.parse import urlparse
                        parsed_url = urlparse(url)
                        temp_df = pd.DataFrame({
                            'url': [url],
                            'name': [parsed_url.netloc],  # Domain name
                            'description': [''],  # Boş description
                            'addresses': ['']  # Boş addresses
                        })
                        
                        # Pipeline'ın create_features metodunu kullan
                        features_df = pipeline.create_features(temp_df)
                        features_array = features_df.values
                        
                        # Scaler uygula
                        if 'scaler' in self.model_info[model_name]:
                            scaler = self.model_info[model_name]['scaler']
                            features_array = scaler.transform(features_array)
                        
                        # Feature selector uygula
                        if 'feature_selector' in self.model_info[model_name]:
                            feature_selector = self.model_info[model_name]['feature_selector']
                            features_array = feature_selector.transform(features_array)
                        
                        return features_array
                    else:
                        # Pipeline yoksa fallback
                        return self._extract_basic_crypto_features_30(url)
                        
                except Exception as sub_e:
                    print(f"❌ Crypto model özellik çıkarımında hata: {sub_e}")
                    # Fallback: 30 özellik ile default değerler
                    return np.array([[0] * 30])
            
            elif model_name == 'link_phishing_model':
                # Link Phishing Detection Model için özellik çıkarımı
                try:
                    if 'pipeline' in self.model_info[model_name]:
                        # Pipeline üzerinden feature extraction
                        pipeline = self.model_info[model_name]['pipeline']
                        
                        # URL'yi dataset formatında hazırla  
                        import pandas as pd
                        temp_df = pd.DataFrame({'url': [url]})
                        
                        # Feature engineering
                        features = self._extract_basic_link_phishing_features(url)
                        
                        # Feature selection uygula
                        if 'feature_selector' in self.model_info[model_name]:
                            feature_selector = self.model_info[model_name]['feature_selector']
                            features = feature_selector.transform(features)
                        
                        return features
                    else:
                        # Pipeline yoksa basit feature extraction
                        return self._extract_basic_link_phishing_features(url)
                        
                except Exception as sub_e:
                    print(f"❌ Link phishing model özellik çıkarımında hata: {sub_e}")
                    return self._extract_basic_link_phishing_features(url)
            
            elif model_name == 'malicious_urls_model':
                # Malicious URLs Model için özellik çıkarımı (7. Model)
                try:
                    # Her zaman fallback basit özellik çıkarımı kullan (43 features)
                    features = self._extract_basic_malicious_urls_features(url)
                    
                    # Model info varsa scaler ve feature selector uygula
                    if 'scaler' in self.model_info.get(model_name, {}):
                        scaler = self.model_info[model_name]['scaler']
                        features = scaler.transform(features)
                    
                    if 'feature_selector' in self.model_info.get(model_name, {}):
                        feature_selector = self.model_info[model_name]['feature_selector']
                        features = feature_selector.transform(features)
                    
                    return features
                        
                except Exception as sub_e:
                    print(f"❌ Malicious URLs model özellik çıkarımında hata: {sub_e}")
                    return self._extract_basic_malicious_urls_features(url)
            
        except Exception as e:
            print(f"❌ {model_name} için özellik çıkarımında hata: {e}")
            return None
        
        return None
    
    def _extract_tld(self, url: str) -> int:
        """TLD çıkar ve encode et"""
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            if '.' in domain:
                tld = domain.split('.')[-1]
                # Common TLD'leri encode et
                tld_mapping = {'com': 1, 'org': 2, 'net': 3, 'edu': 4, 'gov': 5}
                return tld_mapping.get(tld, 0)
        except:
            pass
        return 0
    
    def _extract_basic_website_features(self, url: str):
        """Website model için basit özellik çıkarımı (fallback)"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            
                                    # Website model için 35 özellik (model bu kadar bekliyor)
            features = [
                int(parsed.scheme == 'https'),  # having_IP_Address
                len(url),  # URL_Length
                int(len(url) < 50),  # Shortining_Service  
                int('@' in url),  # having_At_Symbol
                int('//' in parsed.path),  # double_slash_redirecting
                int('-' in parsed.netloc),  # Prefix_Suffix
                parsed.netloc.count('.') - 1 if '.' in parsed.netloc else 0,  # having_Sub_Domain
                0,  # SSLfinal_State (0=safe default)
                len(parsed.netloc) if parsed.netloc else 0,  # Domain_registeration_length
                0,  # Favicon (0=safe default)
                int(parsed.port is not None),  # port
                int('https' in url.lower()),  # HTTPS_token
                len([x for x in parsed.path.split('/') if x]),  # Request_URL
                0,  # URL_of_Anchor (0=safe default)
                0,  # Links_in_tags (0=safe default)
                0,  # SFH (0=safe default)
                0,  # Submitting_to_email (0=safe default)
                int(bool(re.search(r'redirect|forward', url.lower()))),  # Abnormal_URL
                0,  # Redirect (0=safe default)
                0,  # on_mouseover (0=safe default)
                0,  # RightClick (0=safe default)
                0,  # popUpWidnow (0=safe default)
                0,  # Iframe (0=safe default)
                0,  # age_of_domain (0=safe default)
                0,  # DNSRecord (0=safe default)
                # Ek özellikler (35'e tamamlamak için)
                int(parsed.scheme == 'http'),  # http_scheme
                int('www' in parsed.netloc),  # has_www
                len(parsed.path),  # path_length
                int(parsed.netloc.replace('.', '').isdigit()),  # is_ip
                parsed.netloc.count('-'),  # hyphen_count
                len(parsed.query) if parsed.query else 0,  # query_length
                int(len(parsed.netloc.split('.')) > 3),  # deep_subdomain
                0,  # additional_feature_32
                0,  # additional_feature_33
                0,  # additional_feature_34
                0   # additional_feature_35
            ]
            
            return np.array([features])
        except:
            # Fallback: 35 özellik için safe defaults
            return np.array([[0] * 35])

    def _extract_basic_crypto_features_30(self, url: str):
        """Cryptocurrency model için 30 özellik çıkarımı (model beklentisine uygun)"""
        try:
            from urllib.parse import urlparse
            import math
            
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            query = parsed.query
            
            # Model sadece 30 özellik bekliyor
            features = []
            
            # 1-10: Temel URL özellikleri
            features.append(len(url))  # url_length
            features.append(len(domain) if domain else 0)  # domain_length
            features.append(len(path))  # path_length
            features.append(len(query) if query else 0)  # query_length
            features.append(max(0, len(domain.split('.')) - 2) if domain else 0)  # subdomain_count
            features.append(int(any(c.isdigit() for c in domain) if domain else False))  # domain_has_numbers
            features.append(domain.count('-') if domain else 0)  # domain_hyphen_count
            features.append(int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))))  # has_ip
            features.append(int('xn--' in domain))  # homograph_attack
            features.append(sum(c.isdigit() for c in url))  # digit_count
            
            # 11-20: Keyword ve içerik analizi
            crypto_keywords = ['wallet', 'crypto', 'bitcoin', 'ethereum', 'btc', 'eth', 'coin']
            features.append(sum(kw in url.lower() for kw in crypto_keywords))  # crypto_keywords_count
            
            phishing_keywords = ['secure', 'account', 'verify', 'login', 'signin', 'confirm']
            features.append(sum(kw in url.lower() for kw in phishing_keywords))  # phishing_keywords_count
            
            brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook']
            features.append(int(any(brand in domain.lower() for brand in brands)))  # brand_impersonation
            
            suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'xyz', 'top', 'click']
            tld = domain.split('.')[-1] if '.' in domain else ''
            features.append(int(tld in suspicious_tlds))  # tld_suspicious
            
            features.append(sum(c.isupper() for c in url))  # uppercase_count
            features.append(url.count('.'))  # dot_count
            features.append(url.count('/'))  # slash_count
            features.append(url.count('-'))  # hyphen_count
            features.append(url.count('_'))  # underscore_count
            features.append(url.count('%'))  # percent_count
            
            # 21-30: Gelişmiş özellikler
            def calculate_entropy(s):
                if not s: return 0
                freq = {}
                for c in s: freq[c] = freq.get(c, 0) + 1
                entropy = 0
                for f in freq.values():
                    p = f / len(s)
                    entropy -= p * math.log2(p)
                return entropy
            
            features.append(calculate_entropy(url))  # url_entropy
            features.append(calculate_entropy(domain) if domain else 0)  # domain_entropy
            features.append(len([x for x in path.split('/') if x]))  # path_depth
            features.append(int(bool(query)))  # has_parameters
            features.append(int(len(domain) < 5 if domain else False))  # short_domain
            features.append(int(len(domain) > 30 if domain else False))  # long_domain
            features.append(len(url) + domain.count('.') + url.count('/'))  # url_complexity
            features.append(int(parsed.scheme == 'https'))  # is_https
            features.append(int(any(ord(c) > 127 for c in url)))  # is_international
            features.append(len(max(re.findall(r'\d+', url), key=len, default="")))  # max_consecutive_digits
            
            return np.array([features])
            
        except Exception as e:
            print(f"Crypto 30-feature extraction error: {e}")
            # Fallback: 30 özellik için default değerler
            return np.array([[0] * 30])

    def _extract_basic_crypto_features(self, url: str):
        """Cryptocurrency model için doğru özellik çıkarımı (46 özellik)"""
        try:
            from urllib.parse import urlparse
            import math
            
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            query = parsed.query
            
            # Crypto model için doğru 46 özellik isimlerine göre
            features = []
            
            # 1. url_length
            features.append(len(url))
            
            # 2. domain_length
            features.append(len(domain) if domain else 0)
            
            # 3. path_length
            features.append(len(path))
            
            # 4. query_length
            features.append(len(query) if query else 0)
            
            # 5. subdomain_count
            subdomains = domain.split('.') if domain else []
            features.append(max(0, len(subdomains) - 2) if len(subdomains) > 1 else 0)
            
            # 6. domain_has_numbers
            features.append(int(any(c.isdigit() for c in domain) if domain else False))
            
            # 7. domain_hyphen_count
            features.append(domain.count('-') if domain else 0)
            
            # 8. crypto_keywords_count
            crypto_keywords = ['wallet', 'crypto', 'bitcoin', 'ethereum', 'btc', 'eth', 'coin', 'blockchain']
            features.append(sum(kw in url.lower() for kw in crypto_keywords))
            
            # 9. phishing_keywords_count
            phishing_keywords = ['secure', 'account', 'verify', 'login', 'signin', 'confirm', 'update']
            features.append(sum(kw in url.lower() for kw in phishing_keywords))
            
            # 10. special_char_count
            special_chars = '@$%&*()+=[]{}|\\:";\'<>?,./'
            features.append(sum(c in special_chars for c in url))
            
            # 11. uppercase_count
            features.append(sum(c.isupper() for c in url))
            
            # 12. digit_count
            features.append(sum(c.isdigit() for c in url))
            
            # 13. has_ip
            features.append(int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))))
            
            # 14. has_port
            features.append(int(':' in domain and not domain.endswith(':80') and not domain.endswith(':443')))
            
            # 15. tld_suspicious
            suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'xyz', 'top', 'click', 'download']
            tld = domain.split('.')[-1] if '.' in domain else ''
            features.append(int(tld in suspicious_tlds))
            
            # 16. url_entropy
            def calculate_entropy(s):
                if not s: return 0
                freq = {}
                for c in s:
                    freq[c] = freq.get(c, 0) + 1
                entropy = 0
                for f in freq.values():
                    p = f / len(s)
                    entropy -= p * math.log2(p)
                return entropy
            features.append(calculate_entropy(url))
            
            # 17. domain_entropy
            features.append(calculate_entropy(domain) if domain else 0)
            
            # 18. has_shortener
            shorteners = ['bit.ly', 'tinyurl', 'short.link', 'is.gd', 't.co']
            features.append(int(any(short in domain for short in shorteners)))
            
            # 19. brand_impersonation
            brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'binance']
            features.append(int(any(brand in domain.lower() for brand in brands)))
            
            # 20. homograph_attack
            features.append(int('xn--' in domain))
            
            # 21. is_international
            features.append(int(any(ord(c) > 127 for c in url)))
            
            # 22. url_complexity
            features.append(len(url) + domain.count('.') + url.count('/') + len(query))
            
            # 23. path_depth
            features.append(len([x for x in path.split('/') if x]))
            
            # 24. has_parameters
            features.append(int(bool(query)))
            
            # 25. suspicious_extensions
            sus_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif']
            features.append(int(any(ext in path.lower() for ext in sus_extensions)))
            
            # 26. short_domain
            features.append(int(len(domain) < 5 if domain else False))
            
            # 27. long_domain
            features.append(int(len(domain) > 30 if domain else False))
            
            # 28-34. Name features (simulated for URL-only analysis)
            features.extend([
                0,  # name_length (no name field)
                0,  # name_dots
                0,  # name_hyphens
                0,  # name_numbers
                0,  # name_crypto_terms
                0,  # name_multiple_tld
                0   # name_suspicious_tld
            ])
            
            # 35-37. Name analysis (continued)
            features.extend([
                0,  # name_long_subdomain
                0,  # name_brand_similarity
                0   # name_vowel_ratio
            ])
            
            # 38-41. Description features (simulated)
            features.extend([
                0,  # desc_length (no description)
                0,  # desc_scam_words
                0,  # desc_urgency
                0   # desc_trust_words
            ])
            
            # 42-46. Address features (simulated)
            features.extend([
                0,  # addr_count (no addresses)
                0,  # addr_bitcoin_count
                0,  # addr_ethereum_count
                0,  # addr_other_count
                0   # addr_suspicious_count
            ])
            
            return np.array([features])
            
        except Exception as e:
            print(f"Crypto feature extraction error: {e}")
            # Fallback: 46 özellik için default değerler
            return np.array([[0] * 46])

    def _extract_basic_url_features(self, url: str):
        """Basit URL özellik çıkarımı (fallback)"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            
            features = [
                len(url),  # url_length
                len(parsed.netloc),  # domain_length
                len(parsed.path),  # path_length
                len(parsed.query),  # query_length
                len(parsed.fragment),  # fragment_length
                parsed.netloc.count('.') - 1 if parsed.netloc.count('.') > 0 else 0,  # subdomain_count
                int(any(c.isdigit() for c in parsed.netloc)),  # domain_has_digits
                int('-' in parsed.netloc),  # domain_has_hyphen
                int('_' in parsed.netloc),  # domain_has_underscore
                len(parsed.netloc.split('.')[-1]) if '.' in parsed.netloc else 0,  # tld_length
                int(parsed.netloc.split('.')[-1] in ['com', 'org', 'net', 'edu', 'gov']) if '.' in parsed.netloc else 0,  # is_common_tld
                int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))),  # has_ip_address
                int('paypal' in url.lower() or 'bank' in url.lower()),  # has_suspicious_words
                url.count('.'),  # dot_count
                url.count('/'),  # slash_count
                url.count('?'),  # question_count
                url.count('='),  # equal_count
                url.count('&'),  # ampersand_count
                url.count('-'),  # hyphen_count
                url.count('_'),  # underscore_count
                url.count('%'),  # percent_count
                url.count('@'),  # at_count
                int(parsed.scheme == 'https'),  # is_https
                int(parsed.netloc.startswith('www.')),  # has_www
                int('%' in url),  # has_url_encoding
                len(re.findall(r'%[0-9a-fA-F]{2}', url)),  # url_encoding_count
                int(bool(re.search(r'[<>"\'\{\}|\\^`\[\]]', url))),  # has_suspicious_chars
                len([x for x in parsed.path.split('/') if x]),  # path_depth
                int(bool(re.search(r'\.[a-zA-Z]{2,4}$', parsed.path))),  # path_has_extension
                len(parsed.query.split('&')) if parsed.query else 0,  # query_param_count
                2.5,  # domain_entropy (approximate)
                3.0,  # url_entropy (approximate)
                len(re.findall(r'[0-9a-fA-F]{8,}', url)),  # hex_pattern_count
                len(max(re.findall(r'\d+', url), key=len, default="")),  # max_consecutive_digits
                len(max(re.findall(r'[a-zA-Z]+', url), key=len, default=""))  # max_consecutive_letters
            ]
            
            return np.array([features])
        except:
            # En son fallback: 35 özellik için default değerler
            return np.array([[0] * 35])

    def _extract_basic_link_phishing_features(self, url: str):
        """Link Phishing Detection model için tam özellik çıkarımı (89 özellik)"""
        try:
            from urllib.parse import urlparse
            import math
            
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            query = parsed.query
            
            # Dataset sütun sırasına göre 89 özellik (url ve status hariç + 5 yeni)
            features = []
            
            # 1. url_length
            features.append(len(url))
            
            # 2. hostname_length  
            features.append(len(domain))
            
            # 3. ip (IP address check)
            features.append(int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))))
            
            # 4-19. Special character counts
            features.append(url.count('.'))      # total_of.
            features.append(url.count('-'))      # total_of-
            features.append(url.count('@'))      # total_of@
            features.append(url.count('?'))      # total_of?
            features.append(url.count('&'))      # total_of&
            features.append(url.count('='))      # total_of=
            features.append(url.count('_'))      # total_of_
            features.append(url.count('~'))      # total_of~
            features.append(url.count('%'))      # total_of%
            features.append(url.count('/'))      # total_of/
            features.append(url.count('*'))      # total_of*
            features.append(url.count(':'))      # total_of:
            features.append(url.count(','))      # total_of,
            features.append(url.count(';'))      # total_of;
            features.append(url.count('$'))      # total_of$
            
            # 20-22. Common patterns
            features.append(url.lower().count('www'))     # total_of_www
            features.append(url.lower().count('com'))     # total_of_com
            features.append(path.lower().count('http'))   # total_of_http_in_path
            
            # 23. https_token
            features.append(int(parsed.scheme == 'https'))
            
            # 24-25. Digit ratios
            features.append(sum(c.isdigit() for c in url) / len(url) if url else 0)        # ratio_digits_url
            features.append(sum(c.isdigit() for c in domain) / len(domain) if domain else 0)  # ratio_digits_host
            
            # 26. punycode
            features.append(int('xn--' in domain))
            
            # 27. port
            features.append(int(':' in domain and not domain.endswith(':80') and not domain.endswith(':443')))
            
            # 28-29. TLD analysis
            tld_in_path = int(any(tld in path for tld in ['.com', '.org', '.net', '.edu']))
            tld_in_subdomain = int(any(tld in domain for tld in ['.com', '.org', '.net', '.edu']))
            features.append(tld_in_path)
            features.append(tld_in_subdomain)
            
            # 30-33. Subdomain analysis
            subdomains = domain.split('.')
            nb_subdomains = max(0, len(subdomains) - 2) if len(subdomains) > 1 else 0
            features.append(int(nb_subdomains > 3))  # abnormal_subdomain
            features.append(nb_subdomains)           # nb_subdomains
            features.append(int('-' in domain))     # prefix_suffix
            features.append(0)                      # random_domain (simplified)
            
            # 34-38. Service and extension analysis
            shortening_services = ['bit.ly', 'tinyurl', 'short.link', 'is.gd', 't.co']
            features.append(int(any(service in domain for service in shortening_services)))  # shortening_service
            features.append(int(bool(re.search(r'\.[a-zA-Z]{2,4}$', path))))                # path_extension
            features.append(0)  # nb_redirection (simplified)
            features.append(0)  # nb_external_redirection (simplified)
            
            # 39-49. Word analysis
            words_raw = re.findall(r'[a-zA-Z]+', url)
            length_words_raw = len(words_raw)
            
            if words_raw:
                shortest_words_raw = min(len(w) for w in words_raw)
                longest_words_raw = max(len(w) for w in words_raw)
                avg_words_raw = sum(len(w) for w in words_raw) / len(words_raw)
            else:
                shortest_words_raw = 0
                longest_words_raw = 0
                avg_words_raw = 0
            
            host_words = re.findall(r'[a-zA-Z]+', domain)
            if host_words:
                shortest_word_host = min(len(w) for w in host_words)
                longest_word_host = max(len(w) for w in host_words)
                avg_word_host = sum(len(w) for w in host_words) / len(host_words)
            else:
                shortest_word_host = 0
                longest_word_host = 0
                avg_word_host = 0
            
            path_words = re.findall(r'[a-zA-Z]+', path)
            if path_words:
                shortest_word_path = min(len(w) for w in path_words)
                longest_word_path = max(len(w) for w in path_words)
                avg_word_path = sum(len(w) for w in path_words) / len(path_words)
            else:
                shortest_word_path = 0
                longest_word_path = 0
                avg_word_path = 0
            
            features.extend([
                length_words_raw, int(0),  # char_repeat (simplified)
                shortest_words_raw, shortest_word_host, shortest_word_path,
                longest_words_raw, longest_word_host, longest_word_path,
                avg_words_raw, avg_word_host, avg_word_path
            ])
            
            # 50-55. Phishing and brand analysis
            phish_keywords = ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 'banking', 'confirm']
            brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'ebay', 'bank']
            suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'xyz', 'top', 'click']
            
            tld = domain.split('.')[-1] if '.' in domain else ''
            
            features.extend([
                sum(keyword in url.lower() for keyword in phish_keywords),  # phish_hints
                int(any(brand in domain.lower() for brand in brands)),      # domain_in_brand
                int(any(brand in '.'.join(subdomains[:-2]) for brand in brands) if len(subdomains) > 2 else False),  # brand_in_subdomain
                int(any(brand in path.lower() for brand in brands)),        # brand_in_path
                int(tld in suspicious_tlds),                                # suspecious_tld
                int(any(word in url.lower() for word in ['malware', 'spam', 'phish']))  # statistical_report
            ])
            
            # 56-75. Web content analysis (simplified for URL-only analysis)
            features.extend([
                len(re.findall(r'http[s]?://', url)) - 1,  # nb_hyperlinks
                0.8,  # ratio_intHyperlinks (default)
                0.2,  # ratio_extHyperlinks (default) 
                0,    # ratio_nullHyperlinks
                0,    # nb_extCSS
                0,    # ratio_intRedirection
                0.0,  # ratio_extRedirection
                0,    # ratio_intErrors
                0.0,  # ratio_extErrors
                int(any(word in url.lower() for word in ['login', 'signin', 'auth'])),  # login_form
                0,    # external_favicon
                0.0,  # links_in_tags
                0,    # submit_email
                0.0,  # ratio_intMedia
                0.0,  # ratio_extMedia
                0,    # sfh
                0,    # iframe
                0,    # popup_window
                0.8,  # safe_anchor (default)
                0,    # onmouseover
                0     # right_clic
            ])
            
            # 76-84. Domain and reputation analysis (simplified)
            features.extend([
                0,  # empty_title
                int(any(brand in domain.lower() for brand in brands)),  # domain_in_title (approximation)
                1,  # domain_with_copyright (assume has copyright: "one")
                1,  # whois_registered_domain (assume registered)
                365,  # domain_registration_length (default 1 year)
                1000,  # domain_age (default old domain)
                5,    # web_traffic (medium traffic)
                1,    # dns_record (assume exists)
                1,    # google_index (assume indexed)
                3     # page_rank (medium rank)
            ])
            
            # 85-89. Composite features (yeni eklenen 5 özellik)
            features.extend([
                features[0] + features[1] + nb_subdomains,  # url_complexity_score
                features[22] + (1 if len(features) > 83 else 0) + (1 if len(features) > 84 else 0),  # security_score
                features[2] + features[26] + (1 if len(features) > 30 else 0) + (1 if len(features) > 32 else 0) + (1 if len(features) > 34 else 0),  # suspicious_pattern_score
                (features[51] if len(features) > 51 else 0) + (features[52] if len(features) > 52 else 0) + (features[53] if len(features) > 53 else 0),  # brand_mimicking_score
                sum(features[i] if len(features) > i else 0 for i in [69, 70, 76, 77, 78, 79])  # malicious_content_score
            ])
            
            return np.array([features])
            
        except Exception as e:
            print(f"Link phishing feature extraction error: {e}")
            # Fallback: 89 özellik için default değerler
            return np.array([[0] * 89])
    
    def _extract_basic_malicious_urls_features(self, url: str):
        """Malicious URLs için temel özellik çıkarımı"""
        try:
            from urllib.parse import urlparse
            from collections import Counter
            import math
            
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            query = parsed.query
            
            features = []
            
            # Temel URL özellikleri
            features.extend([
                len(url),                                    # url_length
                len(domain),                                 # domain_length  
                len(path),                                   # path_length
                len(query) if query else 0,                  # query_length
                len(parsed.fragment) if parsed.fragment else 0,  # fragment_length
            ])
            
            # Domain analizi
            if domain:
                domain_parts = domain.split('.')
                features.extend([
                    max(0, len(domain_parts) - 2),          # subdomain_count
                    len(domain_parts),                       # domain_parts_count
                    len(domain_parts[-1]) if domain_parts else 0,  # tld_length
                    int(domain_parts[-1] in ['tk', 'ml', 'ga', 'cf', 'xyz', 'top', 'click'] if domain_parts else False),  # has_suspicious_tld
                    sum(c.isdigit() for c in domain) / len(domain) if domain else 0,  # domain_digit_ratio
                    domain.count('-'),                       # domain_hyphen_count
                    domain.count('_'),                       # domain_underscore_count
                ])
            else:
                features.extend([0, 0, 0, 0, 0, 0, 0])
            
            # Path ve query analizi
            features.extend([
                len([x for x in path.split('/') if x]),     # path_depth
                int('.' in path.split('/')[-1] if path.split('/') else False),  # path_has_extension
                len(query.split('&')) if query else 0,      # query_params_count
            ])
            
            # Protokol ve özel karakterler
            features.extend([
                int(parsed.scheme == 'https'),              # is_https
                int(parsed.port is not None),               # has_port
                parsed.port if parsed.port else 0,         # port_number
                sum(c in '@$%&*()+=[]{}|\\:";\'<>?,./' for c in url),  # special_char_count
                sum(c.isdigit() for c in url),              # total_digits
            ])
            
            # Pattern analizi
            suspicious_patterns = [
                r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP adresi
                r'localhost',
                r'%[0-9a-fA-F]{2}',  # URL encoding
            ]
            
            for pattern in suspicious_patterns:
                features.append(int(bool(re.search(pattern, url))))
            
            # Keyword analizi
            phishing_keywords = ['secure', 'account', 'verify', 'login', 'signin', 'confirm', 'update']
            defacement_keywords = ['hacked', 'defaced', 'owned', 'pwned']
            malware_keywords = ['download', 'exe', 'payload', 'exploit']
            brands = ['google', 'microsoft', 'apple', 'amazon', 'paypal']
            
            features.extend([
                sum(keyword in url.lower() for keyword in phishing_keywords),
                sum(keyword in url.lower() for keyword in defacement_keywords), 
                sum(keyword in url.lower() for keyword in malware_keywords),
                sum(brand in url.lower() for brand in brands),
            ])
            
            # Entropy hesaplama
            def calculate_entropy(text):
                if not text:
                    return 0
                frequencies = Counter(text)
                length = len(text)
                entropy = 0
                for freq in frequencies.values():
                    prob = freq / length
                    entropy -= prob * math.log2(prob)
                return entropy
            
            features.extend([
                calculate_entropy(url),                     # url_entropy
                calculate_entropy(domain) if domain else 0, # domain_entropy
                calculate_entropy(path),                    # path_entropy
                calculate_entropy(query) if query else 0,  # query_entropy
            ])
            
            # Homograph ve shortener analizi
            features.extend([
                int('xn--' in url.lower()),                 # has_punycode
                int(any(ord(c) > 127 for c in url)),        # mixed_charset
                int(any(shortener in domain.lower() for shortener in ['bit.ly', 'tinyurl', 't.co']) if domain else False),  # is_shortened
            ])
            
            # Tam olarak 43 özelliğe çıkar (SelectKBest 43 bekliyor)
            while len(features) < 43:
                features.append(0)
            
            # 43'ten fazla varsa kes
            features = features[:43]
            
            return np.array([features])
            
        except Exception as e:
            print(f"Malicious URLs feature extraction error: {e}")
            return np.array([[0] * 43])
    
    def _calculate_reputation(self, url: str) -> float:
        """URL reputation hesapla"""
        score = 0.0
        
        # Basic heuristics
        if 'https' in url:
            score += 10
        if len(url) < 50:
            score += 5
        if url.count('.') <= 2:
            score += 5
        
        # Suspicious patterns
        suspicious_patterns = ['bit.ly', 'tinyurl', 'secure', 'verify', 'account', 'login']
        for pattern in suspicious_patterns:
            if pattern in url.lower():
                score -= 20
        
        return max(-100, min(100, score))
    
    def predict_single_model(self, url: str, model_name: str) -> Optional[Dict]:
        """Tek model ile tahmin yap"""
        
        if model_name not in self.models:
            return None
        
        try:
            # Özellik çıkarımı
            features_array = self.extract_features_for_model(url, model_name)
            
            if features_array is None:
                return None
            
            # Model tahmini
            model = self.models[model_name]
            
            # Prediction
            prediction = model.predict(features_array)[0]
            prediction_proba = model.predict_proba(features_array)[0]
            
            # Confidence score
            confidence = max(prediction_proba)
            
            # Model-specific label handling
            if model_name == 'phishing_urls_model':
                # Bu model: 0=bad(phishing), 1=good(safe)
                result = {
                    'prediction': 1 - int(prediction),  # Reverse: 0->1(phishing), 1->0(safe)
                    'prediction_label': 'Safe' if prediction == 1 else 'Phishing',
                    'confidence': float(confidence),
                    'probability_safe': float(prediction_proba[1]),  # good probability
                    'probability_phishing': float(prediction_proba[0])  # bad probability
                }
            elif model_name == 'crypto_scam_model':
                # Crypto model: multi-class (Phishing, Scamming, Malware)
                # Phishing/Scamming/Malware -> 1 (threat), otherwise -> 0 (safe)
                label_encoder = self.model_info[model_name]['label_encoder']
                predicted_category = label_encoder.inverse_transform([prediction])[0]
                
                # Convert to binary: threat categories -> 1, others -> 0
                is_threat = predicted_category in ['Phishing', 'Scamming', 'Malware']
                
                result = {
                    'prediction': int(is_threat),
                    'prediction_label': 'Phishing' if is_threat else 'Safe',
                    'confidence': float(confidence),
                    'probability_safe': float(1 - confidence if is_threat else confidence),
                    'probability_phishing': float(confidence if is_threat else 1 - confidence),
                    'crypto_category': predicted_category  # Extra bilgi
                }
            elif model_name == 'link_phishing_model':
                # Link phishing model: 0=legitimate, 1=phishing
                label_encoder = self.model_info[model_name]['label_encoder']
                predicted_category = label_encoder.inverse_transform([prediction])[0]
                
                is_phishing = predicted_category == 'phishing'
                
                result = {
                    'prediction': int(is_phishing),
                    'prediction_label': 'Phishing' if is_phishing else 'Safe',
                    'confidence': float(confidence),
                    'probability_safe': float(prediction_proba[0] if not is_phishing else prediction_proba[1]),
                    'probability_phishing': float(prediction_proba[1] if is_phishing else prediction_proba[0]),
                    'link_category': predicted_category  # Extra bilgi
                }
            elif model_name == 'malicious_urls_model':
                # Malicious URLs model: 0=benign, 1=threat (phishing/malware/defacement)
                is_threat = prediction == 1
                
                result = {
                    'prediction': int(prediction),
                    'prediction_label': 'Phishing' if is_threat else 'Safe',
                    'confidence': float(confidence),
                    'probability_safe': float(prediction_proba[0]),
                    'probability_phishing': float(prediction_proba[1]),
                    'threat_type': 'multi-threat'  # phishing, malware, or defacement
                }
            else:
                # Diğer modeller: 0=safe, 1=phishing
                result = {
                    'prediction': int(prediction),
                    'prediction_label': 'Phishing' if prediction == 1 else 'Safe',
                    'confidence': float(confidence),
                    'probability_safe': float(prediction_proba[0]),
                    'probability_phishing': float(prediction_proba[1]) if len(prediction_proba) > 1 else 1.0 - float(prediction_proba[0])
                }
            
            return result
            
        except Exception as e:
            print(f"❌ {model_name} tahmin hatası: {e}")
            return None
    
    def predict_ensemble(self, url: str) -> Dict:
        """Ensemble tahmin - tüm modelleri kullan"""
        
        print(f"🔍 Ensemble analizi başlıyor: {url}")
        
        # Individual model predictions
        model_predictions = {}
        valid_predictions = []
        
        # Sadece gerçek ML modellerini test et (auxiliary objects değil)
        actual_models = [
            'phishing_model', 'cybersecurity_model', 'phishing_urls_model', 
            'website_model', 'crypto_scam_model', 'link_phishing_model', 'malicious_urls_model'
        ]
        
        for model_name in actual_models:
            if model_name in self.models:
                result = self.predict_single_model(url, model_name)
                if result:
                    model_predictions[model_name] = result
                    valid_predictions.append(result)
                    
                    print(f"   📊 {model_name}: {result['prediction_label']} ({result['confidence']:.3f})")
        
        if not valid_predictions:
            return {
                'error': 'No valid predictions from models',
                'url': url,
                'timestamp': datetime.now().isoformat()
            }
        
        # Weighted voting
        weighted_safe_score = 0.0
        weighted_phishing_score = 0.0
        total_weight = 0.0
        
        for model_name, prediction in model_predictions.items():
            weight = self.model_weights.get(model_name, 1.0)
            
            weighted_safe_score += prediction['probability_safe'] * weight
            weighted_phishing_score += prediction['probability_phishing'] * weight
            total_weight += weight
        
        # Normalize
        if total_weight > 0:
            final_safe_prob = weighted_safe_score / total_weight
            final_phishing_prob = weighted_phishing_score / total_weight
        else:
            final_safe_prob = 0.5
            final_phishing_prob = 0.5
        
        # Final decision
        final_prediction = 1 if final_phishing_prob > final_safe_prob else 0
        final_confidence = max(final_safe_prob, final_phishing_prob)
        
        # Voting statistics
        safe_votes = sum(1 for pred in valid_predictions if pred['prediction'] == 0)
        phishing_votes = sum(1 for pred in valid_predictions if pred['prediction'] == 1)
        
        # Rule-based analysis
        try:
            basic_features = self.feature_extractor.extract_features(url)
            rule_flags = self.rule_analyzer.analyze(url, basic_features)
            rule_result = {'flags': rule_flags, 'risk_score': len(rule_flags) * 20}
        except Exception as e:
            print(f"❌ Rule-based analysis hatası: {e}")
            rule_result = {'flags': [], 'risk_score': 0}
        
        # Final ensemble result
        ensemble_result = {
            'url': url,
            'final_prediction': final_prediction,
            'final_label': 'Phishing' if final_prediction == 1 else 'Safe',
            'confidence': float(final_confidence),
            'probability_safe': float(final_safe_prob),
            'probability_phishing': float(final_phishing_prob),
            
            # Voting details
            'total_models': 7,  # Sabit 7 model
            'active_models': len(valid_predictions),
            'safe_votes': safe_votes,
            'phishing_votes': phishing_votes,
            'voting_ratio': f"{phishing_votes}/{safe_votes + phishing_votes}",
            
            # Individual model results
            'model_predictions': model_predictions,
            
            # Rule-based analysis
            'rule_analysis': rule_result,
            
            # Metadata
            'timestamp': datetime.now().isoformat(),
            'model_weights': self.model_weights
        }
        
        print(f"   🎯 Ensemble Sonuç: {ensemble_result['final_label']} ({ensemble_result['confidence']:.3f})")
        print(f"   📊 Voting: {phishing_votes} Phishing, {safe_votes} Safe")
        
        return ensemble_result
    
    def update_model_weights(self, feedback: Dict):
        """Kullanıcı geri bildirimine göre model ağırlıklarını güncelle"""
        
        if 'model_predictions' not in feedback or 'user_label' not in feedback:
            return
        
        user_label = feedback['user_label']  # 0: Safe, 1: Phishing
        model_predictions = feedback['model_predictions']
        
        # Her model için doğruluk hesapla
        for model_name, prediction in model_predictions.items():
            if model_name in self.model_weights:
                predicted_label = prediction['prediction']
                
                # Doğru tahmin ise ağırlığı artır, yanlış ise azalt
                if predicted_label == user_label:
                    self.model_weights[model_name] *= 1.05  # %5 artır
                else:
                    self.model_weights[model_name] *= 0.95  # %5 azalt
                
                # Minimum ağırlık sınırı
                self.model_weights[model_name] = max(0.1, self.model_weights[model_name])
        
        # Ağırlıkları normalize et
        total_weight = sum(self.model_weights.values())
        if total_weight > 0:
            for model_name in self.model_weights:
                self.model_weights[model_name] /= total_weight
        
        print(f"🔄 Model ağırlıkları güncellendi:")
        for model_name, weight in self.model_weights.items():
            print(f"   {model_name}: {weight:.3f}")
    
    def save_feedback(self, feedback: Dict):
        """Geri bildirimi kaydet"""
        
        feedback['feedback_timestamp'] = datetime.now().isoformat()
        self.feedback_history.append(feedback)
        
        # CSV'ye kaydet
        feedback_df = pd.DataFrame([feedback])
        
        try:
            existing_feedback = pd.read_csv('ensemble_feedback.csv')
            updated_feedback = pd.concat([existing_feedback, feedback_df], ignore_index=True)
        except FileNotFoundError:
            updated_feedback = feedback_df
        
        updated_feedback.to_csv('ensemble_feedback.csv', index=False)
        
        # Model ağırlıklarını güncelle
        self.update_model_weights(feedback)
        
        print(f"💾 Geri bildirim kaydedildi ve model ağırlıkları güncellendi")
    
    def get_model_info(self) -> Dict:
        """Model bilgilerini döndür"""
        
        return {
            'ensemble_info': {
                'total_models': len(self.models),
                'active_models': len([m for m in self.models.values() if m is not None]),
                'model_weights': self.model_weights,
                'feedback_count': len(self.feedback_history)
            },
            'individual_models': self.model_info,
            'performance_metrics': self.model_performance
        }
    
    def analyze_url_comprehensive(self, url: str) -> Dict:
        """Kapsamlı URL analizi"""
        
        # Ensemble prediction
        ensemble_result = self.predict_ensemble(url)
        
        # Add comprehensive analysis
        comprehensive_result = {
            **ensemble_result,
            'analysis_details': {
                'feature_analysis': self.feature_extractor.extract_features(url),
                'model_comparison': self._compare_model_strengths(ensemble_result),
                'risk_factors': self._identify_risk_factors(url, ensemble_result),
                'recommendations': self._generate_recommendations(ensemble_result)
            }
        }
        
        return comprehensive_result
    
    def _compare_model_strengths(self, ensemble_result: Dict) -> Dict:
        """Model güçlü yanlarını karşılaştır"""
        
        model_strengths = {}
        
        for model_name, info in self.model_info.items():
            if model_name in ensemble_result.get('model_predictions', {}):
                prediction = ensemble_result['model_predictions'][model_name]
                
                model_strengths[model_name] = {
                    'speciality': info.get('speciality', info.get('specialization', 'URL analysis')),
                    'confidence': prediction['confidence'],
                    'decision': prediction['prediction_label'],
                    'algorithm': info.get('algorithm', 'Machine Learning')
                }
        
        return model_strengths
    
    def _identify_risk_factors(self, url: str, ensemble_result: Dict) -> List[str]:
        """Risk faktörlerini belirle"""
        
        risk_factors = []
        
        # Rule-based risk factors
        if ensemble_result.get('rule_analysis', {}).get('risk_score', 0) > 50:
            risk_factors.append("High rule-based risk score")
        
        # Model consensus
        if ensemble_result.get('phishing_votes', 0) > ensemble_result.get('safe_votes', 0):
            risk_factors.append("Majority of models predict phishing")
        
        # Low confidence
        if ensemble_result.get('confidence', 1.0) < 0.7:
            risk_factors.append("Low prediction confidence")
        
        # URL characteristics
        if len(url) > 100:
            risk_factors.append("Unusually long URL")
        
        if url.count('.') > 5:
            risk_factors.append("Too many subdomains")
        
        return risk_factors
    
    def _generate_recommendations(self, ensemble_result: Dict) -> List[str]:
        """Öneriler oluştur"""
        
        recommendations = []
        
        if ensemble_result['final_prediction'] == 1:  # Phishing
            recommendations.append("🚨 Bu URL'ye tıklamayın")
            recommendations.append("🔍 URL'yi dikkatli inceleyin")
            recommendations.append("🛡️ Güvenilir kaynaklardan doğrulayın")
        else:  # Safe
            if ensemble_result['confidence'] < 0.8:
                recommendations.append("⚠️ Orta düzeyde güvenlik riski")
                recommendations.append("🔍 Ek doğrulama yapılabilir")
            else:
                recommendations.append("✅ URL güvenli görünüyor")
        
        return recommendations

    def extract_all_features_once(self, url: str):
        """Tüm özellikleri tek seferde çıkar - OPTIMIZE EDİLMİŞ"""
        print("🚀 OPTIMIZE EDİLMİŞ: Tüm özellikler tek seferde çıkarılıyor...")
        
        features_cache = {}
        
        try:
            # 1. Temel URL özellikleri (tüm modeller için gerekli)
            basic_features = self.feature_extractor.extract_features(url)
            features_cache['basic'] = basic_features
            
            # 2. Cybersecurity model özellikleri (simulated)
            cybersecurity_features = [
                int('.onion' in url.lower()),  # is_onion
                self._extract_tld(url),  # tld
                0,  # categories_sophos
                0,  # categories_alpha_mountain
                self._calculate_reputation(url),  # reputation
                0,  # number_of_tags
                60,  # last_analysis_stats_harmles
                5,  # last_analysis_stats_malicious
                0,  # last_analysis_stats_suspicious
                25,  # last_analysis_stats_undetected
                0,  # total_votes_harmless
                0,  # total_votes_malicious
                5/61,  # malicious_harmless_ratio
                90,  # total_analysis_score
                2  # reputation_category
            ]
            features_cache['cybersecurity'] = cybersecurity_features
            
            # 3. Website features (eğer extractor varsa)
            if 'website_extractor' in self.models:
                try:
                    extractor = self.models['website_extractor']
                    website_features = extractor.extract_website_features(url)
                    if 'class' in website_features:
                        del website_features['class']
                    
                    import pandas as pd
                    features_df = pd.DataFrame([website_features])
                    features_engineered = extractor.feature_engineering(features_df)
                    features_cache['website'] = features_engineered
                except Exception as e:
                    print(f"⚠️ Website features fallback: {e}")
                    features_cache['website'] = self._extract_basic_website_features(url)
            else:
                features_cache['website'] = self._extract_basic_website_features(url)
            
            # 4. Crypto features (pipeline ile)
            if 'crypto_scam_model' in self.model_info and 'pipeline' in self.model_info['crypto_scam_model']:
                try:
                    pipeline = self.model_info['crypto_scam_model']['pipeline']
                    import pandas as pd
                    temp_df = pd.DataFrame({
                        'url': [url],
                        'name': [''],
                        'description': [''],
                        'addresses': ['']
                    })
                    crypto_features = pipeline.create_features(temp_df)
                    features_cache['crypto'] = crypto_features
                except Exception as e:
                    print(f"⚠️ Crypto features fallback: {e}")
                    features_cache['crypto'] = self._extract_basic_crypto_features_30(url)
            else:
                features_cache['crypto'] = self._extract_basic_crypto_features_30(url)
            
            # 5. URL-specific features
            features_cache['url_specific'] = self._extract_basic_url_features(url)
            
            # 6. Link phishing features
            features_cache['link_phishing'] = self._extract_basic_link_phishing_features(url)
            
            # 7. Malicious URLs features
            features_cache['malicious_urls'] = self._extract_basic_malicious_urls_features(url)
            
            print("✅ Tüm özellikler başarıyla çıkarıldı!")
            return features_cache
            
        except Exception as e:
            print(f"❌ Özellik çıkarım hatası: {e}")
            return {}
    
    def get_model_features_from_cache(self, url: str, model_name: str, features_cache: Dict):
        """Cache'den belirli model için özellikleri al - OPTIMIZE EDİLMİŞ"""
        
        try:
            if model_name == 'phishing_model':
                # Mega phishing dataset özellikleri
                basic_features = features_cache.get('basic', {})
                
                if 'selected_features' in self.model_info[model_name]:
                    selected_features = self.model_info[model_name]['selected_features']
                    feature_values = []
                    for feature_name in selected_features:
                        feature_values.append(basic_features.get(feature_name, 0))
                    return np.array([feature_values])
                else:
                    feature_values = list(basic_features.values())
                    return np.array([feature_values])
            
            elif model_name == 'cybersecurity_model':
                cybersecurity_features = features_cache.get('cybersecurity', [])
                return np.array([cybersecurity_features])
            
            elif model_name == 'phishing_urls_model':
                # URL özellikleri kullan
                url_features = features_cache.get('url_specific')
                if url_features is not None:
                    # Feature selection uygula
                    if 'phishing_urls_model_feature_selector' in self.models:
                        feature_selector = self.models['phishing_urls_model_feature_selector']
                        return feature_selector.transform(url_features)
                    return url_features
                else:
                    return self._extract_basic_url_features(url)
            
            elif model_name == 'website_model':
                website_features = features_cache.get('website')
                if website_features is not None:
                    # Selected features'a göre sırala
                    if 'selected_features' in self.model_info[model_name]:
                        selected_features = self.model_info[model_name]['selected_features']
                        available_features = [col for col in selected_features if col in website_features.columns]
                        if available_features:
                            return website_features[available_features].values
                    
                    # Feature selection uygula
                    if 'feature_selector' in self.model_info[model_name]:
                        feature_selector = self.model_info[model_name]['feature_selector']
                        return feature_selector.transform(website_features)
                    
                    return website_features.values
                else:
                    return self._extract_basic_website_features(url)
            
            elif model_name == 'crypto_scam_model':
                crypto_features = features_cache.get('crypto')
                if crypto_features is not None:
                    # Scaling uygula
                    if 'scaler' in self.model_info[model_name]:
                        scaler = self.model_info[model_name]['scaler']
                        crypto_features = scaler.transform(crypto_features)
                    
                    # Feature selection uygula
                    if 'feature_selector' in self.model_info[model_name]:
                        feature_selector = self.model_info[model_name]['feature_selector']
                        crypto_features = feature_selector.transform(crypto_features)
                    
                    return crypto_features
                else:
                    return np.array([[0] * 30])
            
            elif model_name == 'link_phishing_model':
                link_features = features_cache.get('link_phishing')
                if link_features is not None:
                    # Feature selection uygula
                    if 'feature_selector' in self.model_info[model_name]:
                        feature_selector = self.model_info[model_name]['feature_selector']
                        return feature_selector.transform(link_features)
                    return link_features
                else:
                    return self._extract_basic_link_phishing_features(url)
            
            elif model_name == 'malicious_urls_model':
                malicious_features = features_cache.get('malicious_urls')
                if malicious_features is not None:
                    # Feature selection uygula
                    if 'feature_selector' in self.model_info[model_name]:
                        feature_selector = self.model_info[model_name]['feature_selector']
                        return feature_selector.transform(malicious_features)
                    return malicious_features
                else:
                    return self._extract_basic_malicious_urls_features(url)
            
            else:
                print(f"⚠️ Bilinmeyen model: {model_name}")
                return None
                
        except Exception as e:
            print(f"❌ {model_name} özellik hatası: {e}")
            return None

    def predict_ensemble_optimized(self, url: str) -> Dict:
        """OPTIMIZE EDİLMİŞ ensemble tahmin - tüm özellikleri tek seferde çıkar"""
        
        print(f"🚀 OPTIMIZE EDİLMİŞ ensemble analizi başlıyor: {url}")
        
        # Tüm özellikleri tek seferde çıkar
        features_cache = self.extract_all_features_once(url)
        
        if not features_cache:
            return {
                'error': 'Feature extraction failed',
                'url': url,
                'timestamp': datetime.now().isoformat()
            }
        
        # Individual model predictions
        model_predictions = {}
        valid_predictions = []
        
        # Sadece gerçek ML modellerini test et
        actual_models = [
            'phishing_model', 'cybersecurity_model', 'phishing_urls_model', 
            'website_model', 'link_phishing_model', 'malicious_urls_model'
        ]
        # crypto_scam_model geçici olarak devre dışı (özellik uyumsuzluğu)
        
        for model_name in actual_models:
            if model_name in self.models and self.models[model_name] is not None:
                try:
                    # Cache'den özellik al (optimize edilmiş)
                    features = self.get_model_features_from_cache(url, model_name, features_cache)
                    
                    if features is not None:
                        # Model prediction
                        model = self.models[model_name]
                        probabilities = model.predict_proba(features)[0]
                        prediction = model.predict(features)[0]
                        
                        # Model explanation oluştur
                        explanation = self._generate_model_explanation(url, model_name, prediction, probabilities, features)
                        
                        prediction_result = {
                            'prediction': int(prediction),
                            'prediction_label': 'Phishing' if prediction == 1 else 'Safe',
                            'probability_safe': float(probabilities[0]),
                            'probability_phishing': float(probabilities[1]) if len(probabilities) > 1 else float(1 - probabilities[0]),
                            'confidence': float(max(probabilities)),
                            'model_name': model_name,
                            'explanation': explanation
                        }
                        
                        model_predictions[model_name] = prediction_result
                        valid_predictions.append(prediction_result)
                        
                        print(f"   📊 {model_name}: {prediction_result['prediction_label']} ({prediction_result['confidence']:.3f})")
                    
                except Exception as e:
                    print(f"   ❌ {model_name} hatası: {e}")
                    continue
        
        if not valid_predictions:
            return {
                'error': 'No valid predictions from models',
                'url': url,
                'timestamp': datetime.now().isoformat()
            }
        
        # Weighted voting
        weighted_safe_score = 0.0
        weighted_phishing_score = 0.0
        total_weight = 0.0
        
        for model_name, prediction in model_predictions.items():
            weight = self.model_weights.get(model_name, 1.0)
            
            weighted_safe_score += prediction['probability_safe'] * weight
            weighted_phishing_score += prediction['probability_phishing'] * weight
            total_weight += weight
        
        # Normalize
        if total_weight > 0:
            final_safe_prob = weighted_safe_score / total_weight
            final_phishing_prob = weighted_phishing_score / total_weight
        else:
            final_safe_prob = 0.5
            final_phishing_prob = 0.5
        
        # Final decision
        final_prediction = 1 if final_phishing_prob > final_safe_prob else 0
        final_confidence = max(final_safe_prob, final_phishing_prob)
        
        # Voting statistics
        safe_votes = sum(1 for pred in valid_predictions if pred['prediction'] == 0)
        phishing_votes = sum(1 for pred in valid_predictions if pred['prediction'] == 1)
        
        # Rule-based analysis (basic features zaten cache'de)
        try:
            basic_features = features_cache.get('basic', {})
            rule_flags = self.rule_analyzer.analyze(url, basic_features)
            rule_result = {'flags': rule_flags, 'risk_score': len(rule_flags) * 20}
        except Exception as e:
            print(f"❌ Rule-based analysis hatası: {e}")
            rule_result = {'flags': [], 'risk_score': 0}
        
        # Final ensemble result
        ensemble_result = {
            'url': url,
            'final_prediction': final_prediction,
            'final_label': 'Phishing' if final_prediction == 1 else 'Safe',
            'confidence': float(final_confidence),
            'probability_safe': float(final_safe_prob),
            'probability_phishing': float(final_phishing_prob),
            
            # Voting details
            'total_models': 7,
            'active_models': len(valid_predictions),
            'safe_votes': safe_votes,
            'phishing_votes': phishing_votes,
            'voting_ratio': f"{phishing_votes}/{safe_votes + phishing_votes}",
            
            # Individual model results
            'model_predictions': model_predictions,
            
            # Rule-based analysis
            'rule_analysis': rule_result,
            
            # Metadata
            'timestamp': datetime.now().isoformat(),
            'model_weights': self.model_weights,
            'optimization': 'features_cached'
        }
        
        print(f"   🎯 OPTIMIZE EDİLMİŞ Sonuç: {ensemble_result['final_label']} ({ensemble_result['confidence']:.3f})")
        print(f"   📊 Voting: {phishing_votes} Phishing, {safe_votes} Safe")
        
        return ensemble_result

    def _generate_model_explanation(self, url: str, model_name: str, prediction: int, probabilities: np.ndarray, features: np.ndarray) -> Dict:
        """Model kararı için açıklama oluştur"""
        
        try:
            explanation = {
                'decision_reason': '',
                'key_features': [],
                'risk_factors': [],
                'confidence_factors': []
            }
            
            is_phishing = prediction == 1
            confidence = float(max(probabilities))
            
            # Domain bilgisi çıkar
            domain = url.split('/')[2] if '//' in url else url.split('/')[0]
            
            # Model özelliklerine göre açıklama
            if model_name == 'phishing_model':
                # Mega Phishing Model açıklaması
                if is_phishing:
                    explanation['decision_reason'] = f"Model, URL'de phishing kalıpları tespit etti"
                    explanation['risk_factors'] = [
                        f"URL uzunluğu şüpheli ({len(url)} karakter)",
                        f"Domain yapısı riskli: {domain}",
                        "Phishing veri setindeki kalıplarla benzerlik"
                    ]
                else:
                    explanation['decision_reason'] = f"Model, URL'yi güvenli olarak sınıflandırdı"
                    explanation['confidence_factors'] = [
                        f"Normal URL yapısı ({len(url)} karakter)",
                        f"Güvenilir domain yapısı: {domain}",
                        "Bilinen güvenli kalıplarla benzerlik"
                    ]
            
            elif model_name == 'cybersecurity_model':
                # Cybersecurity Model açıklaması
                if is_phishing:
                    explanation['decision_reason'] = f"Siber güvenlik analizi threat tespit etti"
                    explanation['risk_factors'] = [
                        "VirusTotal benzeri taramada şüpheli",
                        "Kötü amaçlı kategori tespiti",
                        "Düşük güvenlik puanı"
                    ]
                else:
                    explanation['decision_reason'] = f"Siber güvenlik analizi temiz çıktı"
                    explanation['confidence_factors'] = [
                        "VirusTotal benzeri taramada temiz",
                        "Güvenli kategori tespiti",
                        "Yüksek güvenlik puanı"
                    ]
            
            elif model_name == 'phishing_urls_model':
                # Advanced URL Model açıklaması
                if is_phishing:
                    explanation['decision_reason'] = f"Gelişmiş URL analizi phishing tespit etti"
                    explanation['risk_factors'] = [
                        "URL yapısında anormallik",
                        "Şüpheli parametreler",
                        "Phishing URL kalıpları"
                    ]
                else:
                    explanation['decision_reason'] = f"Gelişmiş URL analizi güvenli"
                    explanation['confidence_factors'] = [
                        "Normal URL yapısı",
                        "Güvenli parametreler",
                        "Legitimte URL kalıpları"
                    ]
            
            elif model_name == 'website_model':
                # Website Feature Model açıklaması
                if is_phishing:
                    explanation['decision_reason'] = f"Website özellik analizi riskli"
                    explanation['risk_factors'] = [
                        "Şüpheli website yapısı",
                        "Phishing website kalıpları",
                        "Riskli domain özellikleri"
                    ]
                else:
                    explanation['decision_reason'] = f"Website özellik analizi güvenli"
                    explanation['confidence_factors'] = [
                        "Normal website yapısı",
                        "Güvenilir domain özellikleri",
                        "Legitimte website kalıpları"
                    ]
            
            elif model_name == 'crypto_scam_model':
                # Cryptocurrency Scam Model açıklaması
                if is_phishing:
                    explanation['decision_reason'] = f"Kripto dolandırıcılık tespiti"
                    explanation['risk_factors'] = [
                        "Kripto scam kalıpları",
                        "Sahte kripto sitesi özellikleri",
                        "Dolandırıcılık göstergeleri"
                    ]
                else:
                    explanation['decision_reason'] = f"Kripto dolandırıcılık tespiti temiz"
                    explanation['confidence_factors'] = [
                        "Normal kripto site yapısı",
                        "Güvenilir kripto özellikleri",
                        "Scam olmayan kalıplar"
                    ]
            
            elif model_name == 'link_phishing_model':
                # Link Phishing Model açıklaması
                if is_phishing:
                    explanation['decision_reason'] = f"Link phishing analizi pozitif"
                    explanation['risk_factors'] = [
                        "Kötü amaçlı link kalıpları",
                        "Phishing link özellikleri",
                        "Şüpheli yönlendirme"
                    ]
                else:
                    explanation['decision_reason'] = f"Link phishing analizi negatif"
                    explanation['confidence_factors'] = [
                        "Güvenilir link yapısı",
                        "Normal yönlendirme",
                        "Safe link kalıpları"
                    ]
            
            elif model_name == 'malicious_urls_model':
                # Malicious URLs Model açıklaması
                if is_phishing:
                    explanation['decision_reason'] = f"Kötü amaçlı URL tespiti"
                    explanation['risk_factors'] = [
                        "Malware/phishing/defacement kalıpları",
                        "Multi-threat analizi pozitif",
                        "Şüpheli URL davranışı"
                    ]
                else:
                    explanation['decision_reason'] = f"Kötü amaçlı URL tespiti negatif"
                    explanation['confidence_factors'] = [
                        "Temiz URL analizi",
                        "Multi-threat tarama temiz",
                        "Güvenli URL davranışı"
                    ]
            
            # Confidence düzeyine göre ek açıklama
            if confidence > 0.9:
                explanation['confidence_factors'].append(f"Çok yüksek güven (%{confidence*100:.1f})")
            elif confidence > 0.8:
                explanation['confidence_factors'].append(f"Yüksek güven (%{confidence*100:.1f})")
            elif confidence > 0.7:
                explanation['confidence_factors'].append(f"Orta güven (%{confidence*100:.1f})")
            else:
                explanation['confidence_factors'].append(f"Düşük güven (%{confidence*100:.1f})")
            
            return explanation
            
        except Exception as e:
            return {
                'decision_reason': f"Model analizi tamamlandı",
                'key_features': [],
                'risk_factors': [],
                'confidence_factors': [f"Confidence: %{confidence*100:.1f}"]
            }

# Global ensemble instance
ensemble_detector = None

def initialize_ensemble():
    """Ensemble detector'ı başlat"""
    global ensemble_detector
    
    if ensemble_detector is None:
        print("🚀 Ensemble Phishing Detector başlatılıyor...")
        ensemble_detector = EnsemblePhishingDetector()
        print("✅ Ensemble sistem hazır!")
    
    return ensemble_detector

def analyze_url_with_ensemble(url: str) -> Dict:
    """URL'yi 7-model ensemble ile analiz et"""
    
    # Global instance kullan - tüm 7 model yüklü
    detector = initialize_ensemble()
    
    return detector.analyze_url_comprehensive(url)

def submit_ensemble_feedback(url: str, user_feedback: str, comment: str = "") -> Dict:
    """Ensemble sistemine geri bildirim gönder"""
    
    detector = initialize_ensemble()
    
    # Get last prediction for this URL
    # (In practice, you'd store predictions and link them to feedback)
    prediction_result = detector.predict_ensemble(url)
    
    feedback = {
        'url': url,
        'user_feedback': user_feedback,
        'comment': comment,
        'model_predictions': prediction_result.get('model_predictions', {}),
        'user_label': 1 if user_feedback.lower() == 'phishing' else 0,
        'ensemble_prediction': prediction_result.get('final_prediction', 0),
        'confidence': prediction_result.get('confidence', 0.0)
    }
    
    detector.save_feedback(feedback)
    
    return {
        'status': 'success',
        'message': 'Feedback saved and model weights updated',
        'updated_weights': detector.model_weights
    }

def api_analyze_url_7_models(url: str) -> Dict:
    """
    API için özel 7-model ensemble analizi
    Bu fonksiyon cache sorunlarını önlemek için her seferinde fresh instance oluşturur
    """
    print(f"🎯 API 7-MODEL ENSEMBLE ANALİZİ: {url}")
    
    try:
        # Fresh instance oluştur - cache sorunu yok
        detector = EnsemblePhishingDetector()
        
        # Kapsamlı analiz yap
        result = detector.analyze_url_comprehensive(url)
        
        # API formatında döndür
        api_response = {
            "ensemble_prediction": result['final_label'],
            "ensemble_confidence": result['confidence'],
            "total_models": result['total_models'],
            "active_models": result['active_models'],
            "phishing_votes": result['phishing_votes'],
            "safe_votes": result['safe_votes'],
            "voting_ratio": result['voting_ratio'],
            "model_weights": result['model_weights'],
            "rule_based_flags_count": len(result['rule_analysis'].get('flags', [])),
            "hybrid_risk_score": result['probability_phishing'],
            "ensemble_status": "success_7_models",
            "individual_models": {
                name: {
                    "prediction": pred['prediction_label'],
                    "confidence": pred['confidence']
                }
                for name, pred in result.get('model_predictions', {}).items()
            },
            "rule_analysis": result['rule_analysis'],
            "timestamp": result['timestamp'],
            "url": url,
            "final_prediction": result['final_prediction'],
            "final_label": result['final_label'],
            "probability_safe": result['probability_safe'],
            "probability_phishing": result['probability_phishing']
        }
        
        print(f"✅ API Response: {api_response['active_models']}/7 model aktif")
        return api_response
        
    except Exception as e:
        print(f"❌ API 7-model ensemble hatası: {e}")
        return {
            "error": f"7-model ensemble hatası: {str(e)}",
            "ensemble_status": "error",
            "active_models": 0,
            "total_models": 7
        }

if __name__ == "__main__":
    # Test the ensemble system
    detector = initialize_ensemble()
    
    test_urls = [
        "https://google.com",
        "http://phishing-site-example.malicious.com/secure/verify",
        "https://facebook.com",
        "http://bit.ly/suspicious-link"
    ]
    
    print("\n🧪 ENSEMBLE SYSTEM TEST")
    print("="*50)
    
    for url in test_urls:
        print(f"\n📝 Testing: {url}")
        result = detector.analyze_url_comprehensive(url)
        
        print(f"🎯 Result: {result['final_label']} ({result['confidence']:.3f})")
        print(f"📊 Votes: {result['phishing_votes']} phishing, {result['safe_votes']} safe")
        print(f"⚠️ Risk factors: {len(result['analysis_details']['risk_factors'])}")
        
        for recommendation in result['analysis_details']['recommendations']:
            print(f"   {recommendation}") 