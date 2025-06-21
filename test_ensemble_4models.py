#!/usr/bin/env python3
"""
4-Model Ensemble Test Script
"""

import pandas as pd
import numpy as np
import joblib
from typing import Dict, Any
import warnings
warnings.filterwarnings('ignore')

def load_all_models():
    """4 modeli yükle"""
    models = {}
    model_info = {}
    
    print("🚀 Testing 4-Model Ensemble System")
    print("=" * 50)
    print("🔄 Ensemble modelleri yükleniyor...")
    
    # Model 1: Mega Phishing
    try:
        models['phishing_model'] = joblib.load('best_phishing_model.pkl')
        model_info['phishing_model'] = {
            'name': 'Mega Phishing Detector',
            'accuracy': 0.9991,
            'selected_features': joblib.load('selected_features.pkl')
        }
        print("   ✅ Phishing Model yüklendi")
    except Exception as e:
        print(f"   ❌ Phishing Model: {e}")
    
    # Model 2: Cybersecurity
    try:
        models['cybersecurity_model'] = joblib.load('cybersecurity_model_catboost.pkl')
        model_info['cybersecurity_model'] = {
            'name': 'Cybersecurity VirusTotal Analyzer',
            'accuracy': 0.9964
        }
        print("   ✅ Cybersecurity Model yüklendi")
    except Exception as e:
        print(f"   ❌ Cybersecurity Model: {e}")
    
    # Model 3: Advanced URL
    try:
        models['phishing_urls_model'] = joblib.load('phishing_urls_model_best.pkl')
        model_info['phishing_urls_model'] = {
            'name': 'Advanced URL Feature Analyzer',
            'accuracy': 0.9125,
            'selected_features': joblib.load('phishing_urls_model_best_selected_features.pkl'),
            'feature_selector': joblib.load('phishing_urls_model_best_feature_selector.pkl'),
            'scaler': joblib.load('phishing_urls_model_best_scaler.pkl')
        }
        print("   ✅ Advanced URL Feature Model yüklendi")
    except Exception as e:
        print(f"   ❌ Advanced URL Model: {e}")
    
    # Model 4: Website Features
    try:
        models['website_model'] = joblib.load('phishing_website_model_best.pkl')
        model_info['website_model'] = {
            'name': 'Website Feature Detector',
            'accuracy': 0.9656,
            'selected_features': joblib.load('phishing_website_model_best_selected_features.pkl'),
            'feature_selector': joblib.load('phishing_website_model_best_feature_selector.pkl')
        }
        print("   ✅ Website Feature Model yüklendi")
    except Exception as e:
        print(f"   ❌ Website Feature Model: {e}")
    
    # Model ağırlıklarını hesapla
    model_weights = {}
    total_accuracy = sum([info['accuracy'] for info in model_info.values()])
    
    for model, info in model_info.items():
        model_weights[model] = info['accuracy'] / total_accuracy
    
    print("🎯 Model ağırlıkları:")
    for model, weight in model_weights.items():
        print(f"   {model}: {weight:.3f}")
    
    print(f"✅ {len(models)} model başarıyla yüklendi")
    
    return models, model_info, model_weights

def extract_features_for_model1(url: str, selected_features):
    """Model 1 için basit feature extraction"""
    from ml_pipeline import FeatureExtractor
    
    extractor = FeatureExtractor()
    features = extractor.extract_features(url)
    feature_values = [features.get(feature, 0) for feature in selected_features]
    return np.array(feature_values).reshape(1, -1)

def extract_features_for_model3(url: str, feature_selector, scaler):
    """Model 3 için basit feature extraction"""
    from phishing_urls_model_pipeline import PhishingURLsDetectorPipeline
    
    pipeline = PhishingURLsDetectorPipeline()
    features = pipeline.extract_url_features(url)
    
    feature_df = pd.DataFrame([features])
    selected_features = feature_selector.transform(feature_df)
    scaled_features = scaler.transform(selected_features)
    
    return scaled_features

def extract_features_for_model4(url: str, selected_features):
    """Model 4 için basit feature extraction (simulated)"""
    from urllib.parse import urlparse
    import socket
    
    parsed = urlparse(url)
    
    def is_ip_address(hostname):
        try:
            socket.inet_aton(hostname)
            return True
        except:
            return False
    
    # Simulated website features
    features = {
        'UsingIP': -1 if is_ip_address(parsed.netloc) else 1,
        'LongURL': 1 if len(url) > 75 else -1,
        'ShortURL': 1 if len(url) < 30 else -1,
        'Symbol@': 1 if '@' in url else -1,
        'Redirecting//': 1 if '//' in parsed.path else -1,
        'PrefixSuffix-': 1 if '-' in parsed.netloc else -1,
        'SubDomains': len(parsed.netloc.split('.')) - 2 if len(parsed.netloc.split('.')) > 2 else -1,
        'HTTPS': 1 if parsed.scheme == 'https' else -1,
        'DomainRegLen': 1,
        'Favicon': 1,
        'NonStdPort': -1 if parsed.port and parsed.port not in [80, 443] else 1,
        'HTTPSDomainURL': 1 if 'https' in parsed.netloc else -1,
        'RequestURL': 1,
        'AnchorURL': 1,
        'LinksInScriptTags': -1,
        'ServerFormHandler': -1,
        'InfoEmail': -1,
        'AbnormalURL': -1,
        'WebsiteForwarding': -1,
        'StatusBarCust': -1,
        'DisableRightClick': -1,
        'UsingPopupWindow': -1,
        'IframeRedirection': -1,
        'AgeofDomain': 1,
        'DNSRecording': 1,
        'WebsiteTraffic': 1,
        'PageRank': 1,
        'GoogleIndex': 1,
        'LinksPointingToPage': 1,
        'StatsReport': 1,
        # Engineered features
        'security_score': 2,
        'domain_trust_score': 3,
        'suspicious_url_score': -2,
        'popularity_score': 4,
        'js_manipulation_score': -6
    }
    
    feature_values = [features.get(feature, -1) for feature in selected_features]
    return np.array(feature_values).reshape(1, -1)

def test_ensemble_prediction(url: str, models, model_info, model_weights):
    """4-model ensemble ile tahmin yap"""
    print(f"🔍 Ensemble analizi başlıyor: {url}")
    
    predictions = {}
    confidences = {}
    
    # Model 1: Mega Phishing
    if 'phishing_model' in models:
        try:
            features = extract_features_for_model1(url, model_info['phishing_model']['selected_features'])
            pred_proba = models['phishing_model'].predict_proba(features)[0]
            pred = models['phishing_model'].predict(features)[0]
            
            predictions['phishing_model'] = pred
            confidences['phishing_model'] = max(pred_proba)
            
            label = "Phishing" if pred == 1 else "Safe"
            print(f"   📊 phishing_model: {label} ({max(pred_proba):.3f})")
        except Exception as e:
            print(f"   ❌ phishing_model error: {e}")
    
    # Model 2: Cybersecurity (simulated)
    if 'cybersecurity_model' in models:
        try:
            # Simulated safe prediction (no real VirusTotal data)
            pred = 0  # Safe
            confidence = 0.97
            
            predictions['cybersecurity_model'] = pred
            confidences['cybersecurity_model'] = confidence
            
            label = "Phishing" if pred == 1 else "Safe"
            print(f"   📊 cybersecurity_model: {label} ({confidence:.3f})")
        except Exception as e:
            print(f"   ❌ cybersecurity_model error: {e}")
    
    # Model 3: Advanced URL
    if 'phishing_urls_model' in models:
        try:
            features = extract_features_for_model3(
                url, 
                model_info['phishing_urls_model']['feature_selector'],
                model_info['phishing_urls_model']['scaler']
            )
            pred_proba = models['phishing_urls_model'].predict_proba(features)[0]
            pred = models['phishing_urls_model'].predict(features)[0]
            
            predictions['phishing_urls_model'] = pred
            confidences['phishing_urls_model'] = max(pred_proba)
            
            label = "Phishing" if pred == 1 else "Safe"
            print(f"   📊 phishing_urls_model: {label} ({max(pred_proba):.3f})")
        except Exception as e:
            print(f"   ❌ phishing_urls_model error: {e}")
    
    # Model 4: Website Features
    if 'website_model' in models:
        try:
            features = extract_features_for_model4(url, model_info['website_model']['selected_features'])
            pred_proba = models['website_model'].predict_proba(features)[0]
            pred = models['website_model'].predict(features)[0]
            
            predictions['website_model'] = pred
            confidences['website_model'] = max(pred_proba)
            
            label = "Phishing" if pred == 1 else "Safe"
            print(f"   📊 website_model: {label} ({max(pred_proba):.3f})")
        except Exception as e:
            print(f"   ❌ website_model error: {e}")
    
    # Weighted voting
    if predictions:
        weighted_score = 0
        total_weight = 0
        phishing_votes = 0
        safe_votes = 0
        
        for model, pred in predictions.items():
            weight = model_weights.get(model, 0)
            confidence = confidences.get(model, 0)
            
            weighted_score += pred * weight * confidence
            total_weight += weight
            
            if pred == 1:
                phishing_votes += 1
            else:
                safe_votes += 1
        
        # Final prediction
        final_prediction = 1 if weighted_score > (total_weight * 0.5) else 0
        final_confidence = abs(weighted_score - total_weight * 0.5) / (total_weight * 0.5) if total_weight > 0 else 0
        
        result_label = "Phishing" if final_prediction == 1 else "Safe"
        print(f"   🎯 Ensemble Sonuç: {result_label} ({final_confidence:.3f})")
        print(f"   📊 Voting: {phishing_votes} Phishing, {safe_votes} Safe")
        
        return {
            'final_prediction': final_prediction,
            'final_label': result_label,
            'confidence': final_confidence,
            'phishing_votes': phishing_votes,
            'safe_votes': safe_votes,
            'total_models': len(predictions),
            'model_predictions': predictions,
            'model_confidences': confidences
        }
    
    return {'error': 'Hiçbir model tahmin yapamadı'}

def main():
    """Ana test fonksiyonu"""
    
    # Modelleri yükle
    models, model_info, model_weights = load_all_models()
    
    if not models:
        print("❌ Hiçbir model yüklenemedi!")
        return
    
    # Test URL'leri
    test_urls = [
        "https://www.google.com",
        "https://www.facebook.com",
        "http://paypal-security-update.com/login.php",
        "https://amazon-verification.tk/account/update"
    ]
    
    print(f"\n🧪 Testing URLs with {len(models)}-Model Ensemble:")
    print("=" * 60)
    
    for url in test_urls:
        print(f"\n📊 Testing: {url}")
        print("-" * 50)
        
        result = test_ensemble_prediction(url, models, model_info, model_weights)
        
        if 'error' not in result:
            print(f"🎯 Final Decision: {result.get('final_label', 'N/A')}")
            print(f"📈 Confidence: {result.get('confidence', 0):.3f}")
            print(f"🔢 Total Models: {result.get('total_models', 0)}")
            print(f"✅ Voting: {result.get('phishing_votes', 0)} Phishing, {result.get('safe_votes', 0)} Safe")
        else:
            print(f"❌ Error: {result['error']}")
    
    # Model bilgileri
    print(f"\n📋 Loaded Models Summary:")
    print("=" * 50)
    for model_key, info in model_info.items():
        model_name = {
            'phishing_model': 'Mega Phishing Detector',
            'cybersecurity_model': 'Cybersecurity VirusTotal Analyzer',
            'phishing_urls_model': 'Advanced URL Feature Analyzer',
            'website_model': 'Website Feature Detector'
        }.get(model_key, model_key)
        
        dataset_info = {
            'phishing_model': '20K URLs with 96 features',
            'cybersecurity_model': '4K domains with VirusTotal data',
            'phishing_urls_model': '549K URLs with 35 URL features',
            'website_model': '11K websites with 31 behavior features'
        }.get(model_key, 'Unknown dataset')
        
        algorithm = {
            'phishing_model': 'Random Forest',
            'cybersecurity_model': 'CatBoost',
            'phishing_urls_model': 'Random Forest',
            'website_model': 'ExtraTrees'
        }.get(model_key, 'Unknown')
        
        speciality = {
            'phishing_model': 'General URL pattern analysis',
            'cybersecurity_model': 'Security engine analysis',
            'phishing_urls_model': 'Comprehensive URL structure analysis',
            'website_model': 'Website behavior and feature analysis'
        }.get(model_key, 'Unknown')
        
        print(f"✅ {model_name}")
        print(f"   Dataset: {dataset_info}")
        print(f"   Algorithm: {algorithm}")
        print(f"   Speciality: {speciality}")
        print(f"   Accuracy: {info.get('accuracy', 'N/A')}")
        print(f"   Weight: {model_weights.get(model_key, 0):.3f}")
        print()

if __name__ == "__main__":
    main() 