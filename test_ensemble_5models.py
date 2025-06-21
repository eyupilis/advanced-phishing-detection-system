#!/usr/bin/env python3
"""
5 Modelli Ensemble Test - Cryptocurrency Scam Model Dahil
Test: Tüm 5 modelin başarıyla yüklenip çalıştığını doğrula
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ensemble_phishing_detector import EnsemblePhishingDetector
from cryptocurrency_scam_model_pipeline import CryptocurrencyScamDetectorPipeline

def test_individual_models():
    """Her modeli ayrı ayrı test et"""
    print("🧪 INDIVIDUAL MODEL TESTS")
    print("=" * 50)
    
    # Test URL'leri
    test_urls = [
        "https://www.google.com",
        "http://myetherwallett.com",  # Phishing
        "https://dlsneykonto-login.com",  # Scam
        "http://crypto-scam-exchange.tk"  # Crypto scam
    ]
    
    # 1. Mega Phishing Model Test
    print("🔍 1. Mega Phishing Model Test:")
    try:
        from ml_pipeline import PhishingDetectorPipeline
        mega_model = PhishingDetectorPipeline()
        mega_model.load_model()
        
        for url in test_urls:
            result = mega_model.predict(url)
            print(f"   {url}: {result['prediction']} ({result['confidence']:.3f})")
        print("   ✅ Mega Phishing Model - OK")
    except Exception as e:
        print(f"   ❌ Mega Phishing Model Error: {e}")
    
    # 2. Cybersecurity Model Test
    print("\n🔍 2. Cybersecurity Model Test:")
    try:
        from cybersecurity_model_pipeline import CybersecurityDetectorPipeline
        cyber_model = CybersecurityDetectorPipeline()
        cyber_model.load_model()
        
        for url in test_urls:
            result = cyber_model.predict(url)
            print(f"   {url}: {result['prediction']} ({result['confidence']:.3f})")
        print("   ✅ Cybersecurity Model - OK")
    except Exception as e:
        print(f"   ❌ Cybersecurity Model Error: {e}")
    
    # 3. Advanced URL Feature Model Test
    print("\n🔍 3. Advanced URL Feature Model Test:")
    try:
        from phishing_urls_model_pipeline import PhishingURLsDetectorPipeline
        url_model = PhishingURLsDetectorPipeline()
        url_model.load_model()
        
        for url in test_urls:
            result = url_model.predict(url)
            print(f"   {url}: {result['prediction']} ({result['confidence']:.3f})")
        print("   ✅ Advanced URL Model - OK")
    except Exception as e:
        print(f"   ❌ Advanced URL Model Error: {e}")
    
    # 4. Website Feature Model Test
    print("\n🔍 4. Website Feature Model Test:")
    try:
        from phishing_website_model_pipeline import PhishingWebsiteDetectorPipeline
        website_model = PhishingWebsiteDetectorPipeline()
        website_model.load_model()
        
        for url in test_urls:
            result = website_model.predict(url)
            print(f"   {url}: {result['prediction']} ({result['confidence']:.3f})")
        print("   ✅ Website Feature Model - OK")
    except Exception as e:
        print(f"   ❌ Website Feature Model Error: {e}")
    
    # 5. NEW: Cryptocurrency Scam Model Test
    print("\n🔍 5. 🆕 Cryptocurrency Scam Model Test:")
    try:
        crypto_model = CryptocurrencyScamDetectorPipeline()
        crypto_model.load_model()
        
        for url in test_urls:
            result = crypto_model.predict(url)
            print(f"   {url}: {result['predicted_category']} ({result['confidence']:.3f})")
        print("   ✅ Cryptocurrency Scam Model - OK")
    except Exception as e:
        print(f"   ❌ Cryptocurrency Scam Model Error: {e}")

def test_5model_ensemble():
    """5 Modelli Ensemble Test"""
    print("\n\n🎯 5-MODEL ENSEMBLE TEST")
    print("=" * 50)
    
    test_cases = [
        {
            'url': 'https://www.google.com',
            'description': 'Safe Google site'
        },
        {
            'url': 'https://www.facebook.com', 
            'description': 'Safe Facebook site'
        },
        {
            'url': 'http://myetherwallett.com',
            'description': 'Typosquatting MyEtherWallet phishing'
        },
        {
            'url': 'https://dlsneykonto-login.com',
            'description': 'Disney account phishing scam'
        },
        {
            'url': 'http://crypto-scam-exchange.tk',
            'description': 'Cryptocurrency scam exchange'
        },
        {
            'url': 'https://update-metamask-security.com',
            'description': 'Fake MetaMask security update'
        }
    ]
    
    print("🔄 Ensemble system başlatılıyor...")
    try:
        ensemble = EnsemblePhishingDetector()
        print("✅ Ensemble system yüklendi!")
        
        print(f"\n📊 Test Sonuçları:")
        print("-" * 80)
        
        for i, test_case in enumerate(test_cases, 1):
            url = test_case['url']
            description = test_case['description']
            
            print(f"\n{i}. Test - {description}")
            print(f"   🔗 URL: {url}")
            
            try:
                result = ensemble.analyze_url(url)
                
                print(f"   🎯 Ensemble Result: {result['ensemble_prediction']} ({result['ensemble_confidence']:.3f})")
                print(f"   📊 Voting: {result['phishing_votes']} Phishing, {result['safe_votes']} Safe")
                
                print(f"   📋 Individual Results:")
                for model_name, model_result in result['individual_results'].items():
                    pred = model_result['prediction']
                    conf = model_result['confidence']
                    print(f"     {model_name}: {pred} ({conf:.3f})")
                
            except Exception as e:
                print(f"   ❌ Analysis Error: {e}")
                
    except Exception as e:
        print(f"❌ Ensemble system error: {e}")

def main():
    """Ana test fonksiyonu"""
    print("🚀 5-MODEL ENSEMBLE SYSTEM TEST")
    print("🔥 Cryptocurrency Scam Model Dahil!")
    print("=" * 60)
    
    # Individual model tests
    test_individual_models()
    
    # Ensemble test
    test_5model_ensemble()
    
    print("\n" + "=" * 60)
    print("✅ Test tamamlandı!")
    print("💡 Artık 5 modelli ensemble sistem hazır!")

if __name__ == "__main__":
    main() 