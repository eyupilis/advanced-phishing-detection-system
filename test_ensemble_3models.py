from ensemble_phishing_detector import EnsemblePhishingDetector

def test_ensemble_with_three_models():
    print("🚀 Testing 3-Model Ensemble System")
    print("=" * 50)
    
    # Initialize ensemble
    ensemble = EnsemblePhishingDetector()
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "https://www.facebook.com",
        "http://paypal-security-update.com/login.php",
        "https://amazon-verification.tk/account/update"
    ]
    
    for url in test_urls:
        print(f"\n📊 Testing: {url}")
        print("-" * 50)
        
        try:
            result = ensemble.predict_ensemble(url)
            
            if 'error' in result:
                print(f"❌ Error: {result['error']}")
                continue
            
            print(f"🎯 Final Decision: {result.get('final_prediction_label', 'N/A')}")
            print(f"📈 Confidence: {result.get('final_confidence', 0):.3f}")
            print(f"🔢 Total Models: {result.get('total_models', 0)}")
            print(f"✅ Active Models: {result.get('active_models', 0)}")
            
            # Voting details
            if 'voting_details' in result:
                voting = result['voting_details']
                print(f"🗳️  Safe Votes: {voting.get('safe_votes', 0)}")
                print(f"⚠️  Phishing Votes: {voting.get('phishing_votes', 0)}")
            
            # Individual model results
            if 'model_predictions' in result:
                print("📋 Individual Model Results:")
                for model_name, pred in result['model_predictions'].items():
                    model_info = ensemble.model_info.get(model_name, {})
                    print(f"   {model_info.get('name', model_name)}: {pred['prediction_label']} ({pred['confidence']:.3f})")
        
        except Exception as e:
            print(f"❌ Test failed: {e}")
    
    # Model info summary
    print(f"\n📋 Loaded Models Summary:")
    print("=" * 50)
    for model_name, info in ensemble.model_info.items():
        if model_name in ensemble.models:
            print(f"✅ {info['name']}")
            print(f"   Dataset: {info['dataset']}")
            print(f"   Algorithm: {info['algorithm']}")
            print(f"   Speciality: {info['speciality']}")
            
            # Performance info
            if model_name in ensemble.model_performance:
                perf = ensemble.model_performance[model_name]
                print(f"   Accuracy: {perf.get('accuracy', 'N/A')}")
                print(f"   Weight: {ensemble.model_weights.get(model_name, 'N/A'):.3f}")
            print()

if __name__ == "__main__":
    test_ensemble_with_three_models() 