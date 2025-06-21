import pandas as pd
import numpy as np
import re
import pickle
import joblib
import os
from urllib.parse import urlparse, unquote
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                           f1_score, roc_auc_score, classification_report, confusion_matrix)
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_selection import SelectKBest, chi2, RFE
import xgboost as xgb
import lightgbm as lgb
from catboost import CatBoostClassifier
import matplotlib.pyplot as plt
import seaborn as sns
import tldextract
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

class PhishingURLsDetectorPipeline:
    """
    Advanced Phishing URLs Detection Pipeline
    Extracts comprehensive features from URLs and builds high-performance models
    """
    
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_selector = None
        self.feature_names = []
        self.model_performance = {}
        
    def extract_url_features(self, url):
        """Extract comprehensive features from a single URL"""
        features = {}
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path
            query = parsed_url.query
            fragment = parsed_url.fragment
            
            # Extract TLD info
            tld_info = tldextract.extract(url)
            
            # Basic URL features
            features['url_length'] = len(url)
            features['domain_length'] = len(domain)
            features['path_length'] = len(path)
            features['query_length'] = len(query)
            features['fragment_length'] = len(fragment)
            
            # Domain features
            features['subdomain_count'] = len(tld_info.subdomain.split('.')) if tld_info.subdomain else 0
            features['domain_has_digits'] = int(bool(re.search(r'\d', domain)))
            features['domain_has_hyphen'] = int('-' in domain)
            features['domain_has_underscore'] = int('_' in domain)
            
            # TLD features
            features['tld_length'] = len(tld_info.suffix) if tld_info.suffix else 0
            features['is_common_tld'] = int(tld_info.suffix in ['com', 'org', 'net', 'edu', 'gov'])
            
            # Suspicious patterns
            features['has_ip_address'] = int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))
            features['has_suspicious_words'] = int(bool(re.search(
                r'(paypal|ebay|amazon|apple|microsoft|google|facebook|bank|secure|account|update|verify|login|signin)',
                url.lower()
            )))
            
            # Character analysis
            features['dot_count'] = url.count('.')
            features['slash_count'] = url.count('/')
            features['question_count'] = url.count('?')
            features['equal_count'] = url.count('=')
            features['ampersand_count'] = url.count('&')
            features['hyphen_count'] = url.count('-')
            features['underscore_count'] = url.count('_')
            features['percent_count'] = url.count('%')
            features['at_count'] = url.count('@')
            
            # Protocol features
            features['is_https'] = int(parsed_url.scheme == 'https')
            features['has_www'] = int(domain.startswith('www.'))
            
            # URL encoding
            features['has_url_encoding'] = int('%' in url)
            features['url_encoding_count'] = len(re.findall(r'%[0-9a-fA-F]{2}', url))
            
            # Suspicious characters
            features['has_suspicious_chars'] = int(bool(re.search(r'[<>"\'\{\}|\\^`\[\]]', url)))
            
            # Path analysis
            features['path_depth'] = len([x for x in path.split('/') if x])
            features['path_has_extension'] = int(bool(re.search(r'\.[a-zA-Z]{2,4}$', path)))
            
            # Query parameters
            features['query_param_count'] = len(query.split('&')) if query else 0
            
            # Domain reputation indicators
            features['domain_entropy'] = self._calculate_entropy(domain)
            features['url_entropy'] = self._calculate_entropy(url)
            
            # Hexadecimal patterns
            features['hex_pattern_count'] = len(re.findall(r'[0-9a-fA-F]{8,}', url))
            
            # Consecutive characters
            features['max_consecutive_digits'] = self._max_consecutive_chars(url, r'\d')
            features['max_consecutive_letters'] = self._max_consecutive_chars(url, r'[a-zA-Z]')
            
        except Exception as e:
            print(f"Error extracting features from URL: {url[:50]}... - {str(e)}")
            # Return default features in case of error
            return {f'feature_{i}': 0 for i in range(30)}
            
        return features
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        counter = Counter(text)
        length = len(text)
        entropy = 0
        for count in counter.values():
            p = count / length
            entropy -= p * np.log2(p)
        return entropy
    
    def _max_consecutive_chars(self, text, pattern):
        """Find maximum consecutive characters matching pattern"""
        matches = re.findall(f'({pattern})+', text)
        return max([len(match) for match in matches]) if matches else 0
    
    def prepare_features(self, df):
        """Extract features from all URLs in dataframe"""
        print("🔍 Extracting URL features...")
        
        # Extract features for all URLs
        features_list = []
        for idx, url in enumerate(df['URL']):
            if idx % 10000 == 0:
                print(f"  Processed {idx}/{len(df)} URLs...")
            features = self.extract_url_features(url)
            features_list.append(features)
        
        # Convert to DataFrame
        features_df = pd.DataFrame(features_list)
        
        # Store feature names
        self.feature_names = list(features_df.columns)
        
        print(f"✅ Extracted {len(self.feature_names)} features from {len(df)} URLs")
        
        return features_df
    
    def train_models(self, X, y):
        """Train and evaluate multiple models"""
        print("🤖 Training multiple models...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Keep both numeric and string versions
        y_train_numeric = y_train
        y_test_numeric = y_test
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Define models
        models = {
            'RandomForest': RandomForestClassifier(n_estimators=100, random_state=42),
            'ExtraTrees': ExtraTreesClassifier(n_estimators=100, random_state=42),
            'XGBoost': xgb.XGBClassifier(random_state=42, eval_metric='logloss'),
            'LightGBM': lgb.LGBMClassifier(random_state=42, verbose=-1),
            'CatBoost': CatBoostClassifier(random_state=42, verbose=False),
            'LogisticRegression': LogisticRegression(random_state=42, max_iter=1000),
        }
        
        best_score = 0
        best_model_name = ""
        
        # Train and evaluate each model
        for name, model in models.items():
            print(f"\n📊 Training {name}...")
            
            # Use scaled data for linear models
            if name in ['LogisticRegression']:
                X_train_model = X_train_scaled
                X_test_model = X_test_scaled
            else:
                X_train_model = X_train
                X_test_model = X_test
            
            # Train model with numeric labels
            model.fit(X_train_model, y_train_numeric)
            y_pred = model.predict(X_test_model)
            y_prob = model.predict_proba(X_test_model)[:, 1]
            
            # Calculate metrics with numeric labels (0=bad, 1=good)
            accuracy = accuracy_score(y_test_numeric, y_pred)
            precision = precision_score(y_test_numeric, y_pred, pos_label=0)  # bad=0
            recall = recall_score(y_test_numeric, y_pred, pos_label=0)  # bad=0
            f1 = f1_score(y_test_numeric, y_pred, pos_label=0)  # bad=0
            auc = roc_auc_score(y_test_numeric, y_prob)
            
            # Cross-validation with numeric labels
            cv_scores = cross_val_score(model, X_train_model, y_train_numeric, cv=5, scoring='accuracy')
            
            # Store results
            self.model_performance[name] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'auc_score': auc,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std()
            }
            
            print(f"  Accuracy: {accuracy:.4f}")
            print(f"  Precision: {precision:.4f}")
            print(f"  Recall: {recall:.4f}")
            print(f"  F1-Score: {f1:.4f}")
            print(f"  AUC: {auc:.4f}")
            print(f"  CV Score: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
            
            # Track best model
            if accuracy > best_score:
                best_score = accuracy
                best_model_name = name
                self.model = model
        
        print(f"\n🏆 Best model: {best_model_name} with accuracy: {best_score:.4f}")
        
        return X_test, y_test_numeric
    
    def feature_selection(self, X, y, k=25):
        """Select top k features"""
        print(f"🎯 Selecting top {k} features...")
        
        # Use SelectKBest with chi2
        selector = SelectKBest(chi2, k=k)
        X_selected = selector.fit_transform(X, y)
        
        # Get selected feature names
        selected_indices = selector.get_support(indices=True)
        selected_features = [self.feature_names[i] for i in selected_indices]
        
        self.feature_selector = selector
        
        print(f"✅ Selected features: {selected_features}")
        
        return X_selected, selected_features
    
    def save_model(self, model_name="phishing_urls_model"):
        """Save the trained model and components"""
        print(f"💾 Saving model as {model_name}...")
        
        # Save model
        joblib.dump(self.model, f'{model_name}.pkl')
        
        # Save other components
        joblib.dump(self.scaler, f'{model_name}_scaler.pkl')
        joblib.dump(self.label_encoder, f'{model_name}_label_encoder.pkl')
        if self.feature_selector:
            joblib.dump(self.feature_selector, f'{model_name}_feature_selector.pkl')
        
        # Save feature names and performance
        model_info = {
            'feature_names': self.feature_names,
            'model_performance': self.model_performance,
            'model_type': type(self.model).__name__
        }
        
        with open(f'{model_name}_info.pkl', 'wb') as f:
            pickle.dump(model_info, f)
        
        print(f"✅ Model saved successfully!")
    
    def load_model(self, model_name="phishing_urls_model"):
        """Load a saved model"""
        print(f"📂 Loading model {model_name}...")
        
        self.model = joblib.load(f'{model_name}.pkl')
        self.scaler = joblib.load(f'{model_name}_scaler.pkl')
        self.label_encoder = joblib.load(f'{model_name}_label_encoder.pkl')
        
        if os.path.exists(f'{model_name}_feature_selector.pkl'):
            self.feature_selector = joblib.load(f'{model_name}_feature_selector.pkl')
        
        with open(f'{model_name}_info.pkl', 'rb') as f:
            model_info = pickle.load(f)
            self.feature_names = model_info['feature_names']
            self.model_performance = model_info['model_performance']
        
        print(f"✅ Model loaded successfully!")
    
    def predict_url(self, url):
        """Predict if a single URL is phishing or not"""
        # Extract features
        features = self.extract_url_features(url)
        feature_vector = np.array([features[name] for name in self.feature_names]).reshape(1, -1)
        
        # Apply feature selection if available
        if self.feature_selector:
            feature_vector = self.feature_selector.transform(feature_vector)
        
        # Scale if needed
        if hasattr(self.model, 'coef_'):  # Linear models
            feature_vector = self.scaler.transform(feature_vector)
        
        # Predict
        prediction = self.model.predict(feature_vector)[0]
        probability = self.model.predict_proba(feature_vector)[0]
        
        return {
            'prediction': prediction,
            'probability_good': probability[0] if prediction == 'good' else probability[1],
            'probability_bad': probability[1] if prediction == 'bad' else probability[0],
            'confidence': max(probability)
        }

def main():
    """Main pipeline execution"""
    print("🚀 Starting Phishing URLs Model Pipeline")
    
    # Load dataset
    print("📊 Loading dataset...")
    df = pd.read_csv('phishing_urls_dataset.csv')
    print(f"Dataset shape: {df.shape}")
    
    # Initialize pipeline
    pipeline = PhishingURLsDetectorPipeline()
    
    # Prepare features
    X = pipeline.prepare_features(df)
    y = df['Label']
    
    # Encode labels
    y_encoded = pipeline.label_encoder.fit_transform(y)
    
    # Feature selection
    X_selected, selected_features = pipeline.feature_selection(X, y_encoded, k=25)
    
    # Train models
    X_test, y_test = pipeline.train_models(X_selected, y_encoded)
    
    # Save model
    pipeline.save_model("phishing_urls_model_best")
    
    # Test on sample URLs
    print("\n🧪 Testing on sample URLs...")
    test_urls = [
        "https://www.google.com",
        "https://www.facebook.com", 
        "http://paypal-security-update.com/login.php",
        "https://amazon-verification.tk/account/update"
    ]
    
    for url in test_urls:
        result = pipeline.predict_url(url)
        print(f"URL: {url[:50]}...")
        print(f"  Prediction: {result['prediction']} (confidence: {result['confidence']:.3f})")

if __name__ == "__main__":
    main() 