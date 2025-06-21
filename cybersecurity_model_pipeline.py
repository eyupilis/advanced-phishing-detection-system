import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import LabelEncoder, StandardScaler, OneHotEncoder
from sklearn.feature_selection import SelectKBest, f_classif, RFE
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score
import xgboost as xgb
import lightgbm as lgb
try:
    import catboost as cb
except ImportError:
    print("⚠️ CatBoost yüklü değil, pip install catboost ile yükleyebilirsiniz")
    cb = None

import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import shap
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class CybersecurityDetectorPipeline:
    """
    Cybersecurity veri seti için özel tasarlanmış ML Pipeline
    VirusTotal analiz sonuçlarından güvenilir/güvenilir değil sınıflandırması
    """
    
    def __init__(self):
        self.models = {}
        self.feature_encoders = {}
        self.scaler = StandardScaler()
        self.feature_selector = None
        self.selected_features = None
        self.label_encoder = LabelEncoder()
        self.feature_importance = {}
        self.model_performance = {}
        
    def load_and_preprocess_data(self, filepath):
        """Veri setini yükle ve ön işle"""
        
        print("🔄 Cybersecurity veri seti yükleniyor...")
        df = pd.read_csv(filepath)
        
        print(f"✅ Veri seti yüklendi: {df.shape}")
        
        # Hedef değişkeni belirle
        # white_list sütunu: 't' = güvenilir, 'f' = güvenilir değil
        if 'white_list' in df.columns:
            target_column = 'white_list'
        else:
            # Alternatif hedef değişken arayışı
            potential_targets = ['label', 'target', 'class', 'malicious']
            target_column = None
            for col in df.columns:
                if col.lower() in potential_targets:
                    target_column = col
                    break
            
            if target_column is None:
                print("❌ Hedef değişken bulunamadı!")
                return None, None
        
        print(f"🎯 Hedef değişken: {target_column}")
        
        # Veri ön işleme
        df_processed = self.preprocess_features(df, target_column)
        
        if df_processed is None:
            return None, None
            
        # Özellikler ve hedef değişkeni ayır
        X = df_processed.drop(target_column, axis=1)
        y = df_processed[target_column]
        
        print(f"📊 İşlenmiş veri boyutu: {X.shape}")
        print(f"🎯 Hedef dağılımı:")
        value_counts = y.value_counts()
        for value, count in value_counts.items():
            percentage = (count / len(y)) * 100
            print(f"   {value}: {count:,} ({percentage:.1f}%)")
        
        return X, y
    
    def preprocess_features(self, df, target_column):
        """Özellik mühendisliği ve veri temizleme"""
        
        print("🔧 Özellik mühendisliği başlıyor...")
        
        df_clean = df.copy()
        
        # 1. Gereksiz sütunları çıkar
        columns_to_drop = ['extracted_from', 'domain', 'data_extracted']
        existing_cols_to_drop = [col for col in columns_to_drop if col in df_clean.columns]
        if existing_cols_to_drop:
            df_clean = df_clean.drop(existing_cols_to_drop, axis=1)
            print(f"   Gereksiz sütunlar çıkarıldı: {existing_cols_to_drop}")
        
        # 2. Hedef değişkeni encode et
        if target_column in df_clean.columns:
            # 't' -> 1 (güvenilir), 'f' -> 0 (güvenilir değil)
            df_clean[target_column] = df_clean[target_column].map({'t': 1, 'f': 0})
            print(f"   Hedef değişken encode edildi: t->1, f->0")
        
        # 3. Eksik değerleri doldur
        print(f"   Eksik değer sayısı: {df_clean.isnull().sum().sum()}")
        
        # Sayısal sütunlar için medyan
        numeric_cols = df_clean.select_dtypes(include=[np.number]).columns
        for col in numeric_cols:
            if col != target_column and df_clean[col].isnull().sum() > 0:
                median_val = df_clean[col].median()
                df_clean[col].fillna(median_val, inplace=True)
        
        # Kategorik sütunlar için mod
        categorical_cols = df_clean.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            if col != target_column and df_clean[col].isnull().sum() > 0:
                mode_val = df_clean[col].mode()[0] if len(df_clean[col].mode()) > 0 else 'unknown'
                df_clean[col].fillna(mode_val, inplace=True)
        
        print(f"   Eksik değerler dolduruldu. Kalan eksik: {df_clean.isnull().sum().sum()}")
        
        # 4. Kategorik değişkenleri encode et
        categorical_cols = df_clean.select_dtypes(include=['object']).columns
        categorical_cols = [col for col in categorical_cols if col != target_column]
        
        if len(categorical_cols) > 0:
            print(f"   Kategorik sütunlar encode ediliyor: {categorical_cols}")
            
            for col in categorical_cols:
                # Çok fazla unique değer varsa, label encoding
                if df_clean[col].nunique() > 10:
                    le = LabelEncoder()
                    df_clean[col] = le.fit_transform(df_clean[col].astype(str))
                    self.feature_encoders[col] = le
                else:
                    # Az unique değer varsa, one-hot encoding
                    dummies = pd.get_dummies(df_clean[col], prefix=col)
                    df_clean = pd.concat([df_clean.drop(col, axis=1), dummies], axis=1)
        
        # 5. Boolean sütunları int'e çevir
        bool_cols = df_clean.select_dtypes(include=['bool']).columns
        for col in bool_cols:
            if col != target_column:
                df_clean[col] = df_clean[col].astype(int)
        
        # 6. Yeni özellikler oluştur
        print("   Yeni özellikler oluşturuluyor...")
        
        # Zararlı/zararsız oranı
        if 'last_analysis_stats_malicious' in df_clean.columns and 'last_analysis_stats_harmles' in df_clean.columns:
            df_clean['malicious_harmless_ratio'] = (
                df_clean['last_analysis_stats_malicious'] / 
                (df_clean['last_analysis_stats_harmles'] + 1)
            )
        
        # Toplam analiz puanı
        analysis_cols = [col for col in df_clean.columns if 'last_analysis_stats_' in col]
        if len(analysis_cols) > 0:
            df_clean['total_analysis_score'] = df_clean[analysis_cols].sum(axis=1)
        
        # Reputation kategorisi
        if 'reputation' in df_clean.columns:
            df_clean['reputation_category'] = pd.cut(
                df_clean['reputation'], 
                bins=[-np.inf, -10, 0, 10, np.inf], 
                labels=['very_bad', 'bad', 'neutral', 'good']
            )
            # Kategori değerlerini encode et
            df_clean['reputation_category'] = LabelEncoder().fit_transform(df_clean['reputation_category'])
        
        print(f"✅ Özellik mühendisliği tamamlandı. Final boyut: {df_clean.shape}")
        return df_clean
    
    def feature_selection(self, X, y, n_features=20):
        """En önemli özellikleri seç"""
        
        print(f"🔍 Özellik seçimi başlıyor... ({X.shape[1]} -> {n_features})")
        
        # SelectKBest ile ilk eleme
        selector = SelectKBest(score_func=f_classif, k=min(n_features * 2, X.shape[1]))
        X_selected = selector.fit_transform(X, y)
        selected_features_mask = selector.get_support()
        selected_features = X.columns[selected_features_mask].tolist()
        
        print(f"   SelectKBest ile {len(selected_features)} özellik seçildi")
        
        # Random Forest ile RFE
        rf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
        rfe = RFE(estimator=rf, n_features_to_select=n_features)
        X_rfe = rfe.fit_transform(X[selected_features], y)
        
        final_features = np.array(selected_features)[rfe.support_].tolist()
        
        self.selected_features = final_features
        self.feature_selector = rfe
        
        print(f"✅ Final seçilen özellikler ({len(final_features)} adet):")
        for i, feature in enumerate(final_features, 1):
            print(f"   {i:2d}. {feature}")
        
        return X[final_features]
    
    def train_models(self, X, y):
        """Birden fazla model eğit"""
        
        print("🤖 Model eğitimi başlıyor...")
        
        # Veri setini böl
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"📊 Eğitim seti: {X_train.shape}, Test seti: {X_test.shape}")
        
        # Model tanımları
        models_to_train = {
            'RandomForest': RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            ),
            'XGBoost': xgb.XGBClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                eval_metric='logloss'
            ),
            'LightGBM': lgb.LGBMClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                verbose=-1
            )
        }
        
        # CatBoost ekle (eğer yüklüyse)
        if cb is not None:
            models_to_train['CatBoost'] = cb.CatBoostClassifier(
                iterations=200,
                depth=6,
                learning_rate=0.1,
                random_seed=42,
                verbose=False
            )
        
        # Modelleri eğit ve değerlendir
        for name, model in models_to_train.items():
            print(f"\n🔄 {name} eğitiliyor...")
            
            try:
                # Model eğitimi
                model.fit(X_train, y_train)
                
                # Tahminler
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)[:, 1]
                
                # Performans metrikleri
                accuracy = accuracy_score(y_test, y_pred)
                auc_score = roc_auc_score(y_test, y_pred_proba)
                
                # Cross validation
                cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')
                
                # Sonuçları kaydet
                self.models[name] = model
                self.model_performance[name] = {
                    'accuracy': accuracy,
                    'auc_score': auc_score,
                    'cv_mean': cv_scores.mean(),
                    'cv_std': cv_scores.std(),
                    'classification_report': classification_report(y_test, y_pred)
                }
                
                print(f"   ✅ {name} tamamlandı:")
                print(f"      Accuracy: {accuracy:.4f}")
                print(f"      AUC Score: {auc_score:.4f}")
                print(f"      CV Score: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
                
                # Feature importance (varsa)
                if hasattr(model, 'feature_importances_'):
                    importance = model.feature_importances_
                    feature_importance_df = pd.DataFrame({
                        'feature': X.columns,
                        'importance': importance
                    }).sort_values('importance', ascending=False)
                    
                    self.feature_importance[name] = feature_importance_df
                
            except Exception as e:
                print(f"   ❌ {name} eğitiminde hata: {e}")
        
        # En iyi modeli seç
        if self.model_performance:
            best_model_name = max(
                self.model_performance.keys(),
                key=lambda x: self.model_performance[x]['auc_score']
            )
            
            print(f"\n🏆 EN İYİ MODEL: {best_model_name}")
            print(f"   AUC Score: {self.model_performance[best_model_name]['auc_score']:.4f}")
            
            return X_test, y_test, best_model_name
        
        return None, None, None
    
    def generate_shap_analysis(self, X_test, model_name):
        """SHAP analizi oluştur"""
        
        if model_name not in self.models:
            print(f"❌ Model bulunamadı: {model_name}")
            return
        
        print(f"🔍 {model_name} için SHAP analizi oluşturuluyor...")
        
        try:
            model = self.models[model_name]
            
            # SHAP explainer oluştur
            explainer = shap.TreeExplainer(model)
            shap_values = explainer.shap_values(X_test.iloc[:100])  # İlk 100 örnek
            
            # SHAP summary plot
            plt.figure(figsize=(12, 8))
            if len(shap_values) == 2:  # Binary classification
                shap.summary_plot(shap_values[1], X_test.iloc[:100], show=False)
            else:
                shap.summary_plot(shap_values, X_test.iloc[:100], show=False)
            
            plt.title(f'SHAP Feature Importance - {model_name}')
            plt.tight_layout()
            plt.savefig(f'cybersecurity_shap_analysis_{model_name.lower()}.png', dpi=300, bbox_inches='tight')
            plt.close()
            
            print(f"   ✅ SHAP analizi kaydedildi: cybersecurity_shap_analysis_{model_name.lower()}.png")
            
        except Exception as e:
            print(f"   ❌ SHAP analizi hatası: {e}")
    
    def save_model(self, model_name, filepath_prefix="cybersecurity_model"):
        """En iyi modeli kaydet"""
        
        if model_name not in self.models:
            print(f"❌ Model bulunamadı: {model_name}")
            return
        
        print(f"💾 {model_name} kaydediliyor...")
        
        # Model kaydet
        model_path = f"{filepath_prefix}_{model_name.lower()}.pkl"
        joblib.dump(self.models[model_name], model_path)
        
        # Model bilgileri kaydet
        model_info = {
            'model_name': model_name,
            'performance': self.model_performance[model_name],
            'selected_features': self.selected_features,
            'feature_encoders': self.feature_encoders,
            'training_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'feature_importance': self.feature_importance.get(model_name, {}).to_dict() if model_name in self.feature_importance else {}
        }
        
        info_path = f"{filepath_prefix}_{model_name.lower()}_info.pkl"
        joblib.dump(model_info, info_path)
        
        # Feature importance kaydet
        if model_name in self.feature_importance:
            importance_path = f"{filepath_prefix}_{model_name.lower()}_feature_importance.csv"
            self.feature_importance[model_name].to_csv(importance_path, index=False)
        
        print(f"   ✅ Model kaydedildi:")
        print(f"      Model: {model_path}")
        print(f"      Info: {info_path}")
        if model_name in self.feature_importance:
            print(f"      Feature Importance: {importance_path}")
    
    def print_performance_summary(self):
        """Model performanslarını özetle"""
        
        if not self.model_performance:
            print("❌ Henüz model eğitilmedi!")
            return
        
        print("\n" + "="*80)
        print("📊 CYBERSECURITY MODEL PERFORMANS ÖZETİ")
        print("="*80)
        
        # Performans tablosu
        performance_df = pd.DataFrame({
            model_name: {
                'Accuracy': f"{metrics['accuracy']:.4f}",
                'AUC Score': f"{metrics['auc_score']:.4f}",
                'CV Mean': f"{metrics['cv_mean']:.4f}",
                'CV Std': f"{metrics['cv_std']:.4f}"
            }
            for model_name, metrics in self.model_performance.items()
        }).T
        
        print(performance_df.to_string())
        
        # En iyi model
        best_model = max(
            self.model_performance.keys(),
            key=lambda x: self.model_performance[x]['auc_score']
        )
        
        print(f"\n🏆 EN İYİ MODEL: {best_model}")
        print(f"   AUC Score: {self.model_performance[best_model]['auc_score']:.4f}")
        print(f"   Accuracy: {self.model_performance[best_model]['accuracy']:.4f}")

def main():
    """Ana fonksiyon"""
    
    print("🚀 CYBERSECURITY PHISHING DETECTOR - MODEL EĞİTİMİ")
    print("="*60)
    
    # Pipeline oluştur
    pipeline = CybersecurityDetectorPipeline()
    
    # Veri yükle ve ön işle
    X, y = pipeline.load_and_preprocess_data('cybersecurity_dataset.csv')
    
    if X is None or y is None:
        print("❌ Veri yükleme başarısız!")
        return
    
    # Özellik seçimi
    X_selected = pipeline.feature_selection(X, y, n_features=15)
    
    # Modelleri eğit
    X_test, y_test, best_model = pipeline.train_models(X_selected, y)
    
    if best_model:
        # SHAP analizi
        pipeline.generate_shap_analysis(X_test, best_model)
        
        # Modeli kaydet
        pipeline.save_model(best_model)
        
        # Performans özeti
        pipeline.print_performance_summary()
        
        print(f"\n✅ Model eğitimi tamamlandı!")
        print(f"🎯 En iyi model: {best_model}")
        print(f"📁 Model dosyaları: cybersecurity_model_{best_model.lower()}.pkl")
        
    else:
        print("❌ Model eğitimi başarısız!")

if __name__ == "__main__":
    main() 