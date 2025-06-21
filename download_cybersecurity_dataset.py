import kagglehub
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import os

def download_and_analyze_cybersecurity_dataset():
    """Cybersecurity veri setini indir ve analiz et"""
    
    print("🔄 Cybersecurity veri seti indiriliyor...")
    
    # Download latest version
    path = kagglehub.dataset_download("macisalvsalv/cybersecurity-dataset")
    print(f"📁 Path to dataset files: {path}")
    
    # Klasördeki dosyaları listele
    dataset_path = Path(path)
    files = list(dataset_path.glob("*"))
    print(f"\n📋 Bulunan dosyalar:")
    for file in files:
        print(f"   - {file.name} ({file.stat().st_size / 1024 / 1024:.2f} MB)")
    
    # CSV dosyalarını bul
    csv_files = list(dataset_path.glob("*.csv"))
    
    if not csv_files:
        print("❌ CSV dosyası bulunamadı!")
        return None
    
    # İlk CSV dosyasını yükle
    main_csv = csv_files[0]
    print(f"\n📊 Ana dosya analiz ediliyor: {main_csv.name}")
    
    # Veri setini yükle
    try:
        df = pd.read_csv(main_csv)
        print(f"✅ Veri seti başarıyla yüklendi: {df.shape}")
        
        # Temel analiz
        analyze_dataset(df, "Cybersecurity Dataset")
        
        # Veri setini proje klasörüne kopyala
        local_path = f"cybersecurity_dataset.csv"
        df.to_csv(local_path, index=False)
        print(f"💾 Veri seti yerel olarak kaydedildi: {local_path}")
        
        return df
        
    except Exception as e:
        print(f"❌ Veri seti yüklenirken hata: {e}")
        return None

def analyze_dataset(df, dataset_name):
    """Veri setini detaylı analiz et"""
    
    print(f"\n{'='*60}")
    print(f"📊 {dataset_name.upper()} ANALİZİ")
    print(f"{'='*60}")
    
    # Temel bilgiler
    print(f"\n🔍 TEMEL BİLGİLER:")
    print(f"   Satır sayısı: {df.shape[0]:,}")
    print(f"   Sütun sayısı: {df.shape[1]:,}")
    print(f"   Eksik değer sayısı: {df.isnull().sum().sum():,}")
    print(f"   Bellek kullanımı: {df.memory_usage().sum() / 1024 / 1024:.2f} MB")
    
    # Sütun isimleri ve tipleri
    print(f"\n📋 SÜTUNLAR ({len(df.columns)} adet):")
    for idx, col in enumerate(df.columns, 1):
        null_count = df[col].isnull().sum()
        dtype = df[col].dtype
        unique_count = df[col].nunique()
        print(f"   {idx:2d}. {col:25s} | {str(dtype):10s} | Null: {null_count:6,} | Unique: {unique_count:6,}")
    
    # İlk birkaç satırı göster
    print(f"\n👀 İLK 3 SATIR:")
    print(df.head(3).to_string())
    
    # Hedef değişkenini tespit et
    potential_targets = ['label', 'target', 'class', 'y', 'prediction', 'result', 'output', 'category', 'type']
    target_column = None
    
    for col in df.columns:
        col_lower = col.lower()
        if any(target in col_lower for target in potential_targets):
            target_column = col
            break
    
    if target_column is None:
        # En az unique değere sahip sütunu hedef olarak varsay
        categorical_cols = df.select_dtypes(include=['object', 'category']).columns
        if len(categorical_cols) > 0:
            unique_counts = {col: df[col].nunique() for col in categorical_cols}
            target_column = min(unique_counts, key=unique_counts.get)
    
    if target_column:
        print(f"\n🎯 HEDEF DEĞİŞKEN: {target_column}")
        value_counts = df[target_column].value_counts()
        print("   Dağılım:")
        for value, count in value_counts.items():
            percentage = (count / len(df)) * 100
            print(f"     {value}: {count:,} ({percentage:.1f}%)")
        
        # Dengesizlik kontrolü
        if len(value_counts) == 2:
            ratio = value_counts.max() / value_counts.min()
            if ratio > 1.5:
                print(f"   ⚠️ Sınıf dengesizliği var! Oran: {ratio:.2f}:1")
            else:
                print(f"   ✅ Sınıflar dengeli! Oran: {ratio:.2f}:1")
    
    # Sayısal sütunlar analizi
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols) > 0:
        print(f"\n🔢 SAYISAL SÜTUNLAR ({len(numeric_cols)} adet):")
        print(df[numeric_cols].describe().round(2).to_string())
    
    # Kategorik sütunlar analizi
    categorical_cols = df.select_dtypes(include=['object', 'category']).columns
    if len(categorical_cols) > 0:
        print(f"\n📝 KATEGORİK SÜTUNLAR ({len(categorical_cols)} adet):")
        for col in categorical_cols:
            unique_count = df[col].nunique()
            print(f"   {col}: {unique_count} unique değer")
            if unique_count <= 10:
                print(f"     Değerler: {list(df[col].unique())}")
    
    # Korelasyon analizi (sayısal sütunlar için)
    if len(numeric_cols) > 1:
        print(f"\n🔗 KORELASYON ANALİZİ:")
        correlation_matrix = df[numeric_cols].corr()
        
        # En yüksek korelasyonları bul
        correlation_pairs = []
        for i in range(len(correlation_matrix.columns)):
            for j in range(i+1, len(correlation_matrix.columns)):
                col1 = correlation_matrix.columns[i]
                col2 = correlation_matrix.columns[j]
                corr_value = correlation_matrix.iloc[i, j]
                if abs(corr_value) > 0.5:  # Yüksek korelasyon
                    correlation_pairs.append((col1, col2, corr_value))
        
        if correlation_pairs:
            correlation_pairs.sort(key=lambda x: abs(x[2]), reverse=True)
            print("   Yüksek korelasyonlar (>0.5):")
            for col1, col2, corr in correlation_pairs[:5]:
                print(f"     {col1} - {col2}: {corr:.3f}")
        else:
            print("   Yüksek korelasyon bulunamadı")
    
    return target_column

def suggest_algorithms(df, target_column):
    """Veri setine uygun algoritmaları öner"""
    
    print(f"\n🤖 ALGORITHM ÖNERİLERİ:")
    print("="*40)
    
    n_samples = len(df)
    n_features = len(df.columns) - 1 if target_column else len(df.columns)
    
    # Hedef değişken analizi
    if target_column:
        unique_targets = df[target_column].nunique()
        is_binary = unique_targets == 2
        is_balanced = True
        
        if is_binary:
            value_counts = df[target_column].value_counts()
            ratio = value_counts.max() / value_counts.min()
            is_balanced = ratio <= 1.5
    else:
        is_binary = None
        is_balanced = None
    
    suggestions = []
    
    # Veri boyutuna göre öneriler
    if n_samples < 1000:
        suggestions.append("🔸 **Naive Bayes** - Az veri için ideal")
        suggestions.append("🔸 **SVM** - Küçük veri setleri için etkili")
        suggestions.append("🔸 **Logistic Regression** - Basit ve etkili")
    elif n_samples < 10000:
        suggestions.append("🔸 **Random Forest** - Orta boyut için mükemmel")
        suggestions.append("🔸 **XGBoost** - Yüksek performans")
        suggestions.append("🔸 **LightGBM** - Hızlı ve etkili")
    else:
        suggestions.append("🔸 **LightGBM** - Büyük veri için optimize")
        suggestions.append("🔸 **CatBoost** - Kategorik veriler için")
        suggestions.append("🔸 **XGBoost** - Ensemble learning")
    
    # Özellik sayısına göre
    if n_features > 100:
        suggestions.append("🔸 **Feature Selection** gerekli olabilir")
        suggestions.append("🔸 **Dimensionality Reduction** (PCA)")
    
    # Dengesizlik durumuna göre
    if not is_balanced:
        suggestions.append("🔸 **SMOTE** - Dengesizlik için")
        suggestions.append("🔸 **Class Weight** ayarları")
        suggestions.append("🔸 **Ensemble Methods** dengesizlik için")
    
    # Veri tiplerine göre
    categorical_cols = df.select_dtypes(include=['object', 'category']).columns
    if len(categorical_cols) > 0:
        suggestions.append("🔸 **CatBoost** - Kategorik veriler için özel")
        suggestions.append("🔸 **Target Encoding** kategorik veriler için")
    
    print("\n📋 En Uygun Algoritmalar:")
    for suggestion in suggestions:
        print(f"   {suggestion}")
    
    # Önerilen algoritma sıralaması
    recommended_algorithms = []
    
    if is_binary:
        if n_samples < 10000:
            recommended_algorithms = ['RandomForest', 'XGBoost', 'LightGBM', 'SVM', 'LogisticRegression']
        else:
            recommended_algorithms = ['LightGBM', 'XGBoost', 'CatBoost', 'RandomForest']
    else:
        recommended_algorithms = ['RandomForest', 'XGBoost', 'LightGBM']
    
    print(f"\n🏆 ÖNERİLEN SIRA:")
    for i, algo in enumerate(recommended_algorithms, 1):
        print(f"   {i}. {algo}")
    
    return recommended_algorithms

if __name__ == "__main__":
    # Veri setini indir ve analiz et
    df = download_and_analyze_cybersecurity_dataset()
    
    if df is not None:
        # Hedef değişkeni bul
        potential_targets = ['label', 'target', 'class', 'y', 'prediction', 'result', 'output', 'category', 'type']
        target_column = None
        
        for col in df.columns:
            col_lower = col.lower()
            if any(target in col_lower for target in potential_targets):
                target_column = col
                break
        
        # Algoritma önerilerini al
        recommended_algorithms = suggest_algorithms(df, target_column)
        
        print(f"\n✅ Analiz tamamlandı!")
        print(f"📁 Veri seti: cybersecurity_dataset.csv olarak kaydedildi")
        print(f"🎯 Hedef değişken: {target_column}")
        print(f"🤖 Önerilen algoritma: {recommended_algorithms[0]}")
    else:
        print("❌ Veri seti analizi başarısız!") 