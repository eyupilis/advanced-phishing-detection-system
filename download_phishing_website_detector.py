#!/usr/bin/env python3
"""
4. Veri Seti: Phishing Website Detector Dataset İndirme ve Analiz
Dataset: eswarchandt/phishing-website-detector
"""

import kagglehub
import pandas as pd
import numpy as np
import os
import glob

def download_and_analyze_dataset():
    """Phishing Website Detector veri setini indir ve analiz et"""
    
    print("🚀 4. Veri Seti: Phishing Website Detector Dataset İndiriliyor...")
    print("=" * 60)
    
    try:
        # Dataset'i indir - yeni API
        print("📥 Kaggle'dan veri seti indiriliyor...")
        
        path = kagglehub.dataset_download("eswarchandt/phishing-website-detector")
        print(f"✅ Veri seti indirildi: {path}")
        
        # İndirilen dosyaları bul
        csv_files = glob.glob(os.path.join(path, "*.csv"))
        if not csv_files:
            print("❌ CSV dosyası bulunamadı!")
            return None, None
        
        # İlk CSV dosyasını yükle
        csv_file = csv_files[0]
        print(f"📂 Yüklenen dosya: {csv_file}")
        
        df = pd.read_csv(csv_file)
        print("✅ Veri seti başarıyla yüklendi!")
        
        # Temel bilgileri yazdır
        print("\n📊 Dataset Bilgileri:")
        print(f"   📏 Boyut: {df.shape[0]} satır, {df.shape[1]} sütun")
        print(f"   💾 Bellek kullanımı: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
        
        # İlk 5 kayıt
        print("\n🔍 İlk 5 Kayıt:")
        print(df.head())
        
        # Sütun bilgileri
        print("\n📋 Sütun Bilgileri:")
        print(df.info())
        
        # Eksik değerler
        print("\n❓ Eksik Değer Analizi:")
        missing_data = df.isnull().sum()
        if missing_data.sum() > 0:
            print(missing_data[missing_data > 0])
        else:
            print("   ✅ Eksik değer bulunamadı!")
        
        # Target değişken analizi
        if 'target' in df.columns:
            target_col = 'target'
        elif 'class' in df.columns:
            target_col = 'class'
        elif 'label' in df.columns:
            target_col = 'label'
        elif 'phishing' in df.columns:
            target_col = 'phishing'
        elif 'Result' in df.columns:
            target_col = 'Result'
        else:
            # Son sütunu target olarak kabul et
            target_col = df.columns[-1]
            print(f"⚠️  Target sütunu otomatik olarak '{target_col}' seçildi")
        
        print(f"\n🎯 Target Değişken Analizi ('{target_col}'):")
        print(f"   Benzersiz değerler: {df[target_col].unique()}")
        print(f"   Değer dağılımı:")
        value_counts = df[target_col].value_counts()
        for value, count in value_counts.items():
            percentage = (count / len(df)) * 100
            print(f"     {value}: {count} ({percentage:.1f}%)")
        
        # Sayısal sütunlar
        numeric_columns = df.select_dtypes(include=[np.number]).columns.tolist()
        if target_col in numeric_columns:
            numeric_columns.remove(target_col)
        
        print(f"\n�� Sayısal Özellikler: {len(numeric_columns)} adet")
        if len(numeric_columns) > 0:
            print("   İlk 10 özellik:")
            for col in numeric_columns[:10]:
                print(f"     - {col}")
        
        # Kategorik sütunlar
        categorical_columns = df.select_dtypes(include=['object']).columns.tolist()
        print(f"\n📝 Kategorik Özellikler: {len(categorical_columns)} adet")
        if len(categorical_columns) > 0:
            for col in categorical_columns[:5]:  # İlk 5'i göster
                unique_count = df[col].nunique()
                print(f"     - {col}: {unique_count} benzersiz değer")
        
        # Temel istatistikler
        print(f"\n📈 Temel İstatistikler:")
        print(df.describe())
        
        # Veri setini kaydet
        output_filename = "phishing_website_detector_dataset.csv"
        df.to_csv(output_filename, index=False)
        print(f"\n💾 Veri seti '{output_filename}' olarak kaydedildi")
        
        # Veri seti özelliklerini analiz et
        print(f"\n🔍 Veri Seti Özellikleri:")
        print(f"   📊 Total Features: {len(df.columns) - 1}")
        print(f"   🎯 Target Column: {target_col}")
        print(f"   📏 Dataset Size: {len(df):,} örneklem")
        
        if len(value_counts) >= 2:
            balance_diff = abs(value_counts.iloc[0] - value_counts.iloc[1])
            is_balanced = balance_diff < len(df) * 0.2
            print(f"   💡 Bu veri seti {'dengelenmiş' if is_balanced else 'dengelenmemiş'}")
        
        return df, target_col
        
    except Exception as e:
        print(f"❌ Hata: {e}")
        import traceback
        traceback.print_exc()
        return None, None

if __name__ == "__main__":
    df, target_col = download_and_analyze_dataset()
    
    if df is not None:
        print("\n✅ 4. veri seti başarıyla indirildi ve analiz edildi!")
        print("🚀 Bir sonraki adım: Model pipeline'ı oluşturma")
    else:
        print("❌ Veri seti indirilemedi!") 