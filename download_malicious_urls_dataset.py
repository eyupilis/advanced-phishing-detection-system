#!/usr/bin/env python3
"""
Malicious URLs Dataset İndirme Scripti
Dataset: sid321axn/malicious-urls-dataset
7. Model için veri seti hazırlığı
"""

import kagglehub
import pandas as pd
import os
import time
import glob

def download_malicious_urls_dataset():
    """Malicious URLs Dataset'ini indir ve analiz et"""
    
    print("🔄 Malicious URLs Dataset indiriliyor...")
    print("📊 Dataset: sid321axn/malicious-urls-dataset")
    print("=" * 60)
    
    try:
        start_time = time.time()
        
        # Dataset'i indir (modern method)
        print("📥 Kaggle'dan indiriliyor...")
        
        # Dataset path'ini al
        dataset_path = kagglehub.dataset_download("sid321axn/malicious-urls-dataset")
        print(f"📁 Dataset path: {dataset_path}")
        
        download_time = time.time() - start_time
        print(f"✅ İndirme tamamlandı ({download_time:.2f} saniye)")
        
        # CSV dosyasını bul
        csv_files = glob.glob(os.path.join(dataset_path, "*.csv"))
        print(f"📋 Bulunan CSV dosyaları: {csv_files}")
        
        if not csv_files:
            print("❌ CSV dosyası bulunamadı!")
            return None
        
        # İlk CSV dosyasını yükle
        csv_file = csv_files[0]
        print(f"📊 Yükleniyor: {csv_file}")
        
        df = pd.read_csv(csv_file)
        
        # Dataset analizi
        print(f"\n📊 Dataset Analizi:")
        print(f"   📈 Toplam Kayıt: {len(df):,}")
        print(f"   📋 Sütun Sayısı: {len(df.columns)}")
        print(f"   💾 Boyut: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
        
        print(f"\n📋 Sütunlar:")
        for i, col in enumerate(df.columns, 1):
            print(f"   {i:2d}. {col}")
        
        print(f"\n🔍 İlk 5 Kayıt:")
        print(df.head())
        
        print(f"\n📊 Veri Tipleri:")
        print(df.dtypes)
        
        print(f"\n🔍 Null Değerler:")
        print(df.isnull().sum())
        
        # Hedef sütun analizi - farklı isimleri dene
        target_columns = ['type', 'label', 'class', 'target', 'category', 'malicious', 'status']
        found_target = None
        
        for col in target_columns:
            if col in df.columns:
                found_target = col
                break
        
        if found_target:
            print(f"\n🎯 Hedef Sütun Dağılımı ({found_target}):")
            print(df[found_target].value_counts())
        else:
            print(f"\n⚠️ Hedef sütun bulunamadı. Mevcut sütunlar: {list(df.columns)}")
        
        # Dataset'i yerel olarak kaydet
        output_file = "malicious_urls_dataset.csv"
        df.to_csv(output_file, index=False)
        
        print(f"\n💾 Dataset kaydedildi: {output_file}")
        print(f"📁 Dosya boyutu: {os.path.getsize(output_file) / 1024**2:.2f} MB")
        
        return df
        
    except Exception as e:
        print(f"❌ Hata: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    # Dataset'i indir
    dataset = download_malicious_urls_dataset()
    
    if dataset is not None:
        print("\n🎯 Dataset başarıyla indirildi ve analiz edildi!")
        print(f"📈 Şimdi 7. model pipeline'ını oluşturabiliriz")
    else:
        print("\n❌ Dataset indirilemedi!") 