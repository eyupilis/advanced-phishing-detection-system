#!/usr/bin/env python3
"""
5. Veri Seti: Cryptocurrency Scam Dataset İndirme ve Analiz
Dataset: zongaobian/cryptocurrency-scam-dataset
"""

import kagglehub
import pandas as pd
import numpy as np
import os
import glob

def download_and_analyze_dataset():
    """Cryptocurrency Scam veri setini indir ve analiz et"""
    
    print("🚀 5. Veri Seti: Cryptocurrency Scam Dataset İndiriliyor...")
    print("=" * 60)
    
    try:
        # Dataset'i indir - yeni API
        print("📥 Kaggle'dan veri seti indiriliyor...")
        
        path = kagglehub.dataset_download("zongaobian/cryptocurrency-scam-dataset")
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
        
        # Sütun isimleri
        print("\n📝 Sütun Listesi:")
        for i, col in enumerate(df.columns):
            print(f"   {i+1}. {col}")
        
        # Eksik değerler
        print("\n❓ Eksik Değer Analizi:")
        missing_data = df.isnull().sum()
        if missing_data.sum() > 0:
            print("   Eksik değerler:")
            for col, missing_count in missing_data[missing_data > 0].items():
                percentage = (missing_count / len(df)) * 100
                print(f"     {col}: {missing_count} ({percentage:.1f}%)")
        else:
            print("   ✅ Eksik değer bulunamadı!")
        
        # Target değişken analizi - potansiyel target sütunları
        potential_targets = []
        for col in df.columns:
            if any(keyword in col.lower() for keyword in ['scam', 'label', 'class', 'target', 'fraud', 'phishing']):
                potential_targets.append(col)
        
        if potential_targets:
            target_col = potential_targets[0]
            print(f"🎯 Potansiyel Target Sütun: '{target_col}'")
        else:
            # Son sütunu target olarak kabul et
            target_col = df.columns[-1]
            print(f"⚠️  Target sütunu otomatik olarak '{target_col}' seçildi")
        
        print(f"\n🎯 Target Değişken Analizi ('{target_col}'):")
        if target_col in df.columns:
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
        
        print(f"\n🔢 Sayısal Özellikler: {len(numeric_columns)} adet")
        if len(numeric_columns) > 0:
            print("   İlk 10 özellik:")
            for col in numeric_columns[:10]:
                print(f"     - {col}")
        
        # Kategorik sütunlar
        categorical_columns = df.select_dtypes(include=['object']).columns.tolist()
        if target_col in categorical_columns:
            categorical_columns.remove(target_col)
            
        print(f"\n📝 Kategorik Özellikler: {len(categorical_columns)} adet")
        if len(categorical_columns) > 0:
            for col in categorical_columns[:10]:  # İlk 10'u göster
                unique_count = df[col].nunique()
                print(f"     - {col}: {unique_count} benzersiz değer")
                
                # URL sütunu varsa örnek göster
                if 'url' in col.lower() or 'link' in col.lower() or 'address' in col.lower():
                    print(f"       Örnek: {df[col].dropna().iloc[0] if not df[col].dropna().empty else 'N/A'}")
        
        # Temel istatistikler
        print(f"\n📈 Temel İstatistikler:")
        print(df.describe())
        
        # Veri setini kaydet
        output_filename = "cryptocurrency_scam_dataset.csv"
        df.to_csv(output_filename, index=False)
        print(f"\n💾 Veri seti '{output_filename}' olarak kaydedildi")
        
        # Veri seti özelliklerini analiz et
        print(f"\n🔍 Veri Seti Özellikleri:")
        print(f"   📊 Total Features: {len(df.columns) - 1}")
        print(f"   🎯 Target Column: {target_col}")
        print(f"   📏 Dataset Size: {len(df):,} örneklem")
        
        # Cryptocurrency/Blockchain özelliklerini analiz et
        crypto_features = []
        for col in df.columns:
            if any(keyword in col.lower() for keyword in ['bitcoin', 'btc', 'ethereum', 'eth', 'crypto', 'blockchain', 'address', 'transaction', 'wallet']):
                crypto_features.append(col)
        
        if crypto_features:
            print(f"   💰 Cryptocurrency özellikler: {len(crypto_features)} adet")
            for feature in crypto_features[:5]:
                print(f"     - {feature}")
        
        # URL özelliklerini analiz et
        url_features = []
        for col in df.columns:
            if any(keyword in col.lower() for keyword in ['url', 'link', 'domain', 'website', 'site']):
                url_features.append(col)
        
        if url_features:
            print(f"   🌐 URL özellikler: {len(url_features)} adet")
            for feature in url_features[:3]:
                print(f"     - {feature}")
        
        # Dataset türünü belirle
        if crypto_features and url_features:
            dataset_type = "Cryptocurrency + URL Scam Detection"
        elif crypto_features:
            dataset_type = "Cryptocurrency Scam Detection"
        elif url_features:
            dataset_type = "URL-based Scam Detection"
        else:
            dataset_type = "General Scam Detection"
        
        print(f"   🔍 Dataset Türü: {dataset_type}")
        
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
        print("\n✅ 5. veri seti başarıyla indirildi ve analiz edildi!")
        print("🚀 Bir sonraki adım: Cryptocurrency Scam Model pipeline'ı oluşturma")
        print("💡 Bu veri seti blockchain ve cryptocurrency tabanlı scam detection için kullanılabilir")
    else:
        print("❌ Veri seti indirilemedi!") 