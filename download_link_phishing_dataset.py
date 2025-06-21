#!/usr/bin/env python3
"""
6. Veri Seti: Link Phishing Detection Dataset İndirme ve Analiz
Dataset: winson13/dataset-for-link-phishing-detection
"""

import kagglehub
import pandas as pd
import numpy as np
import os
import glob

def download_and_analyze_dataset():
    """Link Phishing Detection veri setini indir ve analiz et"""
    
    print("🚀 6. Veri Seti: Link Phishing Detection Dataset İndiriliyor...")
    print("=" * 60)
    
    try:
        # Dataset'i indir - yeni API
        print("📥 Kaggle'dan veri seti indiriliyor...")
        
        path = kagglehub.dataset_download("winson13/dataset-for-link-phishing-detection")
        print(f"✅ Veri seti indirildi: {path}")
        
        # İndirilen dosyaları bul
        csv_files = glob.glob(os.path.join(path, "*.csv"))
        if not csv_files:
            # Alternatif dosya formatları ara
            all_files = glob.glob(os.path.join(path, "*"))
            print(f"📁 İndirilen dosyalar: {all_files}")
            
            # JSON, TXT, diğer formatları da kontrol et
            data_files = [f for f in all_files if f.endswith(('.csv', '.json', '.txt', '.tsv'))]
            if data_files:
                csv_files = data_files
        
        if not csv_files:
            print("❌ CSV dosyası bulunamadı!")
            return None
            
        # En büyük CSV dosyasını seç (genellikle ana dataset)
        main_file = max(csv_files, key=os.path.getsize)
        print(f"📄 Ana dosya seçildi: {os.path.basename(main_file)}")
        
        # Veri setini yükle
        print("📊 Veri seti analiz ediliyor...")
        
        # Farklı encoding'leri dene
        encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        df = None
        
        for encoding in encodings:
            try:
                df = pd.read_csv(main_file, encoding=encoding)
                print(f"✅ Encoding '{encoding}' ile başarıyla yüklendi")
                break
            except:
                continue
                
        if df is None:
            print("❌ Veri seti yüklenemedi!")
            return None
        
        # Veri seti bilgileri
        print(f"\n📊 VERİ SETİ BİLGİLERİ:")
        print(f"   📏 Boyut: {df.shape[0]} örneklem, {df.shape[1]} sütun")
        print(f"   💾 Dosya boyutu: {os.path.getsize(main_file) / (1024*1024):.1f} MB")
        
        # Sütun bilgileri
        print(f"\n📋 SÜTUN BİLGİLERİ:")
        for i, col in enumerate(df.columns):
            dtype = df[col].dtype
            null_count = df[col].isnull().sum()
            print(f"   {i+1:2d}. {col:30s} | {str(dtype):10s} | {null_count:5d} null")
        
        # İlk 5 satır
        print(f"\n👀 İLK 5 SATIRN:")
        print(df.head())
        
        # Target sütunu bul
        possible_targets = ['label', 'target', 'class', 'phishing', 'malicious', 'safe', 'result', 'prediction']
        target_col = None
        
        for col in df.columns:
            if col.lower() in possible_targets or 'label' in col.lower() or 'class' in col.lower():
                target_col = col
                break
        
        if target_col:
            print(f"\n🎯 TARGET SÜTUNU: {target_col}")
            print(f"   📊 Dağılım:")
            value_counts = df[target_col].value_counts()
            for value, count in value_counts.items():
                percentage = (count / len(df)) * 100
                print(f"     {value}: {count:,} ({percentage:.1f}%)")
        else:
            print(f"\n❓ Target sütunu bulunamadı. Tüm unique değerler:")
            for col in df.columns:
                unique_count = df[col].nunique()
                if unique_count <= 10:  # Kategorik sütunları göster
                    print(f"   {col}: {df[col].unique()}")
        
        # Veri setini kaydet
        output_file = "link_phishing_dataset.csv"
        df.to_csv(output_file, index=False)
        print(f"\n💾 Veri seti kaydedildi: {output_file}")
        
        # URL sütunu var mı kontrol et
        url_columns = [col for col in df.columns if 'url' in col.lower() or 'link' in col.lower()]
        if url_columns:
            print(f"\n🔗 URL SÜTUNLARI: {url_columns}")
            for col in url_columns[:3]:  # İlk 3 URL örneği
                sample_urls = df[col].dropna().head(3).tolist()
                print(f"   {col} örnekleri: {sample_urls}")
        
        # Özet
        print(f"\n✅ 6. VERİ SETİ HAZIR!")
        print(f"   🎯 Tip: Link/URL Phishing Detection")
        print(f"   📊 Boyut: {df.shape[0]:,} örneklem, {df.shape[1]} özellik")
        if target_col:
            unique_targets = df[target_col].nunique()
            print(f"   🏷️  Target: {target_col} ({unique_targets} sınıf)")
        print(f"   📁 Dosya: {output_file}")
        
        return df
        
    except Exception as e:
        print(f"❌ Hata oluştu: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    download_and_analyze_dataset() 