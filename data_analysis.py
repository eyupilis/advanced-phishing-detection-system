import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import warnings
warnings.filterwarnings('ignore')

# Veri setini yükle
print("Veri seti yükleniyor...")
df = pd.read_csv('mega_phishing_dataset_20k.csv')

# Temel bilgiler
print("=== VERİ SETİ TEMEL BİLGİLERİ ===")
print(f"Satır sayısı: {df.shape[0]}")
print(f"Sütun sayısı: {df.shape[1]}")
print(f"Eksik değer sayısı: {df.isnull().sum().sum()}")

# İlk 5 satırı göster
print("\n=== İLK 5 SATIR ===")
print(df.head())

# Sütun isimleri
print(f"\n=== SÜTUN İSİMLERİ ({len(df.columns)} adet) ===")
print(df.columns.tolist())

# Hedef değişken analizi (phishing/benign)
if 'label' in df.columns:
    target_col = 'label'
elif 'target' in df.columns:
    target_col = 'target'
elif 'class' in df.columns:
    target_col = 'class'
else:
    # Son sütun muhtemelen hedef değişken
    target_col = df.columns[-1]

print(f"\n=== HEDEF DEĞİŞKEN ANALİZİ ({target_col}) ===")
print(df[target_col].value_counts())
print(f"Class dağılımı:\n{df[target_col].value_counts(normalize=True)}")

# Veri tipleri
print(f"\n=== VERİ TİPLERİ ===")
print(df.dtypes.value_counts())

# Temel istatistikler
print(f"\n=== TEMEL İSTATİSTİKLER ===")
print(df.describe())

# Correlation analizi için numeric sütunları bul
numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
if target_col in numeric_cols:
    numeric_cols.remove(target_col)

print(f"\n=== NUMERİK SÜTUNLAR ({len(numeric_cols)} adet) ===")
print(numeric_cols[:10])  # İlk 10 tanesini göster 