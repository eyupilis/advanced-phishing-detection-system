# Install dependencies as needed:
# pip install kagglehub
import kagglehub
import pandas as pd
import numpy as np
import os

def download_and_explore_phishing_urls():
    """Download and explore the phishing site URLs dataset"""
    
    print("=== Phishing Site URLs Dataset Download & Exploration ===")
    
    try:
        # Download the dataset first
        print("📥 Downloading dataset...")
        path = kagglehub.dataset_download("taruntiwarihp/phishing-site-urls")
        print(f"✅ Dataset downloaded to: {path}")
        
        # List files in the downloaded directory
        print("\n=== FILES IN DATASET ===")
        files = os.listdir(path)
        for file in files:
            print(f"  - {file}")
        
        # Find CSV files
        csv_files = [f for f in files if f.endswith('.csv')]
        if not csv_files:
            print("❌ No CSV files found in dataset")
            return None, None
        
        # Load the first CSV file
        csv_file = csv_files[0]
        file_path = os.path.join(path, csv_file)
        print(f"\n📊 Loading file: {csv_file}")
        
        df = pd.read_csv(file_path)
        
        print("✅ Dataset loaded successfully!")
        print("\n=== BASIC INFO ===")
        print(f"Dataset shape: {df.shape}")
        print(f"Columns: {list(df.columns)}")
        
        print("\n=== FIRST 5 RECORDS ===")
        print(df.head())
        
        print("\n=== DATA TYPES ===")
        print(df.dtypes)
        
        print("\n=== MISSING VALUES ===")
        print(df.isnull().sum())
        
        print("\n=== UNIQUE VALUES PER COLUMN ===")
        for col in df.columns:
            print(f"{col}: {df[col].nunique()} unique values")
            if df[col].nunique() < 10:
                print(f"  Values: {df[col].unique()}")
        
        print("\n=== TARGET DISTRIBUTION ===")
        if 'Label' in df.columns:
            print(df['Label'].value_counts())
            print(df['Label'].value_counts(normalize=True))
        elif 'label' in df.columns:
            print(df['label'].value_counts())
            print(df['label'].value_counts(normalize=True))
        else:
            print("No obvious target column found. Columns available:")
            for col in df.columns:
                print(f"  - {col}")
        
        print("\n=== SAMPLE URLS ===")
        if 'URL' in df.columns:
            print("Sample URLs:")
            for i, url in enumerate(df['URL'].head(10)):
                print(f"  {i+1}. {url}")
        elif 'url' in df.columns:
            print("Sample URLs:")
            for i, url in enumerate(df['url'].head(10)):
                print(f"  {i+1}. {url}")
        
        # Save dataset info
        dataset_info = {
            'dataset_name': 'phishing_site_urls',
            'shape': df.shape,
            'columns': list(df.columns),
            'dtypes': df.dtypes.to_dict(),
            'missing_values': df.isnull().sum().to_dict(),
            'unique_counts': {col: df[col].nunique() for col in df.columns}
        }
        
        # Save to file
        df.to_csv('phishing_urls_dataset.csv', index=False)
        print(f"\n✅ Dataset saved to 'phishing_urls_dataset.csv'")
        
        return df, dataset_info
        
    except Exception as e:
        print(f"❌ Error loading dataset: {str(e)}")
        return None, None

if __name__ == "__main__":
    df, info = download_and_explore_phishing_urls()
    if df is not None:
        print(f"\n=== SUMMARY ===")
        print(f"✅ Successfully loaded phishing URLs dataset")
        print(f"📊 Shape: {df.shape}")
        print(f"🎯 Ready for model development!") 