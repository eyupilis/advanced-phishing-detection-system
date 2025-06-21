# 🔧 SUPABASE DATABASE INTEGRATION SETUP

## 1. 🏗️ SUPABASE PROJECT OLUŞTURMA

1. [Supabase Dashboard](https://supabase.com/dashboard)'a gidin
2. "New Project" butonuna tıklayın
3. Project ayarlarını yapın:
   - **Project Name**: `phishing-detector-db`
   - **Database Password**: Güvenli bir şifre oluşturun
   - **Region**: Size en yakın region'ı seçin

## 2. 📊 DATABASE SCHEMA OLUŞTURMA

1. Supabase Dashboard > **SQL Editor**'e gidin
2. `supabase_schema.sql` dosyasındaki SQL komutlarını çalıştırın
3. Tüm tablolar ve view'lar oluşacak

## 3. 🔑 API KEY'LERİ ALMA

1. Supabase Dashboard > **Settings** > **API**'ye gidin
2. Aşağıdaki değerleri alın:
   - **Project URL**: `https://your-project-ref.supabase.co`
   - **Anon/Public Key**: `eyJhbGciOiJI...` (uzun string)

## 4. 🌍 ENVIRONMENT VARIABLES AYARLAMA

Proje klasörünüzde `.env` dosyası oluşturun:

```bash
# SUPABASE CONFIGURATION
SUPABASE_URL=https://your-project-ref.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# API Configuration
API_PORT=8080
API_HOST=0.0.0.0
LOG_LEVEL=INFO
```

## 5. 📦 PYTHON DEPENDENCIES

```bash
pip install requests python-dotenv
```

## 6. 🧪 CONNECTION TEST

```python
from supabase_client import supabase_client

# Test connection
try:
    result = supabase_client._make_request('GET', 'url_analyses?limit=1')
    print("✅ Supabase connection successful!")
except Exception as e:
    print(f"❌ Connection failed: {e}")
```

## 7. 🎛️ DASHBOARD ENDPOINTS

Entegrasyon tamamlandıktan sonra şu endpoint'ler kullanılabilir:

- `GET /dashboard/analytics?days=30` - Günlük analytics
- `GET /dashboard/model-performance` - Model performansı
- `GET /dashboard/false-positives` - False positive hotspots
- `GET /dashboard/recent-analyses?limit=50` - Son analizler
- `POST /dashboard/update-model-stats` - Performance güncelleme

## 8. 📈 SAMPLE QUERIES

```sql
-- En çok analiz edilen domain'ler
SELECT 
    SUBSTRING(url FROM 'https?://([^/]+)') as domain,
    COUNT(*) as analysis_count,
    AVG(ensemble_confidence) as avg_confidence
FROM url_analyses 
GROUP BY domain
ORDER BY analysis_count DESC
LIMIT 10;

-- Günlük false positive oranı
SELECT 
    DATE(analysis_timestamp) as date,
    COUNT(*) as total_analyses,
    SUM(CASE WHEN prediction = 'phishing' THEN 1 ELSE 0 END) as phishing_predictions,
    COUNT(DISTINCT analysis_id) as unique_analyses
FROM url_analyses ua
LEFT JOIN user_feedbacks uf ON ua.id = uf.analysis_id AND uf.user_feedback = 'incorrect'
GROUP BY DATE(analysis_timestamp)
ORDER BY date DESC;
```

## 9. 🔒 SECURITY CONSIDERATIONS

- ✅ **Anon Key**: Frontend'de kullanılabilir (sadece okuma/yazma)
- ❌ **Service Role Key**: Backend'de kullanın (tüm yetkiler)
- 🔐 **Row Level Security**: Kritik tablolar için RLS aktif edin
- 🛡️ **API Rate Limiting**: Supabase'de otomatik olarak gelir

## 10. 📊 MONITORING

Supabase Dashboard'da izlenebilir:
- API request sayısı
- Database usage
- Real-time connections
- Error logs 