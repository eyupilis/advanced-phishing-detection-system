-- PHISHING DETECTOR SUPABASE SCHEMA
-- Tüm analiz sonuçları, feedback'ler ve dashboard için tablolar

-- 1. URL Analiz Sonuçları Tablosu
CREATE TABLE url_analyses (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    url TEXT NOT NULL,
    prediction TEXT NOT NULL, -- 'safe' or 'phishing'
    ensemble_confidence FLOAT NOT NULL,
    risk_score FLOAT NOT NULL,
    total_models INTEGER NOT NULL,
    active_models INTEGER NOT NULL,
    phishing_votes INTEGER NOT NULL,
    safe_votes INTEGER NOT NULL,
    voting_ratio FLOAT NOT NULL,
    ensemble_status TEXT NOT NULL,
    individual_models JSONB NOT NULL, -- Her modelin sonucu
    model_weights JSONB NOT NULL,
    rule_based_flags JSONB,
    rule_flags_count INTEGER DEFAULT 0,
    features JSONB, -- Extracted features
    analysis_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    session_id TEXT
);

-- 2. Kullanıcı Feedback Tablosu  
CREATE TABLE user_feedbacks (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    analysis_id UUID REFERENCES url_analyses(id),
    url TEXT NOT NULL,
    original_prediction TEXT NOT NULL,
    user_feedback TEXT NOT NULL, -- 'correct' or 'incorrect'
    prediction_confidence FLOAT NOT NULL,
    feedback_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    session_id TEXT
);

-- 3. False Positive/Negative Tracking
CREATE TABLE false_predictions (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    analysis_id UUID REFERENCES url_analyses(id),
    feedback_id UUID REFERENCES user_feedbacks(id),
    url TEXT NOT NULL,
    prediction_type TEXT NOT NULL, -- 'false_positive' or 'false_negative'
    model_predictions JSONB NOT NULL, -- Hangi modeller yanlış tahmin etti
    confidence_level FLOAT NOT NULL,
    error_patterns JSONB, -- Pattern analizi için
    flagged_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    reviewed BOOLEAN DEFAULT FALSE,
    notes TEXT
);

-- 4. Model Performance Tracking
CREATE TABLE model_performance (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    model_name TEXT NOT NULL,
    correct_predictions INTEGER DEFAULT 0,
    incorrect_predictions INTEGER DEFAULT 0,
    total_predictions INTEGER DEFAULT 0,
    accuracy_rate FLOAT DEFAULT 0,
    false_positive_rate FLOAT DEFAULT 0,
    false_negative_rate FLOAT DEFAULT 0,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 5. Daily Analytics Dashboard Data
CREATE TABLE daily_analytics (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    date DATE NOT NULL UNIQUE,
    total_analyses INTEGER DEFAULT 0,
    safe_predictions INTEGER DEFAULT 0,
    phishing_predictions INTEGER DEFAULT 0,
    user_feedbacks INTEGER DEFAULT 0,
    correct_feedbacks INTEGER DEFAULT 0,
    incorrect_feedbacks INTEGER DEFAULT 0,
    avg_confidence FLOAT DEFAULT 0,
    top_phishing_domains JSONB,
    model_accuracy JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 6. System Logs  
CREATE TABLE system_logs (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    log_level TEXT NOT NULL, -- 'info', 'warning', 'error'
    event_type TEXT NOT NULL, -- 'analysis', 'feedback', 'error', 'performance'
    message TEXT NOT NULL,
    metadata JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- İNDEXLER
CREATE INDEX idx_url_analyses_timestamp ON url_analyses(analysis_timestamp);
CREATE INDEX idx_url_analyses_prediction ON url_analyses(prediction);
CREATE INDEX idx_url_analyses_url ON url_analyses(url);
CREATE INDEX idx_user_feedbacks_timestamp ON user_feedbacks(feedback_timestamp);
CREATE INDEX idx_false_predictions_type ON false_predictions(prediction_type);
CREATE INDEX idx_model_performance_name ON model_performance(model_name);
CREATE INDEX idx_daily_analytics_date ON daily_analytics(date);
CREATE INDEX idx_system_logs_timestamp ON system_logs(timestamp);
CREATE INDEX idx_system_logs_event_type ON system_logs(event_type);

-- VIEWS
-- Model accuracy özeti
CREATE VIEW model_accuracy_summary AS
SELECT 
    model_name,
    total_predictions,
    accuracy_rate,
    false_positive_rate,
    false_negative_rate,
    last_updated
FROM model_performance
ORDER BY accuracy_rate DESC;

-- Günlük özet
CREATE VIEW daily_summary AS
SELECT 
    date,
    total_analyses,
    ROUND((safe_predictions::FLOAT / total_analyses * 100), 2) as safe_percentage,
    ROUND((phishing_predictions::FLOAT / total_analyses * 100), 2) as phishing_percentage,
    ROUND((correct_feedbacks::FLOAT / user_feedbacks * 100), 2) as feedback_accuracy,
    avg_confidence
FROM daily_analytics
ORDER BY date DESC;

-- En çok false positive veren URL'ler
CREATE VIEW false_positive_hotspots AS
SELECT 
    url,
    COUNT(*) as false_positive_count,
    AVG(confidence_level) as avg_confidence,
    MAX(flagged_timestamp) as last_occurrence
FROM false_predictions 
WHERE prediction_type = 'false_positive'
GROUP BY url
ORDER BY false_positive_count DESC
LIMIT 50; 