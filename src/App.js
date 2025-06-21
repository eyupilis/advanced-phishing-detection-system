import React, { useState, useEffect } from 'react';
import {
  Container,
  Typography,
  TextField,
  Button,
  Card,
  CardContent,
  Grid,
  Chip,
  Box,
  CircularProgress,
  Alert,
  LinearProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  FormLabel,
  RadioGroup,
  FormControlLabel,
  Radio,
  Snackbar,
  AppBar,
  Toolbar,
  IconButton,
  Tabs,
  Tab,
  Paper,
  List,
  ListItem,
  ListItemText,
  ListItemIcon
} from '@mui/material';
import {
  Security,
  Warning,
  CheckCircle,
  Analytics,
  Feedback,
  Shield,
  BugReport
} from '@mui/icons-material';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import axios from 'axios';

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const [feedbackLabel, setFeedbackLabel] = useState('');
  const [feedbackComment, setFeedbackComment] = useState('');
  const [snackbarOpen, setSnackbarOpen] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [tabValue, setTabValue] = useState(0);
  const [modelStats, setModelStats] = useState(null);

  const analyzeUrl = async () => {
    if (!url.trim()) {
      setError('URL girin');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await axios.post('/analyze', { url: url.trim() });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Analiz hatası oluştu');
    } finally {
      setLoading(false);
    }
  };

  const submitFeedback = async () => {
    if (!feedbackLabel) {
      setError('Doğru etiketi seçin');
      return;
    }

    try {
      await axios.post('/feedback', {
        url: result.url,
        predicted_label: result.prediction,
        actual_label: feedbackLabel,
        user_comment: feedbackComment
      });
      
      setSnackbarMessage('Geri bildirim kaydedildi! Teşekkürler 🙏');
      setSnackbarOpen(true);
      setFeedbackOpen(false);
      resetFeedback();
    } catch (err) {
      setError('Geri bildirim gönderilemedi');
    }
  };

  const resetFeedback = () => {
    setFeedbackLabel('');
    setFeedbackComment('');
  };

  const fetchModelStats = async () => {
    try {
      const response = await axios.get('/model-stats');
      setModelStats(response.data);
    } catch (err) {
      console.error('Model stats alınamadı:', err);
    }
  };

  useEffect(() => {
    fetchModelStats();
  }, []);

  const handleKeyPress = (event) => {
    if (event.key === 'Enter') {
      analyzeUrl();
    }
  };

  const RiskMeter = ({ score }) => {
    const percentage = score * 100;
    const color = score < 0.3 ? '#4caf50' : score < 0.7 ? '#ff9800' : '#f44336';
    
    return (
      <Box className="risk-meter">
        <Typography variant="h6" gutterBottom>
          Risk Skoru: {percentage.toFixed(1)}%
        </Typography>
        <Box sx={{ width: '100%', mr: 1 }}>
          <LinearProgress 
            variant="determinate" 
            value={percentage} 
            sx={{
              height: 20,
              borderRadius: 10,
              backgroundColor: '#e0e0e0',
              '& .MuiLinearProgress-bar': {
                backgroundColor: color,
                borderRadius: 10,
              }
            }}
          />
        </Box>
      </Box>
    );
  };

  const FeatureChart = ({ features }) => {
    const chartData = Object.entries(features)
      .slice(0, 8)
      .map(([name, value]) => ({
        name: name.replace(/_/g, ' ').substring(0, 15),
        value: parseFloat(value.toFixed(3))
      }));

    return (
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="name" angle={-45} textAnchor="end" height={100} />
          <YAxis />
          <Tooltip />
          <Legend />
          <Bar dataKey="value" fill="#8884d8" />
        </BarChart>
      </ResponsiveContainer>
    );
  };

  const TabPanel = ({ children, value, index }) => (
    <div hidden={value !== index}>
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );

  return (
    <Box sx={{ flexGrow: 1 }}>
      <AppBar position="static" sx={{ mb: 4 }}>
        <Toolbar>
          <Security sx={{ mr: 2 }} />
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            🔒 Phishing Detector - AI Tabanlı URL Güvenlik Analizi
          </Typography>
          <IconButton color="inherit" onClick={fetchModelStats}>
            <Analytics />
          </IconButton>
        </Toolbar>
      </AppBar>

      <Container maxWidth="lg">
        <Paper sx={{ width: '100%', typography: 'body1' }}>
          <Tabs value={tabValue} onChange={(e, newValue) => setTabValue(newValue)} centered>
            <Tab label="URL Analizi" icon={<Security />} />
            <Tab label="Model İstatistikleri" icon={<Analytics />} />
          </Tabs>

          <TabPanel value={tabValue} index={0}>
            {/* Ana Analiz Paneli */}
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <Card elevation={3}>
                  <CardContent>
                    <Typography variant="h5" gutterBottom align="center">
                      🔍 URL Güvenlik Analizi
                    </Typography>
                    <Typography variant="body2" color="text.secondary" align="center" sx={{ mb: 3 }}>
                      Bir URL girin ve AI modelimiz phishing/dolandırıcılık riskini analiz etsin
                    </Typography>
                    
                    <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                      <TextField
                        fullWidth
                        label="Analiz edilecek URL"
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        onKeyPress={handleKeyPress}
                        placeholder="https://example.com"
                        variant="outlined"
                        disabled={loading}
                      />
                      <Button
                        variant="contained"
                        onClick={analyzeUrl}
                        disabled={loading || !url.trim()}
                        sx={{ minWidth: 120 }}
                        startIcon={loading ? <CircularProgress size={20} /> : <Shield />}
                      >
                        {loading ? 'Analiz...' : 'Analiz Et'}
                      </Button>
                    </Box>

                    {error && (
                      <Alert severity="error" sx={{ mb: 2 }}>
                        {error}
                      </Alert>
                    )}
                  </CardContent>
                </Card>
              </Grid>

              {result && (
                <>
                  {/* Sonuç Özeti */}
                  <Grid item xs={12}>
                    <Card elevation={3}>
                      <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                          {result.prediction === 'safe' ? (
                            <CheckCircle sx={{ color: '#4caf50', mr: 2, fontSize: 40 }} />
                          ) : (
                            <Warning sx={{ color: '#f44336', mr: 2, fontSize: 40 }} />
                          )}
                          <Box>
                            <Typography variant="h5" className={result.prediction === 'safe' ? 'safe-url' : 'phishing-url'}>
                              {result.prediction === 'safe' ? '✅ GÜVENLİ' : '⚠️ RİSKLİ'}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                              Güven: {(result.confidence * 100).toFixed(1)}%
                            </Typography>
                          </Box>
                        </Box>

                        <RiskMeter score={result.risk_score} />

                        <Typography variant="body2" sx={{ mt: 2, p: 2, bgcolor: 'grey.100', borderRadius: 1 }}>
                          <strong>Analiz edilen URL:</strong> {result.url}
                        </Typography>

                        <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
                          <Button
                            variant="outlined"
                            startIcon={<Feedback />}
                            onClick={() => setFeedbackOpen(true)}
                          >
                            Geri Bildirim
                          </Button>
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>

                  {/* Kural Tabanlı Uyarılar */}
                  {result.rule_based_flags && result.rule_based_flags.length > 0 && (
                    <Grid item xs={12}>
                      <Card elevation={3}>
                        <CardContent>
                          <Typography variant="h6" gutterBottom>
                            🚨 Güvenlik Uyarıları
                          </Typography>
                          <List dense>
                            {result.rule_based_flags.map((flag, index) => (
                              <ListItem key={index}>
                                <ListItemIcon>
                                  <BugReport color="error" />
                                </ListItemIcon>
                                <ListItemText primary={flag} />
                              </ListItem>
                            ))}
                          </List>
                        </CardContent>
                      </Card>
                    </Grid>
                  )}

                  {/* Detaylı Analiz */}
                  <Grid item xs={12} md={6}>
                    <Card elevation={3}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>
                          📊 Detaylı Analiz
                        </Typography>
                        <Box sx={{ mt: 2 }}>
                          <Typography variant="body2">
                            <strong>ML Tahmin:</strong> {result.analysis.ml_prediction}
                          </Typography>
                          <Typography variant="body2">
                            <strong>ML Güven:</strong> {(result.analysis.ml_confidence * 100).toFixed(1)}%
                          </Typography>
                          <Typography variant="body2">
                            <strong>Kural İhlali:</strong> {result.analysis.rule_based_flags_count} adet
                          </Typography>
                          <Typography variant="body2">
                            <strong>Hibrit Risk:</strong> {(result.analysis.hybrid_risk_score * 100).toFixed(1)}%
                          </Typography>
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>

                  {/* Özellik Grafği */}
                  <Grid item xs={12} md={6}>
                    <Card elevation={3}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>
                          🔬 Özellik Analizi
                        </Typography>
                        <FeatureChart features={result.features} />
                      </CardContent>
                    </Card>
                  </Grid>
                </>
              )}
            </Grid>
          </TabPanel>

          <TabPanel value={tabValue} index={1}>
            {/* Model İstatistikleri */}
            {modelStats ? (
              <Grid container spacing={3}>
                <Grid item xs={12}>
                  <Card elevation={3}>
                    <CardContent>
                      <Typography variant="h5" gutterBottom>
                        🤖 Model Performansı
                      </Typography>
                      <Grid container spacing={2}>
                        <Grid item xs={12} sm={6} md={3}>
                          <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'primary.light', borderRadius: 1 }}>
                            <Typography variant="h4" color="white">
                              {modelStats.model_name}
                            </Typography>
                            <Typography variant="body2" color="white">
                              Kullanılan Model
                            </Typography>
                          </Box>
                        </Grid>
                        <Grid item xs={12} sm={6} md={3}>
                          <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'success.light', borderRadius: 1 }}>
                            <Typography variant="h4" color="white">
                              {(modelStats.accuracy * 100).toFixed(1)}%
                            </Typography>
                            <Typography variant="body2" color="white">
                              Doğruluk
                            </Typography>
                          </Box>
                        </Grid>
                        <Grid item xs={12} sm={6} md={3}>
                          <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'info.light', borderRadius: 1 }}>
                            <Typography variant="h4" color="white">
                              {(modelStats.auc_score * 100).toFixed(1)}%
                            </Typography>
                            <Typography variant="body2" color="white">
                              AUC Skoru
                            </Typography>
                          </Box>
                        </Grid>
                        <Grid item xs={12} sm={6} md={3}>
                          <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'warning.light', borderRadius: 1 }}>
                            <Typography variant="h4" color="white">
                              {modelStats.feature_count}
                            </Typography>
                            <Typography variant="body2" color="white">
                              Özellik Sayısı
                            </Typography>
                          </Box>
                        </Grid>
                      </Grid>
                    </CardContent>
                  </Card>
                </Grid>

                {modelStats.top_features && modelStats.top_features.length > 0 && (
                  <Grid item xs={12}>
                    <Card elevation={3}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>
                          🏆 En Önemli Özellikler
                        </Typography>
                        <Grid container spacing={1}>
                          {modelStats.top_features.map((feature, index) => (
                            <Grid item key={index}>
                              <Chip
                                label={`${feature.feature}: ${feature.importance.toFixed(3)}`}
                                variant="outlined"
                                size="small"
                                className="feature-chip"
                                color={index < 3 ? 'primary' : 'default'}
                              />
                            </Grid>
                          ))}
                        </Grid>
                      </CardContent>
                    </Card>
                  </Grid>
                )}
              </Grid>
            ) : (
              <Box className="loading">
                <CircularProgress />
              </Box>
            )}
          </TabPanel>
        </Paper>

        {/* Feedback Dialog */}
        <Dialog open={feedbackOpen} onClose={() => setFeedbackOpen(false)} maxWidth="sm" fullWidth>
          <DialogTitle>📝 Geri Bildirim</DialogTitle>
          <DialogContent>
            <Typography variant="body2" sx={{ mb: 2 }}>
              Tahminimiz doğru muydu? Geri bildiriminiz modelimizi iyileştirmemize yardımcı olur.
            </Typography>
            <FormControl component="fieldset" sx={{ mb: 2 }}>
              <FormLabel component="legend">Bu URL gerçekte nasıl?</FormLabel>
              <RadioGroup
                value={feedbackLabel}
                onChange={(e) => setFeedbackLabel(e.target.value)}
              >
                <FormControlLabel value="safe" control={<Radio />} label="✅ Güvenli" />
                <FormControlLabel value="phishing" control={<Radio />} label="⚠️ Phishing/Dolandırıcılık" />
              </RadioGroup>
            </FormControl>
            <TextField
              fullWidth
              multiline
              rows={3}
              label="Ek yorumunuz (isteğe bağlı)"
              value={feedbackComment}
              onChange={(e) => setFeedbackComment(e.target.value)}
              placeholder="Bu URL hakkında ek bilgileriniz..."
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setFeedbackOpen(false)}>İptal</Button>
            <Button onClick={submitFeedback} variant="contained">Gönder</Button>
          </DialogActions>
        </Dialog>

        {/* Snackbar */}
        <Snackbar
          open={snackbarOpen}
          autoHideDuration={6000}
          onClose={() => setSnackbarOpen(false)}
          message={snackbarMessage}
        />
      </Container>
    </Box>
  );
}

export default App; 