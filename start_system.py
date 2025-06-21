#!/usr/bin/env python3
"""
🔒 Phishing Detector Sistemi Başlatma Scripti
Bu script tüm sistemi başlatır ve izler.
"""

import subprocess
import time
import sys
import os
import signal
import threading
from pathlib import Path

class PhishingDetectorSystem:
    def __init__(self):
        self.processes = []
        self.running = True
        
    def log(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")
    
    def check_python_env(self):
        """Python environment kontrolü"""
        env_path = Path("phishing_detector_env")
        if not env_path.exists():
            self.log("❌ Virtual environment bulunamadı!")
            self.log("💡 Lütfen önce 'python3 -m venv phishing_detector_env' çalıştırın")
            return False
        
        self.log("✅ Python virtual environment bulundu")
        return True
    
    def check_node_modules(self):
        """Node modules kontrolü"""
        node_modules_path = Path("node_modules")
        if not node_modules_path.exists():
            self.log("❌ Node modules bulunamadı!")
            self.log("💡 Lütfen önce 'npm install' çalıştırın")
            return False
        
        self.log("✅ Node modules bulundu")
        return True
    
    def check_model_files(self):
        """Model dosyalarını kontrol et"""
        required_files = [
            "best_phishing_model.pkl",
            "selected_features.pkl",
            "feature_importance.csv",
            "model_info.pkl"
        ]
        
        missing_files = []
        for file_name in required_files:
            if not Path(file_name).exists():
                missing_files.append(file_name)
        
        if missing_files:
            self.log(f"❌ Model dosyaları eksik: {missing_files}")
            self.log("💡 Lütfen önce 'python ml_pipeline.py' çalıştırın")
            return False
        
        self.log("✅ Tüm model dosyaları mevcut")
        return True
    
    def start_backend(self):
        """FastAPI backend'i başlat"""
        try:
            self.log("🚀 FastAPI backend başlatılıyor...")
            
            # Virtual environment'ı aktif ederek Python scriptini çalıştır
            if sys.platform == "win32":
                python_cmd = ["phishing_detector_env/Scripts/python.exe"]
            else:
                python_cmd = ["phishing_detector_env/bin/python"]
            
            backend_process = subprocess.Popen(
                python_cmd + ["app.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.processes.append(("Backend", backend_process))
            self.log("✅ FastAPI backend başlatıldı (Port: 8000)")
            
            return True
            
        except Exception as e:
            self.log(f"❌ Backend başlatma hatası: {e}")
            return False
    
    def start_frontend(self):
        """React frontend'i başlat"""
        try:
            self.log("🚀 React frontend başlatılıyor...")
            
            frontend_process = subprocess.Popen(
                ["npm", "start"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.processes.append(("Frontend", frontend_process))
            self.log("✅ React frontend başlatıldı (Port: 3000)")
            
            return True
            
        except Exception as e:
            self.log(f"❌ Frontend başlatma hatası: {e}")
            return False
    
    def start_active_learning(self):
        """Active learning sistemini başlat"""
        try:
            self.log("🧠 Active Learning sistemi başlatılıyor...")
            
            if sys.platform == "win32":
                python_cmd = ["phishing_detector_env/Scripts/python.exe"]
            else:
                python_cmd = ["phishing_detector_env/bin/python"]
            
            # Active learning'i ayrı thread'de çalıştır
            def run_active_learning():
                try:
                    subprocess.run(
                        python_cmd + ["-c", "from active_learning import run_active_learning_scheduler; run_active_learning_scheduler()"],
                        check=True
                    )
                except Exception as e:
                    self.log(f"❌ Active learning hatası: {e}")
            
            al_thread = threading.Thread(target=run_active_learning, daemon=True)
            al_thread.start()
            
            self.log("✅ Active Learning sistemi başlatıldı")
            return True
            
        except Exception as e:
            self.log(f"❌ Active Learning başlatma hatası: {e}")
            return False
    
    def monitor_processes(self):
        """Süreçleri izle"""
        while self.running:
            for name, process in self.processes:
                if process.poll() is not None:
                    self.log(f"⚠️ {name} durdu!")
                    return_code = process.returncode
                    if return_code != 0:
                        self.log(f"❌ {name} hata koduyla çıktı: {return_code}")
                        # Hata mesajını al
                        stdout, stderr = process.communicate()
                        if stderr:
                            self.log(f"🔍 {name} hata detayı: {stderr[:200]}...")
            
            time.sleep(5)  # 5 saniyede bir kontrol et
    
    def signal_handler(self, signum, frame):
        """Sinyal yakalayıcı"""
        self.log("🛑 Durdurma sinyali alındı...")
        self.stop_all()
    
    def stop_all(self):
        """Tüm süreçleri durdur"""
        self.running = False
        self.log("🔄 Tüm süreçler durduruluyor...")
        
        for name, process in self.processes:
            try:
                self.log(f"⏹️ {name} durduruluyor...")
                process.terminate()
                process.wait(timeout=10)
                self.log(f"✅ {name} durduruldu")
            except subprocess.TimeoutExpired:
                self.log(f"⚠️ {name} zorla kapatılıyor...")
                process.kill()
            except Exception as e:
                self.log(f"❌ {name} durdurma hatası: {e}")
        
        self.log("✅ Tüm süreçler durduruldu")
    
    def display_info(self):
        """Sistem bilgilerini göster"""
        print("\n" + "="*60)
        print("🔒 AI TABANLI PHİSHİNG DETECTOR SİSTEMİ")
        print("="*60)
        print()
        print("🌐 Web Arayüzü: http://localhost:3000")
        print("🔧 API Backend:  http://localhost:8000")
        print("📚 API Docs:     http://localhost:8000/docs")
        print()
        print("🎯 Kullanım:")
        print("   1. Web arayüzüne gidin")
        print("   2. Analiz edilecek URL'yi girin")
        print("   3. 'Analiz Et' butonuna tıklayın")
        print("   4. Sonuçları inceleyin")
        print("   5. Geri bildirim verin (isteğe bağlı)")
        print()
        print("⚡ Özellikler:")
        print("   • AI tabanlı phishing tespiti")
        print("   • Real-time URL analizi")
        print("   • Risk skoru hesaplama")
        print("   • Hibrit güvenlik kontrolleri")
        print("   • Active learning sistemi")
        print("   • SHAP açıklanabilirlik")
        print()
        print("🔄 Sistem durdurmak için: Ctrl+C")
        print("="*60)
        print()
    
    def run(self):
        """Ana çalıştırma fonksiyonu"""
        # Sinyal yakalayıcıları ayarla
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            self.log("🚀 Phishing Detector Sistemi başlatılıyor...")
            
            # Ön kontroller
            if not self.check_python_env():
                return False
            
            if not self.check_node_modules():
                return False
            
            if not self.check_model_files():
                return False
            
            # Sistem bileşenlerini başlat
            if not self.start_backend():
                return False
            
            time.sleep(3)  # Backend'in başlaması için bekle
            
            if not self.start_frontend():
                return False
            
            time.sleep(2)  # Frontend'in başlaması için bekle
            
            # Active learning'i başlat (isteğe bağlı)
            self.start_active_learning()
            
            # Sistem bilgilerini göster
            self.display_info()
            
            # Süreçleri izle
            self.monitor_processes()
            
        except KeyboardInterrupt:
            self.log("⏹️ Kullanıcı tarafından durduruldu")
        except Exception as e:
            self.log(f"❌ Sistem hatası: {e}")
        finally:
            self.stop_all()
        
        return True

def main():
    """Ana fonksiyon"""
    system = PhishingDetectorSystem()
    success = system.run()
    
    if success:
        print("\n✅ Sistem başarıyla çalıştırıldı!")
    else:
        print("\n❌ Sistem başlatılamadı!")
        sys.exit(1)

if __name__ == "__main__":
    main() 