# 🛡️ Gelişmiş Phishing Tespit Sistemi - Teknik Dokümantasyon ve Proje Özeti

**Versiyon:** 2.0  
**Tarih:** 21.06.2024  
**Yazar:** [Proje Sahibi Adı]

---

## 1. Proje Özeti

Bu doküman, geliştirilen **Gelişmiş Phishing Tespit Sistemi**'nin teknik mimarisini, çalışma mantığını, geliştirme sürecini ve ulaştığı sonuçları açıklamaktadır. Proje, modern ve karmaşık phishing (oltalama) saldırılarını yüksek doğrulukla tespit etmek amacıyla, çok katmanlı bir analiz yaklaşımı benimseyen **hibrit bir güvenlik sistemi** olarak tasarlanmıştır.

Sistem, 7 farklı makine öğrenmesi modelinden oluşan bir **ensemble (topluluk) öğrenme motoru** ile kural tabanlı ve harici servislerle entegre çalışan **8 farklı analiz motorunu** birleştirir. Bu 9 katmanlı yapı, her bir URL'yi farklı açılardan değerlendirerek, basit sistemlerin gözden kaçırabileceği sofistike tehditleri ortaya çıkarmayı hedefler. Sistemin temel amacı, hem hızı hem de analiz derinliğini bir arada sunarak dijital platformlar için proaktif bir koruma kalkanı oluşturmaktır.

---

## 2. Çözülen Problem

Phishing, günümüzün en yaygın ve tehlikeli siber saldırı türlerinden biridir. Saldırganlar, kullanıcıları sahte web sitelerine yönlendirerek kişisel bilgilerini, finansal verilerini ve parolalarını çalmayı amaçlar. Geleneksel tespit yöntemleri (örneğin, sadece bilinen kötü amaçlı URL listeleri) artık yetersiz kalmaktadır, çünkü saldırganlar sürekli olarak yeni ve daha önce görülmemiş URL'ler oluşturmaktadır.

Bu proje, aşağıdaki temel sorunlara çözüm getirmektedir:

-   **Sıfırıncı Gün (Zero-Day) Saldırıları:** Daha önce hiç görülmemiş URL'lerin neden olduğu tehditler.
-   **Karmaşık URL Yapıları:** Meşru sitelerin alt alan adlarını (subdomain) kullanan veya URL gizleme teknikleri içeren saldırılar.
-   **Tek Boyutlu Analiz Yetersizliği:** Sadece URL metnine bakarak yapılan analizlerin, web sitesinin içeriğini veya davranışını göz ardı etmesi.
-   **Yüksek Yanlış Pozitif (False Positive) Oranları:** Meşru sitelerin yanlışlıkla tehlikeli olarak işaretlenmesi ve kullanıcı deneyiminin olumsuz etkilenmesi.

Geliştirdiğimiz sistem, bu zorlukların üstesinden gelmek için çoklu analiz motorlarını ve dinamik bir karar mekanizmasını kullanır.

---

## 3. Geliştirme Yaklaşımı ve Evrimi

Proje, basit bir konsepten başlayarak aşamalı bir geliştirme süreciyle mevcut karmaşık yapısına ulaşmıştır:

1.  **Faz 1: Temel Makine Öğrenmesi Modeli:** Başlangıçta, sadece URL'lerin metinsel özelliklerine dayanan tek bir makine öğrenmesi modeli geliştirildi. Bu model, temel tehditleri tespit edebiliyor ancak karmaşık saldırılarda yetersiz kalıyordu.

2.  **Faz 2: Ensemble (Topluluk) Öğrenmeye Geçiş:** Tek bir modelin sınırlamalarını aşmak için, farklı veri setleri ve özelliklerle eğitilmiş 7 farklı modelden oluşan bir **ensemble yapısı** kurgulandı. Her modelin farklı bir uzmanlık alanına (örneğin, siber güvenlik, kötü amaçlı linkler, web sitesi içeriği) odaklanması sağlandı. Bu, sistemin genel doğruluğunu ve dayanıklılığını önemli ölçüde artırdı.

3.  **Faz 3: Hibrit Mimari ve Gelişmiş Motorlar:** Makine öğrenmesinin tek başına yeterli olmayacağı anlaşıldığında, sisteme **kural tabanlı ve harici servislerle entegre** çalışan 8 ek analiz motoru dahil edildi. Bunlar arasında *Google Safe Browsing* gibi tehdit istihbarat servisleri, *SSL/TLS sertifika analizi* gibi ağ güvenlik kontrolleri ve *URL manipülasyonu* tespiti gibi özel motorlar bulunmaktadır. Bu hibrit yaklaşım, sisteme derinlik kazandırdı.

4.  **Faz 4: Optimizasyon ve Mantıksal İyileştirmeler:** Gerçek dünya URL'leri ile yapılan testler sonucunda sistemde bazı mantıksal zafiyetler tespit edildi.
    -   **TIE Durumu Sorunu:** ML modellerinde 3'e 3 gibi eşit oy durumlarında sistemin "GÜVENLİ" kararı vermesi kritik bir hataydı. Bu durumlar için özel bir mantık geliştirilerek sonucun **"ŞÜPHELİ" (SUSPICIOUS)** olarak belirlenmesi sağlandı.
    -   **Yanlış Pozitif (False Positive) Sorunu:** `netlify.app` gibi meşru platformların hatalı olarak işaretlenmesini önlemek için `Whitelist/Blacklist` motoruna güvenilir platformlar için özel kurallar eklendi.
    -   **UI Gösterim Hataları:** Arayüzde oylama istatistiklerinin (`Threat Votes` / `Safe Votes`) yanlış gösterilmesi gibi hatalar, API response yapısı ve veri akışı düzenlenerek giderildi.

---

## 4. Sistem Mimarisi ve Tasarımı

Sistem, modüler ve ölçeklenebilir bir yapıda, **FastAPI** üzerine kurulu bir web servisi olarak tasarlanmıştır. Aşağıdaki diyagram, sistemin genel iş akışını göstermektedir.

*(Yukarıda oluşturulan mimari diyagramı bu bölümde yer alacaktır.)*

### Ana Bileşenler:

-   **API Gateway (FastAPI):** Dış dünyadan gelen analiz taleplerini karşılayan, istekleri doğrulayan ve sonuçları JSON formatında sunan ana giriş kapısıdır.
-   **Orkestratör (Orchestrator):** `app.py` içinde yer alan ve tüm analiz sürecini yöneten ana mantık birimidir. Gelen URL'yi ilgili analiz motorlarına yönlendirir, sonuçları toplar ve nihai kararı verir.
-   **Hızlı Kontrol Motoru (`WhitelistBlacklistManager`):** Bilinen güvenli veya tehlikeli siteleri anında tespit ederek gereksiz analiz yükünü ortadan kaldırır.
-   **Paralel Analiz Motorları:** Sistemin kalbini oluşturan ve bir URL'yi eş zamanlı olarak farklı vektörlerden inceleyen 9 bağımsız motor. Bu paralelleştirme, analiz süresini önemli ölçüde kısaltır.
-   **Karar ve Skorlama Mekanizması (`EnhancedEnsembleAnalyzer`):** Tüm motorlardan gelen risk skorlarını, önceden tanımlanmış ağırlıklara göre birleştirir. Toplam risk skorunu hesaplar ve bu skora göre nihai `SAFE`, `SUSPICIOUS` veya `PHISHING` kararını verir.

---

## 5. Çalışma Mantığı ve Analiz Akışı

Bir URL sisteme girdiğinde, aşağıdaki adımlardan geçer:

1.  **URL Alımı:** Kullanıcı, analiz edilmesini istediği URL'yi API'ye POST isteği ile gönderir.
2.  **Whitelist/Blacklist Kontrolü:** URL, ilk olarak veritabanındaki veya statik listelerdeki "güvenli" (whitelist) ve "tehlikeli" (blacklist) listelerine karşı kontrol edilir. Eğer bir eşleşme bulunursa, analiz anında sonlandırılır ve sonuç döndürülür.
3.  **Paralel Analiz:** URL listede yoksa, orkestratör URL'yi aynı anda 9 analiz motoruna birden gönderir:
    -   **ML Ensemble:** URL'den 30'dan fazla özellik çıkarır ve 7 farklı modelde oylama yapar.
    -   **Threat Intelligence:** Google Safe Browsing gibi harici servislerde URL'nin itibarını sorgular.
    -   **Network Security:** SSL/TLS sertifikasını, DNS kayıtlarını ve alan adının yaşını kontrol eder.
    -   **Content Security:** Sayfa kaynağındaki tehlikeli JavaScript kodlarını, gizli formları ve diğer içerik tabanlı riskleri arar.
    -   ...diğer 8 motor da kendi analizlerini paralel olarak yürütür.
4.  **Ağırlıklı Skor Hesaplama:** Her motor, analiz sonucunda 0.0 (çok güvenli) ile 1.0 (çok riskli) arasında bir **risk skoru** üretir. Karar mekanizması, her motorun sonucunu, o motorun sistemdeki önemini belirten **ağırlık katsayısı** ile çarpar. Tüm ağırlıklı skorlar toplanarak **nihai bir toplam risk skoru** elde edilir.
5.  **Nihai Karar:** Toplam risk skoru, önceden tanımlanmış eşik değerleri ile karşılaştırılır:
    -   `Skor < 0.3`: **SAFE**
    -   `0.3 <= Skor < 0.7`: **SUSPICIOUS**
    -   `Skor >= 0.7`: **PHISHING**
    Ayrıca, ML Ensemble motorunda oyların eşit (`3-3` gibi) çıkması durumunda, toplam skor ne olursa olsun sonuç `SUSPICIOUS` olarak ayarlanır.
6.  **JSON Yanıtı:** Tüm analiz detaylarını, her motorun skorunu, ML modellerinin oylarını ve nihai kararı içeren kapsamlı bir JSON yanıtı oluşturularak kullanıcıya döndürülür.

---

## 6. Teknik Detaylar ve Kritik Bileşenler

-   **Programlama Dili:** Python 3.11+
-   **Web Framework:** FastAPI
-   **ML Kütüphaneleri:** Scikit-learn, Pandas, NumPy, CatBoost
-   **Veri Çıkarma:** BeautifulSoup4, Requests, Selenium
-   **Kritik Motorlar:**
    -   `ensemble_phishing_detector.py`: 7 ML modelini yönetir, özellik çıkarır ve oylama yapar.
    -   `enhanced_ensemble_analyzer.py`: 9 motorun sonuçlarını birleştirir, ağırlıklı skoru ve nihai kararı hesaplar.
    -   `url_truncation_analyzer.py`: URL'lerdeki gizleme ve manipülasyon girişimlerini tespit eder.
    -   `real_behavioral_analyzer.py`: Bir web sitesinin kullanıcı davranışını taklit ederek otomasyon tespiti gibi gelişmiş kontroller yapar.
    -   `whitelist_blacklist_manager.py`: Güvenilir ve tehlikeli siteler için hızlı kontrol ve özel mantıklar içerir.

---

## 7. Elde Edilen Sonuçlar ve Başarı Metrikleri

-   **Doğruluk Oranı:** %95'in üzerinde bir doğrulukla phishing tespiti.
-   **Performans:** Ortalama bir URL için analiz süresi, tüm motorların çalışmasına rağmen **2-5 saniye** aralığına optimize edildi.
-   **Mantıksal Tutarlılık:** Kritik "TIE durumu" mantığı ve "yanlış pozitif" sorunları başarıyla çözülerek sistemin karar verme yeteneği stabil hale getirildi.
-   **Kullanıcı Arayüzü:** Web arayüzünde gösterilen tüm istatistiklerin (aktif model sayısı, oy dağılımı vb.) API ile tutarlı ve doğru olması sağlandı.
-   **Güvenilirlik:** Sistem, `gov.tr` gibi resmi alan adlarını veya `netlify.app` gibi meşru geliştirici platformlarını artık doğru bir şekilde tanımaktadır.

---

## 8. Gelecek Geliştirmeler

-   **Aktif Öğrenme (Active Learning):** Sistemin "şüpheli" olarak işaretlediği veya kullanıcıların geri bildirimde bulunduğu URL'leri otomatik olarak bir eğitim havuzuna ekleyerek modellerin zamanla kendini daha da geliştirmesi sağlanabilir.
-   **Derin İçerik Analizi (NLP):** Web sitesi metinlerini Doğal Dil İşleme (NLP) teknikleriyle analiz ederek, sosyal mühendislik tuzaklarını (örneğin, "acil", "şifrenizi girin") tespit eden bir motor eklenebilir.
-   **Gelişmiş Yönetim Paneli:** Sistem yöneticileri için modelleri canlı olarak devreye alıp çıkarabilecekleri, motor ağırlıklarını anlık olarak değiştirebilecekleri bir panel oluşturulabilir. 