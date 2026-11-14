# PENT-18 — Extension Native-Messaging Host Risk Analyzer

- **Öğrenci:** Abdulkadir Erkan · 2520191028
- **Ders:** MYO062 İleri Sızma Testi (Vize Seçenek 21 -> PENT-18)
- **Pull Request:** https://github.com/keyvanarasteh/os-lab/pull/189
- **Kanıt Videosu (2-4 dk):** https://drive.google.com/file/d/1c80yX_N5A6E0sR3kylxoTDKw3Hirm92n/view?usp=drive_link

## 1. Amaç ve Kapsam
Tarayıcı eklentileri (Chrome/Chromium Manifest V2 ve V3) ile işletim sistemi düzeyinde çalışan Native Messaging Host bileşenleri arasındaki yetki sınırlarını denetleyen statik ve yapılandırma tabanlı risk analiz aracı geliştirilmiştir.

## 2. Geliştirilen Dosyalar
- `source-lab/scripts/native_messaging_analyzer.py`: Eklenti manifest.json dosyalarında nativeMessaging iznini, geniş host erişimlerini, hassas API kombinasyonlarını ve zayıf CSP kurallarını; yerel Native Messaging Host manifestlerinde ise wildcard allowed_origins tanımlarını, açıkta kalan kabuk/yorumlayıcı binary hedeflerini, göreceli/geçici yolları ve herkesçe yazılabilir dosya izinlerini denetler (--json ve --fail-on-high destekli).
- `source-lab/tests/test_native_messaging_analyzer.py`: Güvenli ve yüksek riskli senaryoları, dosya sistemi izin kontrollerini ve CLI çıkış kodlarını doğrulayan 9 birim testi içerir.
- `reservations/PENT-18.json`: MYO062 vize seçenek 21 notu ve pr-open durumu ile görev rezervasyonunu kaydeder.

## 3. Doğrulama ve Test Çıktıları
- Çalıştırılan komut: `pytest source-lab/tests/test_native_messaging_analyzer.py -v`
- Sonuç: 9 passed in 0.02s
