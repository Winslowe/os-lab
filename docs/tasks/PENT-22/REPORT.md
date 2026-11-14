# PENT-22: AI-Use Disclosure & Analysis Report Generator

## Proje Özeti
Bu proje (PENT-22), bir sızma testi oturum kaydını (session log) okuyarak standartlara uygun, yapay zeka kullanımını şeffaf bir şekilde beyan eden ve tekrarlanabilirlik adımlarını (reproducibility steps) içeren bir rapor üretir.

## Yapılan İşlemler
1. **Scope Guard Entegrasyonu:** Script, log dosyası içinde hedef dışı (out-of-scope) bir sistemin test edilip edilmediğini kontrol eder. Sadece `127.x`, `10.x` gibi lokal ağları kabul eder.
2. **Otomatik Raporlama:** Log dosyasındaki komutları ayrıştırarak raporun içine ekler.
3. **AI Şeffaflığı:** Raporun sonuna otomatik olarak bir AI-Use (Yapay Zeka Kullanım) eki ekler.
4. **Test & CI Uyumluluğu:** Script, reponun zorunlu kıldığı `bash -n` sözdizimi kontrollerini geçecek şekilde `set -euo pipefail` standartlarında yazılmıştır.

## Kanıt Videosu
**VİDEO LİNKİ:** <https://drive.google.com/file/d/1NQ9x2WOvh4Weqyav9WMqDIoI7yWhghT9/view?usp=sharing>
