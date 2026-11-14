# MYO062 Vize Raporu — `PENT-15`: Two-Stage "Clean Dropper" Detection Harness

- **Öğrenci:** Muhammet Eren Çapan (`@Winslowe`)
- **Ders:** `MYO062` — İleri Sızma Testi (Advanced Penetration Testing)
- **Görev ID:** `PENT-15` — *Two-Stage "Clean Dropper" Detection Harness*
- **Referans Ders:** 19.10 — *Yeni nesil Truva atı (uygulama/eklenti mağazaya tertemiz girer, zararlı 2. aşama yükü sonradan buluttan çekilip `eval`/`exec` ile çalıştırılır)*

---

## 1. Mimari ve Problem Tanımı

Geleneksel statik imzalar yalnızca tekil zararlı çağrıları aradığında ya çok fazla yanlış pozitif (false positive) üretir ya da mağaza denetiminden temiz geçen **iki aşamalı yükleyicileri (clean dropper)** kaçırır. `PENT-15` kapsamında iki bileşen geliştirilmiştir:

1. **İzole İki Aşamalı Dropper Laboratuvarı (`scripts/analysis/dropper_lab/`):**
   - `stage2_server.py`: Sadece yerel geri döngü (`127.0.0.1` / `localhost`) adresinde çalışan ve dış IP/alan adlarını `assert_loopback_host()` ile reddeden yerel 2. aşama sunucusu.
   - `stage1_clean_loader.py`: 1. aşamada temiz görünen, gecikmeli tetikleme (`time.sleep`), yerel sunucudan (`127.0.0.1`) 2. aşama JSON paketini çekme (`urllib.request.urlopen`), `base64.b64decode` ile çözme ve izole sözlük alanında `compile`/`exec` ile çalıştırma zincirini simüle eden Python örneği.
   - `stage1_extension_loader.js`: Tarayıcı eklentisi (`setTimeout` + `fetch` + `atob` + `new Function`/`eval`) iki aşamalı dropper örneği.
   - `benign_utility.py`: Yanlış pozitif (false positive) olmadığını doğrulayan tamamen temiz kontrol betiği.

2. **Çok Aşamalı Korelasyon ve Tespit Motoru (`scripts/analysis/dropper_detect.py` & `console/oslab.py`):**
   - Python AST (`ast.walk`) ve yorumlardan arındırılmış satır imzalarını birleştirerek 4 aşamayı (`fetch`, `defer`, `decode`, `exec`) ayrı ayrı tespit eder.
   - **Korelasyon Motoru (`DROPPER_CHAIN_FETCH_EXEC` & `DROPPER_FULL_FOUR_STAGE_CHAIN`):** Sadece ağ isteği yapan normal betikleri (`stage2_server.py`, sıradan HTTP istemcileri) `CLEAN / BENIGN` olarak bırakırken, uzaktan veri çekme (`fetch`) ile dinamik kod çalıştırma (`exec`) aynı hedef içinde birleştiğinde hedefi `CRITICAL / TWO_STAGE_DROPPER` (`100/100`) olarak sınıflandırır.

---

## 2. Teslim Edilen Dosyalar

| Dosya Yolu | Açıklama |
| --- | --- |
| `reservations/PENT-15.json` | `MYO062` ders rezervasyon kaydı (`@Winslowe`) |
| `scripts/analysis/dropper_detect.py` | AST + imza + çok aşamalı korelasyon tespit motoru (JSON, Markdown ve `--rehearse` destekli) |
| `scripts/analysis/dropper_lab/stage2_server.py` | `127.0.0.1` kapsam korumalı yerel 2. aşama test sunucusu ve prova (`run_lab_rehearsal`) yürütücüsü |
| `scripts/analysis/dropper_lab/stage1_clean_loader.py` | Eğitim amaçlı zararsız Python 1. aşama yükleyici |
| `scripts/analysis/dropper_lab/stage1_extension_loader.js` | Eğitim amaçlı tarayıcı eklentisi 1. aşama yükleyici |
| `scripts/analysis/dropper_lab/benign_utility.py` | Negatif kontrol (False-Positive testi için temiz betik) |
| `console/oslab.py` | `oslab.dropper_audit()` konsol entegrasyonu ve `_scoped` dizin koruması |
| `android-lab/lab/tests/test_dropper_detect.py` | 14 kapsamlı çevrimdışı birim ve `127.0.0.1` prova testi |

---

## 3. Doğrulama ve Test Komutları

```bash
# 1. Markdown Raporu + Canlı 127.0.0.1 İki Aşamalı Prova
python3 scripts/analysis/dropper_detect.py scripts/analysis/dropper_lab --markdown --rehearse

# 2. JSON Çıktısı
python3 scripts/analysis/dropper_detect.py scripts/analysis/dropper_lab --json --rehearse

# 3. Birim Testleri (pytest)
pytest android-lab/lab/tests/test_dropper_detect.py -v
```

---

## 4. Örnek Tespit Özeti

| Dosya | Sınıflandırma | Risk Seviyesi | Puan | Tespit Edilen Aşamalar |
| --- | --- | :---: | :---: | --- |
| `benign_utility.py` | `BENIGN` | **CLEAN** | `0/100` | `none` |
| `stage2_server.py` | `BENIGN` | **CLEAN** | `10/100` | `defer` |
| `stage1_clean_loader.py` | `TWO_STAGE_DROPPER` | **CRITICAL** | `100/100` | `decode, defer, exec, fetch` |
| `stage1_extension_loader.js` | `TWO_STAGE_DROPPER` | **CRITICAL** | `100/100` | `decode, defer, exec, fetch` |

---

## 5. Kanıt Videosu (2–4 Dakika)

- **Video Bağlantısı:** https://youtu.be/8Q2XWHaZurc

