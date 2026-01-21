
---

# 🕶 DarkTLS — Offensive TLS & HTTP Exposure Analyzer

**DarkTLS**, bir hedef alan adının TLS ve HTTP yapılandırmasını **saldırgan perspektifinden** inceleyen, **aktif exploit çalıştırmayan** fakat **gerçekçi saldırı yüzeylerini** teknik olarak ortaya koyan bir analiz aracıdır.

Bu araç bir *vulnerability scanner* ya da *exploit framework* değildir.
Ama bir saldırganın **nereden başlayacağını** net şekilde gösterir.

---

## 🎯 DarkTLS Ne Yapar?

DarkTLS, hedef sistem üzerinde:

* TLS kullanılıp kullanılmadığını **aktif bağlantı kurarak** test eder
* TLS varsa:

  * Sertifika ve PKI yapılandırmasını **offensive bakış açısıyla** analiz eder
  * Certificate Transparency, OCSP, Must-Staple gibi **ileri seviye güven zinciri kontrollerini** inceler
* TLS yoksa veya HTTP açıksa:

  * Gerçek saldırı senaryolarına dayalı **HTTP risk analizi** yapar
* Bulguları **“attacker view”** formatında yorumlar

❗ DarkTLS **exploit üretmez**, **payload göndermez**, **sistemi değiştirmez**.

---

## 🧪 Analiz mi, Test mi?

**DarkTLS bir güvenlik analiz aracıdır.**

✔ Yapılandırma ve mimari zayıflıkları tespit eder
✔ Gerçek TLS/HTTP davranışını temel alır
✔ Saldırı öncesi keşif (pre-attack reconnaissance) için uygundur

❌ Aktif saldırı gerçekleştirmez
❌ TLS kırma / brute-force yapmaz
❌ MITM kurmaz

---

## 🧠 Çalışma Mimarisi (High-Level)

```
[TLS Port Discovery]
        ↓
[TLS / PKI Offensive Analysis]
        ↓
[HTTP Offensive Analysis]
        ↓
[Attacker-Oriented Risk Summary]
```

---

## 🔍 TLS Discovery (Aktif Keşif)

DarkTLS aşağıdaki portlarda **gerçek TLS handshake** dener:

```
443, 8443, 9443, 10443, 4443, 7443
```

Her port için:

* TLS bağlantısı kurulur
* Sunucunun **gerçek sertifikası** çekilir
* OCSP stapling varsa alınır

Bu işlem simülasyon değildir; **canlı bağlantı** üzerinden yapılır.

---

## 🔐 TLS Offensive Analysis (PKI Odaklı)

### ✔ Certificate Transparency (CT)

Kontrol edilen OID:

```
1.3.6.1.4.1.11129.2.4.2
```

| Durum     | Anlam                                          |
| --------- | ---------------------------------------------- |
| CT mevcut | Sertifika CT loglarına kayıtlı                 |
| CT yok    | Sahte sertifika senaryoları fark edilmeyebilir |

**Attacker View:**
CT yokluğu, yanlış veya rogue CA tarafından üretilmiş sertifikaların geç fark edilmesine yol açabilir.

---

### ✔ Must-Staple & OCSP Stapling

Kontrol edilen OID:

```
1.3.6.1.5.5.7.1.24
```

Analiz edilen senaryolar:

* Sertifika Must-Staple istiyor mu?
* Sunucu gerçekten stapled OCSP yanıtı gönderiyor mu?

| Senaryo                      | Risk                      |
| ---------------------------- | ------------------------- |
| Must-Staple var + Staple yok | OCSP soft-fail            |
| Must-Staple yok              | Revocation kontrolü zayıf |

**Attacker View:**
İptal edilmiş bir sertifika, bazı istemcilerde fark edilmeden kabul edilebilir.

---

## 🌐 HTTP Offensive Analysis

TLS yoksa veya HTTP erişim açıksa, DarkTLS:

### 🔹 HTTP → HTTPS Redirect Kontrolü

* Zorunlu yönlendirme yoksa **SSL stripping** mümkündür

### 🔹 Cookie Güvenliği

* `Secure` flag olmayan cookie’ler tespit edilir
* **Session hijacking** yüzeyi değerlendirilir

### 🔹 Credential Exposure

* HTTP üzerinden `password` input alanları aranır
* Kimlik bilgisi sızıntısı riski raporlanır

### 🔹 HSTS Kontrolü

* `Strict-Transport-Security` header yokluğu analiz edilir

Bu kontroller **gerçek saldırı ön koşullarına** dayanır.

---

## 🧨 Attack Summary (Saldırgan Bakışı)

DarkTLS yalnızca “şu eksik” demez.

Her risk için:

* Neden kritik olduğu
* Hangi saldırıya zemin hazırladığı
* Pratikte nasıl sömürülebileceği

net şekilde açıklanır.

Örnek:

```
Session hijack
→ Secure olmayan cookie ağ seviyesinde ele geçirilebilir.
```

Bu bölüm **pentest raporlarında doğrudan kullanılabilir**.

---

## ⚙️ Gereksinimler

* Python 3.9+
* Gerekli kütüphaneler:

  * cryptography
  * requests

Harici OpenSSL bağımlılığı yoktur.

---

## ▶️ Kullanım

```
python3 darktls.py hedef.com
```

Script otomatik olarak:

* TLS portlarını dener
* Analizi başlatır
* Risk özetini üretir

---

## 📊 Çıktı Yapısı

* Renkli terminal çıktısı
* Risk bazlı sınıflandırma
* Attacker-oriented açıklamalar

JSON veya HTML üretmez (bilinçli tasarım kararı).

---

## 🧠 Kimler İçin?

✔ Red Team
✔ Pentester
✔ Security Engineer
✔ Blue Team (TLS hardening doğrulama)
✔ Güvenlik mimarisi değerlendirmesi

❌ Otomatik exploit arayanlar
❌ Script-kiddie kullanım senaryoları

---

## ⚠️ Yasal ve Etik Uyarı

Bu araç **yalnızca yetkili sistemlerde**,
test, analiz ve eğitim amaçlı kullanılmalıdır.

Yetkisiz kullanım **hukuki sorumluluk doğurur**.

---

## 📌 Kısa Özet

DarkTLS sana:

> “Bu sistem hacklenir mi?”
> değil,

> **“Bir saldırgan nereden başlar?”**
> sorusunun cevabını verir.

---
