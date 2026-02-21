# 🔬 AI Threat Model — Kural Büyücüsü v2

Bu belge, [Arcanum PI Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy) `ai_threat_model_questions.md` dosyasındaki sorular temel alınarak hazırlanmıştır.

---

## 1. Uygulama Tanımı

| Soru | Cevap |
|------|-------|
| Uygulama ne yapıyor? | Doğal dilde SIEM kuralları üretiyor |
| AI/LLM entegrasyonu nasıl? | OpenAI GPT API üzerinden kural kodu üretimi |
| Kullanıcı girdisi AI'ya ulaşıyor mu? | Evet — kullanıcı kural adı ve detayları doğrudan LLM'e gönderiliyor |
| Hassas veri işleniyor mu? | Hayır — yalnızca kural talep metinleri (PII yok) |
| Çıktı nereye gidiyor? | Doğrudan kullanıcıya gösteriliyor (SIEM kural kodu) |

---

## 2. Saldırı Yüzeyi Analizi

### 2.1 Giriş Noktaları (Entry Points)

| Giriş Noktası | Risk | Savunma |
|----------------|------|---------|
| Kural Adı input alanı | 🟡 Orta | Sanitization + PI scan + length limit (120) |
| Kural Detayı textarea | 🔴 Yüksek | Sanitization + PI scan + length limit (2000) |
| Platform select | 🟢 Düşük | Server-side whitelist validation |
| API endpoint (/api/generate) | 🔴 Yüksek | Multi-layer validation + rate limiting |

### 2.2 Prompt Injection Vektörleri

| Vektör (Arcanum Taxonomy) | Bu Uygulamada Risk | Mitigasyon |
|---|---|---|
| **Direct Injection** — Kullanıcı girdisinde doğrudan PI | 🔴 Kritik | Client + server PI tarama, 40+ pattern |
| **Indirect Injection** — Harici veri kaynağından PI | 🟢 Düşük | Harici veri kaynağı yok |
| **Context Manipulation** — Context window stuffing | 🟡 Orta | 2000 karakter limiti |
| **Role Assumption** — Rol değiştirme denemeleri | 🔴 Yüksek | Role-locked system prompt |
| **Delimiter Injection** — Markup/delimiter enjeksiyonu | 🔴 Yüksek | Custom delimiter isolation |
| **Encoding Evasion** — Base64/hex encoded payload | 🟡 Orta | Encoding pattern detection |
| **Token Smuggling** — Unicode/zero-width chars | 🟡 Orta | NFKC normalization |

---

## 3. Saldırı Amaçları ve Etkileri

| Amaç (Arcanum Intent) | Olası Etki | Olasılık | Savunma Durumu |
|---|---|---|---|
| **System Prompt Extraction** | Sistem prompt'u sızdırılır, iç mantık açığa çıkar | Yüksek | ✅ Delimiter isolation + leakage detection |
| **Jailbreak** | AI kısıtlamalar aşılır, istenmeyen çıktılar üretilir | Yüksek | ✅ Known pattern matching + role lock |
| **Data Exfiltration** | Ağ komutları ile veri sızdırma | Orta | ✅ Network command detection |
| **Output Manipulation** | Zararlı/yanıltıcı kural kodu üretilmesi | Orta | ✅ Output validation + format check |
| **Destructive Commands** | Yıkıcı komut üretilmesi | Düşük | ✅ Destructive pattern blocking |

---

## 4. Savunma Stratejisi

### Defense-in-Depth Yaklaşımı

```
Kullanıcı Girdisi
    ↓
[1] Input Sanitization (NFKC, zero-width, control chars)
    ↓
[2] Client-Side PI Scan (40+ patterns, risk scoring)
    ↓ ← BLOCK if risk ≥ 25
[3] Server-Side PI Scan (independent verification)
    ↓ ← BLOCK if risk ≥ 25
[4] Hardened System Prompt
    │   ├── Delimiter isolation (###TAG###)
    │   ├── Role locking (SYSTEM_ROLE_LOCKED)
    │   ├── Output constraints (format only)
    │   └── Negative instructions (ASLA, YALNIZCA)
    ↓
[5] LLM API Call (temperature: 0.3, low creativity)
    ↓
[6] Output Validation
    │   ├── System prompt leakage detection
    │   ├── Platform format verification
    │   └── Content safety check
    ↓
[7] Audit Logging (all events)
    ↓
Güvenli Çıktı
```

---

## 5. OWASP LLM Top 10 Uyumu

| OWASP LLM Risk | Uygulanabilirlik | Mitigasyon |
|---|---|---|
| LLM01: Prompt Injection | ✅ Doğrudan uygulanabilir | 5 katmanlı savunma |
| LLM02: Insecure Output Handling | ✅ Uygulanabilir | Output validation layer |
| LLM03: Training Data Poisoning | ⬜ Uygulanabilir değil | Harici model kullanılıyor |
| LLM04: Model Denial of Service | 🟡 Kısmen | Timeout + rate limiting |
| LLM05: Supply Chain Vulnerabilities | 🟡 Kısmen | Tek API bağımlılığı (OpenAI) |
| LLM06: Sensitive Information Disclosure | ✅ Uygulanabilir | Leakage detection |
| LLM07: Insecure Plugin Design | ⬜ Uygulanabilir değil | Plugin yok |
| LLM08: Excessive Agency | 🟢 Düşük risk | Yalnızca metin üretimi, eylem yok |
| LLM09: Overreliance | 🟡 Kısmen | Çıktı doğrulama uyarıları |
| LLM10: Model Theft | ⬜ Uygulanabilir değil | Harici model |

---

## 6. Kalan Riskler ve İyileştirme Önerileri

### Kısa Vadeli
- [ ] Semantic PI detection (embedding-based) eklenmesi
- [ ] Rate limiting middleware implementasyonu
- [ ] CSP (Content Security Policy) header eklenmesi
- [ ] API key rotation mekanizması

### Orta Vadeli
- [ ] LLM Guard model (küçük classifier) eklenmesi
- [ ] Honeypot prompt injection detection
- [ ] Kullanıcı bazlı rate limiting ve abuse scoring
- [ ] Canary token sistemi (prompt leakage tespiti için)

### Uzun Vadeli
- [ ] Self-hosted LLM seçeneği (veri gizliliği)
- [ ] Automated red teaming pipeline
- [ ] Community-driven PI pattern database
- [ ] SIEM platform native validation (syntax checker)

---

*Bu threat model, Arcanum PI Taxonomy v1.5 ve OWASP LLM Top 10 doğrultusunda hazırlanmıştır.*

*Attribution: PI Taxonomy by Jason Haddix, Arcanum Information Security — CC BY 4.0*
