# 🔒 Güvenlik Politikası — Kural Büyücüsü v2

## Güvenlik Mimarisi

Kural Büyücüsü v2, AI destekli uygulamalara yönelik güvenlik tehditlerini ele almak için **5 katmanlı bir savunma mimarisi** kullanır. Bu mimari, [Arcanum Prompt Injection Taxonomy v1.5](https://github.com/Arcanum-Sec/arc_pi_taxonomy) ve [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) rehberliklerinden yararlanarak tasarlanmıştır.

### Savunma Katmanları

| Katman | Konum | İşlev |
|--------|-------|-------|
| 1. Input Sanitizer | Client + Server | Unicode normalization, zero-width karakter temizleme, kontrol karakteri sıyırma |
| 2. PI Detection Engine (Client) | Client | 40+ regex pattern ile real-time PI tespiti, risk skorlama |
| 3. PI Detection Engine (Server) | Server | Bağımsız ikinci tarama, client bypass koruması |
| 4. Hardened System Prompt | Server | Delimiter isolation, role locking, output constraints |
| 5. Output Validator | Server | Sistem prompt sızıntı tespiti, format doğrulama |

### Ek Güvenlik Önlemleri
- **Audit Logging**: Tüm istek/yanıt döngüleri loglanır
- **Rate Limiting**: Vercel edge üzerinden istek hız sınırlama
- **Input Length Limits**: Karakter sınırları (name: 120, detail: 2000)
- **Timeout Protection**: 30 saniye API timeout
- **CORS**: Yapılandırılmış cross-origin koruma

---

## Bilinen Sınırlamalar

1. **Regex-tabanlı tespit**: PI tespiti regex kalıplara dayanır; semantik olarak yeni/bilinmeyen saldırı vektörleri kaçabilir.
2. **Client-side bypass**: Client-side PI kontrolü, doğrudan API çağrıları ile atlanabilir (bu nedenle server-side ikinci katman mevcuttur).
3. **LLM inherent risk**: LLM modellerin doğası gereği deterministik olmayan çıktıları, %100 güvenlik garantisi sunmayı imkansız kılar.
4. **Encoding evasions**: Tüm encoding varyasyonlarını tespit etmek mümkün olmayabilir.

---

## Güvenlik Açığı Bildirme

Bir güvenlik açığı tespit ettiyseniz:

1. **Lütfen public issue açmayın**
2. E-posta ile bildirin: security@argunsec.com
3. Beklenen yanıt süresi: 48 saat içinde ilk dönüş
4. Responsible disclosure politikasına uyulması rica olunur

### Bildirimde Bulunulması Gerekenler
- Açığın detaylı açıklaması
- Tekrarlanabilir adımlar (steps to reproduce)
- Etkinin değerlendirilmesi (impact assessment)
- Varsa düzeltme önerisi

---

## Güvenlik Güncellemeleri

| Tarih | Versiyon | Değişiklik |
|-------|----------|------------|
| 2025-02 | v2.0 | 5 katmanlı PI savunma sistemi eklendi |
| 2025-02 | v2.0 | Arcanum PI Taxonomy v1.5 entegrasyonu |
| 2025-02 | v2.0 | Server-side PI detection katmanı |
| 2025-02 | v2.0 | Output validation ve leakage detection |

---

*Bu belge Arcanum PI Taxonomy ve OWASP LLM Top 10 rehberlikleri doğrultusunda hazırlanmıştır.*
