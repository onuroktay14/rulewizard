// Bu kod, Vercel Serverless Function olarak çalışacaktır.
// Anahtarınızı process.env.GEMINI_API_KEY ortam değişkeninden okur.

const { GoogleGenerativeAI } = require("@google/genai");

// Ortam değişkeninden API anahtarını güvenli bir şekilde okur
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

// API anahtarı yoksa hata fırlat
if (!GEMINI_API_KEY) {
    throw new Error("GEMINI_API_KEY ortam değişkeni ayarlanmadı.");
}

// SDK'yı başlat
const ai = new GoogleGenerativeAI(GEMINI_API_KEY);
const model = "gemini-2.5-flash-preview-09-2025";

// Vercel/Node.js Serverless Function Handler
module.exports = async (req, res) => {
    // Sadece POST isteklerini kabul et
    if (req.method !== 'POST') {
        res.status(405).json({ message: 'Method Not Allowed' });
        return;
    }

    try {
        const { siemPlatform, userRequest, ruleName } = req.body;

        if (!siemPlatform || !userRequest) {
            res.status(400).json({ message: 'SIEM platformu ve kural talebi zorunludur.' });
            return;
        }

        // SIEM Platformu ve Syntax bilgisi
        let syntaxInfo;
        switch(siemPlatform) {
            case 'Splunk':
                syntaxInfo = "Splunk Search Processing Language (SPL)";
                break;
            case 'QRadar':
                syntaxInfo = "QRadar AQL veya QID/LEF tabanlı kural/arama sintaksı";
                break;
            case 'LogSign':
                syntaxInfo = "LogSign Query Language (LQL) sintaksı";
                break;
            case 'Wazuh':
                syntaxInfo = "Wazuh Manager XML Kural Sintaksı (Decoders, Ruleset)";
                break;
            default:
                syntaxInfo = "genel SIEM kural sintaksı";
        }

        const systemPrompt = `Sen bir kıdemli Siber Güvenlik Analisti ve SIEM Kural Geliştiricisiniz. Görevin, kullanıcının talebini alıp, seçilen SIEM platformuna ait doğru ve çalışır kural kodunu üretmektir.
        
        1. Ürettiğiniz kural, hedef platformun (örn: ${siemPlatform}) güncel sintaks yapısına (${syntaxInfo}) tam olarak uymalıdır.
        2. Kuralın içine, kuralın amacını, hangi log kaynaklarını hedeflediğini ve neden önemli olduğunu açıklayan kısa Türkçe yorumlar ekleyin.
        3. Yanıtınız sadece kural kodunu içermelidir (ekstra konuşma metni veya açıklama OLMAMALIDIR).
        4. Kural için gerekli tüm alan isimleri (field names) ve değerleri doğru bir şekilde kullanılmalıdır.
        5. Talep, güncel tehditlere dayanıyorsa (örneğin Powershell komutları), güncel bilgi kullanın.
        `;

        const userQuery = `Platform: ${siemPlatform}. Talep: "${userRequest}". Bu talebe uygun, çalışır ve yorumlanmış bir ${siemPlatform} kuralı üret.`;

        const requestPayload = {
            contents: [{ parts: [{ text: userQuery }] }],
            // Google Search Grounding ile güncel bilgi sağla
            tools: [{ google_search: {} }],
            systemInstruction: { parts: [{ text: systemPrompt }] },
        };

        const apiResponse = await ai.models.generateContent({
            model: model,
            contents: requestPayload.contents,
            config: {
                tools: requestPayload.tools,
                systemInstruction: requestPayload.systemInstruction.parts[0].text,
            },
        });


        const candidate = apiResponse.candidates?.[0];
        let responseText = candidate?.content?.parts?.[0]?.text;
        let sources = [];

        // Kaynak Atıflarını Çıkar
        const groundingMetadata = candidate?.groundingMetadata;
        if (groundingMetadata && groundingMetadata.groundingAttributions) {
            sources = groundingMetadata.groundingAttributions
                .map(attribution => ({
                    uri: attribution.web?.uri,
                    title: attribution.web?.title,
                }))
                .filter(source => source.uri && source.title);
        }

        if (responseText) {
            // Başarılı yanıtı döndür
            res.status(200).json({ text: responseText, sources: sources });
        } else {
            // LLM'den yanıt gelmediyse hata döndür
            res.status(500).json({ message: 'Model yanıt üretmede başarısız oldu.' });
        }

    } catch (error) {
        console.error("Gemini API Error:", error.message);
        // Hata mesajını istemciye döndür
        res.status(500).json({ message: error.message || 'Harici API isteği sırasında bir hata oluştu.' });
    }
};
