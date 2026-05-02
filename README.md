# 🔐 Parola Gücü Analiz Aracı

> Shannon Entropisi tabanlı gerçek zamanlı parola değerlendirme sistemi.
> Spring Boot REST API + Statik HTML/CSS/JS arayüzü.

---

## 🚀 Projeyi Çalıştırma (3 Adımda)

### Gereksinimler
- Java 17+ → `java -version`
- Maven 3.8+ → `mvn -version`

### 1. Projeyi klonlayın / indirin
```bash
cd password-analyzer
```

### 2. Derleyin ve çalıştırın
```bash
mvn spring-boot:run
```

### 3. Tarayıcınızda açın
```
http://localhost:8080
```

**API sağlık kontrolü:**
```
http://localhost:8080/api/health
```

---

## 📡 API Kullanımı

### Parola Analizi
```bash
curl -X POST http://localhost:8080/api/analyze \
     -H "Content-Type: application/json" \
     -d '{"password": "MyP@ss2025!"}'
```

### Örnek Yanıt
```json
{
  "length": 11,
  "score": 80,
  "strengthLabel": "GÜÇLÜ",
  "strengthColor": "#22c55e",
  "hasUpperCase": true,
  "hasLowerCase": true,
  "hasDigit": true,
  "hasSpecialChar": true,
  "entropyBits": 72.06,
  "crackTimeEstimate": "24.1 milyon yıl",
  "commonPassword": false,
  "suggestions": ["Parolanızı en az 12 karakter uzunluğuna çıkarın."]
}
```

---

## 📁 Proje Yapısı

```
password-analyzer/
├── pom.xml
├── AKADEMIK_RAPOR.md
└── src/
    └── main/
        ├── java/com/passwordanalyzer/
        │   ├── PasswordAnalyzerApplication.java   ← Giriş noktası
        │   ├── controller/
        │   │   └── PasswordController.java        ← REST API
        │   ├── service/
        │   │   └── PasswordAnalyzerService.java   ← İş mantığı
        │   └── model/
        │       └── PasswordAnalysisResult.java    ← DTO
        └── resources/
            ├── application.properties
            └── static/
                └── index.html                     ← Arayüz
```

---

## 🧠 Entropi Formülü

```
H = L × log₂(R)

H : Entropi (bit)
L : Parola uzunluğu
R : Karakter havuzu büyüklüğü
  = 26 (küçük) + 26 (büyük) + 10 (rakam) + 32 (özel)
```

---

## 🛡️ Güvenlik Notu

Bu araç **eğitim ve farkındalık** amacıyla geliştirilmiştir.
Gerçek uygulamalarda parolalar ASLA düz metin olarak API'ye gönderilmemelidir;
istemci tarafında hash sonrası iletim veya HTTPS zorunludur.
