package com.passwordanalyzer;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/**
 * PasswordController — HTTP istek/yanıt katmanı.
 *
 * Bu sınıf yalnızca şunlardan sorumludur (SRP):
 *   1. Gelen HTTP isteğini doğrula
 *   2. Servisi çağır
 *   3. HTTP yanıtını oluştur
 *
 * İş mantığı kesinlikle bu sınıfta yer almaz; tümü PasswordAnalyzerService'tedir.
 *
 * @RestController  : @Controller + @ResponseBody birleşimi (JSON otomatik dönüşüm)
 * @RequestMapping  : Bu controller'daki tüm uç noktaların kök yolu
 * @CrossOrigin     : Frontend'in (farklı port) API'ye erişimine izin verir (CORS)
 * @Validated       : Metot parametrelerindeki validation anotasyonlarını etkinleştirir
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")   // Geliştirme ortamı için tüm kaynaklara izin ver
@Validated
public class PasswordController {

    // Spring IoC Container bu bağımlılığı constructor injection ile otomatik sağlar.
    // (DIP: Controller somut sınıfa değil, Spring'in yönettiği Bean'e bağlanır)
    private final PasswordAnalyzerService analyzerService;

    public PasswordController(PasswordAnalyzerService analyzerService) {
        this.analyzerService = analyzerService;
    }

    // ──────────────────────────────────────────────────────────────────────────
    //  ANALİZ UÇNOKTASI
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * POST /api/analyze
     *
     * İstek gövdesi (JSON):
     * {
     *   "password": "MyP@ss123"
     * }
     *
     * Başarılı Yanıt (200 OK):
     * {
     *   "length": 9,
     *   "score": 70,
     *   "strengthLabel": "GÜÇLÜ",
     *   ...
     * }
     *
     * @param request Parola içeren istek nesnesi
     * @return ResponseEntity içinde PasswordAnalysisResult
     */
    @PostMapping("/analyze")
    public ResponseEntity<PasswordAnalysisResult> analyzePassword(
            @RequestBody PasswordRequest request) {

        // Servis katmanını çağır ve sonucu HTTP 200 OK ile döndür
        PasswordAnalysisResult result = analyzerService.analyze(request.getPassword());
        return ResponseEntity.ok(result);
    }

    // ──────────────────────────────────────────────────────────────────────────
    //  SAĞLIK KONTROLÜ UÇNOKTASI
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * GET /api/health
     * Uygulamanın çalışıp çalışmadığını doğrular.
     */
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("✅ Password Analyzer API çalışıyor.");
    }

    // ──────────────────────────────────────────────────────────────────────────
    //  İÇ SINIF: İstek Nesnesi
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * İstek gövdesinin (Request Body) POJO karşılığı.
     * Validation kısıtlamaları burada tanımlanır:
     *   @NotBlank : Boş veya yalnızca boşluk içeren değeri reddeder
     *   @Size     : Maksimum 1000 karakter (sunucu kaynağını koru)
     */
    public static class PasswordRequest {

        @NotBlank(message = "Parola boş olamaz.")
        @Size(max = 1000, message = "Parola 1000 karakterden uzun olamaz.")
        private String password;

        public PasswordRequest() {}

        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }
}