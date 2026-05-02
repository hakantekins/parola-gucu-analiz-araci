package com.passwordanalyzer;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * PasswordAnalyzerService — Tüm parola analiz mantığını barındıran servis katmanı.
 *
 * Bu sınıf SOLID prensiplerini şu şekilde uygular:
 *   S (SRP)  : Yalnızca parola analizi yapar; HTTP veya UI katmanıyla ilgilenmez.
 *   O (OCP)  : Yeni kontroller private metot ekleyerek genişletilebilir.
 *   D (DIP)  : Controller bu sınıfa arayüz üzerinden değil, Spring IoC ile bağlanır.
 *
 * @Service anotasyonu Spring'in bu sınıfı bir Bean olarak yönetmesini sağlar.
 */
@Service
public class PasswordAnalyzerService {

    // ──────────────────────────────────────────────────────────────────────────
    //  SABITLER
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Kaba kuvvet hız varsayımı: Modern GPU kümelerinin saniyede deneyebileceği
     * parola sayısı (10 milyar = 1×10^10 deneme/sn).
     * Kaynak: Hashcat benchmark, bcrypt dışı algoritmalar için makul üst sınır.
     */
    private static final double GUESSES_PER_SECOND = 1e10;

    /**
     * Yaygın / zayıf parola sözlüğü.
     * Gerçek dünya uygulamalarında bu liste 10.000+ kayıt içerebilir
     * (HaveIBeenPwned, RockYou gibi veri tabanları kullanılabilir).
     */
    private static final Set<String> COMMON_PASSWORDS = Set.of(
            "123456", "password", "123456789", "12345678", "12345",
            "1234567", "1234567890", "qwerty", "abc123", "password1",
            "iloveyou", "admin", "letmein", "monkey", "1234",
            "dragon", "master", "sunshine", "princess", "welcome",
            "shadow", "superman", "michael", "football", "mustang",
            "parola", "sifre", "şifre", "123123", "000000",
            "pass", "test", "asdfgh", "zxcvbn", "qazwsx",
            "password123", "admin123", "root", "toor", "guest",
            "login", "hello", "computer", "access", "baseball"
    );

    // ──────────────────────────────────────────────────────────────────────────
    //  ANA ANALİZ METODU
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Verilen parolayı kapsamlı biçimde analiz eder ve sonuç nesnesini döndürür.
     *
     * @param password Analiz edilecek parola (ham metin)
     * @return PasswordAnalysisResult — tüm metrikleri içeren sonuç nesnesi
     */
    public PasswordAnalysisResult analyze(String password) {
        PasswordAnalysisResult result = new PasswordAnalysisResult();

        // 1. Temel karakter özelliklerini belirle
        result.setLength(password.length());
        result.setHasUpperCase(containsUpperCase(password));
        result.setHasLowerCase(containsLowerCase(password));
        result.setHasDigit(containsDigit(password));
        result.setHasSpecialChar(containsSpecialChar(password));

        // 2. Entropi hesapla
        double entropy = calculateEntropy(password);
        result.setEntropyBits(Math.round(entropy * 100.0) / 100.0);

        // 3. Kırılma süresini tahmin et
        result.setCrackTimeEstimate(estimateCrackTime(entropy));

        // 4. Sözlük saldırısı kontrolü
        boolean isCommon = isCommonPassword(password);
        result.setCommonPassword(isCommon);
        if (isCommon) {
            result.setDictionaryWarning(
                    "⚠️ Bu parola yaygın parola listesinde bulunuyor! " +
                            "Sözlük saldırısına karşı savunmasız."
            );
        }

        // 5. Puan hesapla (0–100)
        int score = calculateScore(result, isCommon);
        result.setScore(score);

        // 6. Güç etiketi ve rengini belirle
        applyStrengthLabel(result, score);

        // 7. İyileştirme önerileri oluştur
        result.setSuggestions(generateSuggestions(result, password));

        return result;
    }

    // ──────────────────────────────────────────────────────────────────────────
    //  KARAKTER ÇEŞİTLİLİĞİ KONTROLLERİ
    // ──────────────────────────────────────────────────────────────────────────

    /** Parolada en az bir büyük harf (A–Z) var mı? */
    private boolean containsUpperCase(String password) {
        return password.chars().anyMatch(Character::isUpperCase);
    }

    /** Parolada en az bir küçük harf (a–z) var mı? */
    private boolean containsLowerCase(String password) {
        return password.chars().anyMatch(Character::isLowerCase);
    }

    /** Parolada en az bir rakam (0–9) var mı? */
    private boolean containsDigit(String password) {
        return password.chars().anyMatch(Character::isDigit);
    }

    /**
     * Parolada en az bir özel karakter var mı?
     * Regex: Harf ve rakam olmayan her karakter özel sayılır.
     */
    private boolean containsSpecialChar(String password) {
        return password.chars().anyMatch(c -> !Character.isLetterOrDigit(c));
    }

    // ──────────────────────────────────────────────────────────────────────────
    //  ENTROPİ HESAPLAMA
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Shannon Entropisini hesaplar.
     *
     * Formül: H = L × log₂(R)
     *   H : Entropi (bit)
     *   L : Parola uzunluğu
     *   R : Karakter havuzu büyüklüğü
     *
     * Karakter havuzu (R):
     *   Küçük harf     → +26
     *   Büyük harf     → +26
     *   Rakam          → +10
     *   Özel karakter  → +32 (standart klavye özel karakterleri)
     *
     * Örnek: "P@ss1" → R = 26+26+10+32 = 94, L = 5
     *         H = 5 × log₂(94) ≈ 32.8 bit
     *
     * @param password Entropi hesaplanacak parola
     * @return Entropi değeri (bit cinsinden)
     */
    private double calculateEntropy(String password) {
        int charsetSize = 0;

        if (containsLowerCase(password))   charsetSize += 26;
        if (containsUpperCase(password))   charsetSize += 26;
        if (containsDigit(password))       charsetSize += 10;
        if (containsSpecialChar(password)) charsetSize += 32;

        // Hiçbir grup yoksa (örneğin boş girdi) minimum 1 varsay
        if (charsetSize == 0) return 0;

        // H = L × log₂(R)
        return password.length() * (Math.log(charsetSize) / Math.log(2));
    }

    // ──────────────────────────────────────────────────────────────────────────
    //  KIRILMA SÜRESİ TAHMİNİ
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Verilen entropi değerine göre tahmini kaba kuvvet kırılma süresini hesaplar.
     *
     * Toplam kombinasyon sayısı: C = 2^H
     * Ortalama denemede bulunma: C / 2 (istatistiksel beklenti)
     * Tahmin edilen süre (sn): (2^H / 2) / GUESSES_PER_SECOND
     *
     * @param entropyBits Parolanın bit cinsinden entropisi
     * @return İnsan okunabilir süre metni
     */
    private String estimateCrackTime(double entropyBits) {
        if (entropyBits <= 0) return "Anlık";

        // 2^H / 2 / saniyedeki_deneme_sayısı
        double totalCombinations = Math.pow(2, entropyBits);
        double secondsTocrack = (totalCombinations / 2.0) / GUESSES_PER_SECOND;

        return formatSeconds(secondsTocrack);
    }

    /**
     * Saniye cinsinden süreyi okunabilir zaman dilimine çevirir.
     * (mikrosaniyelerden trilyon yıllara kadar ölçekli)
     */
    private String formatSeconds(double seconds) {
        if (seconds < 0.001)           return "Anlık (< 1 ms)";
        if (seconds < 1)               return String.format("%.0f milisaniye", seconds * 1000);
        if (seconds < 60)              return String.format("%.1f saniye", seconds);
        if (seconds < 3_600)           return String.format("%.1f dakika", seconds / 60);
        if (seconds < 86_400)          return String.format("%.1f saat", seconds / 3_600);
        if (seconds < 2_592_000)       return String.format("%.1f gün", seconds / 86_400);
        if (seconds < 31_536_000)      return String.format("%.1f ay", seconds / 2_592_000);
        if (seconds < 31_536_000_000L) return String.format("%.1f yıl", seconds / 31_536_000);
        if (seconds < 3.156e13)        return String.format("%.1f bin yıl", seconds / 31_536_000_000L);
        if (seconds < 3.156e16)        return String.format("%.1f milyon yıl", seconds / 3.156e13);
        return "Evrenin ömründen fazla (pratik olarak kırılamaz)";
    }

    // ──────────────────────────────────────────────────────────────────────────
    //  SÖZLÜK SALDIRISI SİMÜLASYONU
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Parolanın yaygın parola sözlüğünde bulunup bulunmadığını kontrol eder.
     * Karşılaştırma büyük/küçük harf duyarsızdır.
     *
     * @param password Kontrol edilecek parola
     * @return true ise sözlükte eşleşme var
     */
    private boolean isCommonPassword(String password) {
        return COMMON_PASSWORDS.contains(password.toLowerCase());
    }

    // ──────────────────────────────────────────────────────────────────────────
    //  PUAN HESAPLAMA (0–100)
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Ağırlıklı kriter puanlaması ile 0–100 arası güç skoru üretir.
     *
     * Puanlama tablosu:
     *   Uzunluk (maks 40 puan):
     *     < 6   karakter → 0
     *     6–7   karakter → 10
     *     8–9   karakter → 20
     *     10–11 karakter → 30
     *     12+   karakter → 40
     *
     *   Karakter çeşitliliği (her biri 10 puan, maks 40):
     *     Küçük harf, Büyük harf, Rakam, Özel karakter
     *
     *   Entropi bonusu (maks 20 puan):
     *     Her 10 bit için 5 puan (maks 40 bit eşiğine kadar)
     *
     *   Sözlük cezası: Eşleşme varsa puanı direkt 10'a düşür
     */
    private int calculateScore(PasswordAnalysisResult r, boolean isCommon) {
        if (isCommon) return 10; // Sözlük eşleşmesi → direkt çok zayıf

        int score = 0;

        // 1. Uzunluk puanı
        int len = r.getLength();
        if      (len >= 12) score += 40;
        else if (len >= 10) score += 30;
        else if (len >= 8)  score += 20;
        else if (len >= 6)  score += 10;
        // else 0

        // 2. Karakter çeşitliliği
        if (r.isHasLowerCase())   score += 10;
        if (r.isHasUpperCase())   score += 10;
        if (r.isHasDigit())       score += 10;
        if (r.isHasSpecialChar()) score += 10;

        // 3. Entropi bonusu (her 10 bit için 5 puan, maks 20)
        int entropyBonus = (int) Math.min(20, (r.getEntropyBits() / 10) * 5);
        score += entropyBonus;

        return Math.min(100, score); // 100'ü aşma
    }

    // ──────────────────────────────────────────────────────────────────────────
    //  GÜÇ ETİKETİ ATAMA
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Puana göre güç etiketi ve UI rengi atar.
     * Renk kodu CSS'te doğrudan kullanılabilir.
     */
    private void applyStrengthLabel(PasswordAnalysisResult result, int score) {
        if (score <= 20) {
            result.setStrengthLabel("ÇOK ZAYIF");
            result.setStrengthColor("#ef4444"); // kırmızı
        } else if (score <= 40) {
            result.setStrengthLabel("ZAYIF");
            result.setStrengthColor("#f97316"); // turuncu
        } else if (score <= 60) {
            result.setStrengthLabel("ORTA");
            result.setStrengthColor("#eab308"); // sarı
        } else if (score <= 80) {
            result.setStrengthLabel("GÜÇLÜ");
            result.setStrengthColor("#22c55e"); // yeşil
        } else {
            result.setStrengthLabel("ÇOK GÜÇLÜ");
            result.setStrengthColor("#0ea5e9"); // mavi
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    //  ÖNERİ OLUŞTURMA
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Eksik kriterlere göre kişiselleştirilmiş güvenlik önerileri oluşturur.
     */
    private List<String> generateSuggestions(PasswordAnalysisResult r, String password) {
        List<String> suggestions = new ArrayList<>();

        if (r.isCommonPassword()) {
            suggestions.add("Bu parola çok yaygın. Tamamen farklı bir parola seçin.");
        }
        if (r.getLength() < 12) {
            suggestions.add("Parolanızı en az 12 karakter uzunluğuna çıkarın.");
        }
        if (!r.isHasUpperCase()) {
            suggestions.add("En az bir büyük harf (A–Z) ekleyin.");
        }
        if (!r.isHasLowerCase()) {
            suggestions.add("En az bir küçük harf (a–z) ekleyin.");
        }
        if (!r.isHasDigit()) {
            suggestions.add("En az bir rakam (0–9) ekleyin.");
        }
        if (!r.isHasSpecialChar()) {
            suggestions.add("En az bir özel karakter ekleyin (!@#$%^&* gibi).");
        }
        if (r.getEntropyBits() < 50) {
            suggestions.add("Entropi çok düşük. Daha uzun ve karmaşık bir parola deneyin.");
        }

        // Tüm kriterler sağlandıysa tebrik et
        if (suggestions.isEmpty()) {
            suggestions.add("✅ Mükemmel! Parolanız tüm güvenlik kriterlerini karşılıyor.");
        }

        return suggestions;
    }
}