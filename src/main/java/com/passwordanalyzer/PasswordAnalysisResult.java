package com.passwordanalyzer;

import java.util.List;

/**
 * DTO (Data Transfer Object): API'nin döndürdüğü analiz sonuçlarını taşır.
 *
 * Bu sınıf yalnızca veri taşıma amacı güder (iş mantığı içermez).
 * SRP (Single Responsibility Principle) gereği analiz mantığı bu sınıfın dışındadır.
 */
public class PasswordAnalysisResult {

    // ──────────────────────────────────────────────
    //  Temel Metrikler
    // ──────────────────────────────────────────────

    /** Parolanın karakter uzunluğu */
    private int length;

    /** 0–100 arası genel güç puanı */
    private int score;

    /** İnsan okunabilir güç etiketi: VERY_WEAK / WEAK / FAIR / STRONG / VERY_STRONG */
    private String strengthLabel;

    /** Güç çubuğunun rengi (CSS renk kodu) */
    private String strengthColor;

    // ──────────────────────────────────────────────
    //  Karakter Çeşitliliği
    // ──────────────────────────────────────────────

    private boolean hasUpperCase;   // Büyük harf içeriyor mu?
    private boolean hasLowerCase;   // Küçük harf içeriyor mu?
    private boolean hasDigit;       // Rakam içeriyor mu?
    private boolean hasSpecialChar; // Özel karakter içeriyor mu? (!@#$%^&* vb.)

    // ──────────────────────────────────────────────
    //  Entropi & Kırılma Süresi
    // ──────────────────────────────────────────────

    /**
     * Shannon entropisine dayalı bit cinsinden parola karmaşıklığı.
     * Hesaplama: H = L × log2(R)
     *   L = Parola uzunluğu
     *   R = Olası karakter havuzu büyüklüğü
     */
    private double entropyBits;

    /**
     * 10 milyar deneme/saniye hızında kaba kuvvet saldırısı için
     * tahmin edilen kırılma süresi (okunabilir biçimde).
     */
    private String crackTimeEstimate;

    // ──────────────────────────────────────────────
    //  Güvenlik Kontrolleri
    // ──────────────────────────────────────────────

    /** Yaygın/zayıf parola listesinde bulundu mu? */
    private boolean isCommonPassword;

    /** Sözlük saldırısı uyarı mesajı (eşleşme yoksa null) */
    private String dictionaryWarning;

    /** Kullanıcıya önerilen iyileştirme ipuçları */
    private List<String> suggestions;

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────

    public PasswordAnalysisResult() {}

    // ──────────────────────────────────────────────
    //  Getter / Setter
    // ──────────────────────────────────────────────

    public int getLength() { return length; }
    public void setLength(int length) { this.length = length; }

    public int getScore() { return score; }
    public void setScore(int score) { this.score = score; }

    public String getStrengthLabel() { return strengthLabel; }
    public void setStrengthLabel(String strengthLabel) { this.strengthLabel = strengthLabel; }

    public String getStrengthColor() { return strengthColor; }
    public void setStrengthColor(String strengthColor) { this.strengthColor = strengthColor; }

    public boolean isHasUpperCase() { return hasUpperCase; }
    public void setHasUpperCase(boolean hasUpperCase) { this.hasUpperCase = hasUpperCase; }

    public boolean isHasLowerCase() { return hasLowerCase; }
    public void setHasLowerCase(boolean hasLowerCase) { this.hasLowerCase = hasLowerCase; }

    public boolean isHasDigit() { return hasDigit; }
    public void setHasDigit(boolean hasDigit) { this.hasDigit = hasDigit; }

    public boolean isHasSpecialChar() { return hasSpecialChar; }
    public void setHasSpecialChar(boolean hasSpecialChar) { this.hasSpecialChar = hasSpecialChar; }

    public double getEntropyBits() { return entropyBits; }
    public void setEntropyBits(double entropyBits) { this.entropyBits = entropyBits; }

    public String getCrackTimeEstimate() { return crackTimeEstimate; }
    public void setCrackTimeEstimate(String crackTimeEstimate) { this.crackTimeEstimate = crackTimeEstimate; }

    public boolean isCommonPassword() { return isCommonPassword; }
    public void setCommonPassword(boolean commonPassword) { isCommonPassword = commonPassword; }

    public String getDictionaryWarning() { return dictionaryWarning; }
    public void setDictionaryWarning(String dictionaryWarning) { this.dictionaryWarning = dictionaryWarning; }

    public List<String> getSuggestions() { return suggestions; }
    public void setSuggestions(List<String> suggestions) { this.suggestions = suggestions; }
}