package com.passwordanalyzer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Uygulamanın giriş noktası.
 *
 * @SpringBootApplication anotasyonu üç görevi bir arada yapar:
 *   - @Configuration       : Bu sınıfın Spring Bean tanımları içerdiğini belirtir
 *   - @EnableAutoConfiguration : Spring Boot'un classpath'e göre otomatik yapılandırmasını etkinleştirir
 *   - @ComponentScan       : Bu paketin altındaki tüm bileşenleri tarar
 */
@SpringBootApplication
public class PasswordAnalyzerApplication {

    public static void main(String[] args) {
        SpringApplication.run(PasswordAnalyzerApplication.class, args);
        System.out.println("\n✅ Parola Gücü Analiz Aracı başarıyla başlatıldı.");
        System.out.println("🌐 Arayüz: http://localhost:8080");
        System.out.println("📡 API   : http://localhost:8080/api/analyze\n");
    }
}