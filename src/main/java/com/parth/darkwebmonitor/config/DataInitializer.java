package com.parth.darkwebmonitor.config;

import com.parth.darkwebmonitor.model.MonitoredSource;
import com.parth.darkwebmonitor.model.ThreatIndicator;
import com.parth.darkwebmonitor.repository.MonitoredSourceRepository;
import com.parth.darkwebmonitor.repository.ThreatIndicatorRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner initializeData(
            MonitoredSourceRepository sourceRepository,
            ThreatIndicatorRepository indicatorRepository) {

        return args -> {

            MonitoredSource source;

            if (sourceRepository.count() == 0) {

                source = new MonitoredSource(
                        "DARKWATCH Test Intelligence Feed",
                        "testsource.onion",
                        "Controlled Test"
                );

                source.setStatus("TEST DATA");
                source.setRiskLevel("MEDIUM");
                source.setIndicatorCount(3);
                source.setHttpStatus(200);
                source.setResponseTime(120);
                source.setContentLength(1842);
                source.setLastChecked(
                        LocalDateTime.now().format(
                                DateTimeFormatter.ofPattern(
                                        "yyyy-MM-dd HH:mm:ss"
                                )
                        )
                );

                source = sourceRepository.save(source);

            } else {

                source = sourceRepository.findAll().get(0);
            }


            /*
             * Controlled test intelligence.
             *
             * These records are clearly labeled as TEST DATA.
             * They are NOT real dark-web findings.
             */

            if (indicatorRepository.count() == 0) {

                String detectedAt =
                        LocalDateTime.now().format(
                                DateTimeFormatter.ofPattern(
                                        "yyyy-MM-dd HH:mm:ss"
                                )
                        );


                ThreatIndicator emailIndicator =
                        new ThreatIndicator(
                                source.getId(),
                                source.getName(),
                                "EMAIL",
                                "test.user@example.test",
                                "HIGH",
                                detectedAt
                        );


                ThreatIndicator domainIndicator =
                        new ThreatIndicator(
                                source.getId(),
                                source.getName(),
                                "DOMAIN",
                                "example.test",
                                "MEDIUM",
                                detectedAt
                        );


                ThreatIndicator keywordIndicator =
                        new ThreatIndicator(
                                source.getId(),
                                source.getName(),
                                "KEYWORD",
                                "credential exposure",
                                "LOW",
                                detectedAt
                        );


                indicatorRepository.save(emailIndicator);
                indicatorRepository.save(domainIndicator);
                indicatorRepository.save(keywordIndicator);
            }
        };
    }
}
