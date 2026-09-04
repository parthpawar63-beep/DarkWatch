package com.parth.darkwebmonitor.service;

import com.parth.darkwebmonitor.model.MonitoredSource;
import com.parth.darkwebmonitor.model.ThreatIndicator;
import com.parth.darkwebmonitor.repository.MonitoredSourceRepository;
import com.parth.darkwebmonitor.repository.ThreatIndicatorRepository;

import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class OnionMonitoringService {

    private static final String TOR_PROXY_HOST = "127.0.0.1";
    private static final int TOR_PROXY_PORT = 9050;

    private static final int CONNECT_TIMEOUT = 30_000;
    private static final int READ_TIMEOUT = 30_000;
    private static final int MAX_CONTENT_SIZE = 2_000_000;

    private final MonitoredSourceRepository sourceRepository;
    private final ThreatIndicatorRepository indicatorRepository;

    public OnionMonitoringService(
            MonitoredSourceRepository sourceRepository,
            ThreatIndicatorRepository indicatorRepository) {

        this.sourceRepository = sourceRepository;
        this.indicatorRepository = indicatorRepository;
    }

    public MonitoredSource checkSource(MonitoredSource source) {

        long startTime = System.currentTimeMillis();

        HttpURLConnection connection = null;

        try {

            String address = source.getOnionAddress().trim();

            if (!address.startsWith("http://")
                    && !address.startsWith("https://")) {
                address = "http://" + address;
            }

            URL url = new URL(address);

            Proxy torProxy = new Proxy(
                    Proxy.Type.SOCKS,
                    new InetSocketAddress(
                            TOR_PROXY_HOST,
                            TOR_PROXY_PORT
                    )
            );

            connection =
                    (HttpURLConnection) url.openConnection(torProxy);

            connection.setRequestMethod("GET");
            connection.setConnectTimeout(CONNECT_TIMEOUT);
            connection.setReadTimeout(READ_TIMEOUT);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestProperty(
                    "User-Agent",
                    "DARKWATCH-Monitor/1.0"
            );

            long responseStart = System.currentTimeMillis();

            int responseCode = connection.getResponseCode();

            long responseTime =
                    System.currentTimeMillis() - responseStart;

            source.setResponseTime(responseTime);
            source.setHttpStatus(responseCode);

            if (responseCode >= 200 && responseCode < 400) {

                String content = readLimitedContent(connection);

                long contentLength =
                        content.getBytes(StandardCharsets.UTF_8).length;

                source.setContentLength(contentLength);

                int indicatorCount = analyzeContent(
                        source,
                        content
                );

                source.setIndicatorCount(indicatorCount);

                source.setRiskLevel(
                        calculateRisk(indicatorCount)
                );

                source.setStatus("ONLINE");

            } else {

                source.setContentLength(0);
                source.setIndicatorCount(0);
                source.setRiskLevel("UNKNOWN");

                source.setStatus(
                        "REACHABLE - HTTP " + responseCode
                );
            }

        } catch (Exception e) {

            source.setStatus("OFFLINE");
            source.setHttpStatus(0);
            source.setContentLength(0);
            source.setIndicatorCount(0);
            source.setRiskLevel("UNKNOWN");

            source.setResponseTime(
                    System.currentTimeMillis() - startTime
            );

        } finally {

            if (connection != null) {
                connection.disconnect();
            }
        }

        source.setLastChecked(
                LocalDateTime.now().format(
                        DateTimeFormatter.ofPattern(
                                "yyyy-MM-dd HH:mm:ss"
                        )
                )
        );

        return sourceRepository.save(source);
    }

    private String readLimitedContent(
            HttpURLConnection connection) throws Exception {

        StringBuilder content = new StringBuilder();

        try (BufferedReader reader =
                     new BufferedReader(
                             new InputStreamReader(
                                     connection.getInputStream(),
                                     StandardCharsets.UTF_8
                             ))) {

            char[] buffer = new char[4096];

            int totalRead = 0;
            int read;

            while ((read = reader.read(buffer)) != -1) {

                totalRead += read;

                if (totalRead > MAX_CONTENT_SIZE) {
                    break;
                }

                content.append(buffer, 0, read);
            }
        }

        return content.toString();
    }

    private int analyzeContent(
            MonitoredSource source,
            String content) {

        if (content == null || content.isBlank()) {
            return 0;
        }

        int totalIndicators = 0;

        LocalDateTime now = LocalDateTime.now();

        String detectedAt = now.format(
                DateTimeFormatter.ofPattern(
                        "yyyy-MM-dd HH:mm:ss"
                )
        );

        /*
         * Email indicators
         */
        Pattern emailPattern = Pattern.compile(
                "\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b",
                Pattern.CASE_INSENSITIVE
        );

        Matcher emailMatcher =
                emailPattern.matcher(content);

        Set<String> uniqueEmails =
                new LinkedHashSet<>();

        while (emailMatcher.find()) {
            uniqueEmails.add(emailMatcher.group());
        }

        for (String email : uniqueEmails) {

            saveIndicator(
                    source,
                    "EMAIL",
                    email,
                    determineSeverity("EMAIL"),
                    detectedAt
            );

            totalIndicators++;
        }

        /*
         * Domain indicators
         */
        Pattern domainPattern = Pattern.compile(
                "\\b(?:[a-z0-9-]+\\.)+(?:com|net|org|io|dev|co|in|info|biz|onion)\\b",
                Pattern.CASE_INSENSITIVE
        );

        Matcher domainMatcher =
                domainPattern.matcher(content);

        Set<String> uniqueDomains =
                new LinkedHashSet<>();

        while (domainMatcher.find()) {
            uniqueDomains.add(domainMatcher.group());
        }

        for (String domain : uniqueDomains) {

            saveIndicator(
                    source,
                    "DOMAIN",
                    domain,
                    determineSeverity("DOMAIN"),
                    detectedAt
            );

            totalIndicators++;
        }

        /*
         * Security-related keywords
         */
        String[] keywords = {
                "credential",
                "breach",
                "exposed",
                "leaked",
                "database",
                "compromised",
                "ransomware"
        };

        String lowerContent =
                content.toLowerCase();

        for (String keyword : keywords) {

            if (lowerContent.contains(keyword)) {

                saveIndicator(
                        source,
                        "KEYWORD",
                        keyword,
                        determineSeverity("KEYWORD"),
                        detectedAt
                );

                totalIndicators++;
            }
        }

        return Math.min(totalIndicators, 999);
    }

    private void saveIndicator(
            MonitoredSource source,
            String type,
            String value,
            String severity,
            String detectedAt) {

        ThreatIndicator indicator =
                new ThreatIndicator(
                        source.getId(),
                        source.getName(),
                        type,
                        value,
                        severity,
                        detectedAt
                );

        indicatorRepository.save(indicator);
    }

    private String determineSeverity(String indicatorType) {

        return switch (indicatorType) {

            case "EMAIL" -> "HIGH";

            case "DOMAIN" -> "MEDIUM";

            case "KEYWORD" -> "LOW";

            default -> "LOW";
        };
    }

    private String calculateRisk(int indicatorCount) {

        if (indicatorCount >= 10) {
            return "HIGH";
        }

        if (indicatorCount >= 3) {
            return "MEDIUM";
        }

        if (indicatorCount >= 1) {
            return "LOW";
        }

        return "UNKNOWN";
    }
}
