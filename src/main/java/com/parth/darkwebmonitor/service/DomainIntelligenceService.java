package com.parth.darkwebmonitor.service;

import org.springframework.stereotype.Service;

import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;

@Service
public class DomainIntelligenceService {

    public DomainResult analyze(String input) {

        String domain = cleanDomain(input);

        if (!isValidDomain(domain)) {

            return new DomainResult(
                    false,
                    domain,
                    "INVALID DOMAIN",
                    0,
                    0,
                    "UNKNOWN",
                    "Invalid domain format"
            );
        }

        boolean dnsResolved = false;
        String ipAddress = "";
        int httpStatus = 0;
        long responseTime = 0;
        String httpsStatus = "NOT CHECKED";

        // ==============================
        // DNS CHECK
        // ==============================

        try {

            InetAddress address =
                    InetAddress.getByName(domain);

            dnsResolved = true;
            ipAddress = address.getHostAddress();

        } catch (Exception ignored) {
            // DNS resolution failed
        }


        // ==============================
        // HTTPS CHECK
        // ==============================

        if (dnsResolved) {

            long start =
                    System.currentTimeMillis();

            HttpURLConnection connection = null;

            try {

                URL url =
                        URI.create(
                                "https://" + domain
                        ).toURL();

                connection =
                        (HttpURLConnection)
                                url.openConnection();

                connection.setRequestMethod("HEAD");
                connection.setConnectTimeout(8000);
                connection.setReadTimeout(8000);
                connection.setInstanceFollowRedirects(true);

                httpStatus =
                        connection.getResponseCode();

                responseTime =
                        System.currentTimeMillis() - start;

                if (httpStatus >= 200 &&
                        httpStatus < 400) {

                    httpsStatus = "REACHABLE";

                } else {

                    httpsStatus =
                            "HTTP " + httpStatus;
                }

            } catch (Exception e) {

                httpsStatus = "UNREACHABLE";

            } finally {

                if (connection != null) {
                    connection.disconnect();
                }
            }
        }


        // ==============================
        // RISK CALCULATION
        // ==============================

        String risk;

        if (!dnsResolved) {

            risk = "MEDIUM";

        } else if ("REACHABLE".equals(httpsStatus)) {

            risk = "LOW";

        } else {

            risk = "MEDIUM";
        }


        String message;

        if (!dnsResolved) {

            message =
                    "Domain did not resolve through DNS.";

        } else if ("REACHABLE".equals(httpsStatus)) {

            message =
                    "Domain resolves and HTTPS endpoint is reachable.";

        } else {

            message =
                    "Domain resolves but HTTPS endpoint could not be verified.";
        }


        return new DomainResult(
                true,
                domain,
                "DOMAIN ANALYSIS COMPLETE",
                httpStatus,
                responseTime,
                risk,
                message,
                ipAddress,
                httpsStatus
        );
    }


    private String cleanDomain(String input) {

        String domain = input.trim();

        domain = domain
                .replace("https://", "")
                .replace("http://", "");

        int slash =
                domain.indexOf('/');

        if (slash >= 0) {

            domain =
                    domain.substring(
                            0,
                            slash
                    );
        }

        return domain.toLowerCase();
    }


    private boolean isValidDomain(
            String domain) {

        return domain.matches(
                "^(?=.{1,253}$)"
                        + "(?:[a-zA-Z0-9]"
                        + "(?:[a-zA-Z0-9-]{0,61}"
                        + "[a-zA-Z0-9])?\\.)+"
                        + "[a-zA-Z]{2,63}$"
        );
    }


    public record DomainResult(
            boolean valid,
            String domain,
            String status,
            int httpStatus,
            long responseTime,
            String risk,
            String message,
            String ipAddress,
            String httpsStatus
    ) {

        public DomainResult(
                boolean valid,
                String domain,
                String status,
                int httpStatus,
                long responseTime,
                String risk,
                String message) {

            this(
                    valid,
                    domain,
                    status,
                    httpStatus,
                    responseTime,
                    risk,
                    message,
                    "",
                    "NOT CHECKED"
            );
        }
    }
}
