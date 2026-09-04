package com.parth.darkwebmonitor.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.regex.Pattern;

@Service
public class HibpService {

    private static final String BASE_URL =
            "https://haveibeenpwned.com/api/v3/breachedaccount/";

    private final HttpClient httpClient;

    @Value("${hibp.api-key:}")
    private String apiKey;

    @Value("${hibp.user-agent:DARKWATCH/1.0}")
    private String userAgent;

    public HibpService() {

        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .build();
    }

    public HibpResult checkEmail(String email) {

        if (apiKey == null || apiKey.isBlank()) {

            return HibpResult.demoMode(
                    "HIBP API key not configured."
            );
        }

        try {

            String encodedEmail =
                    URLEncoder.encode(
                            email,
                            StandardCharsets.UTF_8
                    ).replace("+", "%20");

            HttpRequest request =
                    HttpRequest.newBuilder()
                            .uri(
                                    URI.create(
                                            BASE_URL + encodedEmail
                                    )
                            )
                            .timeout(Duration.ofSeconds(20))
                            .header(
                                    "hibp-api-key",
                                    apiKey
                            )
                            .header(
                                    "user-agent",
                                    userAgent
                            )
                            .header(
                                    "accept",
                                    "application/json"
                            )
                            .GET()
                            .build();

            HttpResponse<String> response =
                    httpClient.send(
                            request,
                            HttpResponse.BodyHandlers.ofString()
                    );

            int statusCode = response.statusCode();

            if (statusCode == 200) {

                String body = response.body();

                int breachCount =
                        countBreachObjects(body);

                return new HibpResult(
                        true,
                        false,
                        breachCount,
                        body,
                        "Breach exposure detected"
                );
            }

            if (statusCode == 404) {

                return new HibpResult(
                        false,
                        false,
                        0,
                        "[]",
                        "No breach exposure found"
                );
            }

            if (statusCode == 401) {

                return new HibpResult(
                        false,
                        false,
                        0,
                        "",
                        "HIBP API key is invalid"
                );
            }

            if (statusCode == 403) {

                return new HibpResult(
                        false,
                        false,
                        0,
                        "",
                        "HIBP request was forbidden"
                );
            }

            if (statusCode == 429) {

                return new HibpResult(
                        false,
                        false,
                        0,
                        "",
                        "HIBP rate limit reached"
                );
            }

            return new HibpResult(
                    false,
                    false,
                    0,
                    "",
                    "HIBP returned HTTP " + statusCode
            );

        } catch (InterruptedException e) {

            Thread.currentThread().interrupt();

            return new HibpResult(
                    false,
                    false,
                    0,
                    "",
                    "HIBP request interrupted"
            );

        } catch (Exception e) {

            return new HibpResult(
                    false,
                    false,
                    0,
                    "",
                    "HIBP request failed: "
                            + e.getMessage()
            );
        }
    }

    private int countBreachObjects(String json) {

        if (json == null || json.isBlank()) {
            return 0;
        }

        /*
         * HIBP returns an array of breach objects.
         * Each object begins with a JSON object marker.
         *
         * This lightweight parser avoids adding another
         * Maven dependency just to count the records.
         */
        return (int) Pattern
                .compile("\\{")
                .matcher(json)
                .results()
                .count();
    }

    public record HibpResult(
            boolean breached,
            boolean demoMode,
            int breachCount,
            String rawResponse,
            String message
    ) {

        public static HibpResult demoMode(String message) {

            return new HibpResult(
                    false,
                    true,
                    0,
                    "",
                    message
            );
        }
    }
}
