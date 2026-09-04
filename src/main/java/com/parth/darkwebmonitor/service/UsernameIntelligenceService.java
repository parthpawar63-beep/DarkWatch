package com.parth.darkwebmonitor.service;

import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

@Service
public class UsernameIntelligenceService {

    private final HttpClient httpClient;

    public UsernameIntelligenceService() {

        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public UsernameResult analyze(String username) {

        username = username.trim();

        if (!username.matches("^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,38})$")) {

            return new UsernameResult(
                    false,
                    username,
                    "INVALID USERNAME",
                    "UNKNOWN",
                    0,
                    "Invalid username format"
            );
        }

        try {

            String url =
                    "https://api.github.com/users/"
                            + username;

            HttpRequest request =
                    HttpRequest.newBuilder()
                            .uri(URI.create(url))
                            .timeout(Duration.ofSeconds(15))
                            .header(
                                    "Accept",
                                    "application/vnd.github+json"
                            )
                            .header(
                                    "User-Agent",
                                    "DARKWATCH/1.0"
                            )
                            .GET()
                            .build();

            HttpResponse<String> response =
                    httpClient.send(
                            request,
                            HttpResponse.BodyHandlers.ofString()
                    );

            if (response.statusCode() == 200) {

                return new UsernameResult(
                        true,
                        username,
                        "PUBLIC PROFILE FOUND",
                        "LOW",
                        20,
                        "Public GitHub profile exists"
                );
            }

            if (response.statusCode() == 404) {

                return new UsernameResult(
                        true,
                        username,
                        "NO PUBLIC GITHUB PROFILE",
                        "LOW",
                        0,
                        "No public GitHub profile found"
                );
            }

            if (response.statusCode() == 403) {

                return new UsernameResult(
                        true,
                        username,
                        "LOOKUP RATE LIMITED",
                        "UNKNOWN",
                        0,
                        "GitHub API rate limit reached"
                );
            }

            return new UsernameResult(
                    true,
                    username,
                    "LOOKUP FAILED",
                    "UNKNOWN",
                    0,
                    "GitHub returned HTTP "
                            + response.statusCode()
            );

        } catch (InterruptedException e) {

            Thread.currentThread().interrupt();

            return new UsernameResult(
                    true,
                    username,
                    "LOOKUP INTERRUPTED",
                    "UNKNOWN",
                    0,
                    "Request interrupted"
            );

        } catch (Exception e) {

            return new UsernameResult(
                    true,
                    username,
                    "LOOKUP FAILED",
                    "UNKNOWN",
                    0,
                    "Unable to reach GitHub"
            );
        }
    }

    public record UsernameResult(
            boolean valid,
            String username,
            String status,
            String risk,
            int riskScore,
            String message
    ) {
    }
}
