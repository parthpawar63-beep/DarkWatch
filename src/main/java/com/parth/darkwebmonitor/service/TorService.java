package com.parth.darkwebmonitor.service;

import org.springframework.stereotype.Service;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;

@Service
public class TorService {

    private static final String TOR_PROXY_HOST = "127.0.0.1";
    private static final int TOR_PROXY_PORT = 9050;

    public String checkTorConnection() {

        Proxy torProxy = new Proxy(
                Proxy.Type.SOCKS,
                new InetSocketAddress(
                        TOR_PROXY_HOST,
                        TOR_PROXY_PORT
                )
        );

        HttpsURLConnection connection = null;

        try {

            URL url = new URL(
                    "https://check.torproject.org/api/ip"
            );

            connection =
                    (HttpsURLConnection) url.openConnection(torProxy);

            connection.setRequestMethod("GET");
            connection.setConnectTimeout(20_000);
            connection.setReadTimeout(30_000);

            int responseCode =
                    connection.getResponseCode();

            if (responseCode != 200) {

                return "{\"IsTor\":false,\"error\":\"HTTP "
                        + responseCode
                        + "\"}";
            }

            try (
                    BufferedReader reader =
                            new BufferedReader(
                                    new InputStreamReader(
                                            connection.getInputStream(),
                                            StandardCharsets.UTF_8
                                    )
                            )
            ) {

                StringBuilder response =
                        new StringBuilder();

                String line;

                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }

                return response.toString();
            }

        } catch (IOException e) {

            return "{\"IsTor\":false,\"error\":\""
                    + escapeJson(e.getMessage())
                    + "\"}";

        } finally {

            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private String escapeJson(String value) {

        if (value == null) {
            return "Unknown error";
        }

        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }
}
