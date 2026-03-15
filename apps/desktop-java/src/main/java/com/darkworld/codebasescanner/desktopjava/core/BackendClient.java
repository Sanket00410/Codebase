package com.darkworld.codebasescanner.desktopjava.core;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.HttpURLConnection;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;

public final class BackendClient {
    private static final List<String> DEFAULT_REPORT_PROFILES = List.of(
            "traditional-report",
            "modern-report",
            "executive-summary",
            "machine-readable-json",
            "sarif",
            "markdown",
            "pdf",
            "xml"
    );

    private final String apiRoot;
    private final ObjectMapper objectMapper;

    public BackendClient(String apiRoot) {
        this.apiRoot = apiRoot.endsWith("/") ? apiRoot.substring(0, apiRoot.length() - 1) : apiRoot;
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public boolean health() {
        try {
            request("/health", "GET", null, new TypeReference<Map<String, String>>() {
            });
            return true;
        } catch (IOException | InterruptedException error) {
            return false;
        }
    }

    public List<ApiModels.ScanResult> listResults(int limit) throws IOException, InterruptedException {
        return request("/results?limit=" + limit, "GET", null, new TypeReference<>() {
        });
    }

    public ApiModels.ScanResult getScan(String scanId) throws IOException, InterruptedException {
        return request("/results/" + scanId, "GET", null, new TypeReference<>() {
        });
    }

    public List<ApiModels.PluginDescriptor> listPlugins() throws IOException, InterruptedException {
        return request("/plugins", "GET", null, new TypeReference<>() {
        });
    }

    public List<ApiModels.ReportProfileDefinition> listReportProfiles() throws IOException, InterruptedException {
        return request("/report-profiles", "GET", null, new TypeReference<>() {
        });
    }

    public ApiModels.ScanResult createScan(
            Path repositoryPath,
            boolean offline,
            boolean updateAdvisories,
            boolean includePlusReportVariants
    ) throws IOException, InterruptedException {
        var payload = new ApiModels.ScanRequestPayload(
                repositoryPath.toAbsolutePath().normalize().toString(),
                DEFAULT_REPORT_PROFILES,
                includePlusReportVariants,
                updateAdvisories,
                offline,
                true
        );
        return request("/scan/run-sync", "POST", payload, new TypeReference<>() {
        });
    }

    public List<ApiModels.Artifact> generateReports(
            String scanId,
            List<String> profileIds,
            boolean includePlusVariants
    ) throws IOException, InterruptedException {
        var payload = new ApiModels.GenerateReportsPayload(profileIds, includePlusVariants);
        return request("/reports/" + scanId + "/generate", "POST", payload, new TypeReference<>() {
        });
    }

    public void installTool(String toolName) throws IOException, InterruptedException {
        request("/plugins/" + toolName + "/install", "POST", Map.of(), new TypeReference<Map<String, Object>>() {
        });
    }

    public Map<String, Object> updateAdvisories() throws IOException, InterruptedException {
        return request("/updates/advisories", "POST", Map.of(), new TypeReference<>() {
        });
    }

    private <T> T request(String path, String method, Object body, TypeReference<T> typeReference)
            throws IOException, InterruptedException {
        HttpURLConnection connection = (HttpURLConnection) URI.create(apiRoot + path).toURL().openConnection();
        try {
            connection.setRequestMethod(method);
            connection.setConnectTimeout((int) Duration.ofSeconds(3).toMillis());
            connection.setReadTimeout((int) Duration.ofMinutes(5).toMillis());
            connection.setRequestProperty("Accept", "application/json");

            if (body != null) {
                byte[] payload = serialize(body).getBytes(StandardCharsets.UTF_8);
                connection.setDoOutput(true);
                connection.setRequestProperty("Content-Type", "application/json");
                connection.setRequestProperty("Content-Length", Integer.toString(payload.length));
                try (OutputStream outputStream = connection.getOutputStream()) {
                    outputStream.write(payload);
                }
            }

            int statusCode = connection.getResponseCode();
            try (InputStream responseStream = statusCode >= 200 && statusCode < 300
                    ? connection.getInputStream()
                    : connection.getErrorStream()) {
                String bodyText = responseStream == null
                        ? ""
                        : new String(responseStream.readAllBytes(), StandardCharsets.UTF_8);
                if (statusCode < 200 || statusCode >= 300) {
                    throw new IOException("Backend request failed: " + statusCode + " " + bodyText);
                }
                return objectMapper.readValue(bodyText, typeReference);
            }
        } finally {
            connection.disconnect();
        }
    }

    private String serialize(Object body) throws JsonProcessingException {
        return objectMapper.writeValueAsString(body);
    }
}
