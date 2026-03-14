package com.darkworld.codebasescanner.desktopjava.core;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
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
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public BackendClient(String apiRoot) {
        this.apiRoot = apiRoot.endsWith("/") ? apiRoot.substring(0, apiRoot.length() - 1) : apiRoot;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
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
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(apiRoot + path))
                .timeout(Duration.ofMinutes(5))
                .header("Accept", "application/json");

        if (body != null) {
            requestBuilder.header("Content-Type", "application/json");
            requestBuilder.method(method, HttpRequest.BodyPublishers.ofString(serialize(body)));
        } else {
            requestBuilder.method(method, HttpRequest.BodyPublishers.noBody());
        }

        HttpResponse<String> response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Backend request failed: " + response.statusCode() + " " + response.body());
        }
        return objectMapper.readValue(response.body(), typeReference);
    }

    private String serialize(Object body) throws JsonProcessingException {
        return objectMapper.writeValueAsString(body);
    }
}
