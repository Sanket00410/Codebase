package com.darkworld.codebasescanner.desktopjava.core;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

public final class DesktopApplicationService {
    private final Path repositoryRoot;
    private final BackendClient backendClient;
    private final DesktopRuntimeController runtimeController;

    public DesktopApplicationService(Path repositoryRoot) {
        this.repositoryRoot = repositoryRoot;
        this.backendClient = new BackendClient("http://127.0.0.1:8686");
        this.runtimeController = new DesktopRuntimeController(repositoryRoot, backendClient);
    }

    public DesktopSnapshot bootstrap(Path selectedRepository) throws IOException, InterruptedException {
        runtimeController.ensureBackendRunning();
        return refresh(selectedRepository);
    }

    public DesktopSnapshot refresh(Path selectedRepository) throws IOException, InterruptedException {
        runtimeController.ensureBackendRunning();
        List<ApiModels.ScanResult> scans = backendClient.listResults(20);
        List<ApiModels.PluginDescriptor> plugins = backendClient.listPlugins();
        List<ApiModels.ReportProfileDefinition> reportProfiles = backendClient.listReportProfiles();
        ApiModels.ScanResult activeScan = pickActiveScan(scans, selectedRepository);
        return new DesktopSnapshot(
                true,
                repositoryRoot,
                selectedRepository,
                activeScan,
                scans,
                plugins.stream().sorted(Comparator.comparing(plugin -> plugin.metadata().displayName())).toList(),
                reportProfiles
        );
    }

    public DesktopSnapshot startScan(Path repositoryPath) throws IOException, InterruptedException {
        runtimeController.ensureBackendRunning();
        ApiModels.ScanResult result = backendClient.createScan(repositoryPath, false, false, true);
        DesktopSnapshot snapshot = refresh(repositoryPath);
        return snapshot.withActiveScan(result);
    }

    public ReportGenerationOutcome generateReports(
            String scanId,
            List<String> profileIds,
            boolean includePlusVariants,
            Path selectedRepository
    ) throws IOException, InterruptedException {
        runtimeController.ensureBackendRunning();
        List<ApiModels.Artifact> generatedArtifacts = backendClient.generateReports(scanId, profileIds, includePlusVariants);
        DesktopSnapshot snapshot = refresh(selectedRepository);
        ApiModels.ScanResult refreshedScan = backendClient.getScan(scanId);
        return new ReportGenerationOutcome(generatedArtifacts, snapshot.withActiveScan(refreshedScan));
    }

    public void installTool(String toolName) throws IOException, InterruptedException {
        runtimeController.ensureBackendRunning();
        backendClient.installTool(toolName);
    }

    public Map<String, Object> updateAdvisories() throws IOException, InterruptedException {
        runtimeController.ensureBackendRunning();
        return backendClient.updateAdvisories();
    }

    public void shutdown() {
        runtimeController.stopBackend();
    }

    public Path runtimeDirectory() {
        return runtimeController.runtimeDirectory();
    }

    private ApiModels.ScanResult pickActiveScan(List<ApiModels.ScanResult> scans, Path selectedRepository) {
        if (scans.isEmpty()) {
            return null;
        }
        if (selectedRepository == null) {
            return scans.get(0);
        }
        String normalized = selectedRepository.toAbsolutePath().normalize().toString();
        return scans.stream()
                .filter(scan -> {
                    if (scan.repositoryPath() == null || scan.repositoryPath().isBlank()) {
                        return false;
                    }
                    return normalized.equalsIgnoreCase(Path.of(scan.repositoryPath()).toAbsolutePath().normalize().toString());
                })
                .findFirst()
                .orElse(scans.get(0));
    }

    public record DesktopSnapshot(
            boolean backendReady,
            Path repositoryRoot,
            Path selectedRepository,
            ApiModels.ScanResult activeScan,
            List<ApiModels.ScanResult> recentScans,
            List<ApiModels.PluginDescriptor> plugins,
            List<ApiModels.ReportProfileDefinition> reportProfiles
    ) {
        public DesktopSnapshot withActiveScan(ApiModels.ScanResult scanResult) {
            return new DesktopSnapshot(
                    backendReady,
                    repositoryRoot,
                    selectedRepository,
                    scanResult,
                    recentScans,
                    plugins,
                    reportProfiles
            );
        }
    }

    public record ReportGenerationOutcome(
            List<ApiModels.Artifact> generatedArtifacts,
            DesktopSnapshot snapshot
    ) {
    }
}
