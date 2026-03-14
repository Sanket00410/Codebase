package com.darkworld.codebasescanner.desktopjava.core;

import java.nio.file.Path;
import java.util.Comparator;
import java.util.Map;
import java.util.StringJoiner;

public final class WorkbenchText {
    private WorkbenchText() {
    }

    public static String formatFindingDetails(ApiModels.Finding finding) {
        if (finding == null) {
            return "Select a finding to inspect source, identifiers, remediation, and triage context.";
        }

        StringJoiner joiner = new StringJoiner(System.lineSeparator());
        joiner.add("Title: " + safe(finding.title()));
        joiner.add("Tool: " + safe(finding.sourceTool()));
        joiner.add("Category: " + safe(finding.category()));
        joiner.add("Severity: " + safe(finding.severity()));
        joiner.add("Rule ID: " + safe(finding.ruleId()));
        joiner.add("Package: " + safe(finding.packageName()) + " " + safe(finding.packageVersion()));
        joiner.add("Fixed Version: " + safe(finding.fixedVersion()));
        joiner.add("CVE: " + String.join(", ", finding.safeCveIds()));
        joiner.add("CWE: " + String.join(", ", finding.safeCweIds()));
        joiner.add("Confidence: " + (finding.confidence() == null ? "n/a" : String.format("%.2f", finding.confidence())));
        if (finding.location() != null) {
            joiner.add("File: " + safe(finding.location().path()));
            joiner.add("Line: " + safeInteger(finding.location().line()));
        }
        joiner.add("");
        joiner.add("Description:");
        joiner.add(safe(finding.description()));
        joiner.add("");
        joiner.add("Remediation:");
        joiner.add(safe(finding.remediation()));
        if (finding.aiTriage() != null && !finding.aiTriage().isEmpty()) {
            joiner.add("");
            joiner.add("AI Triage:");
            finding.aiTriage().entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(entry -> joiner.add(" - " + entry.getKey() + ": " + String.valueOf(entry.getValue())));
        }
        return joiner.toString();
    }

    public static String formatArtifactDetails(ApiModels.Artifact artifact) {
        if (artifact == null) {
            return "Select a generated report or supporting artifact to inspect it here.";
        }
        StringJoiner joiner = new StringJoiner(System.lineSeparator());
        joiner.add("Label: " + safe(artifact.label()));
        joiner.add("Kind: " + safe(artifact.kind()));
        joiner.add("Profile: " + safe(artifact.profileId()));
        joiner.add("Media Type: " + safe(artifact.mediaType()));
        joiner.add("Path: " + safe(artifact.path()));
        joiner.add("");
        joiner.add(safe(artifact.description()));
        return joiner.toString();
    }

    public static String formatPluginDetails(ApiModels.PluginDescriptor plugin) {
        if (plugin == null || plugin.metadata() == null) {
            return "Select a tool runtime to inspect install state, binary path, and version.";
        }
        StringJoiner joiner = new StringJoiner(System.lineSeparator());
        joiner.add("Tool: " + safe(plugin.metadata().displayName()));
        joiner.add("Category: " + safe(plugin.metadata().category()));
        joiner.add("Install Strategy: " + safe(plugin.metadata().installStrategy()));
        joiner.add("Available: " + plugin.available());
        if (plugin.binaryStatus() != null) {
            joiner.add("Version: " + safe(plugin.binaryStatus().version()));
            joiner.add("Binary: " + safe(plugin.binaryStatus().resolvedPath()));
            joiner.add("Install Hint: " + safe(plugin.binaryStatus().installHint()));
        }
        joiner.add("");
        joiner.add(safe(plugin.metadata().description()));
        return joiner.toString();
    }

    public static String formatDependencyDetails(ApiModels.DependencyNode dependencyNode, ApiModels.ScanResult scanResult) {
        if (dependencyNode == null) {
            return "Select a dependency to inspect package lineage and related findings.";
        }

        StringJoiner joiner = new StringJoiner(System.lineSeparator());
        joiner.add("Package: " + safe(dependencyNode.id()));
        joiner.add("Ecosystem: " + safe(dependencyNode.ecosystem()));
        joiner.add("Version: " + safe(dependencyNode.version()));
        joiner.add("Direct: " + String.valueOf(Boolean.TRUE.equals(dependencyNode.direct())));
        joiner.add("Declared Dependencies: " + (dependencyNode.dependencies() == null ? 0 : dependencyNode.dependencies().size()));
        joiner.add("");
        joiner.add("Related Findings:");
        if (scanResult == null || scanResult.safeFindings().isEmpty()) {
            joiner.add(" - No findings are attached to the current scan.");
            return joiner.toString();
        }

        scanResult.safeFindings().stream()
                .filter(finding -> dependencyNode.id().equalsIgnoreCase(safe(finding.packageName())))
                .findFirst()
                .ifPresentOrElse(
                        firstFinding -> scanResult.safeFindings().stream()
                                .filter(finding -> dependencyNode.id().equalsIgnoreCase(safe(finding.packageName())))
                                .forEach(finding -> joiner.add(" - [" + safe(finding.severity()) + "] " + safe(finding.title()))),
                        () -> joiner.add(" - No package-linked findings matched this dependency.")
                );
        return joiner.toString();
    }

    public static String formatScanOverview(ApiModels.ScanResult scanResult) {
        if (scanResult == null) {
            return "No persisted scans are available yet. Start a repository scan to populate the workbench.";
        }
        StringJoiner joiner = new StringJoiner(System.lineSeparator());
        joiner.add("Scan ID: " + safe(scanResult.scanId()));
        joiner.add("Repository: " + safe(scanResult.repositoryPath()));
        joiner.add("Status: " + safe(scanResult.status()));
        joiner.add("Started: " + safe(scanResult.startedAt()));
        joiner.add("Completed: " + safe(scanResult.completedAt()));
        if (scanResult.summary() != null) {
            joiner.add("Score: " + safeDouble(scanResult.summary().score()));
            joiner.add("Findings: " + safeInteger(scanResult.summary().totalFindings()));
            joiner.add("Severity Mix:");
            scanResult.summary().safeBySeverity().entrySet().stream()
                    .sorted(Map.Entry.comparingByKey(Comparator.naturalOrder()))
                    .forEach(entry -> joiner.add(" - " + entry.getKey() + ": " + entry.getValue()));
        }
        return joiner.toString();
    }

    public static String formatRepositorySummary(Path repositoryPath, ApiModels.ScanResult activeScan) {
        StringJoiner joiner = new StringJoiner(System.lineSeparator());
        joiner.add("Repository: " + (repositoryPath == null ? "not selected" : repositoryPath.toString()));
        if (activeScan != null && activeScan.repositorySignal() != null) {
            joiner.add("Languages: " + String.join(", ", activeScan.repositorySignal().languages()));
            joiner.add("Manifests: " + String.join(", ", activeScan.repositorySignal().manifests()));
            joiner.add("CI Files: " + String.join(", ", activeScan.repositorySignal().ciFiles()));
            joiner.add("Total Files: " + safeInteger(activeScan.repositorySignal().totalFiles()));
        }
        return joiner.toString();
    }

    private static String safe(String value) {
        return value == null || value.isBlank() ? "n/a" : value;
    }

    private static String safeInteger(Integer value) {
        return value == null ? "n/a" : value.toString();
    }

    private static String safeDouble(Double value) {
        return value == null ? "n/a" : String.format("%.2f", value);
    }
}
