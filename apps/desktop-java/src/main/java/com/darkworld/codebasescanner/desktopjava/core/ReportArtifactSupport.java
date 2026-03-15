package com.darkworld.codebasescanner.desktopjava.core;

import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

public final class ReportArtifactSupport {
    private ReportArtifactSupport() {
    }

    public static List<ApiModels.Artifact> sortArtifacts(List<ApiModels.Artifact> artifacts) {
        return artifacts.stream()
                .sorted(
                        Comparator
                                .comparing(ReportArtifactSupport::isReportArtifact)
                                .reversed()
                                .thenComparing(ReportArtifactSupport::fileName, Comparator.nullsLast(Comparator.reverseOrder()))
                                .thenComparing(artifact -> safe(artifact.profileId()))
                )
                .toList();
    }

    public static boolean isReportArtifact(ApiModels.Artifact artifact) {
        return artifact != null
                && artifact.kind() != null
                && artifact.kind().startsWith("report-");
    }

    public static String displayName(ApiModels.Artifact artifact) {
        if (artifact == null) {
            return "Unknown artifact";
        }
        String fileName = fileName(artifact);
        if (!fileName.isBlank()) {
            return fileName;
        }
        if (artifact.label() != null && !artifact.label().isBlank()) {
            return artifact.label();
        }
        return safe(artifact.kind());
    }

    public static String subtitle(ApiModels.Artifact artifact) {
        if (artifact == null) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        if (isReportArtifact(artifact)) {
            builder.append("Generated report");
        } else {
            builder.append("Supporting artifact");
        }
        if (artifact.profileId() != null && !artifact.profileId().isBlank()) {
            builder.append(" | ").append(artifact.profileId());
        }
        if (artifact.mediaType() != null && !artifact.mediaType().isBlank()) {
            builder.append(" | ").append(artifact.mediaType());
        }
        Path folder = folder(artifact).orElse(null);
        if (folder != null) {
            builder.append(" | ").append(folder.getFileName() != null ? folder.getFileName() : folder.toString());
        }
        return builder.toString();
    }

    public static Optional<Path> reportFolder(List<ApiModels.Artifact> artifacts) {
        return preferredOpenArtifact(artifacts).flatMap(ReportArtifactSupport::folder);
    }

    public static Optional<ApiModels.Artifact> preferredOpenArtifact(List<ApiModels.Artifact> artifacts) {
        return artifacts.stream()
                .sorted(
                        Comparator
                                .comparingInt(ReportArtifactSupport::openPriority)
                                .thenComparing(ReportArtifactSupport::fileName, Comparator.nullsLast(Comparator.reverseOrder()))
                )
                .findFirst();
    }

    public static long generatedReportCount(List<ApiModels.Artifact> artifacts) {
        return artifacts.stream().filter(ReportArtifactSupport::isReportArtifact).count();
    }

    public static long supportingArtifactCount(List<ApiModels.Artifact> artifacts) {
        return artifacts.stream().filter(artifact -> !isReportArtifact(artifact)).count();
    }

    public static String savedSummary(List<ApiModels.Artifact> artifacts) {
        Optional<ApiModels.Artifact> preferred = preferredOpenArtifact(artifacts);
        if (preferred.isEmpty()) {
            return "No generated reports are attached to the active scan yet.";
        }
        String fileName = displayName(preferred.get());
        String folder = reportFolder(artifacts)
                .map(Path::toString)
                .orElse("unavailable");
        return "Latest generated report: " + fileName + System.lineSeparator()
                + "Saved in: " + folder;
    }

    public static Optional<Path> artifactPath(ApiModels.Artifact artifact) {
        if (artifact == null || artifact.path() == null || artifact.path().isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(Path.of(artifact.path()).toAbsolutePath().normalize());
        } catch (Exception error) {
            return Optional.empty();
        }
    }

    public static String fileName(ApiModels.Artifact artifact) {
        return artifactPath(artifact)
                .map(Path::getFileName)
                .map(Path::toString)
                .orElse("");
    }

    private static Optional<Path> folder(ApiModels.Artifact artifact) {
        return artifactPath(artifact).map(Path::getParent);
    }

    private static int openPriority(ApiModels.Artifact artifact) {
        if (!isReportArtifact(artifact)) {
            return 90;
        }
        String profileId = safe(artifact.profileId()).toLowerCase(Locale.ROOT);
        return switch (profileId) {
            case "modern-report", "modern-report-plus" -> 0;
            case "traditional-report", "traditional-report-plus" -> 1;
            case "executive-summary", "executive-summary-plus" -> 2;
            case "pdf", "pdf-plus" -> 3;
            case "markdown", "markdown-plus" -> 4;
            case "sarif", "sarif-plus" -> 5;
            case "machine-readable-json", "machine-readable-json-plus" -> 6;
            case "xml", "xml-plus" -> 7;
            default -> 10;
        };
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
