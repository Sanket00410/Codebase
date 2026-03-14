package com.darkworld.codebasescanner.desktopjava.core;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;

public final class ApiModels {
    private ApiModels() {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record FindingLocation(
            String path,
            Integer line,
            Integer column,
            String snippet
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Finding(
            String findingId,
            String sourceTool,
            String category,
            String severity,
            String title,
            String description,
            String ruleId,
            String packageName,
            String packageVersion,
            String fixedVersion,
            List<String> cveIds,
            List<String> cweIds,
            List<String> references,
            Double confidence,
            FindingLocation location,
            String remediation,
            Map<String, Object> aiTriage
    ) {
        public List<String> safeCveIds() {
            return cveIds != null ? cveIds : List.of();
        }

        public List<String> safeCweIds() {
            return cweIds != null ? cweIds : List.of();
        }

        public List<String> safeReferences() {
            return references != null ? references : List.of();
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Artifact(
            String kind,
            String path,
            String mediaType,
            String profileId,
            String label,
            String description
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ToolExecution(
            String tool,
            String category,
            Double durationSeconds,
            Integer exitCode,
            List<String> command,
            String stdout,
            String stderr,
            List<String> outputFiles,
            String binaryPath
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ScanSummary(
            Integer totalFindings,
            Map<String, Integer> bySeverity,
            Map<String, Integer> byCategory,
            List<String> toolsRun,
            Double score
    ) {
        public Map<String, Integer> safeBySeverity() {
            return bySeverity != null ? bySeverity : Map.of();
        }

        public Map<String, Integer> safeByCategory() {
            return byCategory != null ? byCategory : Map.of();
        }

        public List<String> safeToolsRun() {
            return toolsRun != null ? toolsRun : List.of();
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record RepositorySignal(
            List<String> languages,
            List<String> manifests,
            List<String> ciFiles,
            List<String> dockerFiles,
            List<String> helmCharts,
            List<String> kubernetesFiles,
            List<String> terraformFiles,
            Integer totalFiles,
            Long totalBytes
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record DependencyNode(
            String id,
            String ecosystem,
            String version,
            Boolean direct,
            List<String> dependencies
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record DependencyGraph(
            List<DependencyNode> nodes,
            List<List<String>> edges
    ) {
        public List<DependencyNode> safeNodes() {
            return nodes != null ? nodes : List.of();
        }

        public List<List<String>> safeEdges() {
            return edges != null ? edges : List.of();
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ScanResult(
            String scanId,
            String status,
            String repositoryPath,
            String startedAt,
            String completedAt,
            Integer totalTools,
            Integer completedTools,
            Double progressPercent,
            List<String> activeTools,
            List<Finding> findings,
            List<Artifact> artifacts,
            List<String> errors,
            ScanSummary summary,
            RepositorySignal repositorySignal,
            List<ToolExecution> tools,
            DependencyGraph dependencyGraph
    ) {
        public List<Finding> safeFindings() {
            return findings != null ? findings : List.of();
        }

        public List<Artifact> safeArtifacts() {
            return artifacts != null ? artifacts : List.of();
        }

        public List<String> safeErrors() {
            return errors != null ? errors : List.of();
        }

        public List<ToolExecution> safeTools() {
            return tools != null ? tools : List.of();
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record PluginMetadata(
            String name,
            String displayName,
            String category,
            List<String> supportedLanguages,
            String installStrategy,
            String description
    ) {
        public List<String> safeSupportedLanguages() {
            return supportedLanguages != null ? supportedLanguages : List.of();
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record BinaryStatus(
            String resolvedPath,
            String version,
            String installHint
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record PluginDescriptor(
            PluginMetadata metadata,
            boolean available,
            BinaryStatus binaryStatus
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ReportProfileDefinition(
            String id,
            String label,
            String description,
            String mediaType,
            String extension,
            boolean supportsRichEvidence
    ) {
    }

    public record ScanRequestPayload(
            String repositoryPath,
            List<String> reportProfiles,
            boolean includePlusReportVariants,
            boolean updateAdvisories,
            boolean offline,
            boolean includeGitHistory
    ) {
    }

    public record GenerateReportsPayload(
            List<String> profileIds,
            boolean includePlusVariants
    ) {
    }
}
