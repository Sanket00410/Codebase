package com.darkworld.codebasescanner.desktopjava.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class LocalFilePreviewer {
    private LocalFilePreviewer() {
    }

    public static String sourcePreview(Path repositoryRoot, ApiModels.Finding finding) {
        if (finding == null || finding.location() == null || finding.location().path() == null) {
            return "No file or line information is available for the selected finding.";
        }

        String scannerSnippet = finding.location().snippet();
        if (scannerSnippet != null && !scannerSnippet.isBlank()) {
            return scannerSnippet;
        }

        Path sourcePath = resolveAgainstRepository(repositoryRoot, finding.location().path());
        if (!Files.exists(sourcePath)) {
            return "Unable to resolve source file: " + sourcePath;
        }

        try {
            List<String> lines = Files.readAllLines(sourcePath, StandardCharsets.UTF_8);
            if (lines.isEmpty()) {
                return "Source file is empty: " + sourcePath;
            }
            int focusLine = finding.location().line() != null ? finding.location().line() : 1;
            int start = Math.max(1, focusLine - 8);
            int end = Math.min(lines.size(), focusLine + 12);
            StringBuilder builder = new StringBuilder();
            builder.append(sourcePath).append(System.lineSeparator()).append(System.lineSeparator());
            for (int lineNumber = start; lineNumber <= end; lineNumber++) {
                builder.append(String.format("%5d | %s%n", lineNumber, lines.get(lineNumber - 1)));
            }
            return builder.toString();
        } catch (IOException error) {
            return "Unable to read source preview: " + error.getMessage();
        }
    }

    public static String filePreview(String filePath, int maxBytes, int maxLines) {
        Path previewPath = Path.of(filePath);
        if (!Files.exists(previewPath)) {
            return "Preview file does not exist: " + previewPath;
        }

        String lowerName = previewPath.getFileName() != null
                ? previewPath.getFileName().toString().toLowerCase()
                : "";
        if (lowerName.endsWith(".pdf")) {
            return "PDF report preview is opened externally."
                    + System.lineSeparator() + System.lineSeparator()
                    + "Saved file: " + previewPath.getFileName()
                    + System.lineSeparator()
                    + "Saved folder: " + previewPath.getParent()
                    + System.lineSeparator() + System.lineSeparator()
                    + "Use Open Selected or Open Latest Report to open the PDF in your default viewer.";
        }
        if (lowerName.endsWith(".html") || lowerName.endsWith(".htm")) {
            return "HTML report preview is opened externally."
                    + System.lineSeparator() + System.lineSeparator()
                    + "Saved file: " + previewPath.getFileName()
                    + System.lineSeparator()
                    + "Saved folder: " + previewPath.getParent()
                    + System.lineSeparator() + System.lineSeparator()
                    + "Use Open Selected or Open Latest Report to open the rendered report in your browser.";
        }

        try {
            byte[] bytes = Files.readAllBytes(previewPath);
            if (looksBinary(bytes)) {
                return "Binary report preview is not shown inline."
                        + System.lineSeparator() + System.lineSeparator()
                        + "Saved file: " + previewPath.getFileName()
                        + System.lineSeparator()
                        + "Saved folder: " + previewPath.getParent()
                        + System.lineSeparator() + System.lineSeparator()
                        + "Use Open Selected to inspect it with the associated desktop application.";
            }
            int cappedBytes = Math.min(bytes.length, maxBytes);
            String content = new String(bytes, 0, cappedBytes, StandardCharsets.UTF_8).replace('\0', ' ');
            List<String> lines = content.lines().limit(maxLines).toList();
            String preview = String.join(System.lineSeparator(), lines);
            if (bytes.length > cappedBytes) {
                preview += System.lineSeparator() + System.lineSeparator() + "... preview truncated ...";
            }
            return preview;
        } catch (IOException error) {
            return "Unable to read report preview: " + error.getMessage();
        }
    }

    private static boolean looksBinary(byte[] bytes) {
        int sampleSize = Math.min(bytes.length, 2048);
        int controlBytes = 0;
        for (int index = 0; index < sampleSize; index++) {
            byte value = bytes[index];
            if (value == 0) {
                return true;
            }
            int unsigned = value & 0xFF;
            if (unsigned < 0x09 || (unsigned > 0x0D && unsigned < 0x20)) {
                controlBytes++;
            }
        }
        return sampleSize > 0 && controlBytes > sampleSize / 8;
    }

    public static Path resolveAgainstRepository(Path repositoryRoot, String rawPath) {
        Path candidate = Path.of(rawPath);
        if (candidate.isAbsolute()) {
            return candidate.normalize();
        }
        if (repositoryRoot == null) {
            return candidate.toAbsolutePath().normalize();
        }
        return repositoryRoot.resolve(candidate).normalize();
    }
}
