package com.darkworld.codebasescanner.desktopjava.core;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

public final class DesktopPaths {
    private DesktopPaths() {
    }

    public static Path resolveRepositoryRoot() {
        String explicitRoot = System.getenv("CODE_BASE_SCANNER_ROOT");
        if (explicitRoot != null && !explicitRoot.isBlank()) {
            Path candidate = Path.of(explicitRoot).toAbsolutePath().normalize();
            if (looksLikeRepositoryRoot(candidate)) {
                return candidate;
            }
        }

        Path current = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        List<Path> candidates = new ArrayList<>();
        candidates.add(current);
        Optional<Path> firstParent = Optional.ofNullable(current.getParent());
        firstParent.ifPresent(candidates::add);
        firstParent.flatMap(path -> Optional.ofNullable(path.getParent())).ifPresent(candidates::add);
        firstParent.flatMap(path -> Optional.ofNullable(path.getParent()))
                .flatMap(path -> Optional.ofNullable(path.getParent()))
                .ifPresent(candidates::add);

        return candidates.stream()
                .filter(DesktopPaths::looksLikeRepositoryRoot)
                .findFirst()
                .orElse(current);
    }

    public static Optional<Path> resolvePackagedAppDir() {
        List<String> candidates = List.of(
                System.getProperty("code.base.scanner.app.dir", ""),
                System.getProperty("jpackage.app-path", "")
        );
        return candidates.stream()
                .filter(value -> value != null && !value.isBlank())
                .map(value -> Path.of(value).toAbsolutePath().normalize())
                .map(path -> Files.isRegularFile(path) ? path.getParent() : path)
                .filter(Files::exists)
                .findFirst();
    }

    public static Path resolveJavaRuntimeDir() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        Path basePath;
        if (os.contains("win")) {
            String appData = System.getenv("APPDATA");
            basePath = appData != null && !appData.isBlank()
                    ? Path.of(appData)
                    : Path.of(System.getProperty("user.home"));
            return basePath.resolve("com.darkworld.codebasescanner").resolve("java-runtime");
        }
        return Path.of(System.getProperty("user.home")).resolve(".code-base-scanner").resolve("java-runtime");
    }

    public static boolean looksLikeRepositoryRoot(Path candidate) {
        return Files.exists(candidate.resolve("services").resolve("scanner-core"))
                && Files.exists(candidate.resolve("apps").resolve("desktop"));
    }
}
