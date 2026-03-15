package com.darkworld.codebasescanner.desktopjava.core;

import java.io.IOException;
import java.net.http.HttpTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class DesktopRuntimeController {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 8686;

    private final Path repositoryRoot;
    private final Path runtimeDirectory;
    private final BackendClient backendClient;
    private Process backendProcess;

    public DesktopRuntimeController(Path repositoryRoot, BackendClient backendClient) {
        this.repositoryRoot = repositoryRoot;
        this.runtimeDirectory = DesktopPaths.resolveJavaRuntimeDir();
        this.backendClient = backendClient;
    }

    public synchronized void ensureBackendRunning() throws IOException, InterruptedException {
        Files.createDirectories(runtimeDirectory);
        if (backendClient.health()) {
            return;
        }

        if (backendProcess != null && backendProcess.isAlive()) {
            waitForHealthy(Duration.ofSeconds(20));
            return;
        }

        BackendLaunch launch = resolveBackendLaunch();
        ProcessBuilder builder = new ProcessBuilder(launch.command());
        builder.directory(launch.workingDirectory().toFile());
        builder.environment().putAll(runtimeEnvironment());
        builder.redirectOutput(ProcessBuilder.Redirect.appendTo(runtimeDirectory.resolve("backend.stdout.log").toFile()));
        builder.redirectError(ProcessBuilder.Redirect.appendTo(runtimeDirectory.resolve("backend.stderr.log").toFile()));
        backendProcess = builder.start();

        try {
            waitForHealthy(Duration.ofSeconds(25));
        } catch (IOException error) {
            if (backendProcess != null && backendProcess.isAlive()) {
                backendProcess.destroyForcibly();
            }
            throw error;
        }
    }

    public synchronized void stopBackend() {
        if (backendProcess != null && backendProcess.isAlive()) {
            backendProcess.destroy();
            try {
                backendProcess.waitFor();
            } catch (InterruptedException interruptedException) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public Path runtimeDirectory() {
        return runtimeDirectory;
    }

    private void waitForHealthy(Duration timeout) throws IOException, InterruptedException {
        Instant deadline = Instant.now().plus(timeout);
        while (Instant.now().isBefore(deadline)) {
            if (backendClient.health()) {
                return;
            }
            Thread.sleep(250);
        }
        throw new HttpTimeoutException(
                "Backend did not become healthy on http://" + HOST + ":" + PORT + "/health. Check "
                        + runtimeDirectory.resolve("backend.stderr.log"));
    }

    private Map<String, String> runtimeEnvironment() {
        return Map.of(
                "SCANNER_PLATFORM_HOST", HOST,
                "SCANNER_PLATFORM_PORT", Integer.toString(PORT),
                "SCANNER_PLATFORM_DATA_DIR", runtimeDirectory.toString(),
                "SCANNER_PLATFORM_REPORTS_DIR", DesktopPaths.resolveUserReportsDir().toString(),
                "SCANNER_PLATFORM_PID_FILE", runtimeDirectory.resolve("backend.pid").toString()
        );
    }

    private BackendLaunch resolveBackendLaunch() {
        String explicitBackend = System.getenv("SCANNER_PLATFORM_BACKEND");
        if (explicitBackend != null && !explicitBackend.isBlank()) {
            Path explicitPath = Path.of(explicitBackend).toAbsolutePath().normalize();
            return new BackendLaunch(
                    List.of(explicitPath.toString(), "serve", "--host", HOST, "--port", Integer.toString(PORT)),
                    explicitPath.getParent()
            );
        }

        List<Path> packagedCandidates = new ArrayList<>();
        DesktopPaths.resolvePackagedAppDir().ifPresent(appDir -> {
            packagedCandidates.add(appDir.resolve("backend").resolve(isWindows() ? "security-platform-backend.exe" : "security-platform-backend"));
            packagedCandidates.add(appDir.resolve("lib").resolve("backend").resolve(isWindows() ? "security-platform-backend.exe" : "security-platform-backend"));
        });

        for (Path packagedBackend : packagedCandidates) {
            if (Files.exists(packagedBackend)) {
                return new BackendLaunch(
                        List.of(packagedBackend.toString(), "serve", "--host", HOST, "--port", Integer.toString(PORT)),
                        packagedBackend.getParent()
                );
            }
        }

        Path packagedBackend = repositoryRoot
                .resolve("apps")
                .resolve("desktop")
                .resolve("src-tauri")
                .resolve("backend")
                .resolve(isWindows() ? "security-platform-backend.exe" : "security-platform-backend");
        if (Files.exists(packagedBackend)) {
            return new BackendLaunch(
                    List.of(packagedBackend.toString(), "serve", "--host", HOST, "--port", Integer.toString(PORT)),
                    packagedBackend.getParent()
            );
        }

        Path venvPython = repositoryRoot.resolve(".venv")
                .resolve(isWindows() ? Path.of("Scripts", "python.exe") : Path.of("bin", "python"));
        List<String> command = new ArrayList<>();
        if (Files.exists(venvPython)) {
            command.add(venvPython.toString());
        } else if (isWindows()) {
            command.add("py");
            command.add("-3.12");
        } else {
            command.add("python3");
        }
        command.add("-m");
        command.add("security_platform.cli");
        command.add("serve");
        command.add("--host");
        command.add(HOST);
        command.add("--port");
        command.add(Integer.toString(PORT));
        return new BackendLaunch(command, repositoryRoot.resolve("services").resolve("scanner-core"));
    }

    private boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    private record BackendLaunch(List<String> command, Path workingDirectory) {
    }
}
