package com.darkworld.codebasescanner.desktopjava.core;

import java.awt.Desktop;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

public final class SystemShellSupport {
    private SystemShellSupport() {
    }

    public static void openPath(Path path) throws IOException {
        IOException desktopError = null;
        try {
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().open(path.toFile());
                return;
            }
        } catch (IOException error) {
            desktopError = error;
        }

        if (isWindows()) {
            try {
                new ProcessBuilder("cmd", "/c", "start", "", path.toString()).start();
                return;
            } catch (IOException error) {
                if (desktopError == null) {
                    desktopError = error;
                }
            }
        }

        if (desktopError != null) {
            throw desktopError;
        }
        throw new IOException("No system file-open handler is available for " + path);
    }

    public static void openFolder(Path folder) throws IOException {
        Path target = folder;
        if (Files.isRegularFile(folder)) {
            target = folder.getParent();
        }
        if (target == null) {
            throw new IOException("Unable to resolve a folder for the selected path.");
        }
        openPath(target);
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }
}
