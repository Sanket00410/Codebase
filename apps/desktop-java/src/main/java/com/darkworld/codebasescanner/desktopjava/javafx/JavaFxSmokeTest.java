package com.darkworld.codebasescanner.desktopjava.javafx;

import com.darkworld.codebasescanner.desktopjava.core.DesktopApplicationService;
import com.darkworld.codebasescanner.desktopjava.core.DesktopPaths;

import java.nio.file.Path;

public final class JavaFxSmokeTest {
    private JavaFxSmokeTest() {
    }

    public static void main(String[] args) {
        Path repoRoot = DesktopPaths.resolveRepositoryRoot();
        DesktopApplicationService service = new DesktopApplicationService(repoRoot);
        try {
            var snapshot = service.bootstrap(repoRoot);
            System.out.println("JavaFX smoke test OK | backendReady=" + snapshot.backendReady()
                    + " | scans=" + snapshot.recentScans().size()
                    + " | plugins=" + snapshot.plugins().size());
        } catch (Exception error) {
            error.printStackTrace(System.err);
            System.exit(1);
        } finally {
            service.shutdown();
        }
    }
}
