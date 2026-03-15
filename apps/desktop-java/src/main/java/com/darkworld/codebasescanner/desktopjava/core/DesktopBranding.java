package com.darkworld.codebasescanner.desktopjava.core;

import javafx.scene.image.Image;

import javax.imageio.ImageIO;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

public final class DesktopBranding {
    private static final String ICON_RESOURCE = "/com/darkworld/codebasescanner/desktopjava/branding/app-icon.png";

    private DesktopBranding() {
    }

    public static Image loadFxIcon() {
        try (InputStream stream = DesktopBranding.class.getResourceAsStream(ICON_RESOURCE)) {
            if (stream == null) {
                throw new IOException("Missing JavaFX icon resource: " + ICON_RESOURCE);
            }
            return new Image(stream);
        } catch (IOException error) {
            throw new IllegalStateException("Unable to load JavaFX app icon", error);
        }
    }

    public static java.awt.Image loadAwtIcon() {
        try (InputStream stream = DesktopBranding.class.getResourceAsStream(ICON_RESOURCE)) {
            if (stream == null) {
                throw new IOException("Missing Swing icon resource: " + ICON_RESOURCE);
            }
            return ImageIO.read(stream);
        } catch (IOException error) {
            throw new IllegalStateException("Unable to load Swing app icon", error);
        }
    }

    public static List<java.awt.Image> loadAwtIcons() {
        return List.of(loadAwtIcon());
    }
}
