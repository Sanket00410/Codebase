# Code Base Scanner Java Desktop Rewrite

This module starts the Java desktop rewrite path for the existing scanner platform without replacing the current Tauri host yet.

It contains:

- a shared Java backend client and runtime bootstrap layer
- a Swing desktop workbench launcher
- a JavaFX desktop workbench launcher

## Build

From the repo root:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-java-desktop.ps1 -Task build
```

## Run

Swing:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run-java-desktop-swing.ps1
```

JavaFX:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run-java-desktop-javafx.ps1
```

## Smoke test

Swing smoke test:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-java-desktop.ps1 -Task smokeTestSwing
```

JavaFX smoke test:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-java-desktop.ps1 -Task smokeTestJavaFx
```

## Package

Create Windows app-image packaging for the rewrite path:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\package-java-desktop.ps1 -Flavor both
```

Create Windows installer packaging:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\package-java-desktop.ps1 -Flavor javafx -Type exe
powershell -ExecutionPolicy Bypass -File scripts\package-java-desktop.ps1 -Flavor javafx -Type msi
```

The packaging script bootstraps a portable WiX 3.14 toolchain into `.tools\wix314\bin` automatically for `exe` and `msi` packaging, so the scripted installer path does not require a separate machine-wide WiX installation.
