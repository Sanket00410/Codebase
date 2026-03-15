import org.gradle.internal.os.OperatingSystem
import java.io.ByteArrayOutputStream

plugins {
    application
}

group = "com.darkworld.codebasescanner"
version = "0.1.0"

val javafxVersion = "21.0.6"
val currentOs = OperatingSystem.current()
val javafxPlatform = when {
    currentOs.isWindows -> "win"
    currentOs.isMacOsX -> "mac"
    else -> "linux"
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind:2.18.4")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.18.4")
    implementation("com.formdev:flatlaf:3.6")
    implementation("org.openjfx:javafx-base:$javafxVersion:$javafxPlatform")
    implementation("org.openjfx:javafx-graphics:$javafxVersion:$javafxPlatform")
    implementation("org.openjfx:javafx-controls:$javafxVersion:$javafxPlatform")
}

application {
    mainClass.set("com.darkworld.codebasescanner.desktopjava.swing.SwingWorkbenchLauncher")
}

val installLibDir = layout.buildDirectory.dir("install/${project.name}/lib")
val packageRootDir = layout.buildDirectory.dir("jpackage")
val packagedBackendDir = installLibDir.map { it.dir("backend") }
val backendSourceDir = projectDir.resolveSibling("desktop").resolve("src-tauri").resolve("backend")
val windowsIconFile = projectDir.resolve("branding").resolve("code-base-scanner.ico")

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release.set(21)
}

tasks.register<Copy>("syncPackagedBackend") {
    group = "distribution"
    description = "Copy the packaged backend runtime into the Java desktop distribution input."
    from(backendSourceDir)
    include("security-platform-backend.exe", "security-platform-backend", "README.md")
    into(packagedBackendDir)
    mustRunAfter("installDist")
}

tasks.register<JavaExec>("runSwing") {
    group = "application"
    description = "Run the Swing desktop workbench rewrite."
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set("com.darkworld.codebasescanner.desktopjava.swing.SwingWorkbenchLauncher")
}

tasks.register<JavaExec>("runJavaFx") {
    group = "application"
    description = "Run the JavaFX desktop workbench rewrite."
    mainClass.set("com.darkworld.codebasescanner.desktopjava.javafx.JavaFxWorkbenchLauncher")
    doFirst {
        val runtimeClasspath = sourceSets.main.get().runtimeClasspath.files
        classpath = files(runtimeClasspath.filterNot { it.name.startsWith("javafx-") })
        jvmArgs(
            "--module-path",
            files(runtimeClasspath.filter { it.name.startsWith("javafx-") }).asPath,
            "--add-modules",
            "javafx.controls,javafx.graphics,javafx.base"
        )
    }
}

tasks.register<JavaExec>("smokeTestSwing") {
    group = "verification"
    description = "Bootstrap the Swing rewrite path without keeping the UI open."
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set("com.darkworld.codebasescanner.desktopjava.swing.SwingWorkbenchLauncher")
    args("--smoke-test")
}

tasks.register<JavaExec>("smokeTestJavaFx") {
    group = "verification"
    description = "Bootstrap the JavaFX rewrite path without keeping the UI open."
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set("com.darkworld.codebasescanner.desktopjava.javafx.JavaFxSmokeTest")
}

tasks.register<Exec>("packageSwingAppImage") {
    group = "distribution"
    description = "Package the Swing rewrite path as a jpackage app-image."
    dependsOn("installDist", "syncPackagedBackend")
    doFirst {
        val javaHome = System.getenv("JAVA_HOME") ?: System.getProperty("java.home")
        val jpackageName = if (currentOs.isWindows) "jpackage.exe" else "jpackage"
        val jpackageExecutable = file("$javaHome/bin/$jpackageName")
        val outputDir = packageRootDir.get().dir("swing").asFile
        outputDir.mkdirs()
        outputDir.resolve("CodeBaseScannerSwing").deleteRecursively()
        commandLine(
            jpackageExecutable.absolutePath,
            "--type", "app-image",
            "--dest", outputDir.absolutePath,
            "--name", "CodeBaseScannerSwing",
            "--input", installLibDir.get().asFile.absolutePath,
            "--main-jar", "code-base-scanner-desktop-java-0.1.0.jar",
            "--main-class", "com.darkworld.codebasescanner.desktopjava.swing.SwingWorkbenchLauncher",
            "--icon", windowsIconFile.absolutePath,
            "--java-options", "-Dfile.encoding=UTF-8",
            "--java-options", "-Dcode.base.scanner.app.dir=\$APPDIR"
        )
    }
}

tasks.register<Exec>("packageJavaFxAppImage") {
    group = "distribution"
    description = "Package the JavaFX rewrite path as a jpackage app-image."
    dependsOn("installDist", "syncPackagedBackend")
    doFirst {
        val javaHome = System.getenv("JAVA_HOME") ?: System.getProperty("java.home")
        val jpackageName = if (currentOs.isWindows) "jpackage.exe" else "jpackage"
        val jpackageExecutable = file("$javaHome/bin/$jpackageName")
        val outputDir = packageRootDir.get().dir("javafx").asFile
        outputDir.mkdirs()
        outputDir.resolve("CodeBaseScannerJavaFx").deleteRecursively()
        commandLine(
            jpackageExecutable.absolutePath,
            "--type", "app-image",
            "--dest", outputDir.absolutePath,
            "--name", "CodeBaseScannerJavaFx",
            "--input", installLibDir.get().asFile.absolutePath,
            "--main-jar", "code-base-scanner-desktop-java-0.1.0.jar",
            "--main-class", "com.darkworld.codebasescanner.desktopjava.javafx.JavaFxWorkbenchLauncher",
            "--icon", windowsIconFile.absolutePath,
            "--java-options", "-Dfile.encoding=UTF-8",
            "--java-options", "-Dcode.base.scanner.app.dir=\$APPDIR",
            "--java-options", "--module-path",
            "--java-options", "\$APPDIR",
            "--java-options", "--add-modules",
            "--java-options", "javafx.controls,javafx.graphics,javafx.base"
        )
    }
}

fun wixAvailable(): Boolean {
    if (!currentOs.isWindows) {
        return false
    }
    val candidates = listOf("wix", "candle.exe", "light.exe")
    return candidates.any { candidate ->
        try {
            val output = ByteArrayOutputStream()
            exec {
                isIgnoreExitValue = true
                commandLine("cmd", "/c", "where", candidate)
                standardOutput = output
                errorOutput = output
            }.exitValue == 0
        } catch (_: Exception) {
            false
        }
    }
}

fun configureWindowsInstallerTask(
    taskName: String,
    taskDescription: String,
    packageType: String,
    appName: String,
    mainClassName: String,
    includeJavaFxModules: Boolean
) = tasks.register<Exec>(taskName) {
    group = "distribution"
    description = taskDescription
    dependsOn("installDist", "syncPackagedBackend")
    doFirst {
        if (!currentOs.isWindows) {
            throw GradleException("Windows installer packaging is only supported on Windows builders.")
        }
        if (!wixAvailable()) {
            throw GradleException("WiX Toolset was not found on PATH. Install WiX to build Windows exe/msi installers.")
        }
        val javaHome = System.getenv("JAVA_HOME") ?: System.getProperty("java.home")
        val jpackageExecutable = file("$javaHome/bin/jpackage.exe")
        val outputDir = packageRootDir.get().dir("${appName.lowercase()}-$packageType").asFile
        outputDir.mkdirs()
        outputDir.resolve(appName).deleteRecursively()
        val command = mutableListOf(
            jpackageExecutable.absolutePath,
            "--type", packageType,
            "--dest", outputDir.absolutePath,
            "--name", appName,
            "--input", installLibDir.get().asFile.absolutePath,
            "--main-jar", "code-base-scanner-desktop-java-0.1.0.jar",
            "--main-class", mainClassName,
            "--icon", windowsIconFile.absolutePath,
            "--java-options", "-Dfile.encoding=UTF-8",
            "--java-options", "-Dcode.base.scanner.app.dir=\$APPDIR"
        )
        if (includeJavaFxModules) {
            command.addAll(
                listOf(
                    "--java-options", "--module-path",
                    "--java-options", "\$APPDIR",
                    "--java-options", "--add-modules",
                    "--java-options", "javafx.controls,javafx.graphics,javafx.base"
                )
            )
        }
        commandLine(command)
    }
}

configureWindowsInstallerTask(
    taskName = "packageSwingExe",
    taskDescription = "Package the Swing rewrite path as a Windows exe installer.",
    packageType = "exe",
    appName = "CodeBaseScannerSwing",
    mainClassName = "com.darkworld.codebasescanner.desktopjava.swing.SwingWorkbenchLauncher",
    includeJavaFxModules = false
)

configureWindowsInstallerTask(
    taskName = "packageSwingMsi",
    taskDescription = "Package the Swing rewrite path as a Windows msi installer.",
    packageType = "msi",
    appName = "CodeBaseScannerSwing",
    mainClassName = "com.darkworld.codebasescanner.desktopjava.swing.SwingWorkbenchLauncher",
    includeJavaFxModules = false
)

configureWindowsInstallerTask(
    taskName = "packageJavaFxExe",
    taskDescription = "Package the JavaFX rewrite path as a Windows exe installer.",
    packageType = "exe",
    appName = "CodeBaseScannerJavaFx",
    mainClassName = "com.darkworld.codebasescanner.desktopjava.javafx.JavaFxWorkbenchLauncher",
    includeJavaFxModules = true
)

configureWindowsInstallerTask(
    taskName = "packageJavaFxMsi",
    taskDescription = "Package the JavaFX rewrite path as a Windows msi installer.",
    packageType = "msi",
    appName = "CodeBaseScannerJavaFx",
    mainClassName = "com.darkworld.codebasescanner.desktopjava.javafx.JavaFxWorkbenchLauncher",
    includeJavaFxModules = true
)
