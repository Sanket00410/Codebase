import org.gradle.internal.os.OperatingSystem

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

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release.set(21)
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
    dependsOn("installDist")
    doFirst {
        val javaHome = System.getenv("JAVA_HOME") ?: System.getProperty("java.home")
        val jpackageName = if (currentOs.isWindows) "jpackage.exe" else "jpackage"
        val jpackageExecutable = file("$javaHome/bin/$jpackageName")
        val outputDir = packageRootDir.get().dir("swing").asFile
        outputDir.mkdirs()
        commandLine(
            jpackageExecutable.absolutePath,
            "--type", "app-image",
            "--dest", outputDir.absolutePath,
            "--name", "CodeBaseScannerSwing",
            "--input", installLibDir.get().asFile.absolutePath,
            "--main-jar", "code-base-scanner-desktop-java-0.1.0.jar",
            "--main-class", "com.darkworld.codebasescanner.desktopjava.swing.SwingWorkbenchLauncher",
            "--java-options", "-Dfile.encoding=UTF-8"
        )
    }
}

tasks.register<Exec>("packageJavaFxAppImage") {
    group = "distribution"
    description = "Package the JavaFX rewrite path as a jpackage app-image."
    dependsOn("installDist")
    doFirst {
        val javaHome = System.getenv("JAVA_HOME") ?: System.getProperty("java.home")
        val jpackageName = if (currentOs.isWindows) "jpackage.exe" else "jpackage"
        val jpackageExecutable = file("$javaHome/bin/$jpackageName")
        val outputDir = packageRootDir.get().dir("javafx").asFile
        outputDir.mkdirs()
        commandLine(
            jpackageExecutable.absolutePath,
            "--type", "app-image",
            "--dest", outputDir.absolutePath,
            "--name", "CodeBaseScannerJavaFx",
            "--input", installLibDir.get().asFile.absolutePath,
            "--main-jar", "code-base-scanner-desktop-java-0.1.0.jar",
            "--main-class", "com.darkworld.codebasescanner.desktopjava.javafx.JavaFxWorkbenchLauncher",
            "--java-options", "-Dfile.encoding=UTF-8",
            "--java-options", "--module-path",
            "--java-options", "\$APPDIR\\lib",
            "--java-options", "--add-modules",
            "--java-options", "javafx.controls,javafx.graphics,javafx.base"
        )
    }
}
