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
