package com.darkworld.codebasescanner.desktopjava.javafx;

import com.darkworld.codebasescanner.desktopjava.core.ApiModels;
import com.darkworld.codebasescanner.desktopjava.core.DesktopApplicationService;
import com.darkworld.codebasescanner.desktopjava.core.DesktopPaths;
import com.darkworld.codebasescanner.desktopjava.core.LocalFilePreviewer;
import com.darkworld.codebasescanner.desktopjava.core.WorkbenchText;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.geometry.Orientation;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuBar;
import javafx.scene.control.MenuItem;
import javafx.scene.control.SplitPane;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TextArea;
import javafx.scene.control.ToolBar;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.DirectoryChooser;
import javafx.stage.Stage;

import java.awt.Desktop;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Consumer;

public final class JavaFxWorkbenchLauncher extends Application {
    private final Path repositoryRoot = DesktopPaths.resolveRepositoryRoot();
    private final DesktopApplicationService service = new DesktopApplicationService(repositoryRoot);

    private Stage stage;
    private Label backendStatusLabel;
    private Label repositoryLabel;
    private Label scoreLabel;
    private Label findingsLabel;
    private Label toolsLabel;
    private Label statusLabel;
    private TreeView<String> navigationTree;
    private TabPane workspaceTabs;
    private TextArea overviewArea;
    private TextArea inspectorArea;
    private TextArea sourceArea;
    private TextArea reportPreviewArea;
    private TextArea consoleArea;
    private ListView<ApiModels.ScanResult> scansList;
    private ListView<ApiModels.Finding> findingsList;
    private ListView<ApiModels.Artifact> artifactsList;
    private ListView<ApiModels.PluginDescriptor> pluginsList;

    private DesktopApplicationService.DesktopSnapshot snapshot;
    private Path selectedRepository = repositoryRoot;
    private List<ApiModels.Finding> currentFindings = List.of();
    private List<ApiModels.Artifact> currentArtifacts = List.of();
    private List<ApiModels.PluginDescriptor> currentPlugins = List.of();

    public static void main(String[] args) {
        if (Set.of(args).contains("--smoke-test")) {
            runSmokeTest();
            return;
        }
        launch(args);
    }

    private static void runSmokeTest() {
        Path repoRoot = DesktopPaths.resolveRepositoryRoot();
        DesktopApplicationService smokeTestService = new DesktopApplicationService(repoRoot);
        try {
            var snapshot = smokeTestService.bootstrap(repoRoot);
            System.out.println("JavaFX smoke test OK | backendReady=" + snapshot.backendReady()
                    + " | scans=" + snapshot.recentScans().size()
                    + " | plugins=" + snapshot.plugins().size());
        } catch (Exception error) {
            error.printStackTrace(System.err);
            System.exit(1);
        } finally {
            smokeTestService.shutdown();
        }
    }

    @Override
    public void start(Stage primaryStage) {
        this.stage = primaryStage;
        BorderPane root = new BorderPane();
        root.getStyleClass().add("workbench-root");
        root.setTop(buildTopShell());
        root.setCenter(buildWorkspace());
        root.setBottom(buildStatusBar());

        Scene scene = new Scene(root, 1620, 980);
        scene.getStylesheets().add(getClass().getResource("/com/darkworld/codebasescanner/desktopjava/javafx/workbench.css").toExternalForm());
        primaryStage.setTitle("Code Base Scanner - JavaFX Workbench");
        primaryStage.setScene(scene);
        primaryStage.show();

        loadInitialState();
    }

    @Override
    public void stop() {
        service.shutdown();
    }

    private VBox buildTopShell() {
        VBox box = new VBox();
        box.getChildren().addAll(buildMenuBar(), buildHeaderBar(), buildToolBar());
        return box;
    }

    private MenuBar buildMenuBar() {
        Menu file = new Menu("File");
        MenuItem openRepo = new MenuItem("Open Repository...");
        openRepo.setOnAction(event -> chooseRepository());
        MenuItem exit = new MenuItem("Exit");
        exit.setOnAction(event -> stage.close());
        file.getItems().addAll(openRepo, exit);

        Menu scan = new Menu("Scan");
        MenuItem start = new MenuItem("Start Scan");
        start.setOnAction(event -> startScan());
        MenuItem refresh = new MenuItem("Refresh");
        refresh.setOnAction(event -> refreshSnapshot());
        MenuItem sync = new MenuItem("Sync Advisories");
        sync.setOnAction(event -> syncAdvisories());
        scan.getItems().addAll(start, refresh, sync);

        Menu reports = new Menu("Reports");
        MenuItem generate = new MenuItem("Generate Report Set");
        generate.setOnAction(event -> generateReports());
        MenuItem openSelected = new MenuItem("Open Selected Artifact");
        openSelected.setOnAction(event -> openSelectedArtifact());
        reports.getItems().addAll(generate, openSelected);

        Menu tools = new Menu("Tools");
        MenuItem install = new MenuItem("Install Selected Tool");
        install.setOnAction(event -> installSelectedPlugin());
        tools.getItems().add(install);

        return new MenuBar(file, scan, reports, tools);
    }

    private HBox buildHeaderBar() {
        HBox box = new HBox(16);
        box.getStyleClass().add("header-bar");
        box.setPadding(new Insets(14, 16, 10, 16));
        VBox titleBox = new VBox(4);
        Label title = new Label("Code Base Scanner");
        title.getStyleClass().add("header-title");
        repositoryLabel = new Label("Repository: " + selectedRepository);
        backendStatusLabel = new Label("Backend starting...");
        titleBox.getChildren().addAll(title, repositoryLabel);
        HBox.setHgrow(titleBox, Priority.ALWAYS);
        box.getChildren().addAll(titleBox, backendStatusLabel);
        return box;
    }

    private ToolBar buildToolBar() {
        ToolBar toolBar = new ToolBar();
        toolBar.getItems().addAll(
                actionButton("Start Scan", this::startScan),
                actionButton("Open Repository", this::chooseRepository),
                actionButton("Refresh", this::refreshSnapshot),
                actionButton("Generate Reports", this::generateReports),
                actionButton("Sync Advisories", this::syncAdvisories)
        );
        return toolBar;
    }

    private SplitPane buildWorkspace() {
        navigationTree = new TreeView<>(buildNavigationTree());
        navigationTree.setShowRoot(false);
        navigationTree.getSelectionModel().selectedItemProperty().addListener((obs, oldValue, newValue) -> {
            if (newValue == null) {
                return;
            }
            switch (newValue.getValue()) {
                case "Overview" -> workspaceTabs.getSelectionModel().select(0);
                case "Findings" -> workspaceTabs.getSelectionModel().select(1);
                case "Reports" -> workspaceTabs.getSelectionModel().select(2);
                case "Runtime" -> workspaceTabs.getSelectionModel().select(3);
                default -> {
                }
            }
        });

        workspaceTabs = new TabPane(
                buildOverviewTab(),
                buildFindingsTab(),
                buildReportsTab(),
                buildRuntimeTab()
        );

        TabPane inspectorTabs = new TabPane();
        inspectorArea = readOnlyArea();
        sourceArea = readOnlyArea();
        inspectorTabs.getTabs().addAll(
                nonClosableTab("Details", inspectorArea),
                nonClosableTab("Source", sourceArea)
        );

        SplitPane centerSplit = new SplitPane(workspaceTabs, inspectorTabs);
        centerSplit.setDividerPositions(0.74);

        consoleArea = readOnlyArea();
        consoleArea.setPrefRowCount(8);
        VBox consoleBox = new VBox(8, labeledSection("Event Console"), consoleArea);
        consoleBox.setPadding(new Insets(12));
        consoleBox.getStyleClass().add("console-box");

        SplitPane contentSplit = new SplitPane(new VBox(navigationTree), centerSplit);
        contentSplit.setDividerPositions(0.16);

        SplitPane vertical = new SplitPane(contentSplit, consoleBox);
        vertical.setOrientation(Orientation.VERTICAL);
        vertical.setDividerPositions(0.76);
        return vertical;
    }

    private Tab buildOverviewTab() {
        overviewArea = readOnlyArea();
        scansList = new ListView<>();
        scansList.setCellFactory(list -> new ListCell<>() {
            @Override
            protected void updateItem(ApiModels.ScanResult item, boolean empty) {
                super.updateItem(item, empty);
                setText(empty || item == null ? null : item.startedAt() + " | " + item.status() + " | " + item.repositoryPath());
            }
        });
        scansList.getSelectionModel().selectedItemProperty().addListener((obs, oldValue, newValue) -> {
            if (newValue == null || snapshot == null) {
                return;
            }
            snapshot = snapshot.withActiveScan(newValue);
            applySnapshot(snapshot);
            appendConsole("Loaded historical scan " + newValue.scanId());
        });

        scoreLabel = metricLabel("Score: --");
        findingsLabel = metricLabel("Findings: --");
        toolsLabel = metricLabel("Tools: --");
        statusLabel = metricLabel("Status: idle");
        HBox metrics = new HBox(12, scoreLabel, findingsLabel, toolsLabel, statusLabel);

        VBox content = new VBox(12, metrics, labeledSection("Repository Summary"), overviewArea, labeledSection("Recent Scans"), scansList);
        content.setPadding(new Insets(12));
        VBox.setVgrow(overviewArea, Priority.ALWAYS);
        VBox.setVgrow(scansList, Priority.ALWAYS);
        return nonClosableTab("Overview", content);
    }

    private Tab buildFindingsTab() {
        findingsList = new ListView<>();
        findingsList.setCellFactory(list -> new ListCell<>() {
            @Override
            protected void updateItem(ApiModels.Finding item, boolean empty) {
                super.updateItem(item, empty);
                setText(empty || item == null ? null : "[" + item.severity() + "] " + item.title());
            }
        });
        findingsList.getSelectionModel().selectedItemProperty().addListener((obs, oldValue, newValue) -> {
            if (newValue == null) {
                return;
            }
            inspectorArea.setText(WorkbenchText.formatFindingDetails(newValue));
            sourceArea.setText(LocalFilePreviewer.sourcePreview(selectedRepository, newValue));
        });
        VBox content = new VBox(12, labeledSection("Findings"), findingsList);
        content.setPadding(new Insets(12));
        VBox.setVgrow(findingsList, Priority.ALWAYS);
        return nonClosableTab("Findings", content);
    }

    private Tab buildReportsTab() {
        artifactsList = new ListView<>();
        artifactsList.setCellFactory(list -> new ListCell<>() {
            @Override
            protected void updateItem(ApiModels.Artifact item, boolean empty) {
                super.updateItem(item, empty);
                setText(empty || item == null ? null : (item.label() == null || item.label().isBlank() ? item.kind() : item.label()));
            }
        });
        artifactsList.getSelectionModel().selectedItemProperty().addListener((obs, oldValue, newValue) -> {
            if (newValue == null) {
                return;
            }
            inspectorArea.setText(WorkbenchText.formatArtifactDetails(newValue));
            reportPreviewArea.setText(LocalFilePreviewer.filePreview(newValue.path(), 120_000, 320));
        });

        reportPreviewArea = readOnlyArea();
        Button generateButton = actionButton("Generate Reports", this::generateReports);
        Button openButton = actionButton("Open Selected", this::openSelectedArtifact);
        HBox actions = new HBox(8, generateButton, openButton);
        SplitPane split = new SplitPane(artifactsList, reportPreviewArea);
        split.setDividerPositions(0.3);

        VBox content = new VBox(12, actions, split);
        content.setPadding(new Insets(12));
        VBox.setVgrow(split, Priority.ALWAYS);
        return nonClosableTab("Reports", content);
    }

    private Tab buildRuntimeTab() {
        pluginsList = new ListView<>();
        pluginsList.setCellFactory(list -> new ListCell<>() {
            @Override
            protected void updateItem(ApiModels.PluginDescriptor item, boolean empty) {
                super.updateItem(item, empty);
                setText(empty || item == null ? null : item.metadata().displayName() + " | " + (item.available() ? "Installed" : "Missing"));
            }
        });
        pluginsList.getSelectionModel().selectedItemProperty().addListener((obs, oldValue, newValue) -> {
            if (newValue == null) {
                return;
            }
            inspectorArea.setText(WorkbenchText.formatPluginDetails(newValue));
            sourceArea.setText("Tool runtimes do not have source previews.");
        });
        Button installButton = actionButton("Install Selected", this::installSelectedPlugin);
        VBox content = new VBox(12, installButton, pluginsList);
        content.setPadding(new Insets(12));
        VBox.setVgrow(pluginsList, Priority.ALWAYS);
        return nonClosableTab("Runtime", content);
    }

    private HBox buildStatusBar() {
        HBox bar = new HBox(16);
        bar.getStyleClass().add("status-bar");
        bar.setPadding(new Insets(8, 12, 10, 12));
        bar.getChildren().addAll(
                new Label("Java rewrite path: Swing + JavaFX"),
                new Label("Backend: 127.0.0.1:8686"),
                new Label("Repo root: " + repositoryRoot)
        );
        return bar;
    }

    private void loadInitialState() {
        runBackground("Bootstrapping JavaFX workbench", () -> service.bootstrap(selectedRepository), latest -> {
            snapshot = latest;
            applySnapshot(latest);
            appendConsole("JavaFX workbench ready. Backend runtime: " + service.runtimeDirectory());
        });
    }

    private void refreshSnapshot() {
        runBackground("Refreshing workbench state", () -> service.refresh(selectedRepository), latest -> {
            snapshot = latest;
            applySnapshot(latest);
            appendConsole("Runtime state refreshed.");
        });
    }

    private void startScan() {
        if (selectedRepository == null) {
            chooseRepository();
            if (selectedRepository == null) {
                return;
            }
        }
        runBackground("Running repository scan", () -> service.startScan(selectedRepository), latest -> {
            snapshot = latest;
            applySnapshot(latest);
            appendConsole("Scan completed for " + selectedRepository);
        });
    }

    private void syncAdvisories() {
        runBackground("Refreshing advisory feeds", service::updateAdvisories, result -> {
            appendConsole("Advisory refresh completed: " + result);
            refreshSnapshot();
        });
    }

    private void generateReports() {
        if (snapshot == null || snapshot.activeScan() == null) {
            showError("Generate Reports", new IllegalStateException("No active scan is loaded yet."));
            return;
        }
        List<String> profiles = snapshot.reportProfiles().stream().map(ApiModels.ReportProfileDefinition::id).toList();
        runBackground("Generating report set", () -> service.generateReports(snapshot.activeScan().scanId(), profiles, true), artifacts -> {
            appendConsole("Generated " + artifacts.size() + " report artifacts for scan " + snapshot.activeScan().scanId());
            refreshSnapshot();
            workspaceTabs.getSelectionModel().select(2);
        });
    }

    private void installSelectedPlugin() {
        ApiModels.PluginDescriptor plugin = pluginsList.getSelectionModel().getSelectedItem();
        if (plugin == null) {
            showError("Install Tool", new IllegalStateException("Select a tool first."));
            return;
        }
        runBackground("Installing " + plugin.metadata().displayName(), () -> {
            service.installTool(plugin.metadata().name());
            return plugin.metadata().displayName();
        }, toolName -> {
            appendConsole("Installed tool runtime for " + toolName);
            refreshSnapshot();
        });
    }

    private void chooseRepository() {
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setInitialDirectory(selectedRepository != null ? selectedRepository.toFile() : repositoryRoot.toFile());
        chooser.setTitle("Choose repository to scan");
        var selected = chooser.showDialog(stage);
        if (selected != null) {
            selectedRepository = selected.toPath().toAbsolutePath().normalize();
            repositoryLabel.setText("Repository: " + selectedRepository);
            appendConsole("Repository selected: " + selectedRepository);
            refreshSnapshot();
        }
    }

    private void openSelectedArtifact() {
        ApiModels.Artifact artifact = artifactsList.getSelectionModel().getSelectedItem();
        if (artifact == null) {
            showError("Open Artifact", new IllegalStateException("Select a report artifact first."));
            return;
        }
        try {
            Desktop.getDesktop().open(Path.of(artifact.path()).toFile());
        } catch (Exception error) {
            showError("Open Artifact", error);
        }
    }

    private void applySnapshot(DesktopApplicationService.DesktopSnapshot latest) {
        backendStatusLabel.setText(latest.backendReady() ? "Backend ready" : "Backend unavailable");
        repositoryLabel.setText("Repository: " + latest.selectedRepository());
        overviewArea.setText(WorkbenchText.formatRepositorySummary(latest.selectedRepository(), latest.activeScan())
                + System.lineSeparator() + System.lineSeparator()
                + WorkbenchText.formatScanOverview(latest.activeScan()));
        scansList.setItems(FXCollections.observableArrayList(latest.recentScans()));

        ApiModels.ScanResult activeScan = latest.activeScan();
        currentFindings = activeScan != null ? activeScan.safeFindings() : List.of();
        currentArtifacts = activeScan != null ? activeScan.safeArtifacts() : List.of();
        currentPlugins = latest.plugins();
        findingsList.setItems(FXCollections.observableArrayList(currentFindings));
        artifactsList.setItems(FXCollections.observableArrayList(currentArtifacts));
        pluginsList.setItems(FXCollections.observableArrayList(currentPlugins));

        if (activeScan != null && activeScan.summary() != null) {
            scoreLabel.setText("Score: " + activeScan.summary().score());
            findingsLabel.setText("Findings: " + activeScan.summary().totalFindings());
            toolsLabel.setText("Tools: " + activeScan.completedTools() + "/" + activeScan.totalTools());
            statusLabel.setText("Status: " + activeScan.status());
            inspectorArea.setText(WorkbenchText.formatScanOverview(activeScan));
        } else {
            scoreLabel.setText("Score: --");
            findingsLabel.setText("Findings: --");
            toolsLabel.setText("Tools: --");
            statusLabel.setText("Status: idle");
        }

        if (!currentFindings.isEmpty()) {
            findingsList.getSelectionModel().select(0);
        }
        if (!currentArtifacts.isEmpty()) {
            artifactsList.getSelectionModel().select(0);
        } else {
            reportPreviewArea.setText("No report artifacts are attached to the active scan yet.");
        }
        if (!currentPlugins.isEmpty()) {
            pluginsList.getSelectionModel().select(0);
        }
    }

    private <T> void runBackground(String activity, Callable<T> task, Consumer<T> onSuccess) {
        appendConsole(activity + "...");
        CompletableFuture.supplyAsync(() -> {
            try {
                return task.call();
            } catch (Exception error) {
                throw new CompletionException(error);
            }
        }).whenComplete((result, error) -> Platform.runLater(() -> {
            if (error != null) {
                Throwable cause = error instanceof CompletionException && error.getCause() != null ? error.getCause() : error;
                showError(activity, cause);
                return;
            }
            onSuccess.accept(result);
        }));
    }

    private void appendConsole(String message) {
        if (consoleArea == null) {
            return;
        }
        consoleArea.appendText(message + System.lineSeparator());
    }

    private void showError(String activity, Throwable error) {
        appendConsole(activity + " failed: " + error.getMessage());
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle(activity);
        alert.setHeaderText(activity);
        alert.setContentText(error.getMessage());
        alert.showAndWait();
    }

    private Button actionButton(String label, Runnable action) {
        Button button = new Button(label);
        button.setOnAction(event -> action.run());
        return button;
    }

    private TextArea readOnlyArea() {
        TextArea area = new TextArea();
        area.setEditable(false);
        area.setWrapText(true);
        return area;
    }

    private Tab nonClosableTab(String title, javafx.scene.Node content) {
        Tab tab = new Tab(title, content);
        tab.setClosable(false);
        return tab;
    }

    private TreeItem<String> buildNavigationTree() {
        TreeItem<String> root = new TreeItem<>("Code Base Scanner");
        TreeItem<String> workspace = new TreeItem<>("Workspace");
        workspace.getChildren().addAll(
                new TreeItem<>("Overview"),
                new TreeItem<>("Findings"),
                new TreeItem<>("Reports"),
                new TreeItem<>("Runtime")
        );
        workspace.setExpanded(true);
        root.getChildren().add(workspace);
        root.setExpanded(true);
        return root;
    }

    private Label metricLabel(String text) {
        Label label = new Label(text);
        label.getStyleClass().add("metric-label");
        return label;
    }

    private Label labeledSection(String text) {
        Label label = new Label(text);
        label.getStyleClass().add("section-label");
        return label;
    }
}
