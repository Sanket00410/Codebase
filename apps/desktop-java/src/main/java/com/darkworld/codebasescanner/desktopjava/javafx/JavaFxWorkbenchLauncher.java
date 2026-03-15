package com.darkworld.codebasescanner.desktopjava.javafx;

import com.darkworld.codebasescanner.desktopjava.core.ApiModels;
import com.darkworld.codebasescanner.desktopjava.core.DesktopApplicationService;
import com.darkworld.codebasescanner.desktopjava.core.DesktopBranding;
import com.darkworld.codebasescanner.desktopjava.core.DesktopPaths;
import com.darkworld.codebasescanner.desktopjava.core.LocalFilePreviewer;
import com.darkworld.codebasescanner.desktopjava.core.ReportArtifactSupport;
import com.darkworld.codebasescanner.desktopjava.core.SystemShellSupport;
import com.darkworld.codebasescanner.desktopjava.core.WorkbenchText;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.geometry.Orientation;
import javafx.geometry.Rectangle2D;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuBar;
import javafx.scene.control.MenuItem;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.SplitPane;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.ToolBar;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyCodeCombination;
import javafx.scene.input.KeyCombination;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Region;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.DirectoryChooser;
import javafx.stage.Screen;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;

import java.nio.file.Path;
import java.util.ArrayList;
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
    private Label artifactsLabel;
    private Label missingToolsLabel;
    private Label repositoryStatusLabel;
    private Label backendStateStatusLabel;
    private Label activeScanStatusLabel;
    private Label statusFindingsValueLabel;
    private Label reportsFolderStatusLabel;
    private TreeView<String> navigationTree;
    private TabPane workspaceTabs;
    private TextArea overviewArea;
    private TextArea inspectorArea;
    private TextArea sourceArea;
    private TextArea reportPreviewArea;
    private TextArea consoleArea;
    private TabPane bottomDockTabs;
    private ListView<ApiModels.ScanResult> scansList;
    private ListView<ApiModels.ScanResult> timelineList;
    private ListView<ApiModels.Finding> findingsList;
    private ListView<ApiModels.DependencyNode> dependenciesList;
    private ListView<ApiModels.Artifact> artifactsList;
    private ListView<ApiModels.PluginDescriptor> pluginsList;
    private TextField findingFilterField;
    private TextField pluginFilterField;
    private Label reportFolderLabel;
    private Label latestArtifactLabel;
    private Label generatedReportsLabel;
    private Label selectedArtifactLabel;
    private VBox reportProfilesBox;
    private CheckBox includePlusVariantsCheck;

    private DesktopApplicationService.DesktopSnapshot snapshot;
    private Path selectedRepository = DesktopPaths.looksLikeRepositoryRoot(repositoryRoot) ? repositoryRoot : null;
    private List<ApiModels.Finding> currentFindings = List.of();
    private List<ApiModels.DependencyNode> currentDependencies = List.of();
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

        Rectangle2D bounds = Screen.getPrimary().getVisualBounds();
        double width = Math.min(1460, Math.max(1180, bounds.getWidth() - 56));
        double height = Math.min(920, Math.max(760, bounds.getHeight() - 72));

        Scene scene = new Scene(root, width, height);
        scene.getStylesheets().add(getClass().getResource("/com/darkworld/codebasescanner/desktopjava/javafx/workbench.css").toExternalForm());
        primaryStage.setTitle("Code Base Scanner - JavaFX Workbench");
        primaryStage.getIcons().setAll(DesktopBranding.loadFxIcon());
        primaryStage.setScene(scene);
        primaryStage.setMinWidth(Math.min(width, 1160));
        primaryStage.setMinHeight(Math.min(height, 740));
        primaryStage.setOnCloseRequest(this::handleCloseRequest);
        primaryStage.centerOnScreen();
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
        openRepo.setAccelerator(new KeyCodeCombination(KeyCode.O, KeyCombination.SHORTCUT_DOWN));
        openRepo.setOnAction(event -> chooseRepository());
        MenuItem exit = new MenuItem("Exit");
        exit.setOnAction(event -> stage.close());
        file.getItems().addAll(openRepo, exit);

        Menu scan = new Menu("Scan");
        MenuItem start = new MenuItem("Start Scan");
        start.setAccelerator(new KeyCodeCombination(KeyCode.ENTER, KeyCombination.SHORTCUT_DOWN));
        start.setOnAction(event -> startScan());
        MenuItem refresh = new MenuItem("Refresh");
        refresh.setAccelerator(new KeyCodeCombination(KeyCode.R, KeyCombination.SHORTCUT_DOWN));
        refresh.setOnAction(event -> refreshSnapshot());
        MenuItem sync = new MenuItem("Sync Advisories");
        sync.setOnAction(event -> syncAdvisories());
        scan.getItems().addAll(start, refresh, sync);

        Menu reports = new Menu("Reports");
        MenuItem generate = new MenuItem("Generate Report Set");
        generate.setAccelerator(new KeyCodeCombination(KeyCode.G, KeyCombination.SHORTCUT_DOWN));
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
        titleBox.getStyleClass().add("title-box");
        Label title = new Label("Code Base Scanner");
        title.getStyleClass().add("header-title");
        repositoryLabel = new Label(repositorySummaryText(selectedRepository));
        repositoryLabel.getStyleClass().add("header-subtitle");
        backendStatusLabel = new Label("Backend starting...");
        backendStatusLabel.getStyleClass().addAll("status-pill", "status-pill-pending");
        titleBox.getChildren().addAll(title, repositoryLabel);
        HBox.setHgrow(titleBox, Priority.ALWAYS);
        box.getChildren().addAll(titleBox, backendStatusLabel);
        return box;
    }

    private ToolBar buildToolBar() {
        ToolBar toolBar = new ToolBar();
        toolBar.getStyleClass().add("workbench-toolbar");
        Button startButton = primaryActionButton("Start Scan", this::startScan);
        Button openRepositoryButton = actionButton("Open Repository", this::chooseRepository);
        Button refreshButton = actionButton("Refresh", this::refreshSnapshot);
        Button generateReportsButton = primaryActionButton("Generate Reports", this::generateReports);
        Button syncFeedsButton = actionButton("Sync Advisories", this::syncAdvisories);
        toolBar.getItems().addAll(
                startButton,
                openRepositoryButton,
                refreshButton,
                generateReportsButton,
                syncFeedsButton
        );
        return toolBar;
    }

    private SplitPane buildWorkspace() {
        navigationTree = new TreeView<>(buildNavigationTree());
        navigationTree.getStyleClass().add("navigation-tree");
        navigationTree.setShowRoot(false);
        navigationTree.getSelectionModel().selectedItemProperty().addListener((obs, oldValue, newValue) -> {
            if (newValue == null) {
                return;
            }
            switch (newValue.getValue()) {
                case "Overview" -> workspaceTabs.getSelectionModel().select(0);
                case "Findings" -> workspaceTabs.getSelectionModel().select(1);
                case "Dependencies" -> workspaceTabs.getSelectionModel().select(2);
                case "Reports" -> workspaceTabs.getSelectionModel().select(3);
                case "Runtime" -> workspaceTabs.getSelectionModel().select(4);
                default -> {
                }
            }
        });

        workspaceTabs = new TabPane(
                buildOverviewTab(),
                buildFindingsTab(),
                buildDependenciesTab(),
                buildReportsTab(),
                buildRuntimeTab()
        );
        workspaceTabs.getStyleClass().add("workspace-tabs");

        TabPane inspectorTabs = new TabPane();
        inspectorTabs.getStyleClass().add("inspector-tabs");
        inspectorArea = readOnlyArea();
        sourceArea = readOnlyArea();
        inspectorTabs.getTabs().addAll(
                nonClosableTab("Details", inspectorArea),
                nonClosableTab("Source", sourceArea)
        );

        SplitPane centerSplit = new SplitPane(workspaceTabs, inspectorTabs);
        centerSplit.getStyleClass().add("center-split");
        centerSplit.setDividerPositions(0.74);

        consoleArea = readOnlyArea();
        consoleArea.setPrefRowCount(8);
        timelineList = new ListView<>();
        timelineList.getStyleClass().add("timeline-list");
        timelineList.setCellFactory(list -> new ListCell<>() {
            @Override
            protected void updateItem(ApiModels.ScanResult item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                    return;
                }
                String score = item.summary() != null && item.summary().score() != null
                        ? String.format("%.2f", item.summary().score())
                        : "--";
                String findings = item.summary() != null && item.summary().totalFindings() != null
                        ? item.summary().totalFindings().toString()
                        : "0";
                setText(item.startedAt() + " | " + item.status() + " | score " + score + " | findings " + findings);
            }
        });
        timelineList.getSelectionModel().selectedItemProperty().addListener((obs, oldValue, newValue) -> {
            if (newValue == null || snapshot == null) {
                return;
            }
            loadHistoricalScan(newValue, "Timeline");
        });

        Button loadLatestButton = actionButton("Load Latest", this::loadLatestScan);
        HBox timelineActions = new HBox(8, loadLatestButton);
        VBox timelinePane = new VBox(8, timelineActions, timelineList);
        timelinePane.getStyleClass().add("timeline-pane");
        VBox.setVgrow(timelineList, Priority.ALWAYS);

        bottomDockTabs = new TabPane(
                nonClosableTab("Events", consoleArea),
                nonClosableTab("Timeline", timelinePane)
        );
        VBox consoleBox = new VBox(8, labeledSection("Bottom Dock"), bottomDockTabs);
        consoleBox.setPadding(new Insets(12));
        consoleBox.getStyleClass().add("console-box");
        VBox.setVgrow(bottomDockTabs, Priority.ALWAYS);

        SplitPane contentSplit = new SplitPane(new VBox(navigationTree), centerSplit);
        contentSplit.getStyleClass().add("content-split");
        contentSplit.setDividerPositions(0.16);

        SplitPane vertical = new SplitPane(contentSplit, consoleBox);
        vertical.getStyleClass().add("vertical-split");
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
            loadHistoricalScan(newValue, "Recent scans");
        });

        scoreLabel = metricLabel("Score: --");
        findingsLabel = metricLabel("Findings: --");
        toolsLabel = metricLabel("Tools: --");
        statusLabel = metricLabel("Status: idle");
        artifactsLabel = metricLabel("Artifacts: --");
        missingToolsLabel = metricLabel("Missing tools: --");
        FlowPane metrics = new FlowPane(12, 12, scoreLabel, findingsLabel, toolsLabel, statusLabel, artifactsLabel, missingToolsLabel);
        metrics.getStyleClass().add("metrics-flow");

        VBox content = new VBox(12, metrics, labeledSection("Repository Summary"), overviewArea, labeledSection("Recent Scans"), scansList);
        content.getStyleClass().add("workspace-pane");
        content.setPadding(new Insets(12));
        VBox.setVgrow(overviewArea, Priority.ALWAYS);
        VBox.setVgrow(scansList, Priority.ALWAYS);
        return nonClosableTab("Overview", content);
    }

    private Tab buildFindingsTab() {
        findingFilterField = new TextField();
        findingFilterField.setPromptText("Filter findings by severity, tool, title, or package");
        findingFilterField.textProperty().addListener((obs, oldValue, newValue) -> applyFindingFilter());
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
        VBox content = new VBox(12, labeledSection("Findings"), findingFilterField, findingsList);
        content.getStyleClass().add("workspace-pane");
        content.setPadding(new Insets(12));
        VBox.setVgrow(findingsList, Priority.ALWAYS);
        return nonClosableTab("Findings", content);
    }

    private Tab buildDependenciesTab() {
        dependenciesList = new ListView<>();
        dependenciesList.setCellFactory(list -> new ListCell<>() {
            @Override
            protected void updateItem(ApiModels.DependencyNode item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                    return;
                }
                setText(item.id() + " | " + item.ecosystem() + " | " + (item.version() == null ? "n/a" : item.version()));
            }
        });
        dependenciesList.getSelectionModel().selectedItemProperty().addListener((obs, oldValue, newValue) -> {
            if (newValue == null) {
                return;
            }
            inspectorArea.setText(WorkbenchText.formatDependencyDetails(newValue, snapshot != null ? snapshot.activeScan() : null));
            sourceArea.setText("Dependency intelligence is derived from SBOM and dependency graph data, not direct source previews.");
        });

        VBox content = new VBox(12, labeledSection("Dependencies"), dependenciesList);
        content.getStyleClass().add("workspace-pane");
        content.setPadding(new Insets(12));
        VBox.setVgrow(dependenciesList, Priority.ALWAYS);
        return nonClosableTab("Dependencies", content);
    }

    private Tab buildReportsTab() {
        artifactsList = new ListView<>();
        artifactsList.getStyleClass().add("artifact-list");
        artifactsList.setCellFactory(list -> new ListCell<>() {
            @Override
            protected void updateItem(ApiModels.Artifact item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                    setGraphic(null);
                    return;
                }
                Label primary = new Label(ReportArtifactSupport.displayName(item));
                primary.getStyleClass().add("artifact-primary");
                Label secondary = new Label(ReportArtifactSupport.subtitle(item));
                secondary.getStyleClass().add("artifact-secondary");
                secondary.setWrapText(true);
                VBox content = new VBox(4, primary, secondary);
                content.getStyleClass().add("artifact-cell");
                setText(null);
                setGraphic(content);
            }
        });
        artifactsList.getSelectionModel().selectedItemProperty().addListener((obs, oldValue, newValue) -> {
            if (newValue == null) {
                return;
            }
            selectedArtifactLabel.setText("Selected report: " + ReportArtifactSupport.displayName(newValue));
            inspectorArea.setText(WorkbenchText.formatArtifactDetails(newValue));
            reportPreviewArea.setText(LocalFilePreviewer.filePreview(newValue.path(), 120_000, 320));
        });

        reportPreviewArea = readOnlyArea();
        reportProfilesBox = new VBox(8);
        includePlusVariantsCheck = new CheckBox("Include plus variants with evidence");
        includePlusVariantsCheck.setSelected(true);
        Button generateButton = primaryActionButton("Generate Selected Reports", this::generateReports);
        Button openButton = actionButton("Open Selected", this::openSelectedArtifact);
        Button openFolderButton = actionButton("Open Report Folder", this::openActiveReportFolder);
        Button openLatestButton = actionButton("Open Latest Report", this::openLatestArtifact);
        FlowPane actions = new FlowPane(8, 8, generateButton, openButton, openFolderButton, openLatestButton);
        actions.getStyleClass().add("actions-flow");
        Label reportHintLabel = new Label(
                "Choose the report profiles below. New reports open automatically after generation and the save location is shown here."
        );
        reportHintLabel.getStyleClass().add("status-line");
        reportHintLabel.setWrapText(true);
        reportFolderLabel = new Label("Reports home: " + DesktopPaths.resolveUserReportsDir());
        reportFolderLabel.getStyleClass().add("status-line");
        latestArtifactLabel = new Label("Latest bundle: none");
        latestArtifactLabel.getStyleClass().add("status-line");
        generatedReportsLabel = new Label("Generated reports: --");
        generatedReportsLabel.getStyleClass().add("status-line");
        selectedArtifactLabel = new Label("Selected report: none");
        selectedArtifactLabel.getStyleClass().add("status-line");
        Button selectRecommendedButton = actionButton("Recommended", this::selectRecommendedReportProfiles);
        Button selectAllButton = actionButton("All Profiles", this::selectAllReportProfiles);
        FlowPane profileActions = new FlowPane(8, 8, selectRecommendedButton, selectAllButton);
        ScrollPane profilesScroll = new ScrollPane(reportProfilesBox);
        profilesScroll.setFitToWidth(true);
        profilesScroll.setPrefViewportHeight(180);
        GridPane reportSummary = new GridPane();
        reportSummary.getStyleClass().add("report-summary-grid");
        reportSummary.setHgap(12);
        reportSummary.setVgap(8);
        reportSummary.add(labeledSection("Report Output"), 0, 0);
        reportSummary.add(reportHintLabel, 0, 1, 2, 1);
        reportSummary.add(reportFolderLabel, 0, 2);
        reportSummary.add(latestArtifactLabel, 0, 3);
        reportSummary.add(generatedReportsLabel, 1, 2);
        VBox leftColumn = new VBox(
                10,
                reportSummary,
                labeledSection("Report Profiles"),
                profileActions,
                includePlusVariantsCheck,
                profilesScroll,
                labeledSection("Generated Artifacts"),
                artifactsList
        );
        leftColumn.getStyleClass().add("report-left-column");
        VBox.setVgrow(artifactsList, Priority.ALWAYS);
        VBox previewColumn = new VBox(10, selectedArtifactLabel, reportPreviewArea);
        previewColumn.getStyleClass().add("report-left-column");
        VBox.setVgrow(reportPreviewArea, Priority.ALWAYS);
        SplitPane split = new SplitPane(leftColumn, previewColumn);
        split.getStyleClass().add("report-split");
        split.setDividerPositions(0.36);

        reportPreviewArea.setText("Generate or select a report to preview it here.");
        VBox shell = new VBox(12, actions, split);
        shell.getStyleClass().add("workspace-pane");
        shell.setPadding(new Insets(12));
        VBox.setVgrow(split, Priority.ALWAYS);
        return nonClosableTab("Reports", shell);
    }

    private Tab buildRuntimeTab() {
        pluginFilterField = new TextField();
        pluginFilterField.setPromptText("Filter tools by name, category, version, or install state");
        pluginFilterField.textProperty().addListener((obs, oldValue, newValue) -> applyPluginFilter());
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
        Button installButton = primaryActionButton("Install Selected", this::installSelectedPlugin);
        VBox content = new VBox(12, installButton, pluginFilterField, pluginsList);
        content.getStyleClass().add("workspace-pane");
        content.setPadding(new Insets(12));
        VBox.setVgrow(pluginsList, Priority.ALWAYS);
        return nonClosableTab("Runtime", content);
    }

    private HBox buildStatusBar() {
        HBox bar = new HBox(16);
        bar.getStyleClass().add("status-bar");
        bar.setPadding(new Insets(8, 12, 10, 12));
        repositoryStatusLabel = new Label(repositoryStatusText(selectedRepository));
        backendStateStatusLabel = new Label("Backend: starting");
        activeScanStatusLabel = new Label("Active scan: none");
        statusFindingsValueLabel = new Label("Findings: --");
        reportsFolderStatusLabel = new Label("Reports home: " + DesktopPaths.resolveUserReportsDir());
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        bar.getChildren().addAll(
                new Label("Java rewrite path: Swing + JavaFX"),
                spacer,
                backendStateStatusLabel,
                repositoryStatusLabel,
                activeScanStatusLabel,
                statusFindingsValueLabel,
                reportsFolderStatusLabel
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
        List<String> selectedProfiles = selectedReportProfileIds();
        if (selectedProfiles.isEmpty()) {
            selectedProfiles = snapshot.reportProfiles().stream().map(ApiModels.ReportProfileDefinition::id).toList();
            syncReportProfileSelection(selectedProfiles);
        }
        boolean includePlusVariants = includePlusVariantsCheck != null && includePlusVariantsCheck.isSelected();
        List<String> requestedProfiles = selectedProfiles;
        runBackground(
                "Generating report set",
                () -> service.generateReports(snapshot.activeScan().scanId(), requestedProfiles, includePlusVariants, selectedRepository),
                outcome -> {
            snapshot = outcome.snapshot();
            applySnapshot(snapshot);
            workspaceTabs.getSelectionModel().select(3);
            bottomDockTabs.getSelectionModel().select(0);
            announceGeneratedReports(outcome.generatedArtifacts());
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
        Path initialDirectory = selectedRepository != null
                ? selectedRepository
                : DesktopPaths.looksLikeRepositoryRoot(repositoryRoot)
                ? repositoryRoot
                : Path.of(System.getProperty("user.home"));
        chooser.setInitialDirectory(initialDirectory.toFile());
        chooser.setTitle("Choose repository to scan");
        var selected = chooser.showDialog(stage);
        if (selected != null) {
            selectedRepository = selected.toPath().toAbsolutePath().normalize();
            repositoryLabel.setText(repositorySummaryText(selectedRepository));
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
        openArtifact(artifact, "Open Artifact");
    }

    private void openArtifact(ApiModels.Artifact artifact, String activity) {
        try {
            SystemShellSupport.openPath(Path.of(artifact.path()));
        } catch (Exception error) {
            showError(activity, error);
        }
    }

    private void openLatestArtifact() {
        var artifact = ReportArtifactSupport.preferredOpenArtifact(currentArtifacts);
        if (artifact.isEmpty()) {
            showError("Open Latest Report", new IllegalStateException("No generated artifacts are available yet."));
            return;
        }
        openArtifact(artifact.get(), "Open Latest Report");
    }

    private void openActiveReportFolder() {
        var reportFolder = ReportArtifactSupport.reportFolder(currentArtifacts);
        try {
            SystemShellSupport.openFolder(reportFolder.orElse(DesktopPaths.resolveUserReportsDir()));
        } catch (Exception error) {
            showError("Open Report Folder", error);
        }
    }

    private void announceGeneratedReports(List<ApiModels.Artifact> generatedArtifacts) {
        List<ApiModels.Artifact> sortedArtifacts = ReportArtifactSupport.sortArtifacts(generatedArtifacts);
        appendConsole("Generated " + sortedArtifacts.size() + " report artifacts for scan " + snapshot.activeScan().scanId());
        appendConsole(ReportArtifactSupport.savedSummary(sortedArtifacts));
        selectArtifact(sortedArtifacts);
        ReportArtifactSupport.preferredOpenArtifact(sortedArtifacts).ifPresent(artifact -> openArtifact(artifact, "Open Generated Report"));

        Alert success = new Alert(Alert.AlertType.INFORMATION);
        success.initOwner(stage);
        success.setTitle("Reports Generated");
        success.setHeaderText("Report generation completed");
        success.setContentText(ReportArtifactSupport.savedSummary(sortedArtifacts));
        success.showAndWait();
    }

    private void selectArtifact(List<ApiModels.Artifact> generatedArtifacts) {
        var preferred = ReportArtifactSupport.preferredOpenArtifact(generatedArtifacts);
        if (preferred.isEmpty()) {
            return;
        }
        String preferredPath = preferred.get().path();
        for (ApiModels.Artifact artifact : artifactsList.getItems()) {
            if (artifact != null && preferredPath.equals(artifact.path())) {
                artifactsList.getSelectionModel().select(artifact);
                artifactsList.scrollTo(artifact);
                return;
            }
        }
    }

    private void selectAllReportProfiles() {
        syncReportProfileSelection(snapshot != null
                ? snapshot.reportProfiles().stream().map(ApiModels.ReportProfileDefinition::id).toList()
                : List.of());
    }

    private void selectRecommendedReportProfiles() {
        syncReportProfileSelection(List.of(
                "modern-report",
                "executive-summary",
                "pdf",
                "machine-readable-json",
                "sarif"
        ));
    }

    private void loadLatestScan() {
        if (snapshot == null || snapshot.recentScans().isEmpty()) {
            showError("Load Latest Scan", new IllegalStateException("No persisted scans are available yet."));
            return;
        }
        loadHistoricalScan(snapshot.recentScans().get(0), "Timeline");
    }

    private void loadHistoricalScan(ApiModels.ScanResult scanResult, String origin) {
        snapshot = snapshot.withActiveScan(scanResult);
        applySnapshot(snapshot);
        appendConsole(origin + " loaded scan " + scanResult.scanId());
    }

    private void applySnapshot(DesktopApplicationService.DesktopSnapshot latest) {
        backendStatusLabel.setText(latest.backendReady() ? "Backend ready" : "Backend unavailable");
        backendStatusLabel.getStyleClass().removeAll("status-pill-live", "status-pill-pending");
        backendStatusLabel.getStyleClass().add(latest.backendReady() ? "status-pill-live" : "status-pill-pending");
        repositoryLabel.setText(repositorySummaryText(selectedRepository != null ? selectedRepository : latest.selectedRepository()));
        if (repositoryStatusLabel != null) {
            repositoryStatusLabel.setText(repositoryStatusText(selectedRepository != null ? selectedRepository : latest.selectedRepository()));
        }
        if (backendStateStatusLabel != null) {
            backendStateStatusLabel.setText(latest.backendReady() ? "Backend: ready" : "Backend: unavailable");
        }
        overviewArea.setText(WorkbenchText.formatRepositorySummary(latest.selectedRepository(), latest.activeScan())
                + System.lineSeparator() + System.lineSeparator()
                + WorkbenchText.formatScanOverview(latest.activeScan()));
        scansList.setItems(FXCollections.observableArrayList(latest.recentScans()));
        timelineList.setItems(FXCollections.observableArrayList(latest.recentScans()));

        ApiModels.ScanResult activeScan = latest.activeScan();
        currentFindings = activeScan != null ? activeScan.safeFindings() : List.of();
        currentDependencies = activeScan != null && activeScan.dependencyGraph() != null ? activeScan.dependencyGraph().safeNodes() : List.of();
        currentArtifacts = activeScan != null ? ReportArtifactSupport.sortArtifacts(activeScan.safeArtifacts()) : List.of();
        currentPlugins = latest.plugins();
        rebuildReportProfiles(latest.reportProfiles());
        applyFindingFilter();
        dependenciesList.setItems(FXCollections.observableArrayList(currentDependencies));
        artifactsList.setItems(FXCollections.observableArrayList(currentArtifacts));
        applyPluginFilter();

        if (activeScan != null && activeScan.summary() != null) {
            scoreLabel.setText("Score: " + activeScan.summary().score());
            findingsLabel.setText("Findings: " + activeScan.summary().totalFindings());
            toolsLabel.setText("Tools: " + activeScan.completedTools() + "/" + activeScan.totalTools());
            statusLabel.setText("Status: " + activeScan.status());
            artifactsLabel.setText("Artifacts: " + currentArtifacts.size());
            missingToolsLabel.setText("Missing tools: " + (int) currentPlugins.stream().filter(plugin -> !plugin.available()).count());
            inspectorArea.setText(WorkbenchText.formatScanOverview(activeScan));
            if (activeScanStatusLabel != null) {
                activeScanStatusLabel.setText("Active scan: " + activeScan.scanId());
            }
            if (statusFindingsValueLabel != null) {
                statusFindingsValueLabel.setText("Findings: " + activeScan.summary().totalFindings());
            }
        } else {
            scoreLabel.setText("Score: --");
            findingsLabel.setText("Findings: --");
            toolsLabel.setText("Tools: --");
            statusLabel.setText("Status: idle");
            artifactsLabel.setText("Artifacts: --");
            missingToolsLabel.setText("Missing tools: --");
            if (activeScanStatusLabel != null) {
                activeScanStatusLabel.setText("Active scan: none");
            }
            if (statusFindingsValueLabel != null) {
                statusFindingsValueLabel.setText("Findings: --");
            }
        }

        if (!currentArtifacts.isEmpty()) {
            String latestArtifactName = ReportArtifactSupport.preferredOpenArtifact(currentArtifacts)
                    .map(ReportArtifactSupport::displayName)
                    .orElse("none");
            String latestBundle = ReportArtifactSupport.reportFolder(currentArtifacts)
                    .map(path -> path.getFileName() != null ? path.getFileName().toString() : path.toString())
                    .orElse("none");
            if (reportFolderLabel != null) {
                reportFolderLabel.setText("Reports home: " + DesktopPaths.resolveUserReportsDir());
            }
            if (latestArtifactLabel != null) {
                latestArtifactLabel.setText("Latest bundle: " + latestBundle + " | Latest report: " + latestArtifactName);
            }
            if (generatedReportsLabel != null) {
                generatedReportsLabel.setText(
                        "Generated reports: " + ReportArtifactSupport.generatedReportCount(currentArtifacts)
                                + " | Supporting artifacts: " + ReportArtifactSupport.supportingArtifactCount(currentArtifacts)
                );
            }
            if (reportsFolderStatusLabel != null) {
                reportsFolderStatusLabel.setText("Reports home: " + DesktopPaths.resolveUserReportsDir());
            }
        } else {
            if (reportFolderLabel != null) {
                reportFolderLabel.setText("Reports home: " + DesktopPaths.resolveUserReportsDir());
            }
            if (latestArtifactLabel != null) {
                latestArtifactLabel.setText("Latest bundle: none");
            }
            if (generatedReportsLabel != null) {
                generatedReportsLabel.setText("Generated reports: --");
            }
            if (reportsFolderStatusLabel != null) {
                reportsFolderStatusLabel.setText("Reports home: " + DesktopPaths.resolveUserReportsDir());
            }
        }

        if (!currentFindings.isEmpty()) {
            findingsList.getSelectionModel().select(0);
        }
        if (!currentDependencies.isEmpty()) {
            dependenciesList.getSelectionModel().select(0);
        }
        if (!currentArtifacts.isEmpty()) {
            ReportArtifactSupport.preferredOpenArtifact(currentArtifacts)
                    .ifPresentOrElse(
                            artifact -> artifactsList.getSelectionModel().select(artifact),
                            () -> artifactsList.getSelectionModel().select(0)
                    );
        } else {
            if (selectedArtifactLabel != null) {
                selectedArtifactLabel.setText("Selected report: none");
            }
            reportPreviewArea.setText("No report artifacts are attached to the active scan yet.");
        }
        if (!currentPlugins.isEmpty()) {
            pluginsList.getSelectionModel().select(0);
        }
        if (activeScan != null && timelineList != null) {
            timelineList.getSelectionModel().select(activeScan);
        }
    }

    private void applyFindingFilter() {
        String query = findingFilterField != null && findingFilterField.getText() != null
                ? findingFilterField.getText().trim().toLowerCase()
                : "";
        if (query.isBlank()) {
            findingsList.setItems(FXCollections.observableArrayList(currentFindings));
            return;
        }
        findingsList.setItems(FXCollections.observableArrayList(
                currentFindings.stream().filter(finding -> matchesFindingQuery(finding, query)).toList()
        ));
    }

    private void applyPluginFilter() {
        String query = pluginFilterField != null && pluginFilterField.getText() != null
                ? pluginFilterField.getText().trim().toLowerCase()
                : "";
        if (query.isBlank()) {
            pluginsList.setItems(FXCollections.observableArrayList(currentPlugins));
            return;
        }
        pluginsList.setItems(FXCollections.observableArrayList(
                currentPlugins.stream().filter(plugin -> matchesPluginQuery(plugin, query)).toList()
        ));
    }

    private void rebuildReportProfiles(List<ApiModels.ReportProfileDefinition> profiles) {
        if (reportProfilesBox == null) {
            return;
        }
        List<String> previouslySelected = selectedReportProfileIds();
        reportProfilesBox.getChildren().clear();
        for (ApiModels.ReportProfileDefinition profile : profiles) {
            CheckBox checkBox = new CheckBox(profile.label() + " (" + profile.extension() + ")");
            checkBox.setUserData(profile.id());
            checkBox.setSelected(previouslySelected.isEmpty() || previouslySelected.contains(profile.id()));
            checkBox.setWrapText(true);
            checkBox.setAccessibleText(profile.description());
            reportProfilesBox.getChildren().add(checkBox);
        }
    }

    private void syncReportProfileSelection(List<String> selectedIds) {
        if (reportProfilesBox == null) {
            return;
        }
        reportProfilesBox.getChildren().forEach(node -> {
            if (node instanceof CheckBox checkBox && checkBox.getUserData() instanceof String id) {
                checkBox.setSelected(selectedIds.contains(id));
            }
        });
    }

    private List<String> selectedReportProfileIds() {
        List<String> selectedIds = new ArrayList<>();
        if (reportProfilesBox == null) {
            return selectedIds;
        }
        reportProfilesBox.getChildren().forEach(node -> {
            if (node instanceof CheckBox checkBox && checkBox.isSelected() && checkBox.getUserData() instanceof String id) {
                selectedIds.add(id);
            }
        });
        return selectedIds;
    }

    private boolean matchesFindingQuery(ApiModels.Finding finding, String query) {
        return containsIgnoreCase(finding.title(), query)
                || containsIgnoreCase(finding.severity(), query)
                || containsIgnoreCase(finding.sourceTool(), query)
                || containsIgnoreCase(finding.category(), query)
                || containsIgnoreCase(finding.packageName(), query);
    }

    private boolean matchesPluginQuery(ApiModels.PluginDescriptor plugin, String query) {
        return containsIgnoreCase(plugin.metadata().displayName(), query)
                || containsIgnoreCase(plugin.metadata().category(), query)
                || containsIgnoreCase(plugin.metadata().installStrategy(), query)
                || containsIgnoreCase(plugin.binaryStatus() != null ? plugin.binaryStatus().version() : null, query)
                || containsIgnoreCase(plugin.available() ? "installed" : "missing", query);
    }

    private boolean containsIgnoreCase(String value, String query) {
        return value != null && value.toLowerCase().contains(query);
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
        button.getStyleClass().add("workbench-button");
        button.setOnAction(event -> action.run());
        return button;
    }

    private Button primaryActionButton(String label, Runnable action) {
        Button button = actionButton(label, action);
        button.getStyleClass().add("primary-action");
        return button;
    }

    private TextArea readOnlyArea() {
        TextArea area = new TextArea();
        area.getStyleClass().add("viewer-area");
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
                new TreeItem<>("Dependencies"),
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

    private void handleCloseRequest(WindowEvent event) {
        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION);
        confirm.initOwner(stage);
        confirm.setTitle("Close Code Base Scanner");
        confirm.setHeaderText("Close the workbench?");
        confirm.setContentText(
                "Scan history, generated reports, and runtime settings are saved automatically. "
                        + "No separate project save is required."
        );
        ButtonType closeButton = new ButtonType("Close", ButtonBar.ButtonData.OK_DONE);
        ButtonType cancelButton = new ButtonType("Cancel", ButtonBar.ButtonData.CANCEL_CLOSE);
        confirm.getButtonTypes().setAll(closeButton, cancelButton);
        if (confirm.showAndWait().orElse(cancelButton) != closeButton) {
            event.consume();
        }
    }

    private String repositorySummaryText(Path repository) {
        if (repository == null) {
            return "Repository: no repository selected";
        }
        return "Repository: " + repository;
    }

    private String repositoryStatusText(Path repository) {
        if (repository == null) {
            return "Repository: none";
        }
        return "Repository: " + repository;
    }
}
