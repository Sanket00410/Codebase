package com.darkworld.codebasescanner.desktopjava.swing;

import com.darkworld.codebasescanner.desktopjava.core.ApiModels;
import com.darkworld.codebasescanner.desktopjava.core.DesktopApplicationService;
import com.darkworld.codebasescanner.desktopjava.core.DesktopBranding;
import com.darkworld.codebasescanner.desktopjava.core.DesktopPaths;
import com.darkworld.codebasescanner.desktopjava.core.LocalFilePreviewer;
import com.darkworld.codebasescanner.desktopjava.core.ReportArtifactSupport;
import com.darkworld.codebasescanner.desktopjava.core.WorkbenchText;
import com.formdev.flatlaf.FlatDarkLaf;

import javax.swing.BoxLayout;
import javax.swing.BorderFactory;
import javax.swing.DefaultListSelectionModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JToolBar;
import javax.swing.JTree;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.WindowConstants;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.awt.GridLayout;
import java.awt.Rectangle;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.function.Consumer;

public final class SwingWorkbenchLauncher {
    private final Path repositoryRoot = DesktopPaths.resolveRepositoryRoot();
    private final DesktopApplicationService service = new DesktopApplicationService(repositoryRoot);

    private JFrame frame;
    private JLabel backendStatusLabel;
    private JLabel repositoryLabel;
    private JLabel scoreLabel;
    private JLabel findingsLabel;
    private JLabel toolsLabel;
    private JLabel durationLabel;
    private JTree navigationTree;
    private JTabbedPane workspaceTabs;
    private JTable scansTable;
    private JTable findingsTable;
    private JTable dependenciesTable;
    private JTable pluginsTable;
    private JList<ApiModels.Artifact> artifactsList;
    private JTextArea overviewArea;
    private JTextArea inspectorArea;
    private JTextArea sourceArea;
    private JTextArea reportPreviewArea;
    private JTextArea consoleArea;
    private JLabel reportFolderStatusLabel;
    private JLabel latestArtifactStatusLabel;
    private JLabel generatedReportsStatusLabel;
    private JPanel reportProfilesPanel;
    private JCheckBox includePlusVariantsCheck;
    private DefaultTableModel scansModel;
    private DefaultTableModel findingsModel;
    private DefaultTableModel dependenciesModel;
    private DefaultTableModel pluginsModel;

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
        FlatDarkLaf.setup();
        System.setProperty("apple.awt.application.name", "Code Base Scanner - Swing");
        SwingUtilities.invokeLater(() -> new SwingWorkbenchLauncher().show());
    }

    private static void runSmokeTest() {
        Path repoRoot = DesktopPaths.resolveRepositoryRoot();
        DesktopApplicationService smokeTestService = new DesktopApplicationService(repoRoot);
        try {
            var snapshot = smokeTestService.bootstrap(repoRoot);
            System.out.println("Swing smoke test OK | backendReady=" + snapshot.backendReady()
                    + " | scans=" + snapshot.recentScans().size()
                    + " | plugins=" + snapshot.plugins().size());
        } catch (Exception error) {
            error.printStackTrace(System.err);
            System.exit(1);
        } finally {
            smokeTestService.shutdown();
        }
    }

    private void show() {
        frame = new JFrame("Code Base Scanner - Swing Workbench");
        frame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        frame.setIconImages(DesktopBranding.loadAwtIcons());
        Rectangle bounds = GraphicsEnvironment.getLocalGraphicsEnvironment().getMaximumWindowBounds();
        int width = (int) Math.min(1460, Math.max(1160, bounds.getWidth() - 48));
        int height = (int) Math.min(920, Math.max(760, bounds.getHeight() - 56));
        frame.setMinimumSize(new Dimension(Math.min(width, 1160), Math.min(height, 740)));
        frame.setPreferredSize(new Dimension(width, height));
        frame.setJMenuBar(buildMenuBar());
        frame.add(buildTopShell(), BorderLayout.NORTH);
        frame.add(buildWorkspace(), BorderLayout.CENTER);
        frame.add(buildStatusBar(), BorderLayout.SOUTH);
        frame.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent e) {
                if (confirmClose()) {
                    frame.dispose();
                }
            }

            @Override
            public void windowClosed(java.awt.event.WindowEvent e) {
                service.shutdown();
            }
        });
        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
        loadInitialState();
    }

    private JMenuBar buildMenuBar() {
        JMenuBar menuBar = new JMenuBar();

        JMenu fileMenu = new JMenu("File");
        JMenuItem openRepository = new JMenuItem("Open Repository...");
        openRepository.addActionListener(event -> chooseRepository());
        JMenuItem exit = new JMenuItem("Exit");
        exit.addActionListener(event -> frame.dispose());
        fileMenu.add(openRepository);
        fileMenu.add(exit);

        JMenu scanMenu = new JMenu("Scan");
        JMenuItem startScan = new JMenuItem("Start Scan");
        startScan.addActionListener(event -> startScan());
        JMenuItem refresh = new JMenuItem("Refresh");
        refresh.addActionListener(event -> refreshSnapshot());
        JMenuItem syncFeeds = new JMenuItem("Sync Advisories");
        syncFeeds.addActionListener(event -> syncAdvisories());
        scanMenu.add(startScan);
        scanMenu.add(refresh);
        scanMenu.add(syncFeeds);

        JMenu reportsMenu = new JMenu("Reports");
        JMenuItem generate = new JMenuItem("Generate Report Set");
        generate.addActionListener(event -> generateReports());
        JMenuItem openSelected = new JMenuItem("Open Selected Artifact");
        openSelected.addActionListener(event -> openSelectedArtifact());
        reportsMenu.add(generate);
        reportsMenu.add(openSelected);

        JMenu toolsMenu = new JMenu("Tools");
        JMenuItem installSelected = new JMenuItem("Install Selected Tool");
        installSelected.addActionListener(event -> installSelectedPlugin());
        toolsMenu.add(installSelected);

        menuBar.add(fileMenu);
        menuBar.add(scanMenu);
        menuBar.add(reportsMenu);
        menuBar.add(toolsMenu);
        return menuBar;
    }

    private JPanel buildTopShell() {
        JPanel panel = new JPanel(new BorderLayout(12, 12));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 8, 12));

        JPanel titlePanel = new JPanel(new BorderLayout(12, 4));
        JLabel title = new JLabel("Code Base Scanner");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 24f));
        backendStatusLabel = new JLabel("Backend starting...");
        repositoryLabel = new JLabel(repositorySummaryText(selectedRepository));
        titlePanel.add(title, BorderLayout.NORTH);
        titlePanel.add(repositoryLabel, BorderLayout.CENTER);
        titlePanel.add(backendStatusLabel, BorderLayout.EAST);

        JToolBar toolBar = new JToolBar();
        toolBar.setFloatable(false);
        toolBar.add(makeToolbarButton("Start Scan", this::startScan));
        toolBar.add(makeToolbarButton("Open Repository", this::chooseRepository));
        toolBar.add(makeToolbarButton("Refresh", this::refreshSnapshot));
        toolBar.add(makeToolbarButton("Generate Reports", this::generateReports));
        toolBar.add(makeToolbarButton("Sync Advisories", this::syncAdvisories));

        panel.add(titlePanel, BorderLayout.NORTH);
        panel.add(toolBar, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildWorkspace() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(0, 12, 12, 12));

        navigationTree = new JTree(buildNavigationModel());
        navigationTree.setRootVisible(false);
        navigationTree.addTreeSelectionListener(this::onTreeSelectionChanged);

        JSplitPane leftSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        leftSplit.setLeftComponent(new JScrollPane(navigationTree));
        leftSplit.setRightComponent(buildCenterAndInspector());
        leftSplit.setResizeWeight(0.16);
        leftSplit.setDividerLocation(250);

        JSplitPane verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        verticalSplit.setTopComponent(leftSplit);
        verticalSplit.setBottomComponent(buildConsolePane());
        verticalSplit.setResizeWeight(0.75);
        verticalSplit.setDividerLocation(620);

        panel.add(verticalSplit, BorderLayout.CENTER);
        return panel;
    }

    private JSplitPane buildCenterAndInspector() {
        workspaceTabs = new JTabbedPane();
        workspaceTabs.addTab("Overview", buildOverviewTab());
        workspaceTabs.addTab("Findings", buildFindingsTab());
        workspaceTabs.addTab("Dependencies", buildDependenciesTab());
        workspaceTabs.addTab("Reports", buildReportsTab());
        workspaceTabs.addTab("Runtime", buildRuntimeTab());

        JTabbedPane inspectorTabs = new JTabbedPane();
        inspectorArea = createReadOnlyTextArea();
        sourceArea = createReadOnlyTextArea();
        inspectorTabs.addTab("Details", new JScrollPane(inspectorArea));
        inspectorTabs.addTab("Source", new JScrollPane(sourceArea));

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setLeftComponent(workspaceTabs);
        splitPane.setRightComponent(inspectorTabs);
        splitPane.setResizeWeight(0.75);
        splitPane.setDividerLocation(980);
        return splitPane;
    }

    private JPanel buildOverviewTab() {
        JPanel panel = new JPanel(new BorderLayout(12, 12));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel summaryRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        scoreLabel = createMetricLabel("Score: --");
        findingsLabel = createMetricLabel("Findings: --");
        toolsLabel = createMetricLabel("Tools: --");
        durationLabel = createMetricLabel("Duration: --");
        summaryRow.add(scoreLabel);
        summaryRow.add(findingsLabel);
        summaryRow.add(toolsLabel);
        summaryRow.add(durationLabel);

        overviewArea = createReadOnlyTextArea();
        overviewArea.setRows(10);

        scansModel = tableModel("Started", "Status", "Findings", "Repository");
        scansTable = new JTable(scansModel);
        configureDataTable(scansTable);
        scansTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        scansTable.setSelectionModel(new DefaultListSelectionModel());
        scansTable.getSelectionModel().addListSelectionListener(this::onScanSelected);

        panel.add(summaryRow, BorderLayout.NORTH);
        panel.add(new JScrollPane(overviewArea), BorderLayout.CENTER);
        panel.add(new JScrollPane(scansTable), BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildFindingsTab() {
        JPanel panel = new JPanel(new BorderLayout(12, 12));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        findingsModel = tableModel("Severity", "Category", "Tool", "Title", "Location");
        findingsTable = new JTable(findingsModel);
        configureDataTable(findingsTable);
        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        findingsTable.getSelectionModel().addListSelectionListener(this::onFindingSelected);
        panel.add(new JScrollPane(findingsTable), BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildReportsTab() {
        JPanel panel = new JPanel(new BorderLayout(12, 12));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        artifactsList = new JList<>();
        artifactsList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        artifactsList.setCellRenderer(new javax.swing.DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(
                    JList<?> list,
                    Object value,
                    int index,
                    boolean isSelected,
                    boolean cellHasFocus
            ) {
                JLabel label = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof ApiModels.Artifact artifact) {
                    label.setText("<html><b>" + escapeHtml(ReportArtifactSupport.displayName(artifact)) + "</b><br/>"
                            + "<span style='color:#8ea2c8;'>" + escapeHtml(ReportArtifactSupport.subtitle(artifact)) + "</span></html>");
                    label.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
                }
                return label;
            }
        });
        artifactsList.addListSelectionListener(event -> onArtifactSelected());
        artifactsList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    openSelectedArtifact();
                }
            }
        });
        reportPreviewArea = createReadOnlyTextArea();
        reportPreviewArea.setText("Generate or select a report to preview it here.");

        includePlusVariantsCheck = new JCheckBox("Include plus variants with evidence");
        includePlusVariantsCheck.setSelected(true);
        reportProfilesPanel = new JPanel();
        reportProfilesPanel.setLayout(new BoxLayout(reportProfilesPanel, BoxLayout.Y_AXIS));
        JScrollPane profilesScroll = new JScrollPane(reportProfilesPanel);
        profilesScroll.setPreferredSize(new Dimension(320, 170));

        reportFolderStatusLabel = new JLabel("Report folder: unavailable");
        latestArtifactStatusLabel = new JLabel("Latest artifact: none");
        generatedReportsStatusLabel = new JLabel("Generated reports: --");

        JPanel reportSummaryPanel = new JPanel(new GridLayout(0, 1, 0, 6));
        reportSummaryPanel.add(new JLabel("Report output"));
        reportSummaryPanel.add(new JLabel("<html>New reports open automatically after generation and the save location is shown here.</html>"));
        reportSummaryPanel.add(reportFolderStatusLabel);
        reportSummaryPanel.add(latestArtifactStatusLabel);
        reportSummaryPanel.add(generatedReportsStatusLabel);

        JSplitPane splitPane = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                createReportLeftColumn(reportSummaryPanel, profilesScroll, new JScrollPane(artifactsList)),
                createSectionPanel("Preview", new JScrollPane(reportPreviewArea))
        );
        splitPane.setResizeWeight(0.4);
        splitPane.setDividerLocation(430);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actions.add(makeToolbarButton("Generate Selected Reports", this::generateReports));
        actions.add(makeToolbarButton("Open Selected", this::openSelectedArtifact));
        actions.add(makeToolbarButton("Open Report Folder", this::openActiveReportFolder));
        actions.add(makeToolbarButton("Open Latest Report", this::openLatestArtifact));

        panel.add(actions, BorderLayout.NORTH);
        panel.add(splitPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildDependenciesTab() {
        JPanel panel = new JPanel(new BorderLayout(12, 12));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        dependenciesModel = tableModel("Package", "Ecosystem", "Version", "Direct");
        dependenciesTable = new JTable(dependenciesModel);
        configureDataTable(dependenciesTable);
        dependenciesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        dependenciesTable.getSelectionModel().addListSelectionListener(this::onDependencySelected);
        panel.add(new JScrollPane(dependenciesTable), BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildRuntimeTab() {
        JPanel panel = new JPanel(new BorderLayout(12, 12));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        pluginsModel = tableModel("Tool", "Category", "State", "Version");
        pluginsTable = new JTable(pluginsModel);
        configureDataTable(pluginsTable);
        pluginsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        pluginsTable.getSelectionModel().addListSelectionListener(this::onPluginSelected);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actions.add(makeToolbarButton("Install Selected", this::installSelectedPlugin));
        actions.add(makeToolbarButton("Refresh Runtime", this::refreshSnapshot));

        panel.add(actions, BorderLayout.NORTH);
        panel.add(new JScrollPane(pluginsTable), BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildConsolePane() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEmptyBorder(8, 0, 0, 0),
                BorderFactory.createTitledBorder("Event Console")
        ));
        consoleArea = createReadOnlyTextArea();
        consoleArea.setRows(8);
        panel.add(new JScrollPane(consoleArea), BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildStatusBar() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 16, 6));
        panel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, UIManager.getColor("Component.borderColor")));
        panel.add(new JLabel("Java rewrite path: Swing + JavaFX"));
        panel.add(new JLabel("Backend: 127.0.0.1:8686"));
        panel.add(new JLabel("Repo root: " + repositoryRoot));
        return panel;
    }

    private void loadInitialState() {
        runBackground("Bootstrapping Swing workbench", () -> service.bootstrap(selectedRepository), latest -> {
            snapshot = latest;
            applySnapshot(latest);
            appendConsole("Swing workbench ready. Backend runtime: " + service.runtimeDirectory());
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
            JOptionPane.showMessageDialog(frame, "No active scan is loaded yet.");
            return;
        }
        List<String> profiles = selectedReportProfileIds();
        if (profiles.isEmpty()) {
            profiles = snapshot.reportProfiles().stream().map(ApiModels.ReportProfileDefinition::id).toList();
            rebuildReportProfiles(snapshot.reportProfiles());
        }
        boolean includePlusVariants = includePlusVariantsCheck != null && includePlusVariantsCheck.isSelected();
        List<String> selectedProfiles = profiles;
        runBackground(
                "Generating report set",
                () -> service.generateReports(snapshot.activeScan().scanId(), selectedProfiles, includePlusVariants, selectedRepository),
                outcome -> {
                    snapshot = outcome.snapshot();
                    applySnapshot(snapshot);
                    workspaceTabs.setSelectedIndex(3);
                    announceGeneratedReports(outcome.generatedArtifacts());
                }
        );
    }

    private void installSelectedPlugin() {
        int selectedRow = pluginsTable.getSelectedRow();
        if (selectedRow < 0 || selectedRow >= currentPlugins.size()) {
            JOptionPane.showMessageDialog(frame, "Select a tool first.");
            return;
        }
        ApiModels.PluginDescriptor plugin = currentPlugins.get(selectedRow);
        runBackground("Installing " + plugin.metadata().displayName(), () -> {
            service.installTool(plugin.metadata().name());
            return plugin.metadata().displayName();
        }, toolName -> {
            appendConsole("Installed tool runtime for " + toolName);
            refreshSnapshot();
        });
    }

    private void chooseRepository() {
        Path initialDirectory = selectedRepository != null
                ? selectedRepository
                : DesktopPaths.looksLikeRepositoryRoot(repositoryRoot)
                ? repositoryRoot
                : Path.of(System.getProperty("user.home"));
        JFileChooser chooser = new JFileChooser(initialDirectory.toFile());
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("Choose repository to scan");
        if (chooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            File selected = chooser.getSelectedFile();
            selectedRepository = selected.toPath().toAbsolutePath().normalize();
            repositoryLabel.setText(repositorySummaryText(selectedRepository));
            appendConsole("Repository selected: " + selectedRepository);
            refreshSnapshot();
        }
    }

    private void openSelectedArtifact() {
        ApiModels.Artifact artifact = artifactsList.getSelectedValue();
        if (artifact == null) {
            JOptionPane.showMessageDialog(frame, "Select a report artifact first.");
            return;
        }
        openArtifact(artifact, "Unable to open artifact");
    }

    private void openArtifact(ApiModels.Artifact artifact, String activity) {
        try {
            Desktop.getDesktop().open(Path.of(artifact.path()).toFile());
        } catch (Exception error) {
            showError(activity, error);
        }
    }

    private void openActiveReportFolder() {
        var folder = ReportArtifactSupport.reportFolder(currentArtifacts);
        if (folder.isEmpty()) {
            JOptionPane.showMessageDialog(frame, "No active report folder is available yet.");
            return;
        }
        try {
            Desktop.getDesktop().open(folder.get().toFile());
        } catch (Exception error) {
            showError("Unable to open report folder", error);
        }
    }

    private void openLatestArtifact() {
        var artifact = ReportArtifactSupport.preferredOpenArtifact(currentArtifacts);
        if (artifact.isEmpty()) {
            JOptionPane.showMessageDialog(frame, "No generated report is available yet.");
            return;
        }
        openArtifact(artifact.get(), "Unable to open latest report");
    }

    private void applySnapshot(DesktopApplicationService.DesktopSnapshot latest) {
        backendStatusLabel.setText(latest.backendReady() ? "Backend ready" : "Backend unavailable");
        repositoryLabel.setText(repositorySummaryText(selectedRepository != null ? selectedRepository : latest.selectedRepository()));
        overviewArea.setText(WorkbenchText.formatRepositorySummary(latest.selectedRepository(), latest.activeScan())
                + System.lineSeparator() + System.lineSeparator()
                + WorkbenchText.formatScanOverview(latest.activeScan()));

        scansModel.setRowCount(0);
        latest.recentScans().forEach(scan -> scansModel.addRow(new Object[]{
                scan.startedAt(),
                scan.status(),
                scan.summary() != null ? scan.summary().totalFindings() : 0,
                scan.repositoryPath()
        }));

        ApiModels.ScanResult activeScan = latest.activeScan();
        currentFindings = activeScan != null ? activeScan.safeFindings() : List.of();
        currentDependencies = activeScan != null && activeScan.dependencyGraph() != null ? activeScan.dependencyGraph().safeNodes() : List.of();
        findingsModel.setRowCount(0);
        currentFindings.forEach(finding -> findingsModel.addRow(new Object[]{
                finding.severity(),
                finding.category(),
                finding.sourceTool(),
                finding.title(),
                finding.location() != null ? finding.location().path() + ":" + finding.location().line() : "n/a"
        }));

        dependenciesModel.setRowCount(0);
        currentDependencies.forEach(node -> dependenciesModel.addRow(new Object[]{
                node.id(),
                node.ecosystem(),
                node.version(),
                Boolean.TRUE.equals(node.direct()) ? "yes" : "no"
        }));

        currentArtifacts = activeScan != null ? ReportArtifactSupport.sortArtifacts(activeScan.safeArtifacts()) : List.of();
        artifactsList.setListData(currentArtifacts.toArray(ApiModels.Artifact[]::new));
        reportPreviewArea.setText(currentArtifacts.isEmpty() ? "No report artifacts are attached to the active scan yet." : "");
        rebuildReportProfiles(latest.reportProfiles());
        if (!currentArtifacts.isEmpty()) {
            reportFolderStatusLabel.setText("Report folder: " + ReportArtifactSupport.reportFolder(currentArtifacts).map(Path::toString).orElse("unavailable"));
            latestArtifactStatusLabel.setText(
                    "Latest artifact: " + ReportArtifactSupport.preferredOpenArtifact(currentArtifacts)
                            .map(ReportArtifactSupport::displayName)
                            .orElse("none")
            );
            generatedReportsStatusLabel.setText(
                    "Generated reports: " + ReportArtifactSupport.generatedReportCount(currentArtifacts)
                            + " | Supporting artifacts: " + ReportArtifactSupport.supportingArtifactCount(currentArtifacts)
            );
        } else {
            reportFolderStatusLabel.setText("Report folder: unavailable");
            latestArtifactStatusLabel.setText("Latest artifact: none");
            generatedReportsStatusLabel.setText("Generated reports: --");
        }

        currentPlugins = latest.plugins();
        pluginsModel.setRowCount(0);
        currentPlugins.forEach(plugin -> pluginsModel.addRow(new Object[]{
                plugin.metadata().displayName(),
                plugin.metadata().category(),
                plugin.available() ? "Installed" : "Missing",
                plugin.binaryStatus() != null ? plugin.binaryStatus().version() : "n/a"
        }));

        if (activeScan != null && activeScan.summary() != null) {
            scoreLabel.setText("Score: " + activeScan.summary().score());
            findingsLabel.setText("Findings: " + activeScan.summary().totalFindings());
            toolsLabel.setText("Tools: " + activeScan.completedTools() + "/" + activeScan.totalTools());
            durationLabel.setText("Status: " + activeScan.status());
        } else {
            scoreLabel.setText("Score: --");
            findingsLabel.setText("Findings: --");
            toolsLabel.setText("Tools: --");
            durationLabel.setText("Status: idle");
        }

        inspectorArea.setText(WorkbenchText.formatScanOverview(activeScan));
        sourceArea.setText("Select a finding to load source context.");
        if (!currentFindings.isEmpty()) {
            findingsTable.setRowSelectionInterval(0, 0);
        }
        if (!currentDependencies.isEmpty()) {
            dependenciesTable.setRowSelectionInterval(0, 0);
        }
        if (!currentArtifacts.isEmpty()) {
            ReportArtifactSupport.preferredOpenArtifact(currentArtifacts)
                    .ifPresentOrElse(
                            artifact -> artifactsList.setSelectedValue(artifact, true),
                            () -> artifactsList.setSelectedIndex(0)
                    );
        }
        if (!currentPlugins.isEmpty()) {
            pluginsTable.setRowSelectionInterval(0, 0);
        }
    }

    private void onTreeSelectionChanged(TreeSelectionEvent event) {
        Object lastComponent = event.getPath().getLastPathComponent();
        if (!(lastComponent instanceof DefaultMutableTreeNode node)) {
            return;
        }
        String label = String.valueOf(node.getUserObject());
        switch (label) {
            case "Overview" -> workspaceTabs.setSelectedIndex(0);
            case "Findings" -> workspaceTabs.setSelectedIndex(1);
            case "Dependencies" -> workspaceTabs.setSelectedIndex(2);
            case "Reports" -> workspaceTabs.setSelectedIndex(3);
            case "Runtime" -> workspaceTabs.setSelectedIndex(4);
            default -> {
            }
        }
    }

    private void onScanSelected(ListSelectionEvent event) {
        if (event.getValueIsAdjusting() || snapshot == null) {
            return;
        }
        int selectedRow = scansTable.getSelectedRow();
        if (selectedRow < 0 || selectedRow >= snapshot.recentScans().size()) {
            return;
        }
        snapshot = snapshot.withActiveScan(snapshot.recentScans().get(selectedRow));
        applySnapshot(snapshot);
        appendConsole("Loaded historical scan " + snapshot.activeScan().scanId());
    }

    private void onFindingSelected(ListSelectionEvent event) {
        if (event.getValueIsAdjusting()) {
            return;
        }
        int selectedRow = findingsTable.getSelectedRow();
        if (selectedRow < 0 || selectedRow >= currentFindings.size()) {
            return;
        }
        ApiModels.Finding finding = currentFindings.get(selectedRow);
        inspectorArea.setText(WorkbenchText.formatFindingDetails(finding));
        sourceArea.setText(LocalFilePreviewer.sourcePreview(selectedRepository, finding));
    }

    private void onArtifactSelected() {
        ApiModels.Artifact artifact = artifactsList.getSelectedValue();
        if (artifact == null) {
            return;
        }
        inspectorArea.setText(WorkbenchText.formatArtifactDetails(artifact));
        reportPreviewArea.setText(LocalFilePreviewer.filePreview(artifact.path(), 120_000, 320));
    }

    private void onDependencySelected(ListSelectionEvent event) {
        if (event.getValueIsAdjusting()) {
            return;
        }
        int selectedRow = dependenciesTable.getSelectedRow();
        if (selectedRow < 0 || selectedRow >= currentDependencies.size()) {
            return;
        }
        inspectorArea.setText(WorkbenchText.formatDependencyDetails(
                currentDependencies.get(selectedRow),
                snapshot != null ? snapshot.activeScan() : null
        ));
        sourceArea.setText("Dependency intelligence is derived from SBOM and dependency graph data.");
    }

    private void onPluginSelected(ListSelectionEvent event) {
        if (event.getValueIsAdjusting()) {
            return;
        }
        int selectedRow = pluginsTable.getSelectedRow();
        if (selectedRow < 0 || selectedRow >= currentPlugins.size()) {
            return;
        }
        inspectorArea.setText(WorkbenchText.formatPluginDetails(currentPlugins.get(selectedRow)));
        sourceArea.setText("Tool runtimes do not have source previews.");
    }

    private DefaultTreeModel buildNavigationModel() {
        DefaultMutableTreeNode root = new DefaultMutableTreeNode("Code Base Scanner");
        DefaultMutableTreeNode workspace = new DefaultMutableTreeNode("Workspace");
        workspace.add(new DefaultMutableTreeNode("Overview"));
        workspace.add(new DefaultMutableTreeNode("Findings"));
        workspace.add(new DefaultMutableTreeNode("Dependencies"));
        workspace.add(new DefaultMutableTreeNode("Reports"));
        workspace.add(new DefaultMutableTreeNode("Runtime"));
        root.add(workspace);
        return new DefaultTreeModel(root);
    }

    private JButton makeToolbarButton(String label, Runnable action) {
        JButton button = new JButton(label);
        button.putClientProperty("JButton.buttonType", "roundRect");
        button.addActionListener(event -> action.run());
        return button;
    }

    private JPanel createReportLeftColumn(Component summaryPanel, JScrollPane profilesScroll, JScrollPane artifactsScroll) {
        JPanel profilesSection = new JPanel(new BorderLayout(0, 8));
        profilesSection.add(includePlusVariantsCheck, BorderLayout.NORTH);
        profilesSection.add(profilesScroll, BorderLayout.CENTER);

        JPanel topColumn = new JPanel(new BorderLayout(0, 12));
        topColumn.add(createSectionPanel("Report Output", summaryPanel), BorderLayout.NORTH);
        topColumn.add(createSectionPanel("Report Profiles", profilesSection), BorderLayout.CENTER);

        JPanel leftColumn = new JPanel(new BorderLayout(0, 12));
        leftColumn.add(topColumn, BorderLayout.NORTH);
        leftColumn.add(createSectionPanel("Generated Artifacts", artifactsScroll), BorderLayout.CENTER);
        return leftColumn;
    }

    private JPanel createSectionPanel(String title, Component content) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(title),
                BorderFactory.createEmptyBorder(8, 8, 8, 8)
        ));
        panel.add(content, BorderLayout.CENTER);
        return panel;
    }

    private void rebuildReportProfiles(List<ApiModels.ReportProfileDefinition> profiles) {
        if (reportProfilesPanel == null) {
            return;
        }
        List<String> selectedIds = selectedReportProfileIds();
        reportProfilesPanel.removeAll();
        for (ApiModels.ReportProfileDefinition profile : profiles) {
            JCheckBox checkBox = new JCheckBox(profile.label() + " (" + profile.extension() + ")");
            checkBox.putClientProperty("JButton.buttonType", "roundRect");
            checkBox.setSelected(selectedIds.isEmpty() || selectedIds.contains(profile.id()));
            checkBox.putClientProperty("reportProfileId", profile.id());
            reportProfilesPanel.add(checkBox);
        }
        reportProfilesPanel.revalidate();
        reportProfilesPanel.repaint();
    }

    private List<String> selectedReportProfileIds() {
        if (reportProfilesPanel == null) {
            return List.of();
        }
        return java.util.Arrays.stream(reportProfilesPanel.getComponents())
                .filter(component -> component instanceof JCheckBox)
                .map(component -> (JCheckBox) component)
                .filter(JCheckBox::isSelected)
                .map(checkBox -> String.valueOf(checkBox.getClientProperty("reportProfileId")))
                .toList();
    }

    private JLabel createMetricLabel(String text) {
        JLabel label = new JLabel(text);
        label.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UIManager.getColor("Component.borderColor")),
                BorderFactory.createEmptyBorder(8, 12, 8, 12)
        ));
        return label;
    }

    private JTextArea createReadOnlyTextArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        return area;
    }

    private DefaultTableModel tableModel(String... columns) {
        return new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
    }

    private void configureDataTable(JTable table) {
        table.setRowHeight(28);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.setFillsViewportHeight(true);
    }

    private <T> void runBackground(String activity, Callable<T> task, Consumer<T> onSuccess) {
        appendConsole(activity + "...");
        new SwingWorker<T, Void>() {
            @Override
            protected T doInBackground() throws Exception {
                return task.call();
            }

            @Override
            protected void done() {
                try {
                    onSuccess.accept(get());
                } catch (Exception error) {
                    showError(activity, error);
                }
            }
        }.execute();
    }

    private void appendConsole(String message) {
        if (consoleArea == null) {
            return;
        }
        consoleArea.append(message + System.lineSeparator());
        consoleArea.setCaretPosition(consoleArea.getDocument().getLength());
    }

    private void showError(String activity, Exception error) {
        appendConsole(activity + " failed: " + error.getMessage());
        JOptionPane.showMessageDialog(frame, error.getMessage(), activity, JOptionPane.ERROR_MESSAGE);
    }

    private void announceGeneratedReports(List<ApiModels.Artifact> generatedArtifacts) {
        List<ApiModels.Artifact> sortedArtifacts = ReportArtifactSupport.sortArtifacts(generatedArtifacts);
        appendConsole("Generated " + sortedArtifacts.size() + " report artifacts for scan " + snapshot.activeScan().scanId());
        appendConsole(ReportArtifactSupport.savedSummary(sortedArtifacts));
        selectArtifact(sortedArtifacts);
        ReportArtifactSupport.preferredOpenArtifact(sortedArtifacts)
                .ifPresent(artifact -> openArtifact(artifact, "Unable to open generated report"));
        JOptionPane.showMessageDialog(
                frame,
                ReportArtifactSupport.savedSummary(sortedArtifacts),
                "Reports Generated",
                JOptionPane.INFORMATION_MESSAGE
        );
    }

    private void selectArtifact(List<ApiModels.Artifact> generatedArtifacts) {
        ReportArtifactSupport.preferredOpenArtifact(generatedArtifacts)
                .ifPresent(artifact -> artifactsList.setSelectedValue(artifact, true));
    }

    private String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    private boolean confirmClose() {
        int choice = JOptionPane.showOptionDialog(
                frame,
                "Close Code Base Scanner?\n\nScan history, generated reports, and runtime settings are saved automatically.\nNo separate project save is required.",
                "Close Code Base Scanner",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                null,
                new Object[]{"Close", "Cancel"},
                "Cancel"
        );
        return choice == JOptionPane.OK_OPTION;
    }

    private String repositorySummaryText(Path repository) {
        if (repository == null) {
            return "Repository: no repository selected";
        }
        return "Repository: " + repository;
    }
}
