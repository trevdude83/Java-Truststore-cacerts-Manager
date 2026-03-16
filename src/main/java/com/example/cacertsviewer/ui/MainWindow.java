package com.example.cacertsviewer.ui;

import com.example.cacertsviewer.model.BackupRecord;
import com.example.cacertsviewer.model.CertificateRecord;
import com.example.cacertsviewer.model.TrustStoreDocument;
import com.example.cacertsviewer.service.BackupService;
import com.example.cacertsviewer.service.PasswordAwareLoadResult;
import com.example.cacertsviewer.service.SystemTrustStoreLocator;
import com.example.cacertsviewer.service.TrustStoreService;
import com.example.cacertsviewer.util.CertificateFormatter;
import com.example.cacertsviewer.util.FingerprintUtils;
import javafx.beans.InvalidationListener;
import javafx.beans.binding.Bindings;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.collections.transformation.FilteredList;
import javafx.collections.transformation.SortedList;
import javafx.geometry.Insets;
import javafx.geometry.Orientation;
import javafx.scene.Parent;
import javafx.scene.control.*;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.input.Dragboard;
import javafx.scene.input.TransferMode;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

public class MainWindow {
    private final Stage stage;
    private final BorderPane root = new BorderPane();
    private final TrustStoreService trustStoreService = new TrustStoreService();
    private final BackupService backupService = new BackupService();
    private final SystemTrustStoreLocator trustStoreLocator = new SystemTrustStoreLocator();
    private final ObjectProperty<TrustStoreDocument> documentProperty = new SimpleObjectProperty<>();
    private final ObjectProperty<CertificateRecord> selectedRecord = new SimpleObjectProperty<>();
    private final InvalidationListener dirtyStateListener = observable -> refreshDocumentChrome();
    private FilteredList<CertificateRecord> filteredCertificates;

    private final TableView<CertificateRecord> table = new TableView<>();
    private final TextField searchField = new TextField();
    private final TextArea detailsArea = new TextArea();
    private final Label statusLabel = new Label("Open a truststore to begin.");
    private final Label pathLabel = new Label("No truststore loaded");
    private final Label bannerLabel = new Label();
    private final Button openButton = new Button("Open");
    private final Button openDefaultButton = new Button("Open Default Cacerts");
    private final Button saveButton = new Button("Save");
    private final Button saveAsButton = new Button("Save As");
    private final Button importButton = new Button("Import");
    private final Button deleteButton = new Button("Delete");
    private final Button restoreButton = new Button("Restore");
    private final Button toolbarExportButton = new Button("Export");
    private final Button detailExportButton = new Button("Export Selected");
    private final Button copyButton = new Button("Copy Details");

    public MainWindow(Stage stage) {
        this.stage = stage;
        buildUi();
        bindState();
        registerEvents();
    }

    public Parent getRoot() {
        return root;
    }

    public void onShown() {
        trustStoreLocator.locateDefaultCacerts().ifPresent(path ->
                status("Detected default cacerts at " + path));
    }

    private void buildUi() {
        ToolBar toolBar = new ToolBar(
                openDefaultButton,
                openButton,
                new Separator(Orientation.VERTICAL),
                saveButton,
                saveAsButton,
                new Separator(Orientation.VERTICAL),
                importButton,
                deleteButton,
                toolbarExportButton,
                new Separator(Orientation.VERTICAL),
                restoreButton
        );
        toolBar.getStyleClass().add("app-toolbar");

        bannerLabel.getStyleClass().add("warning-banner");
        bannerLabel.setVisible(false);
        bannerLabel.setManaged(false);

        VBox top = new VBox(toolBar, bannerLabel);
        root.setTop(top);

        searchField.setPromptText("Search alias, subject, issuer, serial, or thumbprint");

        configureTable();
        detailsArea.setEditable(false);
        detailsArea.setWrapText(true);
        detailsArea.getStyleClass().add("details-area");

        VBox detailsBox = new VBox(10,
                sectionTitle("Certificate Details"),
                detailsArea,
                new HBox(10, copyButton, detailExportButton)
        );
        detailsBox.setPadding(new Insets(16));
        VBox.setVgrow(detailsArea, Priority.ALWAYS);

        VBox centerBox = new VBox(10, searchField, table);
        centerBox.setPadding(new Insets(16));
        VBox.setVgrow(table, Priority.ALWAYS);

        SplitPane splitPane = new SplitPane(centerBox, detailsBox);
        splitPane.setDividerPositions(0.62);
        root.setCenter(splitPane);

        HBox statusBar = new HBox(16, statusLabel, new Separator(Orientation.VERTICAL), pathLabel);
        statusBar.getStyleClass().add("status-bar");
        statusBar.setPadding(new Insets(10, 16, 10, 16));
        root.setBottom(statusBar);
    }

    private Label sectionTitle(String title) {
        Label label = new Label(title);
        label.getStyleClass().add("section-title");
        return label;
    }

    private void configureTable() {
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.getColumns().add(column("Alias", 160, CertificateRecord::alias));
        table.getColumns().add(column("Entry Type", 140, CertificateRecord::entryType));
        table.getColumns().add(column("Subject", 220, CertificateRecord::subject));
        table.getColumns().add(column("Issuer", 220, CertificateRecord::issuer));
        table.getColumns().add(column("Serial", 160, CertificateRecord::serialNumber));
        table.getColumns().add(column("Valid From", 170, record -> CertificateFormatter.DATE_FORMAT.format(record.validFrom())));
        table.getColumns().add(column("Valid To", 170, record -> CertificateFormatter.DATE_FORMAT.format(record.validTo())));
        table.getColumns().add(column("Signature", 140, CertificateRecord::signatureAlgorithm));
        table.getColumns().add(column("SHA-1", 250, CertificateRecord::sha1));
        table.getColumns().add(column("SHA-256", 360, CertificateRecord::sha256));
        table.setPlaceholder(new Label("No certificates to display"));

        table.setRowFactory(ignore -> new TableRow<>() {
            @Override
            protected void updateItem(CertificateRecord item, boolean empty) {
                super.updateItem(item, empty);
                getStyleClass().removeAll("expired-row", "future-row");
                if (!empty && item != null) {
                    if (item.expired()) {
                        getStyleClass().add("expired-row");
                    } else if (item.notYetValid()) {
                        getStyleClass().add("future-row");
                    }
                }
            }
        });
    }

    private TableColumn<CertificateRecord, String> column(String title, double width,
                                                          java.util.function.Function<CertificateRecord, String> mapper) {
        TableColumn<CertificateRecord, String> column = new TableColumn<>(title);
        column.setPrefWidth(width);
        column.setCellValueFactory(data -> Bindings.createStringBinding(() -> mapper.apply(data.getValue())));
        return column;
    }

    private void bindState() {
        saveAsButton.disableProperty().bind(documentProperty.isNull());
        importButton.disableProperty().bind(documentProperty.isNull());
        restoreButton.disableProperty().bind(documentProperty.isNull());
        deleteButton.disableProperty().bind(selectedRecord.isNull());
        toolbarExportButton.disableProperty().bind(selectedRecord.isNull());
        detailExportButton.disableProperty().bind(selectedRecord.isNull());
        copyButton.disableProperty().bind(selectedRecord.isNull());

        documentProperty.addListener((obs, oldDoc, newDoc) -> {
            if (oldDoc != null) {
                oldDoc.dirtyProperty().removeListener(dirtyStateListener);
            }
            table.getSelectionModel().clearSelection();
            if (newDoc == null) {
                table.setItems(null);
                filteredCertificates = null;
                detailsArea.clear();
                pathLabel.setText("No truststore loaded");
                bannerLabel.setVisible(false);
                bannerLabel.setManaged(false);
                searchField.clear();
                refreshDocumentChrome();
                return;
            }

            newDoc.dirtyProperty().addListener(dirtyStateListener);
            filteredCertificates = new FilteredList<>(newDoc.getCertificates(), item -> true);
            SortedList<CertificateRecord> sorted = new SortedList<>(filteredCertificates);
            sorted.comparatorProperty().bind(table.comparatorProperty());
            table.setItems(sorted);

            pathLabel.setText(newDoc.getPath() == null ? "Unsaved truststore" : newDoc.getPath().toString());
            updateFilter();
            updateBanner();
            refreshDocumentChrome();
        });

        selectedRecord.bind(table.getSelectionModel().selectedItemProperty());
        selectedRecord.addListener((obs, oldRecord, newRecord) -> renderDetails(newRecord));
        searchField.textProperty().addListener((obs, oldValue, newValue) -> updateFilter());
    }

    private void registerEvents() {
        openButton.setOnAction(event -> openTruststoreFromDialog());
        openDefaultButton.setOnAction(event -> trustStoreLocator.locateDefaultCacerts()
                .ifPresentOrElse(this::openTruststore,
                        () -> Dialogs.showInfo(stage, "Default Cacerts", "No default cacerts file was detected.")));
        saveButton.setOnAction(event -> saveCurrent(false));
        saveAsButton.setOnAction(event -> saveCurrent(true));
        importButton.setOnAction(event -> importFromDialog());
        deleteButton.setOnAction(event -> deleteSelected());
        restoreButton.setOnAction(event -> restoreBackup());
        toolbarExportButton.setOnAction(event -> exportSelected());
        detailExportButton.setOnAction(event -> exportSelected());
        copyButton.setOnAction(event -> copySelectedDetails());

        root.setOnDragOver(event -> {
            if (event.getDragboard().hasFiles()) {
                event.acceptTransferModes(TransferMode.COPY);
            }
            event.consume();
        });
        root.setOnDragDropped(event -> {
            Dragboard dragboard = event.getDragboard();
            boolean success = false;
            if (dragboard.hasFiles()) {
                List<Path> paths = dragboard.getFiles().stream().map(file -> file.toPath()).toList();
                if (paths.size() == 1 && isStoreFile(paths.get(0))) {
                    openTruststore(paths.get(0));
                } else if (documentProperty.get() != null) {
                    for (Path path : paths) {
                        if (isCertificateFile(path)) {
                            importCertificatePath(path);
                        }
                    }
                }
                success = true;
            }
            event.setDropCompleted(success);
            event.consume();
        });

        stage.setOnCloseRequest(this::handleCloseRequest);
        refreshDocumentChrome();
    }

    private void openTruststoreFromDialog() {
        if (!checkUnsavedChanges()) {
            return;
        }
        FileChooser chooser = Dialogs.createStoreChooser();
        Optional.ofNullable(chooser.showOpenDialog(stage))
                .map(file -> file.toPath())
                .ifPresent(this::openTruststore);
    }

    private void openTruststore(Path path) {
        if (!checkUnsavedChanges()) {
            return;
        }
        Optional<char[]> password = Dialogs.promptPassword(stage, "Open Truststore", "Enter the password for " + path.getFileName());
        if (password.isEmpty()) {
            return;
        }

        try {
            PasswordAwareLoadResult result = trustStoreService.load(path, password.get());
            documentProperty.set(result.document());
            status("Opened " + path.getFileName() + " as " + result.detectedType());
        } catch (Exception ex) {
            Dialogs.showError(stage, "Open Truststore Failed", "Could not open the truststore. Check the password, file type, and try the default cacerts password 'changeit' if needed.", ex);
            status("Open failed for " + path.getFileName());
        }
    }

    private void importFromDialog() {
        FileChooser chooser = Dialogs.createCertificateChooser();
        List<java.io.File> files = chooser.showOpenMultipleDialog(stage);
        if (files == null) {
            return;
        }
        for (java.io.File file : files) {
            importCertificatePath(file.toPath());
        }
    }

    private void importCertificatePath(Path path) {
        TrustStoreDocument document = documentProperty.get();
        if (document == null) {
            return;
        }
        try {
            List<X509Certificate> certificates = trustStoreService.parseCertificates(path);
            for (int index = 0; index < certificates.size(); index++) {
                X509Certificate certificate = certificates.get(index);
                String chosenAlias = Dialogs.promptAlias(stage, inferAlias(path, certificate, index)).orElse(null);
                if (chosenAlias == null) {
                    return;
                }
                boolean replace = false;
                while (trustStoreService.aliasExists(document, chosenAlias)) {
                    Dialogs.AliasConflictResolution resolution = Dialogs.promptAliasConflict(stage, chosenAlias);
                    if (resolution == Dialogs.AliasConflictResolution.CANCEL) {
                        return;
                    }
                    if (resolution == Dialogs.AliasConflictResolution.REPLACE) {
                        replace = true;
                        break;
                    }
                    chosenAlias = Dialogs.promptAlias(stage, chosenAlias + "-copy").orElse(null);
                    if (chosenAlias == null) {
                        return;
                    }
                }

                CertificateRecord preview = new CertificateRecord(
                        chosenAlias,
                        "Trusted Certificate",
                        CertificateFormatter.shortDn(certificate.getSubjectX500Principal().getName()),
                        CertificateFormatter.shortDn(certificate.getIssuerX500Principal().getName()),
                        certificate.getSerialNumber().toString(16).toUpperCase(Locale.ROOT),
                        certificate.getNotBefore().toInstant(),
                        certificate.getNotAfter().toInstant(),
                        certificate.getSigAlgName(),
                        FingerprintUtils.fingerprintSha1(certificate),
                        FingerprintUtils.fingerprintSha256(certificate),
                        certificate,
                        certificate.getNotAfter().toInstant().isBefore(Instant.now()),
                        certificate.getNotBefore().toInstant().isAfter(Instant.now()),
                        1,
                        path
                );
                if (!Dialogs.confirmImport(stage, preview)) {
                    continue;
                }
                trustStoreService.importCertificate(document, chosenAlias, certificate, replace);
                status("Imported " + chosenAlias);
                updateBanner();
                refreshDocumentChrome();
            }
        } catch (Exception ex) {
            Dialogs.showError(stage, "Import Failed", "The certificate file could not be imported.", ex);
            status("Import failed for " + path.getFileName());
        }
    }

    private void deleteSelected() {
        TrustStoreDocument document = documentProperty.get();
        CertificateRecord record = selectedRecord.get();
        if (document == null || record == null) {
            return;
        }
        if (!Dialogs.confirmDelete(stage, record)) {
            return;
        }
        try {
            trustStoreService.deleteAlias(document, record.alias());
            status("Deleted " + record.alias());
            updateBanner();
            refreshDocumentChrome();
        } catch (Exception ex) {
            Dialogs.showError(stage, "Delete Failed", "Could not delete the selected certificate.", ex);
        }
    }

    private void saveCurrent(boolean saveAs) {
        TrustStoreDocument document = documentProperty.get();
        if (document == null) {
            return;
        }

        Path target = document.getPath();
        if (saveAs || target == null) {
            FileChooser chooser = Dialogs.createStoreChooser();
            java.io.File file = chooser.showSaveDialog(stage);
            if (file == null) {
                return;
            }
            target = file.toPath();
        }

        Optional<char[]> updatedPassword = Dialogs.promptPassword(stage, "Save Truststore", "Enter the password to store the file");
        if (updatedPassword.isEmpty()) {
            return;
        }

        try {
            if (Files.exists(target)) {
                backupService.createBackup(target);
            }
            trustStoreService.save(document, target, updatedPassword.get());
            pathLabel.setText(target.toString());
            status("Saved " + target.getFileName());
            refreshDocumentChrome();
        } catch (Exception ex) {
            Dialogs.showError(stage, "Save Failed", "The truststore could not be saved.", ex);
        }
    }

    private void restoreBackup() {
        TrustStoreDocument document = documentProperty.get();
        if (document == null || document.getPath() == null) {
            Dialogs.showInfo(stage, "Restore Backup", "Save the truststore to disk before using restore.");
            return;
        }
        try {
            List<BackupRecord> backups = backupService.listBackups(document.getPath());
            if (backups.isEmpty()) {
                Dialogs.showInfo(stage, "Restore Backup", "No backups were found for this truststore.");
                return;
            }

            Optional<BackupRecord> backupChoice = Dialogs.chooseBackup(stage, backups);
            if (backupChoice.isEmpty()) {
                return;
            }
            BackupRecord backupRecord = backupChoice.get();
            if (!Dialogs.confirmRestore(stage, backupRecord)) {
                return;
            }

            backupService.restoreBackup(backupRecord);
            PasswordAwareLoadResult reloaded = trustStoreService.load(document.getPath(), document.getPassword());
            documentProperty.set(reloaded.document());
            status("Restored backup " + backupRecord.backupPath().getFileName());
        } catch (Exception ex) {
            Dialogs.showError(stage, "Restore Failed", "The selected backup could not be restored.", ex);
        }
    }

    private void exportSelected() {
        CertificateRecord record = selectedRecord.get();
        if (record == null) {
            return;
        }
        FileChooser chooser = Dialogs.createExportChooser(record.alias());
        java.io.File target = chooser.showSaveDialog(stage);
        if (target == null) {
            return;
        }
        boolean pem = target.getName().toLowerCase(Locale.ROOT).endsWith(".pem");
        try {
            trustStoreService.exportCertificate(record.certificate(), target.toPath(), pem);
            status("Exported " + record.alias());
        } catch (Exception ex) {
            Dialogs.showError(stage, "Export Failed", "The certificate could not be exported.", ex);
        }
    }

    private void copySelectedDetails() {
        CertificateRecord record = selectedRecord.get();
        if (record == null) {
            return;
        }
        ClipboardContent content = new ClipboardContent();
        content.putString(detailsArea.getText());
        Clipboard.getSystemClipboard().setContent(content);
        status("Copied details for " + record.alias());
    }

    private void renderDetails(CertificateRecord record) {
        if (record == null) {
            detailsArea.clear();
            return;
        }
        try {
            detailsArea.setText(CertificateFormatter.formatCertificateDetails(record.certificate()));
        } catch (Exception ex) {
            detailsArea.setText("Could not render certificate details: " + ex.getMessage());
        }
    }

    private void handleCloseRequest(WindowEvent event) {
        if (!checkUnsavedChanges()) {
            event.consume();
        }
    }

    private boolean checkUnsavedChanges() {
        TrustStoreDocument document = documentProperty.get();
        return document == null || !document.isDirty() || Dialogs.confirmUnsavedChanges(stage);
    }

    private void updateBanner() {
        TrustStoreDocument document = documentProperty.get();
        if (document == null) {
            bannerLabel.setVisible(false);
            bannerLabel.setManaged(false);
            return;
        }
        long expiredCount = document.getCertificates().stream().filter(CertificateRecord::expired).count();
        long futureCount = document.getCertificates().stream().filter(CertificateRecord::notYetValid).count();
        if (expiredCount == 0 && futureCount == 0) {
            bannerLabel.setVisible(false);
            bannerLabel.setManaged(false);
            return;
        }
        bannerLabel.setText(expiredCount + " expired certificate(s), " + futureCount + " not yet valid certificate(s)");
        bannerLabel.setVisible(true);
        bannerLabel.setManaged(true);
    }

    private void updateFilter() {
        if (filteredCertificates != null) {
            filteredCertificates.setPredicate(record -> matchesFilter(record, searchField.getText()));
        }
    }

    private boolean matchesFilter(CertificateRecord record, String filter) {
        if (filter == null || filter.isBlank()) {
            return true;
        }
        String normalized = filter.toLowerCase(Locale.ROOT);
        return contains(record.alias(), normalized)
                || contains(record.subject(), normalized)
                || contains(record.issuer(), normalized)
                || contains(record.serialNumber(), normalized)
                || contains(record.sha1(), normalized)
                || contains(record.sha256(), normalized);
    }

    private boolean contains(String value, String filter) {
        return value != null && value.toLowerCase(Locale.ROOT).contains(filter);
    }

    private boolean isStoreFile(Path path) {
        String fileName = path.getFileName().toString().toLowerCase(Locale.ROOT);
        return fileName.endsWith(".jks") || fileName.endsWith(".p12")
                || fileName.endsWith(".pkcs12") || fileName.endsWith(".cacerts") || fileName.equals("cacerts");
    }

    private boolean isCertificateFile(Path path) {
        String fileName = path.getFileName().toString().toLowerCase(Locale.ROOT);
        return fileName.endsWith(".cer") || fileName.endsWith(".crt")
                || fileName.endsWith(".pem") || fileName.endsWith(".der");
    }

    private String inferAlias(Path path, X509Certificate certificate, int index) {
        String baseName = path.getFileName().toString().replaceFirst("\\.[^.]+$", "");
        String subject = CertificateFormatter.shortDn(certificate.getSubjectX500Principal().getName())
                .replace("CN=", "")
                .trim()
                .replaceAll("[^a-zA-Z0-9._-]+", "-")
                .toLowerCase(Locale.ROOT);
        String alias = subject.isBlank() ? baseName : subject;
        return index == 0 ? alias : alias + "-" + (index + 1);
    }

    private void refreshDocumentChrome() {
        TrustStoreDocument document = documentProperty.get();
        saveButton.setDisable(document == null || !document.isDirty());
        stage.setTitle(document == null ? "CACerts Viewer" : document.getDisplayName() + (document.isDirty() ? " *" : "") + " - CACerts Viewer");
    }

    private void status(String message) {
        statusLabel.setText(message);
    }
}