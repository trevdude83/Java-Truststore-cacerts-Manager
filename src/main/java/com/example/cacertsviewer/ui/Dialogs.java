package com.example.cacertsviewer.ui;

import com.example.cacertsviewer.model.BackupRecord;
import com.example.cacertsviewer.model.CertificateRecord;
import com.example.cacertsviewer.util.CertificateFormatter;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Window;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;

public final class Dialogs {
    private static final DateTimeFormatter BACKUP_TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private Dialogs() {
    }

    public static Optional<char[]> promptPassword(Window owner, String title, String header) {
        Dialog<char[]> dialog = new Dialog<>();
        dialog.initOwner(owner);
        dialog.setTitle(title);
        dialog.setHeaderText(header);
        dialog.getDialogPane().getButtonTypes().addAll(ButtonType.OK, ButtonType.CANCEL);

        PasswordField passwordField = new PasswordField();
        passwordField.setPromptText("Leave blank if no password is set");

        GridPane gridPane = new GridPane();
        gridPane.setHgap(12);
        gridPane.setVgap(12);
        gridPane.add(new Label("Password"), 0, 0);
        gridPane.add(passwordField, 1, 0);
        GridPane.setHgrow(passwordField, Priority.ALWAYS);
        dialog.getDialogPane().setContent(gridPane);

        Node okButton = dialog.getDialogPane().lookupButton(ButtonType.OK);
        okButton.disableProperty().unbind();

        dialog.setResultConverter(button -> button == ButtonType.OK ? passwordField.getText().toCharArray() : null);
        return dialog.showAndWait();
    }

    public static Optional<String> promptAlias(Window owner, String suggestedAlias) {
        TextInputDialog dialog = new TextInputDialog(suggestedAlias);
        dialog.initOwner(owner);
        dialog.setTitle("Certificate Alias");
        dialog.setHeaderText("Choose an alias for the imported certificate");
        dialog.setContentText("Alias");
        return dialog.showAndWait().map(String::trim).filter(value -> !value.isBlank());
    }

    public static boolean confirmDelete(Window owner, CertificateRecord record) {
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.initOwner(owner);
        alert.setTitle("Delete Certificate");
        alert.setHeaderText("Delete the selected certificate?");
        alert.setContentText("Alias: " + record.alias() + "\nSubject: " + record.subject());
        return alert.showAndWait().filter(ButtonType.OK::equals).isPresent();
    }

    public static AliasConflictResolution promptAliasConflict(Window owner, String alias) {
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.initOwner(owner);
        alert.setTitle("Alias Already Exists");
        alert.setHeaderText("The alias \"" + alias + "\" is already in use.");
        ButtonType replace = new ButtonType("Replace existing");
        ButtonType chooseNew = new ButtonType("Choose new alias");
        alert.getButtonTypes().setAll(replace, chooseNew, ButtonType.CANCEL);
        Optional<ButtonType> result = alert.showAndWait();
        if (result.isEmpty() || result.get() == ButtonType.CANCEL) {
            return AliasConflictResolution.CANCEL;
        }
        return result.get() == replace ? AliasConflictResolution.REPLACE : AliasConflictResolution.CHOOSE_NEW;
    }

    public static boolean confirmImport(Window owner, CertificateRecord previewRecord) {
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.initOwner(owner);
        alert.setTitle("Import Certificate");
        alert.setHeaderText("Import this certificate into the truststore?");
        TextArea area = new TextArea();
        area.setEditable(false);
        area.setWrapText(true);
        area.setText("Alias: " + previewRecord.alias()
                + "\nSubject: " + previewRecord.certificate().getSubjectX500Principal().getName()
                + "\nIssuer: " + previewRecord.certificate().getIssuerX500Principal().getName()
                + "\nValid To: " + CertificateFormatter.DATE_FORMAT.format(previewRecord.validTo()));
        area.setPrefColumnCount(60);
        area.setPrefRowCount(8);
        alert.getDialogPane().setContent(area);
        return alert.showAndWait().filter(ButtonType.OK::equals).isPresent();
    }

    public static Optional<BackupRecord> chooseBackup(Window owner, List<BackupRecord> backups) {
        Dialog<BackupRecord> dialog = new Dialog<>();
        dialog.initOwner(owner);
        dialog.setTitle("Restore Backup");
        dialog.setHeaderText("Choose a backup to restore");
        dialog.getDialogPane().getButtonTypes().addAll(ButtonType.OK, ButtonType.CANCEL);

        ListView<BackupRecord> listView = new ListView<>(FXCollections.observableArrayList(backups));
        listView.setCellFactory(ignore -> new ListCell<>() {
            @Override
            protected void updateItem(BackupRecord item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                    return;
                }
                setText(BACKUP_TIME_FORMAT.format(item.createdAt()) + "  |  "
                        + item.backupPath().getFileName() + "  |  " + item.size() + " bytes");
            }
        });
        if (!backups.isEmpty()) {
            listView.getSelectionModel().selectFirst();
        }

        VBox content = new VBox(10, new Label("Backups"), listView);
        content.setPadding(new Insets(10));
        VBox.setVgrow(listView, Priority.ALWAYS);
        dialog.getDialogPane().setContent(content);

        Node okButton = dialog.getDialogPane().lookupButton(ButtonType.OK);
        okButton.disableProperty().bind(listView.getSelectionModel().selectedItemProperty().isNull());
        dialog.setResultConverter(button -> button == ButtonType.OK ? listView.getSelectionModel().getSelectedItem() : null);
        dialog.getDialogPane().setPrefSize(820, 420);
        return dialog.showAndWait();
    }

    public static boolean confirmRestore(Window owner, BackupRecord backupRecord) {
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.initOwner(owner);
        alert.setTitle("Restore Backup");
        alert.setHeaderText("Restore this backup over the current truststore?");
        alert.setContentText("Backup: " + backupRecord.backupPath().getFileName()
                + "\nCreated: " + BACKUP_TIME_FORMAT.format(backupRecord.createdAt())
                + "\nTarget: " + backupRecord.originalPath());
        return alert.showAndWait().filter(ButtonType.OK::equals).isPresent();
    }

    public static void showError(Window owner, String title, String message, Throwable throwable) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.initOwner(owner);
        alert.setTitle(title);
        alert.setHeaderText(message);
        if (throwable != null && throwable.getMessage() != null) {
            TextArea area = new TextArea(throwable.getMessage());
            area.setEditable(false);
            area.setWrapText(true);
            area.setPrefColumnCount(60);
            area.setPrefRowCount(6);
            alert.getDialogPane().setExpandableContent(area);
        }
        alert.showAndWait();
    }

    public static void showInfo(Window owner, String title, String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.initOwner(owner);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    public static boolean confirmUnsavedChanges(Window owner) {
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.initOwner(owner);
        alert.setTitle("Unsaved Changes");
        alert.setHeaderText("You have unsaved changes.");
        alert.setContentText("Close without saving?");
        return alert.showAndWait().filter(ButtonType.OK::equals).isPresent();
    }

    public static FileChooser createStoreChooser() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Open Truststore");
        chooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Truststores", "*.jks", "*.p12", "*.pkcs12", "*.cacerts", "cacerts"),
                new FileChooser.ExtensionFilter("All files", "*.*")
        );
        return chooser;
    }

    public static FileChooser createCertificateChooser() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Import Certificate");
        chooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Certificate files", "*.cer", "*.crt", "*.pem", "*.der"),
                new FileChooser.ExtensionFilter("All files", "*.*")
        );
        return chooser;
    }

    public static FileChooser createExportChooser(String alias) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Export Certificate");
        chooser.setInitialFileName(alias + ".cer");
        chooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("DER Certificate", "*.cer"),
                new FileChooser.ExtensionFilter("PEM Certificate", "*.pem")
        );
        return chooser;
    }

    public enum AliasConflictResolution {
        CANCEL,
        REPLACE,
        CHOOSE_NEW
    }
}