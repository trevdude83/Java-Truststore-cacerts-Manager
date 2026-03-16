package com.example.cacertsviewer.model;

import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import java.nio.file.Path;
import java.security.KeyStore;

public class TrustStoreDocument {
    private final ObservableList<CertificateRecord> certificates = FXCollections.observableArrayList();
    private final BooleanProperty dirty = new SimpleBooleanProperty(false);

    private KeyStore keyStore;
    private Path path;
    private String storeType;
    private char[] password;

    public ObservableList<CertificateRecord> getCertificates() {
        return certificates;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public Path getPath() {
        return path;
    }

    public void setPath(Path path) {
        this.path = path;
    }

    public String getStoreType() {
        return storeType;
    }

    public void setStoreType(String storeType) {
        this.storeType = storeType;
    }

    public char[] getPassword() {
        return password;
    }

    public void setPassword(char[] password) {
        this.password = password == null ? null : password.clone();
    }

    public BooleanProperty dirtyProperty() {
        return dirty;
    }

    public boolean isDirty() {
        return dirty.get();
    }

    public void setDirty(boolean value) {
        dirty.set(value);
    }

    public String getDisplayName() {
        return path == null ? "Untitled Truststore" : path.getFileName().toString();
    }
}
