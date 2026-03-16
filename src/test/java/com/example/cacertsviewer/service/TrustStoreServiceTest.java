package com.example.cacertsviewer.service;

import com.example.cacertsviewer.model.BackupRecord;
import com.example.cacertsviewer.model.TrustStoreDocument;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TrustStoreServiceTest {
    private final TrustStoreService trustStoreService = new TrustStoreService();
    private final BackupService backupService = new BackupService();

    @TempDir
    Path tempDir;

    @Test
    void loadsAndDetectsJksStore() throws Exception {
        Path path = tempDir.resolve("test.jks");
        TrustStoreDocument document = trustStoreService.createEmpty("JKS", "changeit".toCharArray());
        X509Certificate certificate = TestCertificateFactory.createSelfSigned("load-test");
        trustStoreService.importCertificate(document, "load-test", certificate, false);
        trustStoreService.save(document, path, "changeit".toCharArray());

        PasswordAwareLoadResult loaded = trustStoreService.load(path, "changeit".toCharArray());

        assertEquals("JKS", loaded.detectedType());
        assertEquals(1, loaded.document().getCertificates().size());
        assertEquals("load-test", loaded.document().getCertificates().get(0).alias());
    }

    @Test
    void importsAndDeletesCertificate() throws Exception {
        TrustStoreDocument document = trustStoreService.createEmpty("PKCS12", "changeit".toCharArray());
        X509Certificate certificate = TestCertificateFactory.createSelfSigned("import-delete");

        trustStoreService.importCertificate(document, "sample", certificate, false);

        assertTrue(trustStoreService.aliasExists(document, "sample"));
        assertEquals(1, document.getCertificates().size());

        trustStoreService.deleteAlias(document, "sample");

        assertFalse(trustStoreService.aliasExists(document, "sample"));
        assertTrue(document.getCertificates().isEmpty());
    }

    @Test
    void parsesPemCertificateForImport() throws Exception {
        X509Certificate certificate = TestCertificateFactory.createSelfSigned("pem-import");
        Path path = tempDir.resolve("cert.pem");
        Files.writeString(path, com.example.cacertsviewer.util.CertificateFormatter.toPem(certificate));

        List<X509Certificate> certificates = trustStoreService.parseCertificates(path);

        assertEquals(1, certificates.size());
        assertEquals(certificate.getSubjectX500Principal(), certificates.get(0).getSubjectX500Principal());
    }

    @Test
    void createsBackupBeforeOverwrite() throws Exception {
        Path storePath = tempDir.resolve("store.jks");
        Files.writeString(storePath, "before");

        BackupRecord backupRecord = backupService.createBackup(storePath);

        assertTrue(Files.exists(backupRecord.backupPath()));
        assertEquals("before", Files.readString(backupRecord.backupPath()));
    }

    @Test
    void restoresBackupContents() throws Exception {
        Path storePath = tempDir.resolve("store.jks");
        Files.writeString(storePath, "original");
        BackupRecord backupRecord = backupService.createBackup(storePath);
        Files.writeString(storePath, "modified");

        backupService.restoreBackup(backupRecord);

        assertEquals("original", Files.readString(storePath));
    }
}