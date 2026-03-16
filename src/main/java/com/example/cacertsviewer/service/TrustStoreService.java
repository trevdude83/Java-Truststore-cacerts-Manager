package com.example.cacertsviewer.service;

import com.example.cacertsviewer.model.CertificateRecord;
import com.example.cacertsviewer.model.TrustStoreDocument;
import com.example.cacertsviewer.util.CertificateFormatter;
import com.example.cacertsviewer.util.FingerprintUtils;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

public class TrustStoreService {
    public PasswordAwareLoadResult load(Path path, char[] password)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(path, "path");
        char[] effectivePassword = password == null ? new char[0] : password.clone();

        List<String> candidates = detectCandidateTypes(path);
        Exception last = null;
        for (String type : candidates) {
            try {
                KeyStore store = KeyStore.getInstance(type);
                try (InputStream inputStream = new BufferedInputStream(Files.newInputStream(path))) {
                    store.load(inputStream, effectivePassword);
                }

                TrustStoreDocument document = new TrustStoreDocument();
                document.setPath(path);
                document.setStoreType(type);
                document.setPassword(effectivePassword);
                document.setKeyStore(store);
                refresh(document);
                document.setDirty(false);
                return new PasswordAwareLoadResult(document, type);
            } catch (IOException | GeneralSecurityException ex) {
                last = ex;
            }
        }

        if (last instanceof IOException ioException) {
            throw ioException;
        }
        if (last instanceof GeneralSecurityException securityException) {
            throw securityException;
        }
        throw new KeyStoreException("Could not open truststore.");
    }

    public void refresh(TrustStoreDocument document) throws GeneralSecurityException {
        List<CertificateRecord> records = new ArrayList<>();
        Enumeration<String> aliases = document.getKeyStore().aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate certificate = document.getKeyStore().getCertificate(alias);
            if (!(certificate instanceof X509Certificate x509Certificate)) {
                continue;
            }

            String entryType = describeEntryType(document.getKeyStore(), alias);
            boolean expired = x509Certificate.getNotAfter().toInstant().isBefore(Instant.now());
            boolean notYetValid = x509Certificate.getNotBefore().toInstant().isAfter(Instant.now());
            int chainLength = 0;
            Certificate[] chain = document.getKeyStore().getCertificateChain(alias);
            if (chain != null) {
                chainLength = chain.length;
            }

            records.add(new CertificateRecord(
                    alias,
                    entryType,
                    CertificateFormatter.shortDn(x509Certificate.getSubjectX500Principal().getName()),
                    CertificateFormatter.shortDn(x509Certificate.getIssuerX500Principal().getName()),
                    x509Certificate.getSerialNumber().toString(16).toUpperCase(Locale.ROOT),
                    x509Certificate.getNotBefore().toInstant(),
                    x509Certificate.getNotAfter().toInstant(),
                    x509Certificate.getSigAlgName(),
                    FingerprintUtils.fingerprintSha1(x509Certificate),
                    FingerprintUtils.fingerprintSha256(x509Certificate),
                    x509Certificate,
                    expired,
                    notYetValid,
                    chainLength,
                    document.getPath()
            ));
        }
        records.sort(Comparator.comparing(CertificateRecord::alias, String.CASE_INSENSITIVE_ORDER));
        document.getCertificates().setAll(records);
    }

    public TrustStoreDocument createEmpty(String storeType, char[] password) throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance(storeType);
        char[] effectivePassword = password == null ? new char[0] : password.clone();
        store.load(null, effectivePassword);
        TrustStoreDocument document = new TrustStoreDocument();
        document.setStoreType(storeType);
        document.setPassword(effectivePassword);
        document.setKeyStore(store);
        refresh(document);
        return document;
    }

    public List<X509Certificate> parseCertificates(Path certificatePath) throws IOException, GeneralSecurityException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        try (InputStream inputStream = new BufferedInputStream(Files.newInputStream(certificatePath))) {
            Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(inputStream);
            List<X509Certificate> result = new ArrayList<>();
            for (Certificate certificate : certificates) {
                if (certificate instanceof X509Certificate x509Certificate) {
                    result.add(x509Certificate);
                }
            }
            if (result.isEmpty()) {
                throw new GeneralSecurityException("No X.509 certificate was found in the file.");
            }
            return result;
        }
    }

    public boolean aliasExists(TrustStoreDocument document, String alias) throws KeyStoreException {
        return document.getKeyStore().containsAlias(alias);
    }

    public void importCertificate(TrustStoreDocument document, String alias, X509Certificate certificate, boolean replaceExisting)
            throws GeneralSecurityException {
        if (!replaceExisting && document.getKeyStore().containsAlias(alias)) {
            throw new KeyStoreException("Alias already exists.");
        }
        if (replaceExisting && document.getKeyStore().containsAlias(alias)) {
            document.getKeyStore().deleteEntry(alias);
        }
        document.getKeyStore().setCertificateEntry(alias, certificate);
        refresh(document);
        document.setDirty(true);
    }

    public void deleteAlias(TrustStoreDocument document, String alias) throws GeneralSecurityException {
        if (!document.getKeyStore().containsAlias(alias)) {
            throw new KeyStoreException("Alias not found.");
        }
        document.getKeyStore().deleteEntry(alias);
        refresh(document);
        document.setDirty(true);
    }

    public void save(TrustStoreDocument document, Path targetPath, char[] password) throws IOException, GeneralSecurityException {
        char[] effectivePassword = password == null ? new char[0] : password.clone();
        try (OutputStream outputStream = Files.newOutputStream(targetPath)) {
            document.getKeyStore().store(outputStream, effectivePassword);
        }
        document.setPath(targetPath);
        document.setPassword(effectivePassword);
        document.setDirty(false);
    }

    public void exportCertificate(X509Certificate certificate, Path outputPath, boolean pemFormat)
            throws IOException, GeneralSecurityException {
        if (pemFormat) {
            Files.writeString(outputPath, CertificateFormatter.toPem(certificate));
            return;
        }
        Files.write(outputPath, certificate.getEncoded());
    }

    private List<String> detectCandidateTypes(Path path) {
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.endsWith(".p12") || name.endsWith(".pfx") || name.endsWith(".pkcs12")) {
            return List.of("PKCS12", "JKS");
        }
        if (name.endsWith(".jks") || name.endsWith(".cacerts") || name.equals("cacerts")) {
            return List.of("JKS", "PKCS12");
        }
        return List.of("JKS", "PKCS12");
    }

    private String describeEntryType(KeyStore keyStore, String alias) throws KeyStoreException {
        if (keyStore.isCertificateEntry(alias)) {
            return "Trusted Certificate";
        }
        if (keyStore.isKeyEntry(alias)) {
            return "Key Entry";
        }
        return "Unknown";
    }
}