package com.example.cacertsviewer.model;

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Instant;

public record CertificateRecord(
        String alias,
        String entryType,
        String subject,
        String issuer,
        String serialNumber,
        Instant validFrom,
        Instant validTo,
        String signatureAlgorithm,
        String sha1,
        String sha256,
        X509Certificate certificate,
        boolean expired,
        boolean notYetValid,
        int chainLength,
        Path sourcePath
) {
}
