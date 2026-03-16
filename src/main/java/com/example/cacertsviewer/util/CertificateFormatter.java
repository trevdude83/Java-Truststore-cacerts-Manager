package com.example.cacertsviewer.util;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.StringJoiner;

public final class CertificateFormatter {
    public static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z", Locale.ROOT).withZone(ZoneId.systemDefault());

    private CertificateFormatter() {
    }

    public static String shortDn(String dn) {
        String[] parts = dn.split(",");
        return parts.length == 0 ? dn : parts[0].trim();
    }

    public static String formatCertificateDetails(X509Certificate certificate) throws GeneralSecurityException {
        StringBuilder builder = new StringBuilder();
        builder.append("Subject: ").append(certificate.getSubjectX500Principal().getName()).append('\n');
        builder.append("Issuer: ").append(certificate.getIssuerX500Principal().getName()).append('\n');
        builder.append("Serial Number: ").append(certificate.getSerialNumber().toString(16).toUpperCase(Locale.ROOT)).append('\n');
        builder.append("Valid From: ").append(DATE_FORMAT.format(certificate.getNotBefore().toInstant())).append('\n');
        builder.append("Valid To: ").append(DATE_FORMAT.format(certificate.getNotAfter().toInstant())).append('\n');
        builder.append("Signature Algorithm: ").append(certificate.getSigAlgName()).append('\n');
        builder.append("Public Key: ").append(describePublicKey(certificate.getPublicKey())).append('\n');
        builder.append("CA Certificate: ").append(certificate.getBasicConstraints() >= 0 ? "Yes" : "No").append('\n');
        builder.append("Basic Constraints: ").append(certificate.getBasicConstraints()).append('\n');
        builder.append("Key Usage: ").append(formatKeyUsage(certificate.getKeyUsage())).append('\n');
        builder.append("Extended Key Usage: ").append(formatExtendedKeyUsage(certificate)).append('\n');
        builder.append("Subject Alternative Names: ").append(formatSan(certificate)).append('\n');
        builder.append("SHA-1: ").append(FingerprintUtils.fingerprintSha1(certificate)).append('\n');
        builder.append("SHA-256: ").append(FingerprintUtils.fingerprintSha256(certificate)).append('\n');
        builder.append('\n').append(toPem(certificate));
        return builder.toString();
    }

    public static String toPem(X509Certificate certificate) throws CertificateEncodingException {
        String encoded = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(certificate.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + encoded + "\n-----END CERTIFICATE-----\n";
    }

    public static String formatSan(X509Certificate certificate) {
        try {
            Collection<List<?>> sans = certificate.getSubjectAlternativeNames();
            if (sans == null || sans.isEmpty()) {
                return "None";
            }
            StringJoiner joiner = new StringJoiner(", ");
            for (List<?> san : sans) {
                if (san.size() > 1) {
                    joiner.add(String.valueOf(san.get(1)));
                }
            }
            return joiner.length() == 0 ? "Present" : joiner.toString();
        } catch (Exception ex) {
            return "Unavailable";
        }
    }

    public static String formatKeyUsage(boolean[] keyUsage) {
        if (keyUsage == null) {
            return "None";
        }
        String[] labels = {
                "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
                "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"
        };
        StringJoiner joiner = new StringJoiner(", ");
        for (int i = 0; i < Math.min(keyUsage.length, labels.length); i++) {
            if (keyUsage[i]) {
                joiner.add(labels[i]);
            }
        }
        return joiner.length() == 0 ? "None" : joiner.toString();
    }

    private static String formatExtendedKeyUsage(X509Certificate certificate) {
        try {
            List<String> usage = certificate.getExtendedKeyUsage();
            return usage == null || usage.isEmpty() ? "None" : String.join(", ", usage);
        } catch (Exception ex) {
            return "Unavailable";
        }
    }

    private static String describePublicKey(PublicKey publicKey) {
        return publicKey.getAlgorithm() + " (" + publicKey.getFormat() + ", " + inferKeySize(publicKey) + " bits)";
    }

    private static int inferKeySize(PublicKey publicKey) {
        byte[] encoded = publicKey.getEncoded();
        return encoded == null ? -1 : encoded.length * 8;
    }
}
