package com.example.cacertsviewer.service;

import com.example.cacertsviewer.model.CertificateRecord;
import com.example.cacertsviewer.model.TrustStoreDocument;
import com.example.cacertsviewer.util.CertificateFormatter;

import javax.security.auth.x500.X500Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class ChainAnalysisService {
    public ChainAnalysisResult analyze(TrustStoreDocument document, CertificateRecord record) {
        X509Certificate certificate = record.certificate();
        boolean trustedDirectly = true;
        boolean selfSigned = isLikelySelfSigned(certificate);
        boolean certificateAuthority = certificate.getBasicConstraints() >= 0;
        List<String> chainSubjects = new ArrayList<>();
        List<String> diagnostics = new ArrayList<>();
        Set<String> visitedSubjects = new HashSet<>();

        X509Certificate current = certificate;
        chainSubjects.add(formatSubject(current));
        boolean chainBuildComplete = false;
        boolean missingIssuer = false;
        String trustAnchorAlias = selfSigned ? record.alias() : null;

        diagnostics.add("This certificate is stored directly in the open truststore under alias '" + record.alias() + "'.");
        if (certificateAuthority) {
            diagnostics.add("The selected certificate has CA basic constraints and can act as a trust anchor.");
        } else {
            diagnostics.add("The selected certificate is not marked as a CA certificate.");
        }

        if (selfSigned) {
            chainBuildComplete = true;
            diagnostics.add("The certificate appears to be self-signed.");
        } else {
            while (true) {
                String currentSubject = current.getSubjectX500Principal().getName(X500Principal.RFC2253);
                if (!visitedSubjects.add(currentSubject)) {
                    diagnostics.add("Chain building stopped because a certificate loop was detected.");
                    break;
                }

                Optional<IssuerMatch> issuerRecord = findIssuer(document, current, record.alias());
                if (issuerRecord.isEmpty()) {
                    missingIssuer = true;
                    diagnostics.add("No issuer certificate in this truststore could be matched to the selected certificate.");
                    break;
                }

                IssuerMatch issuer = issuerRecord.get();
                current = issuer.record().certificate();
                chainSubjects.add(formatSubject(current));
                if (issuer.signatureVerified()) {
                    diagnostics.add("Found issuer match in truststore alias '" + issuer.record().alias() + "' and verified the signature.");
                } else {
                    diagnostics.add("Found likely issuer match in truststore alias '" + issuer.record().alias() + "' based on issuer/subject names, but signature verification did not complete.");
                }

                if (isLikelySelfSigned(current)) {
                    trustAnchorAlias = issuer.record().alias();
                    chainBuildComplete = true;
                    diagnostics.add("Chain terminates at a likely self-signed trust anchor alias '" + issuer.record().alias() + "'.");
                    break;
                }
            }
        }

        return new ChainAnalysisResult(
                trustedDirectly,
                selfSigned,
                certificateAuthority,
                chainBuildComplete,
                missingIssuer,
                trustAnchorAlias,
                List.copyOf(chainSubjects),
                List.copyOf(diagnostics)
        );
    }

    private Optional<IssuerMatch> findIssuer(TrustStoreDocument document, X509Certificate certificate, String currentAlias) {
        String issuerDn = certificate.getIssuerX500Principal().getName(X500Principal.RFC2253);
        List<CertificateRecord> candidates = document.getCertificates().stream()
                .filter(candidate -> !candidate.alias().equals(currentAlias))
                .filter(candidate -> candidate.certificate().getSubjectX500Principal().getName(X500Principal.RFC2253).equals(issuerDn))
                .toList();

        for (CertificateRecord candidate : candidates) {
            if (verifiesAgainst(certificate, candidate.certificate().getPublicKey())) {
                return Optional.of(new IssuerMatch(candidate, true));
            }
        }
        if (!candidates.isEmpty()) {
            return Optional.of(new IssuerMatch(candidates.get(0), false));
        }
        return Optional.empty();
    }

    private boolean verifiesAgainst(X509Certificate certificate, PublicKey publicKey) {
        try {
            certificate.verify(publicKey);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    private boolean isLikelySelfSigned(X509Certificate certificate) {
        boolean sameSubjectAndIssuer = certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal());
        if (!sameSubjectAndIssuer) {
            return false;
        }
        return verifiesAgainst(certificate, certificate.getPublicKey()) || certificate.getBasicConstraints() >= 0;
    }

    private String formatSubject(X509Certificate certificate) {
        return CertificateFormatter.shortDn(certificate.getSubjectX500Principal().getName());
    }

    private record IssuerMatch(CertificateRecord record, boolean signatureVerified) {
    }
}