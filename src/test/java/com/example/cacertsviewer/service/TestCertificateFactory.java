package com.example.cacertsviewer.service;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

final class TestCertificateFactory {
    private static final String TEST_CERTIFICATE_PEM = """
            -----BEGIN CERTIFICATE-----
            MIICujCCAaKgAwIBAgIIIj4p0ugEW0YwDQYJKoZIhvcNAQELBQAwHTEbMBkGA1UEAxMS
            Y2FjZXJ0c3ZpZXdlci10ZXN0MB4XDTI2MDMxNTEwMzI0MloXDTI3MDMxNjEwMzI0Mlow
            HTEbMBkGA1UEAxMSY2FjZXJ0c3ZpZXdlci10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOC
            AQ8AMIIBCgKCAQEAo0FWhq4b9Ysd1qbStTvqAXMIYn/TBDWcOvcSEeAP/G1O1Fm9+GAt
            XPZeIhE1mOy0ky1S+6B+nwCc7Dm1JLbMNhbSmAZUdhdo9aaMVqNISQJwLutLKa0gGdNt
            oeX5itSv14AcPr3gfO3leFYKB39T47ypryKt6BvdBsfxS6ff96dmjFV7DwGZeJf1aFyN
            NVWrSt7fYEhbgqZnmH3LxhJoxcju9uSCexf2Zd+DqBHB/ghUjrwfiWlfR1cU1MJL9CRY
            dnvuzhxMHP1MkPkYAUMZTaumcbQUT1AEzji5MYsPyCmBPgtxKMpGPlmmKGseVPH/evLa
            AXhKAoiT4Wcpzl0JdQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQA+ML5YsM5nyHZ3ZW5J
            NahJtJnqsXwxLsqhxIP2dJWpG1l8rkOlSN+FVDc92EEIesN2p8+ChFF9Sey05DLiDRcq
            a2GSDF94sH3TqyZqE1uCwQHYxpmLL0FkoYru2RCNcAjpeFJJCPP/99uumz2kBC/G7Rdm
            ct1UnWArCw+E+tg+9NmvoqxiL9yF15q1HpsRe2zZ9zTvzPj8TwrOqtkNimCQ+E+CO5Hs
            btehiG8b1O3n2S0PiP8s2+gAzxdeSjk7Ca7QvA6CNIiKEiDYgEdHfx3L4DM5MbIuerOz
            eR2Zc3tgtqNN+CpsrKjLkyYtTHPTTD+zErIqAOk6NcB/jL4WY0nC
            -----END CERTIFICATE-----
            """;

    private TestCertificateFactory() {
    }

    static X509Certificate createSelfSigned(String commonName) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(TEST_CERTIFICATE_PEM.getBytes(StandardCharsets.US_ASCII))) {
            return (X509Certificate) certificateFactory.generateCertificate(inputStream);
        }
    }
}