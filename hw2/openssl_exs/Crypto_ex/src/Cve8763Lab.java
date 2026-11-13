
import java.io.FileInputStream;
import java.security.Security;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.x509.PKIXNameConstraintValidator;

public class Cve8763Lab {

    public static void main(String[] args) throws Exception {

        System.out.println("======================================");
        System.out.println("       CVE-2026-8763 - JAVA LAB");
        System.out.println("======================================");

        // Register Bouncy Castle
        Security.addProvider(new BouncyCastleProvider());

        String version = BouncyCastleProvider.class
                .getPackage()
                .getImplementationVersion();

        System.out.println("[INFO] Provider: BC");
        System.out.println("[INFO] Version: " + version);

        if (version == null) {
            System.out.println(
                "[WARNING] Versione non disponibile nel manifest."
            );
        } else if (version.startsWith("1.84")) {
            System.out.println(
                "[WARNING] Versione precedente alla patch 1.85."
            );
        } else {
            System.out.println(
                "[INFO] Confrontare con le versioni corrette."
            );
        }

        // Check PKIX validator availability
        Class<?> validator =
            PKIXNameConstraintValidator.class;

        System.out.println(
            "[INFO] PKIX validator: " +
            validator.getName()
        );

        System.out.println(
            "[INFO] Provider registrato: " +
            Security.getProvider("BC").getName()
        );

        String[] certificatePaths = {
            "certs/rootCA.crt",
            "certs/interCA.crt",
            "certs/server_trailing_dot.crt"
        };

        CertificateFactory factory =
            CertificateFactory.getInstance("X.509");

        for (String file : certificatePaths) {
            System.out.println("\n--------------------------------");
            System.out.println("Certificate: " + file);

            try (FileInputStream in =
                    new FileInputStream(file)) {

                X509Certificate cert =
                    (X509Certificate)
                    factory.generateCertificate(in);

                System.out.println(
                    "Subject: " +
                    cert.getSubjectX500Principal()
                );

                System.out.println(
                    "Issuer: " +
                    cert.getIssuerX500Principal()
                );

                System.out.println(
                    "Valid from: " + cert.getNotBefore()
                );

                System.out.println(
                    "Valid until: " + cert.getNotAfter()
                );

                Collection<List<?>> sans =
                    cert.getSubjectAlternativeNames();

                if (sans == null) {
                    System.out.println("SAN: none");
                    continue;
                }

                for (List<?> san : sans) {

                    Integer type = (Integer) san.get(0);
                    Object value = san.get(1);

                    String typeName;

                    switch (type) {
                        case 1:
                            typeName = "rfc822Name";
                            break;
                        case 2:
                            typeName = "dNSName";
                            break;
                        case 6:
                            typeName = "URI";
                            break;
                        default:
                            typeName = "Other";
                    }

                    String name = String.valueOf(value);

                    System.out.println(
                        "[SAN] " + typeName + ": " + name
                    );
                }
            }
        }

        System.out.println("\n======================================");
        System.out.println("          ANALYSIS COMPLETED");
        System.out.println("======================================");
        System.out.println("\n======================================");
        System.out.println("       PKIX CERTIFICATE VALIDATION");
        System.out.println("======================================");

        validateServerCertificate(List.of(certificatePaths));
    }

    private static void validateServerCertificate(List<String> certificatePaths) throws Exception {

        CertificateFactory factory =
            CertificateFactory.getInstance("X.509");

        // Load certificates
        X509Certificate root;
        X509Certificate intermediate;
        X509Certificate server;

        try (FileInputStream in = new FileInputStream(certificatePaths.get(0))) {
            root = (X509Certificate) factory.generateCertificate(in);
        }

        try (FileInputStream in = new FileInputStream(certificatePaths.get(1))) {
            intermediate = (X509Certificate) factory.generateCertificate(in);
        }

        try (FileInputStream in = new FileInputStream(certificatePaths.get(2))) {
            server = (X509Certificate) factory.generateCertificate(in);
        }

        // Root CA is trusted explicitly
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        trustAnchors.add(new TrustAnchor(root, null));

        // Build certification path: server -> intermediate
        List<X509Certificate> chain = new ArrayList<>();
        chain.add(server);
        chain.add(intermediate);

        CertPath certPath = factory.generateCertPath(chain);

        // Configure PKIX validation
        PKIXParameters parameters =
            new PKIXParameters(trustAnchors);

        // Disable CRL/OCSP checking for this local lab
        parameters.setRevocationEnabled(false);

        // Validate using Bouncy Castle
        CertPathValidator validator =
            CertPathValidator.getInstance("PKIX", "BC");

        try {
            validator.validate(certPath, parameters);

            System.out.println("[SUCCESS] Certificate chain is VALID.");

        } catch (CertPathValidatorException e) {

            System.out.println("[FAIL] Certificate chain is INVALID.");
            System.out.println("[ERROR] " + e.getMessage());
            System.out.println("[INDEX] " + e.getIndex());
        }
    }
}
