package it.unina.crypto;

import org.bouncycastle.asn1.x509.PKIXNameConstraintValidator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.security.Security;
import java.security.cert.*;
import java.util.*;

public class Cve8763Lab {

    private static final String[] CERT_PATHS = {
            "certs/rootCA.crt",
            "certs/interCA.crt",
            "certs/server_trailing_dot.crt"
    };

    public static void run() throws Exception {
        System.out.println("\n==================================================");
        System.out.println("       CVE-2026-8763 - PKIX VALIDATION LAB");
        System.out.println("==================================================");

        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // 1. Check Bouncy Castle version & PKIX validator presence
        String version = BouncyCastleProvider.class.getPackage().getImplementationVersion();
        System.out.println("[INFO] Provider:       " + Security.getProvider("BC").getName());
        System.out.println("[INFO] BC Version:     " + (version != null ? version : "Unknown"));
        System.out.println("[INFO] PKIX Validator: " + PKIXNameConstraintValidator.class.getName());

        if (version != null) {
            if (isVulnerableVersion(version)) {
                System.out.println("[WARN] Version < 1.85 detected: VULNERABLE to trailing-dot Name Constraints bypass.");
            } else {
                System.out.println("[OK]   Version >= 1.85 detected: PATCHED against CVE-2026-8763.");
            }
        }

        // 2. Verify certificate files exist before proceeding
        List<X509Certificate> loadedCerts = new ArrayList<>();
        CertificateFactory factory = CertificateFactory.getInstance("X.509");

        for (String path : CERT_PATHS) {
            File file = new File(path);
            if (!file.exists()) {
                System.err.println("\n[ERROR] Missing certificate file: " + file.getAbsolutePath());
                System.err.println("[HINT]  Place 'rootCA.crt', 'interCA.crt', and 'server_trailing_dot.crt' inside the 'certs/' folder at the project root.");
                return;
            }

            try (FileInputStream in = new FileInputStream(file)) {
                X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
                loadedCerts.add(cert);
                inspectCertificateSan(path, cert);
            }
        }

        // 3. Execute PKIX Path Validation
        System.out.println("\n--------------------------------------------------");
        System.out.println("RUNNING PKIX CERTIFICATION PATH VALIDATION");
        System.out.println("--------------------------------------------------");
        validateChain(loadedCerts.get(0), loadedCerts.get(1), loadedCerts.get(2), factory);
    }

    private static void inspectCertificateSan(String filePath, X509Certificate cert) throws CertificateParsingException {
        System.out.println("\n--------------------------------------------------");
        System.out.println("File:    " + filePath);
        System.out.println("Subject: " + cert.getSubjectX500Principal());
        System.out.println("Issuer:  " + cert.getIssuerX500Principal());
        System.out.println("Valid:   " + cert.getNotBefore() + " -> " + cert.getNotAfter());

        Collection<List<?>> sans = cert.getSubjectAlternativeNames();
        if (sans == null || sans.isEmpty()) {
            System.out.println("SAN:     none");
            return;
        }

        for (List<?> san : sans) {
            int type = (Integer) san.get(0);
            String value = String.valueOf(san.get(1));

            String typeName = switch (type) {
                case 1 -> "rfc822Name";
                case 2 -> "dNSName";
                case 6 -> "URI";
                case 7 -> "iPAddress";
                default -> "Other(" + type + ")";
            };

            System.out.println("[SAN]    " + typeName + ": " + value);
        }
    }

    private static void validateChain(
            X509Certificate root,
            X509Certificate intermediate,
            X509Certificate leaf,
            CertificateFactory factory) throws Exception {

        Set<TrustAnchor> trustAnchors = Collections.singleton(new TrustAnchor(root, null));

        // Build path from leaf -> intermediate
        List<X509Certificate> chain = List.of(leaf, intermediate);
        CertPath certPath = factory.generateCertPath(chain);

        PKIXParameters params = new PKIXParameters(trustAnchors);
        params.setRevocationEnabled(false); // Offline lab validation

        CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");

        try {
            validator.validate(certPath, params);
            System.out.println("[RESULT: VALID]   Certificate chain passed PKIX validation.");
            System.out.println("[NOTE]            If Name Constraints excluded this namespace, the trailing dot bypassed enforcement.");
        } catch (CertPathValidatorException e) {
            System.out.println("[RESULT: BLOCKED] Certificate chain rejected by PKIX validator.");
            System.out.println("[REASON]          " + e.getMessage());
            System.out.println("[CERT INDEX]      " + e.getIndex());
        }
    }

    private static boolean isVulnerableVersion(String version) {
        try {
            String[] parts = version.split("\\.");
            int major = Integer.parseInt(parts[0]);
            int minor = Integer.parseInt(parts[1]);
            return major == 1 && minor < 85;
        } catch (Exception e) {
            return false;
        }
    }
}