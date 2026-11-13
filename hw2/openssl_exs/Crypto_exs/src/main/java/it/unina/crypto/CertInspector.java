package it.unina.crypto;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class CertInspector {

    private static final String[] KEY_USAGE_NAMES = {
            "digitalSignature", "nonRepudiation", "keyEncipherment",
            "dataEncipherment", "keyAgreement", "keyCertSign",
            "cRLSign", "encipherOnly", "decipherOnly"
    };

    public static void printCertificateDetails(X509Certificate cert) {
        System.out.println("=================================================================");
        System.out.println("ISPEZIONE CERTIFICATO X.509 v" + cert.getVersion());
        System.out.println("=================================================================");
        System.out.println("Subject DN:      " + cert.getSubjectX500Principal().getName());
        System.out.println("Issuer DN:       " + cert.getIssuerX500Principal().getName());
        System.out.println("Serial Number:   " + cert.getSerialNumber().toString(16).toUpperCase());
        System.out.println("Algoritmo Firma: " + cert.getSigAlgName() + " (" + cert.getSigAlgOID() + ")");
        System.out.println("Valido dal:      " + cert.getNotBefore());
        System.out.println("Valido al:       " + cert.getNotAfter());

        // Analisi Chiave Pubblica
        PublicKey pk = cert.getPublicKey();
        String keySizeInfo = "";
        if (pk instanceof RSAPublicKey rsa) {
            keySizeInfo = " (" + rsa.getModulus().bitLength() + " bit)";
        } else if (pk instanceof ECPublicKey ec) {
            keySizeInfo = " (" + ec.getParams().getOrder().bitLength() + " bit)";
        }
        System.out.println("Chiave Pubblica: " + pk.getAlgorithm() + keySizeInfo + " [Formato: " + pk.getFormat() + "]");

        // Basic Constraints (-1 = End Entity, >= 0 = CA)
        int bc = cert.getBasicConstraints();
        System.out.println("Tipo Entita':    " + (bc == -1 ? "End-Entity (Foglia)" : "Certificate Authority (PathLen: " + bc + ")"));

        // Decodifica Key Usage
        boolean[] ku = cert.getKeyUsage();
        if (ku != null) {
            List<String> activeKu = new ArrayList<>();
            for (int i = 0; i < Math.min(ku.length, KEY_USAGE_NAMES.length); i++) {
                if (ku[i]) activeKu.add(KEY_USAGE_NAMES[i]);
            }
            System.out.println("Key Usage:       " + String.join(", ", activeKu));
        }

        // Extended Key Usage
        try {
            List<String> eku = cert.getExtendedKeyUsage();
            if (eku != null) {
                System.out.println("Extended KU:     " + String.join(", ", eku));
            }
        } catch (Exception e) {
            System.out.println("Extended KU:     Errore parsing (" + e.getMessage() + ")");
        }

        // Subject Alternative Names (SAN)
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                System.out.println("Subject Alternative Names (SAN):");
                for (List<?> san : sans) {
                    int type = (Integer) san.get(0);
                    String typeLabel = switch (type) {
                        case 1 -> "rfc822Name (Email)";
                        case 2 -> "dNSName";
                        case 6 -> "URI";
                        case 7 -> "iPAddress";
                        default -> "Altro (" + type + ")";
                    };
                    System.out.println("  - [" + typeLabel + "]: " + san.get(1));
                }
            }
        } catch (Exception e) {
            System.out.println("SAN:             Errore parsing (" + e.getMessage() + ")");
        }
        System.out.println("=================================================================\n");
    }
}