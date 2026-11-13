package it.unina.crypto;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class DssSignatureLab {

    public static void run(char[] keystorePassword) throws Exception {
        File ksFile = new File(PkiBuilder.DEFAULT_P12_PATH);
        if (!ksFile.exists()) {
            System.out.println("[INFO] Keystore not found. Invoking PkiBuilder first...");
            PkiBuilder.build3TierPki(PkiBuilder.DEFAULT_P12_PATH, keystorePassword);
        }

        // 1. Load 3-tier chain from PKCS#12
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(ksFile)) {
            ks.load(fis, keystorePassword);
        }

        Certificate[] chain = ks.getCertificateChain(PkiBuilder.SIGNER_ALIAS);
        X509Certificate signerCert = (X509Certificate) chain[0];
        X509Certificate interCert  = (X509Certificate) chain[1];
        X509Certificate rootCert   = (X509Certificate) chain[2];

        System.out.println("\n--- INSPECTING SIGNER CERTIFICATE (Leaf) ---");
        CertInspector.printCertificateDetails(signerCert);

        System.out.println("--- INSPECTING INTERMEDIATE CA CERTIFICATE ---");
        CertInspector.printCertificateDetails(interCert);

        // 2. Sign and validate using EU DSS
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                PkiBuilder.DEFAULT_P12_PATH,
                new PasswordProtection(keystorePassword))) {

            DSSPrivateKeyEntry signingKey = token.getKeys().get(0);
            SignatureEngine engine = new SignatureEngine(rootCert);

            // CAdES Attached (.p7m)
            byte[] rawData = "Contratto riservato: importo 15.000 EUR.".getBytes(StandardCharsets.UTF_8);
            DSSDocument originalDoc = new InMemoryDocument(rawData, "contratto.txt");

            DSSDocument cadesAttached = engine.signCAdES(originalDoc, token, signingKey, true);
            cadesAttached.save("contratto.txt.p7m");
            engine.verifyDocument(new FileDocument("contratto.txt.p7m"), null);

            // CAdES Detached (.p7s)
            DSSDocument cadesDetached = engine.signCAdES(originalDoc, token, signingKey, false);
            cadesDetached.save("contratto.txt.p7s");
            engine.verifyDocument(new FileDocument("contratto.txt.p7s"), originalDoc);

            // PAdES Visible (.pdf)
            byte[] pdfBytes = createSamplePdf("Documento Ufficiale Firmato con Catena a 3 Livelli");
            DSSDocument pdfDoc = new InMemoryDocument(pdfBytes, "documento.pdf");

            DSSDocument padesSigned = engine.signPAdES(pdfDoc, token, signingKey, true);
            padesSigned.save("documento_firmato.pdf");
            engine.verifyDocument(new FileDocument("documento_firmato.pdf"), null);

            // Tampering check
            System.out.println(">>> Simulating tampering on CAdES Detached...");
            byte[] tamperedData = "Contratto riservato: importo 99.000 EUR.".getBytes(StandardCharsets.UTF_8);
            DSSDocument tamperedDoc = new InMemoryDocument(tamperedData, "contratto.txt");
            engine.verifyDocument(new FileDocument("contratto.txt.p7s"), tamperedDoc);
        }
    }

    private static byte[] createSamplePdf(String text) throws Exception {
        try (PDDocument doc = new PDDocument(); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            PDPage page = new PDPage();
            doc.addPage(page);
            try (PDPageContentStream cs = new PDPageContentStream(doc, page)) {
                cs.beginText();
                cs.setFont(PDType1Font.HELVETICA_BOLD, 14);
                cs.newLineAtOffset(50, 700);
                cs.showText(text);
                cs.endText();
            }
            doc.save(baos);
            return baos.toByteArray();
        }
    }
}