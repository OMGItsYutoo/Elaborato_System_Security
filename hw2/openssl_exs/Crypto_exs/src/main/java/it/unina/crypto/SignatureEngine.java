package it.unina.crypto;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.awt.*;
import java.security.cert.X509Certificate;
import java.util.Collections;

public class SignatureEngine {

    private final CommonCertificateVerifier verifier;

    public SignatureEngine(X509Certificate rootCaCert) {
        this.verifier = new CommonCertificateVerifier();
        CommonTrustedCertificateSource trustedSource = new CommonTrustedCertificateSource();
        trustedSource.addCertificate(new CertificateToken(rootCaCert));
        this.verifier.setTrustedCertSources(trustedSource);
        this.verifier.setCheckRevocationForUntrustedChains(false);
    }

    public DSSDocument signCAdES(DSSDocument document, Pkcs12SignatureToken token,
                                 DSSPrivateKeyEntry key, boolean attached) {
        CAdESSignatureParameters params = new CAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        params.setSignaturePackaging(attached ? SignaturePackaging.ENVELOPING : SignaturePackaging.DETACHED);
        params.setDigestAlgorithm(DigestAlgorithm.SHA256);
        params.setSigningCertificate(key.getCertificate());
        params.setCertificateChain(key.getCertificateChain());

        CAdESService service = new CAdESService(verifier);
        ToBeSigned dataToSign = service.getDataToSign(document, params);
        SignatureValue signatureValue = token.sign(dataToSign, params.getDigestAlgorithm(), key);

        return service.signDocument(document, params, signatureValue);
    }

    public DSSDocument signPAdES(DSSDocument pdfDocument, Pkcs12SignatureToken token,
            DSSPrivateKeyEntry key, boolean visibleSignature) {
PAdESSignatureParameters params = new PAdESSignatureParameters();
params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
params.setDigestAlgorithm(DigestAlgorithm.SHA256);
params.setSigningCertificate(key.getCertificate());
params.setCertificateChain(key.getCertificateChain());
params.setReason("Documento firmato digitalmente tramite EU DSS");
params.setLocation("Pozzuoli / Napoli, IT");

if (visibleSignature) {
SignatureImageParameters imageParams = new SignatureImageParameters();
SignatureFieldParameters fieldParams = new SignatureFieldParameters();
fieldParams.setPage(1);
fieldParams.setOriginX(50);
fieldParams.setOriginY(50);
fieldParams.setWidth(220);
fieldParams.setHeight(60);
imageParams.setFieldParameters(fieldParams);

SignatureImageTextParameters textParams = new SignatureImageTextParameters();
textParams.setText("Firmato digitalmente da:\n" + key.getCertificate().getSubject().getPrettyPrintRFC2253());
textParams.setTextColor(Color.DARK_GRAY);
textParams.setBackgroundColor(new Color(240, 244, 248));
imageParams.setTextParameters(textParams);

params.setImageParameters(imageParams);
}

PAdESService service = new PAdESService(verifier);

// 1. Misura i byte reali della busta CMS PAdES
params.setContentSize(16384);
ToBeSigned dummyTbs = service.getDataToSign(pdfDocument, params);
SignatureValue dummySig = token.sign(dummyTbs, params.getDigestAlgorithm(), key);
DSSDocument dummySigned = service.signDocument(pdfDocument, params, dummySig);

try (java.io.InputStream is = dummySigned.openStream();
org.apache.pdfbox.pdmodel.PDDocument pdDoc = org.apache.pdfbox.Loader.loadPDF(is.readAllBytes())) {
byte[] contents = pdDoc.getSignatureDictionaries().get(0).getContents();
// Rimuove gli zeri finali (0x00) di padding per ottenere la lunghezza ASN.1 esatta
int realLength = contents.length;
while (realLength > 0 && contents[realLength - 1] == 0) {
realLength--;
}
params.setContentSize(realLength);
} catch (java.io.IOException e) {
throw new RuntimeException("Errore calcolo dimensione PAdES", e);
}

// 2. Firma definitiva con contentSize esatto al byte (zero byte di padding)
ToBeSigned dataToSign = service.getDataToSign(pdfDocument, params);
SignatureValue signatureValue = token.sign(dataToSign, params.getDigestAlgorithm(), key);

return service.signDocument(pdfDocument, params, signatureValue);
}

    public void verifyDocument(DSSDocument signedDoc, DSSDocument detachedOriginalContent) throws Exception {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDoc);
        validator.setCertificateVerifier(verifier);

        if (detachedOriginalContent != null) {
            validator.setDetachedContents(Collections.singletonList(detachedOriginalContent));
        }

        // Adatta la policy di validazione per laboratori offline (senza server CRL/OCSP)
        EtsiValidationPolicy policy = (EtsiValidationPolicy) ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        LevelConstraint warnOnly = new LevelConstraint();
        warnOnly.setLevel(Level.WARN);
        if (policy.getSignatureConstraints() != null && policy.getSignatureConstraints().getBasicSignatureConstraints() != null) {
            var signingCert = policy.getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate();
            if (signingCert != null) {
                signingCert.setRevocationDataAvailable(warnOnly);
            }
            var caCert = policy.getSignatureConstraints().getBasicSignatureConstraints().getCACertificate();
            if (caCert != null) {
                caCert.setRevocationDataAvailable(warnOnly);
            }
        }

        Reports reports = validator.validateDocument(policy);
        SimpleReport simpleReport = reports.getSimpleReport();

        System.out.println("--- REPORT DI VALIDAZIONE EU DSS ---");
        System.out.println("Documento:      " + signedDoc.getName());
        System.out.println("Firme trovate:  " + simpleReport.getSignaturesCount());

        for (String sigId : simpleReport.getSignatureIdList()) {
            System.out.println("  * ID Firma:       " + sigId);
            System.out.println("  * Formato:        " + simpleReport.getSignatureFormat(sigId));
            System.out.println("  * Firmatario:     " + simpleReport.getSignedBy(sigId));
            System.out.println("  * Data Firma:     " + simpleReport.getBestSignatureTime(sigId));
            System.out.println("  * Esito (Indic.): " + simpleReport.getIndication(sigId));
            if (simpleReport.getSubIndication(sigId) != null) {
                System.out.println("  * SubIndication:  " + simpleReport.getSubIndication(sigId));
            }

            // Stampa leggibile degli errori e dei warning (getKey + getValue)
            simpleReport.getAdESValidationErrors(sigId).forEach(msg ->
                    System.out.println("  * [ERRORE]        " + msg.getKey() + " -> " + msg.getValue()));
            simpleReport.getAdESValidationWarnings(sigId).forEach(msg ->
                    System.out.println("  * [WARNING]       " + msg.getKey() + " -> " + msg.getValue()));
        }
        System.out.println("------------------------------------\n");
    }
}