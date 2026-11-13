package it.unina.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class PkiBuilder {

    public static final String DEFAULT_P12_PATH = "keystore.p12";
    public static final String SIGNER_ALIAS = "signer_alias";

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public record PkiBundle(
            X509Certificate rootCert,
            X509Certificate intermediateCert,
            X509Certificate signerCert,
            String p12Path
    ) {}

    public static PkiBundle build3TierPki(String p12Path, char[] password) throws Exception {
        System.out.println("\n--- GENERATING 3-TIER PKI (Root -> Intermediate -> Signer) ---");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048, new SecureRandom());

        Instant now = Instant.now();
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider("BC");

        // 1. ROOT CA (Self-Signed)
        KeyPair rootKp = kpg.generateKeyPair();
        X500Name rootDn = new X500Name("CN=Unina Root CA, O=Laboratorio Sicurezza, C=IT");
        X509v3CertificateBuilder rootBuilder = new JcaX509v3CertificateBuilder(
                rootDn,
                BigInteger.valueOf(1),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(3650, ChronoUnit.DAYS)),
                rootDn,
                rootKp.getPublic()
        );
        rootBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        rootBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        rootBuilder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(rootKp.getPublic()));

        ContentSigner rootSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC")
                .build(rootKp.getPrivate());
        X509Certificate rootCert = certConverter.getCertificate(rootBuilder.build(rootSigner));

        // 2. INTERMEDIATE CA (Signed by Root CA, pathLen = 0)
        KeyPair interKp = kpg.generateKeyPair();
        X500Name interDn = new X500Name("CN=Unina Intermediate Issuing CA, O=Laboratorio Sicurezza, C=IT");
        X509v3CertificateBuilder interBuilder = new JcaX509v3CertificateBuilder(
                rootDn,
                BigInteger.valueOf(2),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(1825, ChronoUnit.DAYS)),
                interDn,
                interKp.getPublic()
        );
        interBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        interBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        interBuilder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(interKp.getPublic()));
        interBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(rootCert));

        X509Certificate interCert = certConverter.getCertificate(interBuilder.build(rootSigner));

        // 3. END-ENTITY SIGNER (Signed by Intermediate CA)
        KeyPair signerKp = kpg.generateKeyPair();
        X500Name signerDn = new X500Name("CN=Mario Rossi, SERIALNUMBER=RSSMRA85M01F839K, O=Unina Lab, C=IT");
        X509v3CertificateBuilder signerBuilder = new JcaX509v3CertificateBuilder(
                interDn,
                BigInteger.valueOf(3),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                signerDn,
                signerKp.getPublic()
        );
        signerBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        signerBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment));
        signerBuilder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(signerKp.getPublic()));
        signerBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(interCert));

        // Estensione AIA (Authority Information Access - OCSP / CA Issuers)
        AccessDescription caIssuers = new AccessDescription(
                AccessDescription.id_ad_caIssuers,
                new GeneralName(GeneralName.uniformResourceIdentifier, "http://pki.unina.it/ca/inter.crt")
        );
        signerBuilder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(caIssuers));

        // Estensione CDP (CRL Distribution Points)
        DistributionPointName dpName = new DistributionPointName(
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, "http://pki.unina.it/crl/inter.crl"))
        );
        DistributionPoint dp = new DistributionPoint(dpName, null, null);
        signerBuilder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[]{dp}));

        GeneralNames sans = new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.rfc822Name, "mario.rossi@unina.it"),
                new GeneralName(GeneralName.uniformResourceIdentifier, "https://unina.it/identita/mario.rossi")
        });
        signerBuilder.addExtension(Extension.subjectAlternativeName, false, sans);

        ContentSigner interSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC")
                .build(interKp.getPrivate());
        X509Certificate signerCert = certConverter.getCertificate(signerBuilder.build(interSigner));

        // Verify cryptographic chain
        interCert.verify(rootCert.getPublicKey());
        signerCert.verify(interCert.getPublicKey());
        System.out.println("[OK] 3-Tier Chain verified cryptographically.");

        // 4. Save to PKCS#12 Keystore
        Certificate[] chain = new Certificate[]{signerCert, interCert, rootCert};
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, null);
        ks.setKeyEntry(SIGNER_ALIAS, signerKp.getPrivate(), password, chain);

        try (FileOutputStream fos = new FileOutputStream(p12Path)) {
            ks.store(fos, password);
        }
        System.out.println("[OK] Keystore saved to '" + p12Path + "' (Alias: " + SIGNER_ALIAS + ").");

        return new PkiBundle(rootCert, interCert, signerCert, p12Path);
    }
}