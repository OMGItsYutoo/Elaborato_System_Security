import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class EserciziCrittografia {

    public static void main(String[] args) throws Exception {
        // Registrazione del provider Bouncy Castle
        Security.addProvider(new BouncyCastleProvider());

        // 1. CRITTOGRAFIA SIMMETRICA (AES-256 in modalità CBC)
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        byte[] messaggioOriginale = "Dati top secret da cifrare".getBytes(StandardCharsets.UTF_8);

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = aesCipher.getIV(); // Recupera l'IV generato casualmente
        byte[] testoCifrato = aesCipher.doFinal(messaggioOriginale);

        // Decifratura di verifica
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        String testoDecifrato = new String(aesCipher.doFinal(testoCifrato), StandardCharsets.UTF_8);
        System.out.println("[1] AES Decifrato: " + testoDecifrato);

        // 2. CHIAVI ASIMMETRICHE E FIRMA DIGITALE (RSA-2048)
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);

        KeyPair caKeyPair = rsaGen.generateKeyPair();     // Chiavi della Root CA
        KeyPair serverKeyPair = rsaGen.generateKeyPair(); // Chiavi del Server

        // Firma di un documento
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initSign(serverKeyPair.getPrivate());
        firma.update(messaggioOriginale);
        byte[] bytesFirma = firma.sign();

        // Verifica della firma
        firma.initVerify(serverKeyPair.getPublic());
        firma.update(messaggioOriginale);
        System.out.println("[2] Firma RSA valida: " + firma.verify(bytesFirma));

        // 3. GENERAZIONE CERTIFICATI X.509 v3 E CATENA (Root CA -> Server)
        long adesso = System.currentTimeMillis();
        Date validoDa = new Date(adesso);
        Date validoFinoA = new Date(adesso + (365L * 24 * 60 * 60 * 1000)); // +1 anno

        // Creazione certificato Root CA (Self-Signed)
        X500Name nomeCA = new X500Name("CN=MiaRootCA, O=Laboratorio, C=IT");
        X509v3CertificateBuilder caBuilder = new JcaX509v3CertificateBuilder(
                nomeCA,
                BigInteger.valueOf(1),
                validoDa,
                validoFinoA,
                nomeCA,
                caKeyPair.getPublic()
        );
        // Estensioni X.509 v3
        caBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        caBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner caSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(caKeyPair.getPrivate());
        X509Certificate rootCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(caBuilder.build(caSigner));

        // Creazione certificato Server (Firmato dalla Root CA)
        X500Name nomeServer = new X500Name("CN=localhost, O=Laboratorio, C=IT");
        X509v3CertificateBuilder serverBuilder = new JcaX509v3CertificateBuilder(
                nomeCA, // Emesso dalla CA
                BigInteger.valueOf(2),
                validoDa,
                validoFinoA,
                nomeServer,
                serverKeyPair.getPublic()
        );
        // Estensioni X.509 v3: certificato finale (non CA) per firma digitale e cifratura chiavi
        serverBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        serverBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        // Firmato con la chiave privata della CA
        X509Certificate serverCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(serverBuilder.build(caSigner));

        // Verifica crittografica della catena (il cert Server è stato davvero firmato dalla CA?)
        serverCert.verify(rootCert.getPublicKey());
        System.out.println("[3] Catena X.509 v3 generata e verificata con successo!");

        // 4. SALVATAGGIO IN KEYSTORE PKCS#12 (.p12)
        X509Certificate[] catena = new X509Certificate[]{serverCert, rootCert};
        char[] password = "changeit".toCharArray();

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("server_alias", serverKeyPair.getPrivate(), password, catena);

        try (FileOutputStream fos = new FileOutputStream("keystore.p12")) {
            keyStore.store(fos, password);
        }
        System.out.println("[4] File 'keystore.p12' salvato su disco.");
    }
}