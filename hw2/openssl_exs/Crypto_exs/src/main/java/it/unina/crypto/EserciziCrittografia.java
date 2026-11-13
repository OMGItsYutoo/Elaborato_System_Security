package it.unina.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class EserciziCrittografia {

    public static void run() throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // 1. Symmetric Encryption (AES-256 CBC)
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        keyGen.init(256, new SecureRandom());
        SecretKey aesKey = keyGen.generateKey();

        byte[] plaintext = "Dati top secret da cifrare".getBytes(StandardCharsets.UTF_8);

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = aesCipher.getIV();
        byte[] ciphertext = aesCipher.doFinal(plaintext);

        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        String decrypted = new String(aesCipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        System.out.println("[1] AES-256-CBC Decrypted: " + decrypted);

        // 2. Asymmetric Raw Digital Signature (RSA-2048)
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA", "BC");
        rsaGen.initialize(2048, new SecureRandom());
        KeyPair kp = rsaGen.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withRSA", "BC");
        sig.initSign(kp.getPrivate());
        sig.update(plaintext);
        byte[] signatureBytes = sig.sign();

        sig.initVerify(kp.getPublic());
        sig.update(plaintext);
        System.out.println("[2] Raw RSA-2048 Signature valid: " + sig.verify(signatureBytes));
    }
}