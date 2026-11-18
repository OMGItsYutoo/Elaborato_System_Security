package it.unina.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class EserciziCrittografia {

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public static void run() throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        
        byte[] plaintext = "Dati top secret da cifrare".getBytes(StandardCharsets.UTF_8);
        
        // 1. Symmetric Encryption
        // 1.1. 3DES (Triple DES) 
        KeyGenerator deskeyGen = KeyGenerator.getInstance("DESede", "BC");
        deskeyGen.init(168, new SecureRandom());
        SecretKey desKey = deskeyGen.generateKey();

        Cipher desCipher = Cipher.getInstance("DESede/CBC/PKCS5Padding", "BC");
        desCipher.init(Cipher.ENCRYPT_MODE, desKey);
        byte[] desCiphertext = desCipher.doFinal(plaintext);

        desCipher.init(Cipher.DECRYPT_MODE, desKey, new IvParameterSpec(desCipher.getIV()));
        String desDecrypted = new String(desCipher.doFinal(desCiphertext), StandardCharsets.UTF_8);
        System.out.println("[1] 3DES Encrypted: " + bytesToHex(desCiphertext));
        System.out.println("[1] 3DES Decrypted: " + desDecrypted);

        // 1.2. AES-256 CBC
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        keyGen.init(256, new SecureRandom());
        SecretKey aesKey = keyGen.generateKey();

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = aesCipher.getIV();
        byte[] ciphertext = aesCipher.doFinal(plaintext);

        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        String decrypted = new String(aesCipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        System.out.println("[2] AES-256-CBC Encrypted: " + bytesToHex(ciphertext));
        System.out.println("[2] AES-256-CBC Decrypted: " + decrypted);

        // 1.3. Cammelia-256 CBC
        KeyGenerator camelliaGen = KeyGenerator.getInstance("Camellia", "BC");
        camelliaGen.init(256, new SecureRandom());
        SecretKey camelliaKey = camelliaGen.generateKey();

        Cipher camelliaCipher = Cipher.getInstance("Camellia/CBC/PKCS5Padding", "BC");
        camelliaCipher.init(Cipher.ENCRYPT_MODE, camelliaKey);
        byte[] camelliaIv = camelliaCipher.getIV();
        byte[] camelliaCiphertext = camelliaCipher.doFinal(plaintext);

        camelliaCipher.init(Cipher.DECRYPT_MODE, camelliaKey, new IvParameterSpec(camelliaIv));
        String camelliaDecrypted = new String(camelliaCipher.doFinal(camelliaCiphertext), StandardCharsets.UTF_8);
        System.out.println("[3] Camellia-256-CBC Encrypted: " + bytesToHex(camelliaCiphertext));
        System.out.println("[3] Camellia-256-CBC Decrypted: " + camelliaDecrypted);

        // 2. Asymmetric Raw Digital Signature (RSA-2048)
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA", "BC");
        rsaGen.initialize(2048, new SecureRandom());
        KeyPair kp = rsaGen.generateKeyPair();

        // 2.1. Raw RSA-2048 Encryption/Decryption
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        rsaCipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] rsaCiphertext = rsaCipher.doFinal(plaintext);
        rsaCipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        String rsaDecrypted = new String(rsaCipher.doFinal(rsaCiphertext), StandardCharsets.UTF_8);
        System.out.println("[4] Raw RSA-2048 Encrypted: " + bytesToHex(rsaCiphertext));
        System.out.println("[4] Raw RSA-2048 Decrypted: " + rsaDecrypted);

        // 2.2. Raw RSA-2048 Signature
        Signature sig = Signature.getInstance("SHA256withRSA", "BC");
        sig.initSign(kp.getPrivate());
        sig.update(plaintext);
        byte[] signatureBytes = sig.sign();
        System.out.println("[4] Raw RSA-2048 Signature: " + bytesToHex(signatureBytes));
        System.out.println("[4] Raw RSA-2048 Signature Length: " + signatureBytes.length + " bytes");   

        sig.initVerify(kp.getPublic());
        sig.update(plaintext);
        System.out.println("[4] Raw RSA-2048 Signature valid: " + sig.verify(signatureBytes));
    }
}