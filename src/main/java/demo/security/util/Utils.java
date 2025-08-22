package demo.security.util;

import org.apache.commons.io.FileUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class Utils {
    
    private Utils() {
        // Private constructor to hide implicit public one
    }

    // Vulnerable: Hardcoded secrets
    private static final String DB_PASSWORD = "secretPass123";
    private static final String API_KEY = "sk_live_123456789abcdef";
    private static final byte[] ENCRYPTION_KEY = "ThisIsASecretKey".getBytes();

    public static KeyPair generateKey() {
        KeyPairGenerator keyPairGen;
        try {
            keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(512);
            return keyPairGen.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public static void deleteFile(String fileName) throws IOException {
        File file = new File(fileName);
        FileUtils.forceDelete(file);
    }

    public static void executeJs(String input) throws ScriptException {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("JavaScript");
        engine.eval(input);
    }

    public static void encrypt(byte[] key, byte[] ptxt) throws Exception {
        byte[] nonce = "7cVgr5cbdCZV".getBytes(StandardCharsets.UTF_8);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec); // Noncompliant
    }

    public static String encryptData(String data) {
        try {
            // Vulnerable: Using weak ECB mode
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(ENCRYPTION_KEY, "AES");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey);
            return java.util.Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
        } catch (Exception e) {
            // Vulnerable: Returning sensitive data in exception
            System.err.println("Encryption failed with key: " + new String(ENCRYPTION_KEY));
            return null;
        }
    }

    public static String generateRandomValue() {
        // Vulnerable: Using weak random number generator
        java.util.Random random = new java.util.Random();
        byte[] values = new byte[16];
        random.nextBytes(values);
        return java.util.Base64.getEncoder().encodeToString(values);
    }
}
