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

    public static byte[] encrypt(byte[] key, byte[] data) throws GeneralSecurityException {
        // Generate a random nonce
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[12];
        secureRandom.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        return cipher.doFinal(data);
    }

    public static String hashPassword(String password) throws NoSuchAlgorithmException {
        // Using SHA-256 instead of MD5
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }

    public static <T> T deserialize(String base64Data, Class<T> type) throws IOException {
        // Using JSON deserialization instead of Java serialization
        try {
            byte[] data = Base64.getDecoder().decode(base64Data);
            String json = new String(data, StandardCharsets.UTF_8);
            return new com.fasterxml.jackson.databind.ObjectMapper()
                .readerFor(type)
                .readValue(json);
        } catch (Exception e) {
            throw new IOException("Failed to deserialize data", e);
        }
    }
}
