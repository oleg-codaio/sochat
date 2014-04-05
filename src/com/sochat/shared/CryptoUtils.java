package com.sochat.shared;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class CryptoUtils {

    public SecretKey generateSecretKey() {
        KeyGenerator keygen;

        try {
            // use 128 bits here, as Java might have problems with 256
            keygen = KeyGenerator.getInstance("AES");
            keygen.init(128);
            SecretKey aesKey = keygen.generateKey();
            return aesKey;
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    public BigInteger generateRandom() {
        return new BigInteger(64, new SecureRandom());
    }

    public byte[] encryptData(String data, PublicKey publicKey) throws IOException {
        byte[] dataToEncrypt = data.getBytes("UTF-8");
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptedData = cipher.doFinal(dataToEncrypt);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedData;
    }

    public String decryptData(byte[] data, PrivateKey privateKey) throws IOException {
        byte[] decryptedData = null;

        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decryptedData = cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new String(decryptedData, "UTF-8");
    }

    public byte[] encryptWithSharedKey(SecretKey key, String message) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

        // get an AES cipher (with default Cipher Block Chaining for good
        // security) with the standard PKCS-defined padding
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, key);

        // and encrypt the contents
        return aesCipher.doFinal(message.getBytes());
    }

    public String decryptWithSharedKey(SecretKey key, byte[] data) throws IllegalBlockSizeException,
            BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, key);
        return new String(aesCipher.doFinal(data));
    }

}
