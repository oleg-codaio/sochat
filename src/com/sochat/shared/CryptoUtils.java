package com.sochat.shared;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
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
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;

public class CryptoUtils {

    // TODO: send IV over the network for each message for most security
    // see http://stackoverflow.com/a/4626404/832776
    private static final byte[] IV = { (byte) 184, (byte) 215, (byte) 138, (byte) 65, (byte) 172, (byte) 211, (byte) 248, (byte) 245, (byte) 135,
            (byte) 151, (byte) 132, (byte) 250, (byte) 0, (byte) 61, (byte) 1, (byte) 20 };

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

    public byte[] encryptData(String data, PublicKey publicKey) throws IOException, IllegalBlockSizeException, BadPaddingException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        byte[] dataToEncrypt = data.getBytes("UTF-8");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encryptedData = cipher.doFinal(dataToEncrypt);
        return encryptedData;
    }

    public String decryptData(byte[] data, PrivateKey privateKey) throws IOException, IllegalBlockSizeException, BadPaddingException,
            InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedData = cipher.doFinal(data);

        return new String(decryptedData, "UTF-8");
    }

    public byte[] encryptWithSharedKey(SecretKey key, String message) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        // get an AES cipher (with default Cipher Block Chaining for good
        // security) with the standard PKCS-defined padding
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));

        // and encrypt the contents
        return aesCipher.doFinal(message.getBytes());
    }

    public String decryptWithSharedKey(SecretKey key, byte[] data) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));

        // decrypt the data
        return new String(aesCipher.doFinal(data));
    }

    /**
     * Calculates the Lamport hash: hash^n(password|salt)
     * 
     * @param password
     * @param salt
     * @param n
     * @return
     * @throws UnsupportedEncodingException
     * @throws GeneralSecurityException
     */
    public String calculateLamportHash(String passwordBase64, byte[] salt, int n) throws UnsupportedEncodingException, GeneralSecurityException {
        if (n <= 0)
            throw new GeneralSecurityException("N too low.");

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

        byte[] p = DatatypeConverter.parseBase64Binary(passwordBase64);
        for (int i = n; i > 0; i--) {
            messageDigest.update(p);
            messageDigest.update(salt);
            p = messageDigest.digest();
            messageDigest.reset();
        }

        return DatatypeConverter.printBase64Binary(p);
    }

}
