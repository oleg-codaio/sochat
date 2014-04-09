package com.sochat.server.db;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import com.sochat.shared.CryptoUtils;
import com.sochat.shared.UserInfo;

/**
 * Package-private class that also contains server-pertinent user info. This POJO is used internally in the user
 * database.
 */
class ServerUserInfo extends UserInfo {

    private static final CryptoUtils mCrypto = new CryptoUtils();

    private static final int MAX_N = 1000;

    private String passwordHash;
    private byte[] salt;
    private int n;

    /**
     * Session key - this will be forgotten when the user logs out or server shuts down.
     */
    private SecretKey c1Sym;

    private boolean isAuthenticated = false;

    public static ServerUserInfo create(String username, String password) throws UnsupportedEncodingException,
            GeneralSecurityException {
        ServerUserInfo info = new ServerUserInfo(username);

        // generate salt
        final Random saltr = new SecureRandom();
        byte[] salt = new byte[32];
        saltr.nextBytes(salt);
        info.setSalt(salt);

        // compute hash^1000(P|salt))
        String passwordBase64 = DatatypeConverter.printBase64Binary(password.getBytes("UTF-8"));
        String hash = mCrypto.calculateLamportHash(passwordBase64, salt, MAX_N);
        info.setPasswordHash(hash);

        // and set N to 1000
        info.setN(MAX_N);

        return info;
    }

    private ServerUserInfo(String username) {
        super(username);
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public boolean isConnected() {
        return getAddress() != null;
    }

    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    public void setAuthenticated(boolean authenticated) {
        isAuthenticated = authenticated;
    }

    public SecretKey getC1Sym() {
        return c1Sym;

    }

    public void setC1Sym(SecretKey c1Sym) {
        this.c1Sym = c1Sym;
    }

    public byte[] getSalt() {
        return salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    public int getN() {
        return n;
    }

    public void setN(int n) {
        this.n = n;
    }

}
