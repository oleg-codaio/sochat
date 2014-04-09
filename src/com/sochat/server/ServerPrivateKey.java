package com.sochat.server;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.RSAPrivateKeySpec;

public class ServerPrivateKey {

    public static PrivateKey getServerPrivateKey(String privateKeyModulus, String privateKeyExponent)
            throws GeneralSecurityException {
        BigInteger modulus = new BigInteger(privateKeyModulus, 16);
        BigInteger exponent = new BigInteger(privateKeyExponent, 16);

        RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(privKeySpec);
    }
}
