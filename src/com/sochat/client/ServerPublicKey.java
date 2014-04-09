package com.sochat.client;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;

public class ServerPublicKey {

    public static PublicKey getServerPublicKey(String publicKeyModulus, String publicKeyExponent)
            throws GeneralSecurityException {
        BigInteger modulus = new BigInteger(publicKeyModulus, 16);
        BigInteger exponent = new BigInteger(publicKeyExponent, 16);

        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(pubKeySpec);
    }
}
