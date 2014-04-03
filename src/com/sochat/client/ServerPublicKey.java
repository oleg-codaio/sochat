package com.sochat.client;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;

public class ServerPublicKey {

    private static final String SERVER_PUB_KEY_MODULUS = "abce913f9c8dab1723d22bfc6cc2aae7b7e97df34ef6b8545ebbb74c3fd8f80748e3dac80566e6ee22ed5614dc6b73b4ccbb937fae3a35474f931be914701cdc411da1949f20c115ecce0ff87325d994c7c892e52c3d1b70aea4bea52b37c06ef5a6a14d77899852fc2b38649969a2be74d604157138cf5708a1a1784f106145";
    private static final String SERVER_PUB_KEY_EXPONENT = "10001";

    public static PublicKey getServerPublicKey() throws GeneralSecurityException {
        BigInteger modulus = new BigInteger(SERVER_PUB_KEY_MODULUS, 16);
        BigInteger exponent = new BigInteger(SERVER_PUB_KEY_EXPONENT, 16);

        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(pubKeySpec);
    }
}
