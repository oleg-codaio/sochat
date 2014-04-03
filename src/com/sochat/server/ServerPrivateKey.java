package com.sochat.server;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.RSAPrivateKeySpec;

public class ServerPrivateKey {

    private static final String SERVER_PRIV_KEY_MODULUS = "abce913f9c8dab1723d22bfc6cc2aae7b7e97df34ef6b8545ebbb74c3fd8f80748e3dac80566e6ee22ed5614dc6b73b4ccbb937fae3a35474f931be914701cdc411da1949f20c115ecce0ff87325d994c7c892e52c3d1b70aea4bea52b37c06ef5a6a14d77899852fc2b38649969a2be74d604157138cf5708a1a1784f106145";
    private static final String SERVER_PRIV_KEY_EXPONENT = "52747017446e656754a4c0c183fd2582d22c386b764148940d6730006340214175c50d32240d8fd54863f9854788365ed6474bf1e24f4354b727162515cefcba1b2466c3d2d696c120da1a2a67f9825a7905f66329053af86155e58dcda434dbe0deef45cdae6cbf4b4e6c10d41ad5e8f0a8308b390815c1cb11be60a03af521";

    public static PrivateKey getServerPrivateKey() throws GeneralSecurityException {
        BigInteger modulus = new BigInteger(SERVER_PRIV_KEY_MODULUS, 16);
        BigInteger exponent = new BigInteger(SERVER_PRIV_KEY_EXPONENT, 16);

        RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(privKeySpec);
    }
}
