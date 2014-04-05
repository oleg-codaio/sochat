package com.sochat.client;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;

public class ServerPublicKey {

    private static final String SERVER_PUB_KEY_MODULUS = "f0d8b10045cf1e1a8121f741390019369cd9ed170c2c7f0b47dcc4af1ca8b764e8efc4391c842329eb863e8099607dda3fd9ba70cc27d8b340e6dabe2964952405f164f187d9c6848343de6f193d16c7708355919b4d419400a82bac0f1c6472fe0c0c757a9c5362799a60c0f204b22a9eece9a82e95f827fb077a1dad07101ac03500ca7b0411331dc7b27ef9112eff9a1d75b6ac0ae85d03694c9e09ae8b04eb31a992de9d5e1cce14bb1abd26b0e56da9abb57d7f4acd9efa72c43dcf05c666ee1a739e2e69fdfeaa388282a731c99f248f9e4bba1d926d1c5c3d3bfbbe17bbc2faa2bb39ab60464691a5396582789f3639d3ed9751cad9ad1252d2443f6d";
    private static final String SERVER_PUB_KEY_EXPONENT = "10001";

    public static PublicKey getServerPublicKey() throws GeneralSecurityException {
        BigInteger modulus = new BigInteger(SERVER_PUB_KEY_MODULUS, 16);
        BigInteger exponent = new BigInteger(SERVER_PUB_KEY_EXPONENT, 16);

        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(pubKeySpec);
    }
}
