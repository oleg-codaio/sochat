package com.sochat.onetime;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * Stand-alone application that can be used to generate an RSA public/private key pair.
 * 
 * @author Oleg
 */
public class ServerAsymmetricKeyGenerator {

    public static void main(String args[]) throws GeneralSecurityException {
        // generate RSA public key and private key to be hard-coded into client
        // and server, respectively
        System.out.println("=== Public/Private Key Pair Generator ===");

        // generate key pair
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        KeyFactory factory = KeyFactory.getInstance("RSA");
        gen.initialize(2048);
        KeyPair pair = gen.generateKeyPair();

        // get public keys
        PublicKey pub = pair.getPublic();
        PrivateKey priv = pair.getPrivate();

        // get the key specs
        RSAPublicKeySpec pubSpec = factory.getKeySpec(pub, RSAPublicKeySpec.class);
        RSAPrivateKeySpec privSpec = factory.getKeySpec(priv, RSAPrivateKeySpec.class);

        // now we know the exponent and modulus! Print out as hex
        System.out.println(" --- Public Key ---");
        System.out.println("Exponent: " + pubSpec.getPublicExponent().toString(16));
        System.out.println("Modulus: " + pubSpec.getModulus().toString(16));

        System.out.println(" --- Private Key ---");
        System.out.println("Exponent: " + privSpec.getPrivateExponent().toString(16));
        System.out.println("Modulus: " + privSpec.getModulus().toString(16));

    }

}
