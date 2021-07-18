package com.bibibiu.oauthserver.infrastructure.security.jose;

import lombok.experimental.UtilityClass;

import javax.crypto.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

/**
 * @author arthurmita
 * created 14/07/2021 at 21:35
 **/
@UtilityClass
class KeyGeneratorUtils {

    SecretKey generateSecretKey() {
        SecretKey hmacKey;
        try {
            hmacKey = KeyGenerator.getInstance("HmacSha256").generateKey();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return hmacKey;
    }

    KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    KeyPair generateEcKey() {
        EllipticCurve ellipticCurve = new EllipticCurve(
                new ECFieldFp(new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948")),
                new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291"),
                new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951")
        );
        ECPoint ecPoint = new ECPoint(
                new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109"),
                new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286")
        );
        ECParameterSpec ecParameterSpec = new ECParameterSpec(
                ellipticCurve,
                ecPoint,
                new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
                1
        );

        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(ecParameterSpec);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
}
