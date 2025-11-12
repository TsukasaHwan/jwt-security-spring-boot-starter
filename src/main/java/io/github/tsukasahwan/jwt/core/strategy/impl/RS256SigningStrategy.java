package io.github.tsukasahwan.jwt.core.strategy.impl;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import io.github.tsukasahwan.jwt.config.properties.JwtSecurityProperties;
import io.github.tsukasahwan.jwt.core.strategy.JwtSigningStrategy;
import org.springframework.util.Assert;

/**
 * @author Teamo
 * @since 2025/11/12
 */
public class RS256SigningStrategy implements JwtSigningStrategy {

    private final JwtSecurityProperties.Secret secret;

    public RS256SigningStrategy(JwtSecurityProperties.Secret secret) {
        this.secret = secret;
    }

    @Override
    public JWSHeader createJWSHeader() {
        return new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .build();
    }

    @Override
    public JWSSigner createSigner() {
        Assert.notNull(secret.getPrivateKey(), "RSA private key must not be null");
        return new RSASSASigner(secret.getPrivateKey());
    }

    @Override
    public JWSVerifier createVerifier() {
        Assert.notNull(secret.getPublicKey(), "RSA public key must not be null");
        return new RSASSAVerifier(secret.getPublicKey());
    }
}
