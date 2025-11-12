package io.github.tsukasahwan.jwt.core.strategy.impl;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import io.github.tsukasahwan.jwt.config.properties.JwtSecurityProperties;
import io.github.tsukasahwan.jwt.core.strategy.JwtSigningStrategy;
import org.springframework.util.Assert;

import java.nio.charset.StandardCharsets;

/**
 * @author Teamo
 * @since 2025/11/12
 */
public class HS256SigningStrategy implements JwtSigningStrategy {

    private final JwtSecurityProperties.Secret secret;

    public HS256SigningStrategy(JwtSecurityProperties.Secret secret) {
        this.secret = secret;
    }

    @Override
    public JWSHeader createJWSHeader() {
        return new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT)
                .build();
    }

    @Override
    public JWSSigner createSigner() {
        Assert.hasText(secret.getHmacSecret(), "HMAC secret must not be empty");
        byte[] secretKey = secret.getHmacSecret().getBytes(StandardCharsets.UTF_8);
        try {
            return new MACSigner(secretKey);
        } catch (JOSEException e) {
            throw new IllegalArgumentException("Failed to create HMAC signer", e);
        }
    }

    @Override
    public JWSVerifier createVerifier() {
        Assert.hasText(secret.getHmacSecret(), "HMAC secret must not be empty");
        byte[] secretKey = secret.getHmacSecret().getBytes(StandardCharsets.UTF_8);
        try {
            return new MACVerifier(secretKey);
        } catch (JOSEException e) {
            throw new IllegalArgumentException("Failed to create HMAC verifier", e);
        }
    }
}
