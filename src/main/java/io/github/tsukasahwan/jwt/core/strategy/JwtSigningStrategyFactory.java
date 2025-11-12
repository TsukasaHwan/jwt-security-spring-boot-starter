package io.github.tsukasahwan.jwt.core.strategy;

import io.github.tsukasahwan.jwt.config.properties.JwtSecurityProperties;
import io.github.tsukasahwan.jwt.core.strategy.impl.HS256SigningStrategy;
import io.github.tsukasahwan.jwt.core.strategy.impl.RS256SigningStrategy;
import org.springframework.util.Assert;

/**
 * @author Teamo
 * @since 2025/11/12
 */
public class JwtSigningStrategyFactory {

    /**
     * 根据算法类型创建对应的签名策略
     *
     * @param secret JWT 密钥配置
     * @return 对应的签名策略
     */
    public static JwtSigningStrategy createStrategy(JwtSecurityProperties.Secret secret) {
        Assert.notNull(secret, "JWT secret configuration must not be null");
        Assert.notNull(secret.getAlgorithm(), "JWT algorithm type must not be null");

        switch (secret.getAlgorithm()) {
            case HS256:
                Assert.hasText(secret.getHmacSecret(), "HMAC secret must not be empty when using HS256 algorithm");
                return new HS256SigningStrategy(secret);
            case RS256:
                Assert.notNull(secret.getPublicKey(), "RSA public key must not be null when using RS256 algorithm");
                Assert.notNull(secret.getPrivateKey(), "RSA private key must not be null when using RS256 algorithm");
                return new RS256SigningStrategy(secret);
            default:
                throw new IllegalArgumentException("Unsupported JWT algorithm type: " + secret.getAlgorithm());
        }
    }
}
