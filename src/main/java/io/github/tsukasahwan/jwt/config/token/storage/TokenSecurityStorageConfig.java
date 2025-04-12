package io.github.tsukasahwan.jwt.config.token.storage;

import io.github.tsukasahwan.jwt.config.properties.JwtSecurityProperties;
import org.springframework.util.Assert;

/**
 * @author Teamo
 * @since 2025/4/11
 */
public abstract class TokenSecurityStorageConfig {

    protected final JwtSecurityProperties jwtSecurityProperties;

    protected TokenSecurityStorageConfig(JwtSecurityProperties jwtSecurityProperties) {
        this.jwtSecurityProperties = jwtSecurityProperties;
    }

    protected String getRevokeKeyPrefix() {
        String keyPrefix = this.jwtSecurityProperties.getTokenSecurity().getRefreshTokenRevoke().getKeyPrefix();
        Assert.notNull(keyPrefix, "'jwt.security.token-security.refresh-token-revoke.key-prefix' cannot be null");
        return keyPrefix;
    }

    protected String getBlacklistKeyPrefix() {
        String keyPrefix = this.jwtSecurityProperties.getTokenSecurity().getAccessTokenBlacklist().getKeyPrefix();
        Assert.notNull(keyPrefix, "'jwt.security.token-security.access-token-blacklist.key-prefix' cannot be null");
        return keyPrefix;
    }
}
