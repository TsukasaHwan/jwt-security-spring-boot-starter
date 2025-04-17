package io.github.tsukasahwan.jwt.security.token;

import io.github.tsukasahwan.jwt.core.JwtGrantType;
import io.github.tsukasahwan.jwt.core.JwtToken;
import io.github.tsukasahwan.jwt.exception.InvalidTokenException;

/**
 * @author Teamo
 * @since 2025/4/9
 */
public abstract class AbstractRefreshTokenRevokeManager implements RefreshTokenRevokeManager {

    protected final String keyPrefix;

    protected AbstractRefreshTokenRevokeManager(String keyPrefix) {
        this.keyPrefix = keyPrefix;
    }

    protected String buildKey(JwtToken jwtToken) {
        return this.keyPrefix + jwtToken.getSubject() + ":" + jwtToken.getId();
    }

    protected void validate(JwtToken jwtToken) {
        if (jwtToken == null || jwtToken.getTokenValue().isBlank()) {
            throw new InvalidTokenException("Refresh Token cannot be empty");
        }
        if (!JwtGrantType.REFRESH_TOKEN.equals(jwtToken.getGrantType())) {
            throw new InvalidTokenException("Token must be a refresh token. Actual type: " + jwtToken.getGrantType().getValue());
        }
        if (jwtToken.getId() == null || jwtToken.getId().isBlank()) {
            throw new InvalidTokenException("Refresh token must contain jti claim. Token: " + jwtToken.getTokenValue());
        }
    }

    public String getKeyPrefix() {
        return keyPrefix;
    }
}
