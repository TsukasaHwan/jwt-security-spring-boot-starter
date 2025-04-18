package io.github.tsukasahwan.jwt.security.token;

import io.github.tsukasahwan.jwt.core.JwtGrantType;
import io.github.tsukasahwan.jwt.core.JwtToken;
import io.github.tsukasahwan.jwt.exception.InvalidTokenException;

/**
 * @author Teamo
 * @since 2025/4/10
 */
public abstract class AbstractAccessTokenBlacklistManager implements AccessTokenBlacklistManager {

    protected final String keyPrefix;

    protected AbstractAccessTokenBlacklistManager(String keyPrefix) {
        this.keyPrefix = keyPrefix;
    }

    protected String buildKey(String jti) {
        return this.keyPrefix + jti;
    }

    protected void validate(JwtToken jwtToken) {
        if (jwtToken == null || jwtToken.getTokenValue().isBlank()) {
            throw new InvalidTokenException("Access Token cannot be empty");
        }
        if (jwtToken.getSubject() == null || jwtToken.getSubject().isBlank()) {
            throw new InvalidTokenException("Access token must contain subject claim. Token: " + jwtToken.getTokenValue());
        }
        if (!JwtGrantType.ACCESS_TOKEN.equals(jwtToken.getGrantType())) {
            throw new InvalidTokenException("Token must be an access token. Actual type: " + jwtToken.getGrantType().getValue());
        }
        if (jwtToken.getId() == null || jwtToken.getId().isBlank()) {
            throw new InvalidTokenException("Access token must contain jti claim. Token: " + jwtToken.getTokenValue());
        }
    }

    public String getKeyPrefix() {
        return keyPrefix;
    }
}
