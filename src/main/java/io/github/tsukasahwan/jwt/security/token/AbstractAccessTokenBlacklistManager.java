package io.github.tsukasahwan.jwt.security.token;

import io.github.tsukasahwan.jwt.core.JwtToken;
import io.github.tsukasahwan.jwt.core.JwtTokenType;
import io.github.tsukasahwan.jwt.exception.InvalidTokenException;
import io.github.tsukasahwan.jwt.util.JwtUtils;
import io.jsonwebtoken.Claims;

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

    protected Claims validate(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            throw new InvalidTokenException("Access Token cannot be empty");
        }
        JwtToken jwtToken = JwtUtils.parseToken(accessToken);
        if (!JwtTokenType.ACCESS_TOKEN.equals(jwtToken.getTokenType())) {
            throw new InvalidTokenException("Token must be an access token. Actual type: " + jwtToken.getTokenType().getValue());
        }
        Claims payload = jwtToken.getJws().getPayload();
        if (payload.getId() == null || payload.getId().isBlank()) {
            throw new InvalidTokenException("Access token must contain jti claim. Token: " + accessToken);
        }
        return payload;
    }

    public String getKeyPrefix() {
        return keyPrefix;
    }
}
