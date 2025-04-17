package io.github.tsukasahwan.jwt.security.token;

import io.github.tsukasahwan.jwt.core.JwtToken;
import io.github.tsukasahwan.jwt.core.JwtTokenType;
import io.github.tsukasahwan.jwt.core.token.GenericJwtToken;
import io.github.tsukasahwan.jwt.exception.InvalidTokenException;
import io.github.tsukasahwan.jwt.util.JwtUtils;

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

    protected GenericJwtToken validate(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            throw new InvalidTokenException("Access Token cannot be empty");
        }
        JwtToken jwtToken = JwtUtils.parseToken(accessToken);
        GenericJwtToken genericJwtToken = jwtToken.getGenericJwtToken();
        if (!JwtTokenType.ACCESS_TOKEN.equals(genericJwtToken.getTokenType())) {
            throw new InvalidTokenException("Token must be an access token. Actual type: " + genericJwtToken.getTokenType().getValue());
        }
        if (genericJwtToken.getJti() == null || genericJwtToken.getJti().isBlank()) {
            throw new InvalidTokenException("Access token must contain jti claim. Token: " + accessToken);
        }
        return genericJwtToken;
    }

    public String getKeyPrefix() {
        return keyPrefix;
    }
}
