package io.github.tsukasahwan.jwt.security.token;

import io.github.tsukasahwan.jwt.core.JwtToken;
import io.github.tsukasahwan.jwt.core.JwtTokenType;
import io.github.tsukasahwan.jwt.core.token.GenericJwtToken;
import io.github.tsukasahwan.jwt.exception.InvalidTokenException;
import io.github.tsukasahwan.jwt.util.JwtUtils;

/**
 * @author Teamo
 * @since 2025/4/9
 */
public abstract class AbstractRefreshTokenRevokeManager implements RefreshTokenRevokeManager {

    protected final String keyPrefix;

    protected AbstractRefreshTokenRevokeManager(String keyPrefix) {
        this.keyPrefix = keyPrefix;
    }

    protected String buildKey(GenericJwtToken genericJwtToken) {
        return this.keyPrefix + genericJwtToken.getSubject() + ":" + genericJwtToken.getJti();
    }

    protected GenericJwtToken validate(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new InvalidTokenException("Refresh Token cannot be empty");
        }
        JwtToken jwtToken = JwtUtils.parseToken(refreshToken);
        GenericJwtToken genericJwtToken = jwtToken.getGenericJwtToken();
        if (!JwtTokenType.REFRESH_TOKEN.equals(genericJwtToken.getTokenType())) {
            throw new InvalidTokenException("Token must be a refresh token. Actual type: " + genericJwtToken.getTokenType().getValue());
        }
        if (genericJwtToken.getJti() == null || genericJwtToken.getJti().isBlank()) {
            throw new InvalidTokenException("Refresh token must contain jti claim. Token: " + refreshToken);
        }
        return genericJwtToken;
    }

    public String getKeyPrefix() {
        return keyPrefix;
    }
}
