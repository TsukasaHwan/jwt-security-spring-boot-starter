package com.github.TsukasaHwan.jwt.security.token;

import com.github.TsukasaHwan.jwt.core.JwtToken;
import com.github.TsukasaHwan.jwt.core.JwtTokenType;
import com.github.TsukasaHwan.jwt.exception.InvalidTokenException;
import com.github.TsukasaHwan.jwt.security.token.RefreshTokenRevokeManager;
import com.github.TsukasaHwan.jwt.util.JwtUtils;
import io.jsonwebtoken.Claims;

/**
 * @author Teamo
 * @since 2025/4/9
 */
public abstract class AbstractRefreshTokenRevokeManager implements RefreshTokenRevokeManager {

    protected final String keyPrefix;

    protected AbstractRefreshTokenRevokeManager(String keyPrefix) {
        this.keyPrefix = keyPrefix;
    }

    protected String buildKey(Claims payload) {
        return this.keyPrefix + payload.getSubject() + ":" + payload.getId();
    }

    protected Claims validate(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new InvalidTokenException("Refresh Token cannot be empty");
        }
        JwtToken jwtToken = JwtUtils.parseToken(refreshToken);
        if (!JwtTokenType.REFRESH_TOKEN.equals(jwtToken.getTokenType())) {
            throw new InvalidTokenException("Token must be a refresh token. Actual type: " + jwtToken.getTokenType().getValue());
        }
        Claims payload = jwtToken.getJws().getPayload();
        if (payload.getId() == null || payload.getId().isBlank()) {
            throw new InvalidTokenException("Refresh token must contain jti claim. Token: " + refreshToken);
        }
        return payload;
    }

    public String getKeyPrefix() {
        return keyPrefix;
    }
}
