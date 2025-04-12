package com.github.TsukasaHwan.jwt.core.token;

import com.github.TsukasaHwan.jwt.core.AbstractToken;
import com.github.TsukasaHwan.jwt.core.JwtTokenType;
import com.github.TsukasaHwan.jwt.util.IdUtils;
import io.jsonwebtoken.Claims;

import java.util.Map;

/**
 * @author Teamo
 * @since 2025/4/8
 */
public class RefreshToken extends AbstractToken {

    protected RefreshToken(String id, String subject, Map<String, Object> header, Map<String, Object> claims) {
        super(id, subject, header, claims);
    }

    public static RefreshTokenBuilder builder() {
        return new RefreshTokenBuilder();
    }

    public static class RefreshTokenBuilder extends Builder<RefreshToken> {

        RefreshTokenBuilder() {
            super(JwtTokenType.REFRESH_TOKEN);
            super.id(IdUtils.simpleUUID());
        }

        @Override
        public RefreshToken build() {
            validate();
            String id = this.claims.get(Claims.ID) == null ? null : this.claims.get(Claims.ID).toString();
            String subject = this.claims.get(Claims.SUBJECT).toString();
            return new RefreshToken(id, subject, header, claims);
        }
    }
}
