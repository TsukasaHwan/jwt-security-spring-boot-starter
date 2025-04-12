package io.github.tsukasahwan.jwt.core.token;

import io.github.tsukasahwan.jwt.core.AbstractToken;
import io.github.tsukasahwan.jwt.core.JwtTokenType;
import io.github.tsukasahwan.jwt.util.IdUtils;
import io.jsonwebtoken.Claims;

import java.util.Map;

/**
 * @author Teamo
 * @since 2025/4/8
 */
public class AccessToken extends AbstractToken {

    protected AccessToken(String id, String subject, Map<String, Object> header, Map<String, Object> claims) {
        super(id, subject, header, claims);
    }

    public static AccessTokenBuilder builder() {
        return new AccessTokenBuilder();
    }

    public static class AccessTokenBuilder extends Builder<AccessToken> {

        AccessTokenBuilder() {
            super(JwtTokenType.ACCESS_TOKEN);
            super.id(IdUtils.simpleUUID());
        }

        @Override
        public AccessToken build() {
            validate();
            String id = this.claims.get(Claims.ID) == null ? null : this.claims.get(Claims.ID).toString();
            String subject = this.claims.get(Claims.SUBJECT).toString();
            return new AccessToken(id, subject, this.header, this.claims);
        }
    }

}
