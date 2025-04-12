package io.github.tsukasahwan.jwt.core.token;

import io.github.tsukasahwan.jwt.core.AbstractToken;
import io.github.tsukasahwan.jwt.core.JwtTokenType;
import io.jsonwebtoken.Claims;

import java.util.Map;

/**
 * @author Teamo
 * @since 2025/4/8
 */
public class GenericJwtToken extends AbstractToken {

    protected GenericJwtToken(String id, String subject, Map<String, Object> header, Map<String, Object> claims) {
        super(id, subject, header, claims);
    }

    public static GenericJwtTokenBuilder withTokenType(JwtTokenType tokenType) {
        return new GenericJwtTokenBuilder(tokenType);
    }

    public static class GenericJwtTokenBuilder extends Builder<GenericJwtToken> {

        protected GenericJwtTokenBuilder(JwtTokenType tokenType) {
            super(tokenType);
        }

        @Override
        public GenericJwtToken build() {
            validate();
            String id = this.claims.get(Claims.ID) == null ? null : this.claims.get(Claims.ID).toString();
            String subject = this.claims.get(Claims.SUBJECT).toString();
            return new GenericJwtToken(id, subject, header, claims);
        }
    }
}
