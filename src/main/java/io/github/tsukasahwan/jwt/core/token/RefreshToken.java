package io.github.tsukasahwan.jwt.core.token;

import io.github.tsukasahwan.jwt.core.AbstractToken;
import io.github.tsukasahwan.jwt.core.JwtTokenType;
import io.github.tsukasahwan.jwt.util.IdUtils;

import java.util.Map;

/**
 * @author Teamo
 * @since 2025/4/8
 */
public class RefreshToken extends AbstractToken {

    protected RefreshToken(Map<String, Object> claims) {
        super(claims);
    }

    public static RefreshTokenBuilder builder() {
        return new RefreshTokenBuilder();
    }

    public static class RefreshTokenBuilder extends Builder<RefreshToken> {

        RefreshTokenBuilder() {
            super(JwtTokenType.REFRESH_TOKEN);
            super.jti(IdUtils.simpleUUID());
        }

        @Override
        public RefreshToken build() {
            validate();
            return new RefreshToken(this.claims);
        }
    }
}
