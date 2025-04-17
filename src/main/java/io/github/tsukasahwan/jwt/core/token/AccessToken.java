package io.github.tsukasahwan.jwt.core.token;

import io.github.tsukasahwan.jwt.core.AbstractToken;
import io.github.tsukasahwan.jwt.core.JwtTokenType;
import io.github.tsukasahwan.jwt.util.IdUtils;

import java.util.Map;

/**
 * @author Teamo
 * @since 2025/4/8
 */
public class AccessToken extends AbstractToken {

    protected AccessToken(Map<String, Object> claims) {
        super(claims);
    }

    public static AccessTokenBuilder builder() {
        return new AccessTokenBuilder();
    }

    public static class AccessTokenBuilder extends Builder<AccessToken> {

        AccessTokenBuilder() {
            super(JwtTokenType.ACCESS_TOKEN);
            super.jti(IdUtils.simpleUUID());
        }

        @Override
        public AccessToken build() {
            validate();
            return new AccessToken(this.claims);
        }
    }

}
