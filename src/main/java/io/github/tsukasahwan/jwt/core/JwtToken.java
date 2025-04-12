package io.github.tsukasahwan.jwt.core;

import io.github.tsukasahwan.jwt.util.JsonUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.util.Assert;

/**
 * @author Teamo
 * @since 2025/4/6
 */
public class JwtToken {

    private final String tokenValue;

    private final Jws<Claims> jws;

    private final JwtTokenType tokenType;

    public JwtToken(String tokenValue, Jws<Claims> jws, JwtTokenType tokenType) {
        Assert.hasText(tokenValue, "tokenValue cannot be empty");
        this.tokenValue = tokenValue;
        this.jws = jws;
        this.tokenType = tokenType;
    }

    public static Builder withTokenValue(String tokenValue) {
        return new Builder(tokenValue);
    }

    public String getTokenValue() {
        return tokenValue;
    }

    public Jws<Claims> getJws() {
        return jws;
    }

    public JwtTokenType getTokenType() {
        return tokenType;
    }

    public static class Builder {

        private String tokenValue;

        private Jws<Claims> jws;

        private JwtTokenType tokenType;

        private Builder(String tokenValue) {
            this.tokenValue = tokenValue;
        }

        public Builder tokenValue(String tokenValue) {
            this.tokenValue = tokenValue;
            return this;
        }

        public Builder jws(Jws<Claims> jws) {
            this.jws = jws;
            return this;
        }

        public Builder tokenType(JwtTokenType tokenType) {
            this.tokenType = tokenType;
            return this;
        }

        public JwtToken build() {
            if (jws != null) {
                tokenType = getTokenType(jws.getPayload().get(JwtClaimsNames.GRANT_TYPE));
            }
            return new JwtToken(tokenValue, jws, tokenType);
        }

        private JwtTokenType getTokenType(Object jwtTokenType) {
            return jwtTokenType == null ? null : JsonUtil.convertValue(jwtTokenType, JwtTokenType.class);
        }
    }
}
