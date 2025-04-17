package io.github.tsukasahwan.jwt.core;

import io.github.tsukasahwan.jwt.core.token.GenericJwtToken;
import org.springframework.util.Assert;

/**
 * @author Teamo
 * @since 2025/4/6
 */
public class JwtToken {

    private final String tokenValue;

    private final GenericJwtToken genericJwtToken;

    public JwtToken(String tokenValue, GenericJwtToken genericJwtToken) {
        Assert.hasText(tokenValue, "tokenValue cannot be empty");
        this.tokenValue = tokenValue;
        this.genericJwtToken = genericJwtToken;
    }

    public static Builder withTokenValue(String tokenValue) {
        return new Builder(tokenValue);
    }

    public String getTokenValue() {
        return tokenValue;
    }

    public GenericJwtToken getGenericJwtToken() {
        return genericJwtToken;
    }

    public static class Builder {

        private String tokenValue;

        private GenericJwtToken genericJwtToken;

        private Builder(String tokenValue) {
            this.tokenValue = tokenValue;
        }

        public Builder tokenValue(String tokenValue) {
            this.tokenValue = tokenValue;
            return this;
        }

        public Builder genericJwtToken(GenericJwtToken genericJwtToken) {
            this.genericJwtToken = genericJwtToken;
            return this;
        }

        public JwtToken build() {
            return new JwtToken(tokenValue, this.genericJwtToken);
        }
    }
}
