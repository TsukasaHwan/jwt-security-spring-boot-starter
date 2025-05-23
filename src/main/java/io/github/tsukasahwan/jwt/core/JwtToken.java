package io.github.tsukasahwan.jwt.core;

import org.springframework.util.Assert;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * @author Teamo
 * @since 2025/4/6
 */
public class JwtToken implements JwtClaimAccessor {

    private final String tokenValue;

    private final Map<String, Object> claims;

    public JwtToken(String tokenValue, Map<String, Object> claims) {
        Assert.hasText(tokenValue, "tokenValue cannot be empty");
        Assert.notEmpty(claims, "claims cannot be empty");
        this.tokenValue = tokenValue;
        this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
    }

    public static Builder withTokenValue(String tokenValue) {
        return new Builder(tokenValue);
    }

    public String getTokenValue() {
        return tokenValue;
    }

    @Override
    public Map<String, Object> getClaims() {
        return claims;
    }

    public static class Builder {

        private String tokenValue;

        private final Map<String, Object> claims = new LinkedHashMap<>();

        private Builder(String tokenValue) {
            this.tokenValue = tokenValue;
        }

        public Builder tokenValue(String tokenValue) {
            this.tokenValue = tokenValue;
            return this;
        }

        public Builder claim(String name, Object value) {
            this.claims.put(name, value);
            return this;
        }

        public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
            claimsConsumer.accept(this.claims);
            return this;
        }

        public Builder jti(String jti) {
            return claim(JwtClaimNames.JTI, jti);
        }

        public Builder subject(String subject) {
            return claim(JwtClaimNames.SUB, subject);
        }

        public Builder issuedAt(Instant issuedAt) {
            return claim(JwtClaimNames.IAT, issuedAt);
        }

        public Builder expiresAt(Instant expiresAt) {
            return claim(JwtClaimNames.EXP, expiresAt);
        }

        public Builder grantType(JwtGrantType grantType) {
            Assert.notNull(grantType, "grantType cannot be null");
            return claim(JwtClaimNames.GRANT_TYPE, grantType);
        }

        public JwtToken build() {
            return new JwtToken(this.tokenValue, this.claims);
        }
    }
}
