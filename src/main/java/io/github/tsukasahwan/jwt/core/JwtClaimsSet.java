package io.github.tsukasahwan.jwt.core;

import org.springframework.util.Assert;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * @author Teamo
 * @since 2025/4/17
 */
public class JwtClaimsSet implements JwtClaimAccessor {

    private final Map<String, Object> claims;

    private JwtClaimsSet(Map<String, Object> claims) {
        this.claims = Map.copyOf(claims);
    }

    @Override
    public Map<String, Object> getClaims() {
        return this.claims;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder from(JwtClaimsSet claims) {
        return new Builder(claims);
    }

    public static final class Builder {

        private final Map<String, Object> claims = new HashMap<>();

        private Builder() {
        }

        private Builder(JwtClaimsSet claims) {
            Assert.notNull(claims, "claims cannot be null");
            this.claims.putAll(claims.getClaims());
        }

        public Builder subject(String subject) {
            return claim(JwtClaimNames.SUB, subject);
        }

        public Builder expiresAt(Instant expiresAt) {
            return claim(JwtClaimNames.EXP, expiresAt);
        }

        public Builder issuedAt(Instant issuedAt) {
            return claim(JwtClaimNames.IAT, issuedAt);
        }

        public Builder id(String jti) {
            return claim(JwtClaimNames.JTI, jti);
        }

        public Builder grantType(JwtGrantType grantType) {
            Assert.notNull(grantType, "grantType cannot be null");
            return claim(JwtClaimNames.GRANT_TYPE, grantType);
        }

        public Builder claim(String name, Object value) {
            Assert.hasText(name, "name cannot be empty");
            Assert.notNull(value, "value cannot be null");
            this.claims.put(name, value);
            return this;
        }

        public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
            claimsConsumer.accept(this.claims);
            return this;
        }

        public JwtClaimsSet build() {
            Assert.notEmpty(this.claims, "claims cannot be empty");
            Assert.notNull(this.claims.get(JwtClaimNames.GRANT_TYPE), "grantType cannot be null");
            return new JwtClaimsSet(this.claims);
        }

    }
}
