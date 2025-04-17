package io.github.tsukasahwan.jwt.core;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonSetter;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * @author Teamo
 * @since 2025/4/6
 */
public abstract class AbstractToken {

    private final Map<String, Object> claims;

    protected AbstractToken(Map<String, Object> claims) {
        this.claims = claims;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }

    public String getJti() {
        return (String) claims.get(JwtClaimsNames.JTI);
    }

    public String getSubject() {
        return (String) claims.get(JwtClaimsNames.SUB);
    }

    public Instant getIssuedAt() {
        return (Instant) claims.get(JwtClaimsNames.IAT);
    }

    public Instant getExpiresAt() {
        return (Instant) claims.get(JwtClaimsNames.EXP);
    }

    public JwtTokenType getTokenType() {
        return (JwtTokenType) claims.get(JwtClaimsNames.GRANT_TYPE);
    }

    public abstract static class Builder<T extends AbstractToken> {

        protected final JwtTokenType tokenType;

        protected final Map<String, Object> claims = new LinkedHashMap<>();

        protected Builder(JwtTokenType tokenType) {
            this.tokenType = tokenType;
            this.claims.put(JwtClaimsNames.GRANT_TYPE, tokenType);
        }

        @JsonAnySetter
        public Builder<T> claim(String name, Object value) {
            this.claims.put(name, value);
            return this;
        }

        public Builder<T> claims(Consumer<Map<String, Object>> claimsConsumer) {
            claimsConsumer.accept(this.claims);
            return this;
        }

        @JsonSetter(JwtClaimsNames.JTI)
        public Builder<T> jti(String jti) {
            claims.put(JwtClaimsNames.JTI, jti);
            return this;
        }

        @JsonSetter(JwtClaimsNames.SUB)
        public Builder<T> subject(String subject) {
            claims.put(JwtClaimsNames.SUB, subject);
            return this;
        }

        @JsonSetter(JwtClaimsNames.IAT)
        public Builder<T> issuedAt(Instant issuedAt) {
            claims.put(JwtClaimsNames.IAT, issuedAt);
            return this;
        }

        @JsonSetter(JwtClaimsNames.EXP)
        public Builder<T> expiresAt(Instant expiresAt) {
            claims.put(JwtClaimsNames.EXP, expiresAt);
            return this;
        }

        public abstract T build();

        protected void validate() {
            Object sub = claims.get(JwtClaimsNames.SUB);
            if (sub == null || sub.toString().isBlank()) {
                throw new IllegalStateException("subject must not be null or blank");
            }
            Object actualType = claims.get(JwtClaimsNames.GRANT_TYPE);
            if (!tokenType.equals(actualType)) {
                throw new IllegalStateException("Invalid token type. Expected: " + tokenType);
            }
        }
    }
}
