package com.github.TsukasaHwan.jwt.core;

import io.jsonwebtoken.Claims;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Teamo
 * @since 2025/4/6
 */
public abstract class AbstractToken {

    private final String id;

    private final String subject;

    private final Map<String, Object> header;

    private final Map<String, Object> claims;

    protected AbstractToken(String id, String subject, Map<String, Object> header, Map<String, Object> claims) {
        this.id = id;
        this.subject = subject;
        this.header = header;
        this.claims = claims;
    }

    public String getId() {
        return id;
    }

    public String getSubject() {
        return subject;
    }

    public Map<String, Object> getHeader() {
        return header;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }

    public abstract static class Builder<T extends AbstractToken> {

        protected final JwtTokenType tokenType;

        protected final Map<String, Object> header = new HashMap<>(16);

        protected final Map<String, Object> claims = new HashMap<>(16);

        protected Builder(JwtTokenType tokenType) {
            this.tokenType = tokenType;
            this.claims.put(JwtClaimsNames.GRANT_TYPE, tokenType);
        }

        public Builder<T> id(String id) {
            claims.put(Claims.ID, id);
            return this;
        }

        public Builder<T> subject(String sub) {
            claims.put(Claims.SUBJECT, sub);
            return this;
        }

        public HeaderBuilder header() {
            return new HeaderBuilder(this, header);
        }

        public ClaimsBuilder claims() {
            return new ClaimsBuilder(this, claims);
        }

        public abstract T build();

        protected void validate() {
            Object sub = claims.get(Claims.SUBJECT);
            if (sub == null || sub.toString().isBlank()) {
                throw new IllegalStateException("subject must not be null or blank");
            }
            Object actualType = claims.get(JwtClaimsNames.GRANT_TYPE);
            if (!tokenType.equals(actualType)) {
                throw new IllegalStateException("Invalid token type. Expected: " + tokenType);
            }
        }
    }

    public static class HeaderBuilder {

        private final Builder<?> builder;

        private final Map<String, Object> header;

        HeaderBuilder(Builder<?> builder, Map<String, Object> header) {
            this.builder = builder;
            this.header = header;
        }

        public HeaderBuilder add(String name, Object value) {
            this.header.put(name, value);
            return this;
        }

        public HeaderBuilder add(Map<String, Object> header) {
            this.header.putAll(header);
            return this;
        }

        public Builder<?> and() {
            return builder;
        }
    }

    public static class ClaimsBuilder {

        private final Builder<?> builder;

        private final Map<String, Object> claims;

        ClaimsBuilder(Builder<?> builder, Map<String, Object> claims) {
            this.builder = builder;
            this.claims = claims;
        }

        public ClaimsBuilder add(String name, Object value) {
            this.claims.put(name, value);
            return this;
        }

        public ClaimsBuilder add(Map<String, Object> claims) {
            this.claims.putAll(claims);
            return this;
        }

        public Builder<?> and() {
            return builder;
        }
    }
}
