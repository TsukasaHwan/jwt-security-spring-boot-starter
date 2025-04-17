package io.github.tsukasahwan.jwt.core;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * @author Teamo
 * @since 2025/4/6
 */
@JsonDeserialize(builder = JwtToken.Builder.class)
public class JwtToken implements JwtClaimAccessor, Serializable {

    private final String tokenValue;

    private final JwtGrantType grantType;

    private final Map<String, Object> claims;

    public JwtToken(String tokenValue, JwtGrantType grantType, Map<String, Object> claims) {
        Assert.hasText(tokenValue, "tokenValue cannot be empty");
        Assert.notNull(grantType, "grantType cannot be null");
        Assert.notEmpty(claims, "claims cannot be empty");
        this.tokenValue = tokenValue;
        this.grantType = grantType;
        this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
    }

    public static Builder withTokenValue(String tokenValue) {
        return new Builder(tokenValue);
    }

    public String getTokenValue() {
        return tokenValue;
    }

    public JwtGrantType getGrantType() {
        return grantType;
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

        @JsonAnySetter
        public Builder claim(String name, Object value) {
            this.claims.put(name, value);
            return this;
        }

        public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
            claimsConsumer.accept(this.claims);
            return this;
        }

        @JsonSetter(JwtClaimNames.JTI)
        public Builder jti(String jti) {
            claim(JwtClaimNames.JTI, jti);
            return this;
        }

        @JsonSetter(JwtClaimNames.SUB)
        public Builder subject(String subject) {
            claim(JwtClaimNames.SUB, subject);
            return this;
        }

        @JsonSetter(JwtClaimNames.IAT)
        public Builder issuedAt(Instant issuedAt) {
            claim(JwtClaimNames.IAT, issuedAt);
            return this;
        }

        @JsonSetter(JwtClaimNames.EXP)
        public Builder expiresAt(Instant expiresAt) {
            claim(JwtClaimNames.EXP, expiresAt);
            return this;
        }

        @JsonSetter(JwtClaimNames.GRANT_TYPE)
        public Builder grantType(JwtGrantType grantType) {
            Assert.notNull(grantType, "grantType cannot be null");
            claim(JwtClaimNames.GRANT_TYPE, grantType);
            return this;
        }

        public JwtToken build() {
            return new JwtToken(this.tokenValue, (JwtGrantType) this.claims.get(JwtClaimNames.GRANT_TYPE), this.claims);
        }
    }
}
