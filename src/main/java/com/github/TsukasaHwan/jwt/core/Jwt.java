package com.github.TsukasaHwan.jwt.core;

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import java.io.Serializable;

/**
 * @author Teamo
 * @since 2023/4/2
 */
@JsonDeserialize(builder = Jwt.Builder.class)
public class Jwt implements Serializable {

    private final String accessToken;

    private final String refreshToken;

    private final Long expiresIn;

    Jwt(String accessToken, String refreshToken, Long expiresIn) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public Long getExpiresIn() {
        return expiresIn;
    }

    public static class Builder {
        private String accessToken;

        private String refreshToken;

        private Long expiresIn;

        Builder() {
        }

        @JsonSetter("accessToken")
        public Builder accessToken(String accessToken) {
            this.accessToken = accessToken;
            return this;
        }

        @JsonSetter("refreshToken")
        public Builder refreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
            return this;
        }

        @JsonSetter("expiresIn")
        public Builder expiresIn(Long expiresIn) {
            this.expiresIn = expiresIn;
            return this;
        }

        public Jwt build() {
            return new Jwt(this.accessToken, this.refreshToken, this.expiresIn);
        }
    }
}
