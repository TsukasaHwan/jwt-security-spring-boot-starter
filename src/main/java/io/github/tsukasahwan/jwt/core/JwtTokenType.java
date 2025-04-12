package io.github.tsukasahwan.jwt.core;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.util.Assert;

import java.io.Serializable;

/**
 * @author Teamo
 * @since 2025/4/6
 */
public class JwtTokenType implements Serializable {

    public static final JwtTokenType ACCESS_TOKEN = new JwtTokenType("access_token");

    public static final JwtTokenType REFRESH_TOKEN = new JwtTokenType("refresh_token");

    private final String value;

    @JsonCreator
    public JwtTokenType(@JsonProperty("value") String value) {
        Assert.hasText(value, "value cannot be empty");
        this.value = value;
    }

    public String getValue() {
        return this.value;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || this.getClass() != obj.getClass()) {
            return false;
        }
        JwtTokenType that = (JwtTokenType) obj;
        return getValue().equals(that.getValue());
    }

    @Override
    public int hashCode() {
        return getValue().hashCode();
    }
}
