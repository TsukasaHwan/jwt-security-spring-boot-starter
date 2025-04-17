package io.github.tsukasahwan.jwt.core;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.util.Assert;

import java.io.Serializable;

/**
 * @author Teamo
 * @since 2025/4/6
 */
public class JwtGrantType implements Serializable {

    public static final JwtGrantType ACCESS_TOKEN = new JwtGrantType("access_token");

    public static final JwtGrantType REFRESH_TOKEN = new JwtGrantType("refresh_token");

    private final String value;

    @JsonCreator
    public JwtGrantType(@JsonProperty("value") String value) {
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
        JwtGrantType that = (JwtGrantType) obj;
        return getValue().equals(that.getValue());
    }

    @Override
    public int hashCode() {
        return getValue().hashCode();
    }
}
