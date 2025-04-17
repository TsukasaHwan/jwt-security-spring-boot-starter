package io.github.tsukasahwan.jwt.core.token;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.github.tsukasahwan.jwt.core.AbstractToken;
import io.github.tsukasahwan.jwt.core.JwtClaimsNames;
import io.github.tsukasahwan.jwt.core.JwtTokenType;

import java.util.Map;

/**
 * @author Teamo
 * @since 2025/4/8
 */
@JsonDeserialize(builder = GenericJwtToken.GenericJwtTokenBuilder.class)
public class GenericJwtToken extends AbstractToken {

    protected GenericJwtToken(Map<String, Object> claims) {
        super(claims);
    }

    public static GenericJwtTokenBuilder withTokenType(JwtTokenType tokenType) {
        return new GenericJwtTokenBuilder(tokenType);
    }

    public static class GenericJwtTokenBuilder extends Builder<GenericJwtToken> {

        @JsonCreator
        protected GenericJwtTokenBuilder(@JsonProperty(JwtClaimsNames.GRANT_TYPE) JwtTokenType tokenType) {
            super(tokenType);
        }

        @Override
        public GenericJwtToken build() {
            validate();
            return new GenericJwtToken(claims);
        }
    }
}
