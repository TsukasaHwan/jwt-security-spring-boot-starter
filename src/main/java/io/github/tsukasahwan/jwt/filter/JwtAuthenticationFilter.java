package io.github.tsukasahwan.jwt.filter;

import io.github.tsukasahwan.jwt.core.JwtToken;
import io.github.tsukasahwan.jwt.core.JwtTokenType;
import io.github.tsukasahwan.jwt.exception.ExpiredJwtAuthenticationException;
import io.github.tsukasahwan.jwt.exception.JwtAuthenticationException;
import io.github.tsukasahwan.jwt.security.authenticator.AbstractTokenAuthenticator;
import io.github.tsukasahwan.jwt.security.authenticator.TokenAuthenticatorRegistry;
import io.github.tsukasahwan.jwt.util.JwtUtils;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

/**
 * JwtAuthenticationFilter
 *
 * @author Teamo
 * @since 2025/4/3
 */
public class JwtAuthenticationFilter extends AbstractAuthenticationFilter {

    public static final String JWT_TOKEN = JwtAuthenticationFilter.class.getName() + ".JWT_TOKEN";

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final TokenAuthenticatorRegistry tokenAuthenticatorRegistry;

    public JwtAuthenticationFilter(TokenAuthenticatorRegistry tokenAuthenticatorRegistry,
                                   AuthenticationSuccessHandler successHandler,
                                   AuthenticationFailureHandler failureHandler) {
        super(successHandler, failureHandler);
        this.tokenAuthenticatorRegistry = tokenAuthenticatorRegistry;
    }

    @Override
    protected Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String authToken = JwtUtils.getTokenValue(request);
        if (authToken == null) {
            return null;
        }

        JwtToken jwtToken = JwtUtils.getJwtToken(request);
        JwtTokenType tokenType = jwtToken.getTokenType();
        AbstractTokenAuthenticator authenticator = this.tokenAuthenticatorRegistry.getTokenAuthenticator(tokenType);
        return authenticator.authenticate(request, jwtToken);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, Exception e) throws ServletException, IOException {
        SecurityContextHolder.clearContext();
        AuthenticationException exception = convertException(e);
        this.failureHandler.onAuthenticationFailure(request, response, exception);
    }

    /**
     * Convert to AuthenticationException
     *
     * @param e Exception
     * @return {@link AuthenticationException}
     */
    private AuthenticationException convertException(Exception e) {
        if (e instanceof ExpiredJwtException) {
            return new ExpiredJwtAuthenticationException(e.getMessage(), e);
        } else if (e instanceof JwtException) {
            return new JwtAuthenticationException(e.getMessage(), e);
        } else if (e instanceof AuthenticationException authenticationException) {
            return authenticationException;
        } else {
            log.error("Unexpected authentication error", e);
            return new JwtAuthenticationException("Authentication failed", e);
        }
    }
}
