package io.github.tsukasahwan.jwt.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * @author Teamo
 * @since 2024/5/25
 */
public class JwtAuthenticationException extends AuthenticationException {

    public JwtAuthenticationException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public JwtAuthenticationException(String msg) {
        super(msg);
    }
}
