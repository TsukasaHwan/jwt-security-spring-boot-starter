package io.github.tsukasahwan.jwt.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * @author Teamo
 * @since 2025/4/9
 */
public class RefreshTokenRevokedException extends AuthenticationException {

    public RefreshTokenRevokedException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public RefreshTokenRevokedException(String msg) {
        super(msg);
    }

}
