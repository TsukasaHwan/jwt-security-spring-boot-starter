package com.github.TsukasaHwan.jwt.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * @author Teamo
 * @since 2025/4/9
 */
public class InvalidTokenException extends AuthenticationException {

    public InvalidTokenException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public InvalidTokenException(String msg) {
        super(msg);
    }
}
