package com.github.TsukasaHwan.jwt.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * @author Teamo
 * @since 2023/3/16
 */
public class ExpiredJwtAuthenticationException extends AuthenticationException {

    public ExpiredJwtAuthenticationException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public ExpiredJwtAuthenticationException(String msg) {
        super(msg);
    }
}
