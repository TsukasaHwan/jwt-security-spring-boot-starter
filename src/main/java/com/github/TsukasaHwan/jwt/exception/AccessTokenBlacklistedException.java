package com.github.TsukasaHwan.jwt.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * @author Teamo
 * @since 2025/4/11
 */
public class AccessTokenBlacklistedException extends AuthenticationException {

    public AccessTokenBlacklistedException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public AccessTokenBlacklistedException(String msg) {
        super(msg);
    }
}
