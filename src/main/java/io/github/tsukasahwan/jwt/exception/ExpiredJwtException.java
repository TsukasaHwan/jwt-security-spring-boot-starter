package io.github.tsukasahwan.jwt.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * @author Teamo
 * @since 2023/3/16
 */
public class ExpiredJwtException extends AuthenticationException {

    public ExpiredJwtException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public ExpiredJwtException(String msg) {
        super(msg);
    }
}
