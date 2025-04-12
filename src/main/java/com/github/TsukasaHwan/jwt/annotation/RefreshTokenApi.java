package com.github.TsukasaHwan.jwt.annotation;

import java.lang.annotation.*;

/**
 * @author Teamo
 * @since 2025/4/3
 */
@Documented
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RefreshTokenApi {
}
