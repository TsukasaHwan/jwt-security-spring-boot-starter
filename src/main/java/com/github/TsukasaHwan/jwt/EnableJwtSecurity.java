package com.github.TsukasaHwan.jwt;

import com.github.TsukasaHwan.jwt.config.JwtSecurityWebConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * @author Teamo
 * @since 2023/6/8
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@Import(JwtSecurityWebConfiguration.class)
@Configuration
public @interface EnableJwtSecurity {
}
