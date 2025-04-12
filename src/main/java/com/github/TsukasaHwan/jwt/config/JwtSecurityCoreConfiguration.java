package com.github.TsukasaHwan.jwt.config;

import com.github.TsukasaHwan.jwt.security.authentication.DefaultJwtAuthenticationManager;
import com.github.TsukasaHwan.jwt.security.authentication.JwtAuthenticationManager;
import com.github.TsukasaHwan.jwt.security.authentication.NoOpAuthenticationSuccessHandler;
import com.github.TsukasaHwan.jwt.security.authenticator.AccessTokenAuthenticator;
import com.github.TsukasaHwan.jwt.security.authenticator.RefreshTokenAuthenticator;
import com.github.TsukasaHwan.jwt.security.authenticator.TokenAuthenticatorRegistry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

/**
 * @author Teamo
 * @since 2025/4/3
 */
@Configuration(proxyBeanMethods = false)
public class JwtSecurityCoreConfiguration {

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    public PasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationManager jwtAuthenticationManager() {
        return new DefaultJwtAuthenticationManager();
    }

    @Bean
    @ConditionalOnMissingBean
    public AccessTokenAuthenticator accessTokenAuthenticator(UserDetailsService userDetailsService) {
        return new AccessTokenAuthenticator(userDetailsService);
    }

    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenAuthenticator refreshTokenAuthenticator(UserDetailsService userDetailsService) {
        return new RefreshTokenAuthenticator(userDetailsService);
    }

    @Bean
    public TokenAuthenticatorRegistry tokenAuthenticatorRegistry() {
        return new TokenAuthenticatorRegistry();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationSuccessHandler noOpAuthenticationSuccessHandler() {
        return new NoOpAuthenticationSuccessHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationEntryPoint httpStatusEntryPoint() {
        return new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
    }

    @Bean
    @ConditionalOnMissingBean
    public AccessDeniedHandler accessDeniedHandlerImpl() {
        return new AccessDeniedHandlerImpl();
    }

}
