package com.github.TsukasaHwan.jwt.config.token;

import com.github.TsukasaHwan.jwt.config.properties.JwtSecurityProperties;
import com.github.TsukasaHwan.jwt.config.token.storage.caffeine.CaffeineRefreshTokenRevokeConfig;
import com.github.TsukasaHwan.jwt.config.token.storage.redis.RedisRefreshTokenRevokeConfig;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * @author Teamo
 * @since 2025/4/9
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(value = {JwtSecurityProperties.class})
@ConditionalOnProperty(value = "jwt.security.token-security.refresh-token-revoke.enabled", havingValue = "true")
@Import({RedisRefreshTokenRevokeConfig.class, CaffeineRefreshTokenRevokeConfig.class})
public class RefreshTokenRevokeConfiguration {

}
