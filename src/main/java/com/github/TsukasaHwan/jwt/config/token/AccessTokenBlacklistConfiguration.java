package com.github.TsukasaHwan.jwt.config.token;

import com.github.TsukasaHwan.jwt.config.properties.JwtSecurityProperties;
import com.github.TsukasaHwan.jwt.config.token.storage.caffeine.CaffeineAccessTokenBlacklistConfig;
import com.github.TsukasaHwan.jwt.config.token.storage.redis.RedisAccessTokenBlacklistConfig;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * @author Teamo
 * @since 2025/4/10
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(value = {JwtSecurityProperties.class})
@ConditionalOnProperty(value = "jwt.security.token-security.access-token-blacklist.enabled", havingValue = "true")
@Import({RedisAccessTokenBlacklistConfig.class, CaffeineAccessTokenBlacklistConfig.class})
public class AccessTokenBlacklistConfiguration {

}
