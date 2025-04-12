package com.github.TsukasaHwan.jwt.config.token.storage.redis;

import com.github.TsukasaHwan.jwt.config.properties.JwtSecurityProperties;
import com.github.TsukasaHwan.jwt.security.token.RefreshTokenRevokeManager;
import com.github.TsukasaHwan.jwt.security.token.storage.redis.RedisRefreshTokenRevokeManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;

/**
 * @author Teamo
 * @since 2025/4/9
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(RedisTemplate.class)
@ConditionalOnProperty(name = "jwt.security.token-security.storage-type", havingValue = "redis")
public class RedisRefreshTokenRevokeConfig extends RedisTokenStorageConfig {

    protected RedisRefreshTokenRevokeConfig(JwtSecurityProperties jwtSecurityProperties) {
        super(jwtSecurityProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenRevokeManager refreshTokenRevokeManager(
            @Qualifier("jwtRedisTemplate") RedisTemplate<String, Object> jwtRedisTemplate) {
        String keyPrefix = this.getRevokeKeyPrefix();
        return new RedisRefreshTokenRevokeManager(keyPrefix, jwtRedisTemplate);
    }
}
