package io.github.tsukasahwan.jwt.config.token.storage.redis;

import io.github.tsukasahwan.jwt.config.properties.JwtSecurityProperties;
import io.github.tsukasahwan.jwt.security.token.AccessTokenBlacklistManager;
import io.github.tsukasahwan.jwt.security.token.storage.redis.RedisAccessTokenBlacklistManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;

/**
 * @author Teamo
 * @since 2025/4/11
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(RedisTemplate.class)
@ConditionalOnProperty(name = "jwt.security.token-security.storage-type", havingValue = "redis", matchIfMissing = true)
public class RedisAccessTokenBlacklistConfig extends RedisTokenStorageConfig {

    protected RedisAccessTokenBlacklistConfig(JwtSecurityProperties jwtSecurityProperties) {
        super(jwtSecurityProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public AccessTokenBlacklistManager accessTokenBlacklistManager(
            @Qualifier("jwtRedisTemplate") RedisTemplate<String, Object> jwtRedisTemplate) {
        String keyPrefix = this.getBlacklistKeyPrefix();
        return new RedisAccessTokenBlacklistManager(keyPrefix, jwtRedisTemplate);
    }
}
