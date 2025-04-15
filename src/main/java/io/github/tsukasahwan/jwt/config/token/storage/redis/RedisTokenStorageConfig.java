package io.github.tsukasahwan.jwt.config.token.storage.redis;

import io.github.tsukasahwan.jwt.config.properties.JwtSecurityProperties;
import io.github.tsukasahwan.jwt.config.token.storage.TokenSecurityStorageConfig;
import io.github.tsukasahwan.jwt.security.token.AccessTokenBlacklistManager;
import io.github.tsukasahwan.jwt.security.token.RefreshTokenRevokeManager;
import io.github.tsukasahwan.jwt.security.token.storage.redis.RedisAccessTokenBlacklistManager;
import io.github.tsukasahwan.jwt.security.token.storage.redis.RedisRefreshTokenRevokeManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializer;

/**
 * @author Teamo
 * @since 2025/4/12
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(RedisTemplate.class)
@ConditionalOnProperty(name = "jwt.security.token-security.storage-type", havingValue = "redis")
public class RedisTokenStorageConfig extends TokenSecurityStorageConfig {

    public RedisTokenStorageConfig(JwtSecurityProperties jwtSecurityProperties) {
        super(jwtSecurityProperties);
    }

    @Bean
    @ConditionalOnMissingBean(name = "jwtRedisTemplate")
    public RedisTemplate<String, Object> jwtRedisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);
        redisTemplate.setKeySerializer(RedisSerializer.string());
        redisTemplate.setValueSerializer(RedisSerializer.json());
        return redisTemplate;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(value = "jwt.security.token-security.access-token-blacklist.enabled", havingValue = "true")
    public AccessTokenBlacklistManager accessTokenBlacklistManager(
            @Qualifier("jwtRedisTemplate") RedisTemplate<String, Object> jwtRedisTemplate) {
        String keyPrefix = this.getBlacklistKeyPrefix();
        return new RedisAccessTokenBlacklistManager(keyPrefix, jwtRedisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(value = "jwt.security.token-security.refresh-token-revoke.enabled", havingValue = "true")
    public RefreshTokenRevokeManager refreshTokenRevokeManager(
            @Qualifier("jwtRedisTemplate") RedisTemplate<String, Object> jwtRedisTemplate) {
        String keyPrefix = this.getRevokeKeyPrefix();
        return new RedisRefreshTokenRevokeManager(keyPrefix, jwtRedisTemplate);
    }
}
