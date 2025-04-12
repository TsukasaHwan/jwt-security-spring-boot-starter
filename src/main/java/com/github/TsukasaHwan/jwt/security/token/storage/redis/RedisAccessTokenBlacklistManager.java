package com.github.TsukasaHwan.jwt.security.token.storage.redis;

import com.github.TsukasaHwan.jwt.security.token.AbstractAccessTokenBlacklistManager;
import io.jsonwebtoken.Claims;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.Instant;

/**
 * @author Teamo
 * @since 2025/4/10
 */
public class RedisAccessTokenBlacklistManager extends AbstractAccessTokenBlacklistManager {

    private final RedisTemplate<String, Object> redisTemplate;

    public RedisAccessTokenBlacklistManager(String keyPrefix, RedisTemplate<String, Object> redisTemplate) {
        super(keyPrefix);
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void addToBlacklist(String accessToken) {
        Claims payload = validate(accessToken);
        final String cacheKey = buildKey(payload.getId());
        Duration ttl = Duration.between(Instant.now(), payload.getExpiration().toInstant());
        this.redisTemplate.opsForValue().set(cacheKey, 1, ttl);
    }

    @Override
    public boolean isBlacklisted(String accessToken) {
        Claims payload = validate(accessToken);
        final String cacheKey = buildKey(payload.getId());
        Boolean hasKey = this.redisTemplate.hasKey(cacheKey);
        return Boolean.TRUE.equals(hasKey);
    }
}
