package io.github.tsukasahwan.jwt.security.token.storage.redis;

import io.github.tsukasahwan.jwt.core.JwtToken;
import io.github.tsukasahwan.jwt.security.token.AbstractAccessTokenBlacklistManager;
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
    public void addToBlacklist(JwtToken accessToken) {
        this.validate(accessToken);
        final String cacheKey = buildKey(accessToken.getId());

        Duration ttl = Duration.between(Instant.now(), accessToken.getExpiresAt());
        this.redisTemplate.opsForValue().set(cacheKey, 1, ttl);
    }

    @Override
    public boolean isBlacklisted(JwtToken accessToken) {
        this.validate(accessToken);
        final String cacheKey = buildKey(accessToken.getId());

        Boolean hasKey = this.redisTemplate.hasKey(cacheKey);
        return Boolean.TRUE.equals(hasKey);
    }
}
