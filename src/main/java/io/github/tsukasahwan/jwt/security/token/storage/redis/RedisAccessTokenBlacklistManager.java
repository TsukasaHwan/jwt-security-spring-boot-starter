package io.github.tsukasahwan.jwt.security.token.storage.redis;

import io.github.tsukasahwan.jwt.core.token.GenericJwtToken;
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
    public void addToBlacklist(String accessToken) {
        GenericJwtToken genericJwtToken = validate(accessToken);
        final String cacheKey = buildKey(genericJwtToken.getJti());
        Duration ttl = Duration.between(Instant.now(), genericJwtToken.getExpiresAt());
        this.redisTemplate.opsForValue().set(cacheKey, 1, ttl);
    }

    @Override
    public boolean isBlacklisted(String accessToken) {
        GenericJwtToken genericJwtToken = validate(accessToken);
        final String cacheKey = buildKey(genericJwtToken.getJti());
        Boolean hasKey = this.redisTemplate.hasKey(cacheKey);
        return Boolean.TRUE.equals(hasKey);
    }
}
