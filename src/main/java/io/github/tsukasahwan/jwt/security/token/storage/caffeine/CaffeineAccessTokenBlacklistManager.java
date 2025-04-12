package io.github.tsukasahwan.jwt.security.token.storage.caffeine;

import io.github.tsukasahwan.jwt.security.token.AbstractAccessTokenBlacklistManager;
import io.github.tsukasahwan.jwt.support.CaffeineExpireValue;
import com.github.benmanes.caffeine.cache.Cache;
import io.jsonwebtoken.Claims;

import java.time.Duration;
import java.time.Instant;

/**
 * @author Teamo
 * @since 2025/4/10
 */
public class CaffeineAccessTokenBlacklistManager extends AbstractAccessTokenBlacklistManager {

    private final Cache<String, CaffeineExpireValue<Object>> cache;

    public CaffeineAccessTokenBlacklistManager(String keyPrefix, Cache<String, CaffeineExpireValue<Object>> cache) {
        super(keyPrefix);
        this.cache = cache;
    }

    @Override
    public void addToBlacklist(String accessToken) {
        Claims payload = validate(accessToken);
        final String cacheKey = buildKey(payload.getId());
        Duration ttl = Duration.between(Instant.now(), payload.getExpiration().toInstant());
        CaffeineExpireValue<Object> expireValue = new CaffeineExpireValue<>();
        expireValue.setValue(1);
        expireValue.setTtl(ttl);
        this.cache.put(cacheKey, expireValue);
    }

    @Override
    public boolean isBlacklisted(String accessToken) {
        Claims payload = validate(accessToken);
        final String cacheKey = buildKey(payload.getId());
        Boolean hasKey = this.cache.getIfPresent(cacheKey) != null;
        return Boolean.TRUE.equals(hasKey);
    }
}
