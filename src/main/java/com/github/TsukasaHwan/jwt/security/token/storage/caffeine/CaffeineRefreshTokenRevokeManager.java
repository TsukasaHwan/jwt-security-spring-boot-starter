package com.github.TsukasaHwan.jwt.security.token.storage.caffeine;

import com.github.TsukasaHwan.jwt.security.token.AbstractRefreshTokenRevokeManager;
import com.github.TsukasaHwan.jwt.support.CaffeineExpireValue;
import com.github.benmanes.caffeine.cache.Cache;
import io.jsonwebtoken.Claims;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Teamo
 * @since 2025/4/9
 */
public class CaffeineRefreshTokenRevokeManager extends AbstractRefreshTokenRevokeManager {

    private final Cache<String, CaffeineExpireValue<Object>> cache;

    public CaffeineRefreshTokenRevokeManager(String keyPrefix, Cache<String, CaffeineExpireValue<Object>> cache) {
        super(keyPrefix);
        this.cache = cache;
    }

    @Override
    public void save(String refreshToken) {
        Claims payload = validate(refreshToken);
        final String cacheKey = buildKey(payload);
        CaffeineExpireValue<Object> value = createCaffeineExpireValue(refreshToken, payload);
        this.cache.put(cacheKey, value);
    }

    @Override
    public boolean isRevoked(String refreshToken) {
        Claims payload = validate(refreshToken);
        final String cacheKey = buildKey(payload);
        CaffeineExpireValue<Object> entity = this.cache.getIfPresent(cacheKey);
        return entity == null;
    }

    @Override
    public void revoke(String refreshToken) {
        Claims payload = validate(refreshToken);
        final String cacheKey = buildKey(payload);
        this.cache.invalidate(cacheKey);
    }

    @Override
    public void revokeAll(String subject) {
        List<String> revokeKeys = this.cache.asMap().keySet()
                .stream()
                .filter(key -> key.contains(subject))
                .collect(Collectors.toList());
        this.cache.invalidateAll(revokeKeys);
    }

    private CaffeineExpireValue<Object> createCaffeineExpireValue(String refreshToken, Claims payload) {
        Duration expireTime = Duration.between(Instant.now(), payload.getExpiration().toInstant());
        CaffeineExpireValue<Object> expireValue = new CaffeineExpireValue<>();
        expireValue.setValue(refreshToken);
        expireValue.setTtl(expireTime);
        return expireValue;
    }
}
