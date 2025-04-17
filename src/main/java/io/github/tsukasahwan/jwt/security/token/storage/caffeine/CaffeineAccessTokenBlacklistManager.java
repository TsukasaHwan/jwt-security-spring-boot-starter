package io.github.tsukasahwan.jwt.security.token.storage.caffeine;

import com.github.benmanes.caffeine.cache.Cache;
import io.github.tsukasahwan.jwt.core.token.GenericJwtToken;
import io.github.tsukasahwan.jwt.security.token.AbstractAccessTokenBlacklistManager;
import io.github.tsukasahwan.jwt.support.CaffeineExpireValue;

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
        GenericJwtToken genericJwtToken = validate(accessToken);
        final String cacheKey = buildKey(genericJwtToken.getJti());
        Duration ttl = Duration.between(Instant.now(), genericJwtToken.getExpiresAt());
        CaffeineExpireValue<Object> expireValue = new CaffeineExpireValue<>();
        expireValue.setValue(1);
        expireValue.setTtl(ttl);
        this.cache.put(cacheKey, expireValue);
    }

    @Override
    public boolean isBlacklisted(String accessToken) {
        GenericJwtToken genericJwtToken = validate(accessToken);
        final String cacheKey = buildKey(genericJwtToken.getJti());
        Boolean hasKey = this.cache.getIfPresent(cacheKey) != null;
        return Boolean.TRUE.equals(hasKey);
    }
}
