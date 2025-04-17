package io.github.tsukasahwan.jwt.security.token.storage.caffeine;

import com.github.benmanes.caffeine.cache.Cache;
import io.github.tsukasahwan.jwt.core.JwtToken;
import io.github.tsukasahwan.jwt.security.token.AbstractRefreshTokenRevokeManager;
import io.github.tsukasahwan.jwt.support.CaffeineExpireValue;

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
    public void save(JwtToken refreshToken) {
        this.validate(refreshToken);
        final String cacheKey = buildKey(refreshToken);

        CaffeineExpireValue<Object> value = createCaffeineExpireValue(refreshToken);
        this.cache.put(cacheKey, value);
    }

    @Override
    public boolean isRevoked(JwtToken refreshToken) {
        this.validate(refreshToken);
        final String cacheKey = buildKey(refreshToken);

        CaffeineExpireValue<Object> entity = this.cache.getIfPresent(cacheKey);
        return entity == null;
    }

    @Override
    public void revoke(JwtToken refreshToken) {
        this.validate(refreshToken);
        final String cacheKey = buildKey(refreshToken);

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

    private CaffeineExpireValue<Object> createCaffeineExpireValue(JwtToken jwtToken) {
        Duration expireTime = Duration.between(Instant.now(), jwtToken.getExpiresAt());
        CaffeineExpireValue<Object> expireValue = new CaffeineExpireValue<>();
        expireValue.setValue(jwtToken.getTokenValue());
        expireValue.setTtl(expireTime);
        return expireValue;
    }
}
