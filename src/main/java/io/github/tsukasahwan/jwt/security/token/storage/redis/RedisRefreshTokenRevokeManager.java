package io.github.tsukasahwan.jwt.security.token.storage.redis;

import io.github.tsukasahwan.jwt.core.JwtToken;
import io.github.tsukasahwan.jwt.security.token.AbstractRefreshTokenRevokeManager;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ScanOptions;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Teamo
 * @since 2025/4/9
 */
public class RedisRefreshTokenRevokeManager extends AbstractRefreshTokenRevokeManager {

    private static final long DEFAULT_SCAN_COUNT = 100L;

    private final RedisTemplate<String, Object> redisTemplate;

    public RedisRefreshTokenRevokeManager(String keyPrefix, RedisTemplate<String, Object> redisTemplate) {
        super(keyPrefix);
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void save(JwtToken refreshToken) {
        this.validate(refreshToken);
        final String cacheKey = buildKey(refreshToken);

        Duration expireTime = Duration.between(Instant.now(), refreshToken.getExpiresAt());
        this.redisTemplate.opsForValue().set(cacheKey, refreshToken.getTokenValue(), expireTime);
    }

    @Override
    public boolean isRevoked(JwtToken refreshToken) {
        this.validate(refreshToken);
        final String cacheKey = buildKey(refreshToken);

        Boolean hasKey = this.redisTemplate.hasKey(cacheKey);
        return Boolean.FALSE.equals(hasKey);
    }

    @Override
    public void revoke(JwtToken refreshToken) {
        this.validate(refreshToken);
        final String cacheKey = buildKey(refreshToken);

        this.redisTemplate.delete(cacheKey);
    }

    @Override
    public void revokeAll(String subject) {
        ScanOptions scanOptions = ScanOptions.scanOptions()
                .count(DEFAULT_SCAN_COUNT)
                .match(String.format("%s%s:*", this.keyPrefix, subject))
                .build();
        Set<String> keys = new HashSet<>();
        try (Cursor<String> scan = this.redisTemplate.scan(scanOptions)) {
            while (scan.hasNext()) {
                keys.add(scan.next());
            }
        }
        this.redisTemplate.delete(keys);
    }
}
