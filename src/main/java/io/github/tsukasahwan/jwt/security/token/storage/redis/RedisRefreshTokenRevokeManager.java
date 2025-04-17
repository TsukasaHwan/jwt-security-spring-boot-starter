package io.github.tsukasahwan.jwt.security.token.storage.redis;

import io.github.tsukasahwan.jwt.core.token.GenericJwtToken;
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
    public void save(String refreshToken) {
        GenericJwtToken genericJwtToken = validate(refreshToken);
        final String cacheKey = buildKey(genericJwtToken);
        Duration expireTime = Duration.between(Instant.now(), genericJwtToken.getExpiresAt());
        this.redisTemplate.opsForValue().set(cacheKey, refreshToken, expireTime);
    }

    @Override
    public boolean isRevoked(String refreshToken) {
        GenericJwtToken genericJwtToken = validate(refreshToken);
        final String cacheKey = buildKey(genericJwtToken);
        Boolean hasKey = this.redisTemplate.hasKey(cacheKey);
        return Boolean.FALSE.equals(hasKey);
    }

    @Override
    public void revoke(String refreshToken) {
        GenericJwtToken genericJwtToken = validate(refreshToken);
        final String cacheKey = buildKey(genericJwtToken);
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
