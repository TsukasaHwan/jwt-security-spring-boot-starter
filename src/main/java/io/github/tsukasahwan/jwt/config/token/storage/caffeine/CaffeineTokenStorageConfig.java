package io.github.tsukasahwan.jwt.config.token.storage.caffeine;

import io.github.tsukasahwan.jwt.config.properties.JwtSecurityProperties;
import io.github.tsukasahwan.jwt.config.token.storage.TokenSecurityStorageConfig;
import io.github.tsukasahwan.jwt.support.CaffeineExpireValue;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import org.checkerframework.checker.index.qual.NonNegative;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * @author Teamo
 * @since 2025/4/11
 */
abstract class CaffeineTokenStorageConfig extends TokenSecurityStorageConfig {

    protected CaffeineTokenStorageConfig(JwtSecurityProperties jwtSecurityProperties) {
        super(jwtSecurityProperties);
    }

    @Bean
    @ConditionalOnMissingBean(name = "jwtCaffeineCache")
    public Cache<String, CaffeineExpireValue<Object>> jwtCaffeineCache() {
        return Caffeine.newBuilder()
                .expireAfter(new Expiry<String, CaffeineExpireValue<Object>>() {
                    @Override
                    public long expireAfterCreate(String key, CaffeineExpireValue<Object> value, long currentTime) {
                        return value.getTtl().toNanos();
                    }

                    @Override
                    public long expireAfterUpdate(String key, CaffeineExpireValue<Object> value, long currentTime, @NonNegative long currentDuration) {
                        return currentDuration;
                    }

                    @Override
                    public long expireAfterRead(String key, CaffeineExpireValue<Object> value, long currentTime, @NonNegative long currentDuration) {
                        return currentDuration;
                    }
                }).build();
    }
}
