package io.github.tsukasahwan.jwt.config.token.storage.caffeine;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import io.github.tsukasahwan.jwt.config.properties.JwtSecurityProperties;
import io.github.tsukasahwan.jwt.config.token.storage.TokenSecurityStorageConfig;
import io.github.tsukasahwan.jwt.security.token.AccessTokenBlacklistManager;
import io.github.tsukasahwan.jwt.security.token.RefreshTokenRevokeManager;
import io.github.tsukasahwan.jwt.security.token.storage.caffeine.CaffeineAccessTokenBlacklistManager;
import io.github.tsukasahwan.jwt.security.token.storage.caffeine.CaffeineRefreshTokenRevokeManager;
import io.github.tsukasahwan.jwt.support.CaffeineExpireValue;
import org.checkerframework.checker.index.qual.NonNegative;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author Teamo
 * @since 2025/4/11
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(Caffeine.class)
@ConditionalOnProperty(name = "jwt.security.token-security.storage-type", havingValue = "caffeine")
public class CaffeineTokenStorageConfig extends TokenSecurityStorageConfig {

    public CaffeineTokenStorageConfig(JwtSecurityProperties jwtSecurityProperties) {
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

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(value = "jwt.security.token-security.access-token-blacklist.enabled", havingValue = "true")
    public AccessTokenBlacklistManager accessTokenBlacklistManager(
            @Qualifier("jwtCaffeineCache") Cache<String, CaffeineExpireValue<Object>> jwtCaffeineCache) {
        String keyPrefix = this.getBlacklistKeyPrefix();
        return new CaffeineAccessTokenBlacklistManager(keyPrefix, jwtCaffeineCache);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(value = "jwt.security.token-security.refresh-token-revoke.enabled", havingValue = "true")
    public RefreshTokenRevokeManager refreshTokenRevokeManager(
            @Qualifier("jwtCaffeineCache") Cache<String, CaffeineExpireValue<Object>> jwtCaffeineCache) {
        String keyPrefix = this.getRevokeKeyPrefix();
        return new CaffeineRefreshTokenRevokeManager(keyPrefix, jwtCaffeineCache);
    }
}
