package com.github.TsukasaHwan.jwt.config.token.storage.caffeine;

import com.github.TsukasaHwan.jwt.config.properties.JwtSecurityProperties;
import com.github.TsukasaHwan.jwt.security.token.RefreshTokenRevokeManager;
import com.github.TsukasaHwan.jwt.security.token.storage.caffeine.CaffeineRefreshTokenRevokeManager;
import com.github.TsukasaHwan.jwt.support.CaffeineExpireValue;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author Teamo
 * @since 2025/4/9
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(Caffeine.class)
@ConditionalOnProperty(name = "jwt.security.token-security.storage-type", havingValue = "caffeine")
public class CaffeineRefreshTokenRevokeConfig extends CaffeineTokenStorageConfig {

    public CaffeineRefreshTokenRevokeConfig(JwtSecurityProperties jwtSecurityProperties) {
        super(jwtSecurityProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenRevokeManager refreshTokenRevokeManager(
            @Qualifier("jwtCaffeineCache") Cache<String, CaffeineExpireValue<Object>> jwtCaffeineCache) {
        String keyPrefix = this.getRevokeKeyPrefix();
        return new CaffeineRefreshTokenRevokeManager(keyPrefix, jwtCaffeineCache);
    }
}
