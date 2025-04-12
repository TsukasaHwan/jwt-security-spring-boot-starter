package io.github.tsukasahwan.jwt.config.token.storage.caffeine;

import io.github.tsukasahwan.jwt.config.properties.JwtSecurityProperties;
import io.github.tsukasahwan.jwt.security.token.RefreshTokenRevokeManager;
import io.github.tsukasahwan.jwt.security.token.storage.caffeine.CaffeineRefreshTokenRevokeManager;
import io.github.tsukasahwan.jwt.support.CaffeineExpireValue;
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
