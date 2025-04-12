package com.github.TsukasaHwan.jwt.config.token;

import com.github.TsukasaHwan.jwt.config.properties.JwtSecurityProperties;
import com.github.TsukasaHwan.jwt.security.authentication.DefaultJwtAuthenticationManager;
import com.github.TsukasaHwan.jwt.security.authenticator.AccessTokenAuthenticator;
import com.github.TsukasaHwan.jwt.security.authenticator.RefreshTokenAuthenticator;
import com.github.TsukasaHwan.jwt.security.token.AccessTokenBlacklistManager;
import com.github.TsukasaHwan.jwt.security.token.RefreshTokenRevokeManager;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.util.Assert;

/**
 * @author Teamo
 * @since 2025/4/11
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(value = {JwtSecurityProperties.class})
@ConditionalOnProperty(value = "jwt.security.token-security.enabled", havingValue = "true")
@Import({AccessTokenBlacklistConfiguration.class, RefreshTokenRevokeConfiguration.class})
public class TokenSecurityConfiguration {

    public final JwtSecurityProperties jwtSecurityProperties;

    public TokenSecurityConfiguration(JwtSecurityProperties jwtSecurityProperties) {
        this.jwtSecurityProperties = jwtSecurityProperties;
    }

    @Autowired
    public void setAccessTokenAuthenticator(AccessTokenAuthenticator accessTokenAuthenticator,
                                            ObjectProvider<AccessTokenBlacklistManager> provider) {
        Boolean enabledAccessTokenBlacklist = jwtSecurityProperties.getTokenSecurity().getAccessTokenBlacklist().getEnabled();
        if (enabledAccessTokenBlacklist) {
            AccessTokenBlacklistManager blacklistManager = provider.getIfAvailable();
            Assert.notNull(blacklistManager, "AccessTokenBlacklistManager must be provided when 'jwt.security.token-security.access-token-blacklist.enabled' is true");
        }
        accessTokenAuthenticator.setEnabledAccessTokenBlacklist(enabledAccessTokenBlacklist);
        provider.ifAvailable(accessTokenAuthenticator::setAccessTokenBlacklistManager);
    }

    @Autowired
    public void setRefreshTokenAuthenticator(RefreshTokenAuthenticator refreshTokenAuthenticator,
                                             ObjectProvider<RefreshTokenRevokeManager> provider) {
        Boolean enabledRefreshTokenRevoke = jwtSecurityProperties.getTokenSecurity().getRefreshTokenRevoke().getEnabled();
        if (enabledRefreshTokenRevoke) {
            RefreshTokenRevokeManager revokeManager = provider.getIfAvailable();
            Assert.notNull(revokeManager, "RefreshTokenRevokeManager must be provided when 'jwt.security.token-security.refresh-token-revoke.enabled' is true");
        }
        refreshTokenAuthenticator.setEnabledRefreshTokenRevoke(enabledRefreshTokenRevoke);
        provider.ifAvailable(refreshTokenAuthenticator::setRefreshTokenRevokeManager);
    }

    @Autowired
    public void setJwtAuthenticationManager(DefaultJwtAuthenticationManager defaultJwtAuthenticationManager,
                                            ObjectProvider<AccessTokenBlacklistManager> blacklistProvider,
                                            ObjectProvider<RefreshTokenRevokeManager> revokeProvider) {
        JwtSecurityProperties.TokenSecurity tokenSecurity = jwtSecurityProperties.getTokenSecurity();
        Boolean enabledRefreshTokenRevoke = tokenSecurity.getRefreshTokenRevoke().getEnabled();
        Boolean enabledAccessTokenBlacklist = tokenSecurity.getAccessTokenBlacklist().getEnabled();
        if (enabledAccessTokenBlacklist) {
            AccessTokenBlacklistManager blacklistManager = blacklistProvider.getIfAvailable();
            Assert.notNull(blacklistManager, "AccessTokenBlacklistManager must be provided when 'jwt.security.token-security.access-token-blacklist.enabled' is true");
        }
        if (enabledRefreshTokenRevoke) {
            RefreshTokenRevokeManager revokeManager = revokeProvider.getIfAvailable();
            Assert.notNull(revokeManager, "RefreshTokenRevokeManager must be provided when 'jwt.security.token-security.refresh-token-revoke.enabled' is true");
        }
        defaultJwtAuthenticationManager.setEnabledRefreshTokenRevoke(enabledRefreshTokenRevoke);
        defaultJwtAuthenticationManager.setEnabledAccessTokenBlacklist(enabledAccessTokenBlacklist);
        revokeProvider.ifAvailable(defaultJwtAuthenticationManager::setRefreshTokenRevokeManager);
        blacklistProvider.ifAvailable(defaultJwtAuthenticationManager::setAccessTokenBlacklistManager);
    }
}
