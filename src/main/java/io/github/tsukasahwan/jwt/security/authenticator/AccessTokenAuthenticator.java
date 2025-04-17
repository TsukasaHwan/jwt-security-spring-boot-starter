package io.github.tsukasahwan.jwt.security.authenticator;

import io.github.tsukasahwan.jwt.core.JwtGrantType;
import io.github.tsukasahwan.jwt.core.JwtToken;
import io.github.tsukasahwan.jwt.exception.AccessTokenBlacklistedException;
import io.github.tsukasahwan.jwt.security.token.AccessTokenBlacklistManager;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @author Teamo
 * @since 2025/4/7
 */
public class AccessTokenAuthenticator extends AbstractTokenAuthenticator {

    private AccessTokenBlacklistManager accessTokenBlacklistManager;

    private boolean enabledAccessTokenBlacklist = false;

    public AccessTokenAuthenticator(UserDetailsService userDetailsService) {
        super(userDetailsService);
    }

    @Override
    protected JwtGrantType getGrantType() {
        return JwtGrantType.ACCESS_TOKEN;
    }

    @Override
    public Authentication authenticate(HttpServletRequest request, JwtToken token) {
        if (isRefreshPath(request)) {
            return null;
        }

        checkBlacklistIfEnabled(token);

        return doAuthenticate(request, token);
    }

    public AccessTokenBlacklistManager getAccessTokenBlacklistManager() {
        return accessTokenBlacklistManager;
    }

    public void setAccessTokenBlacklistManager(AccessTokenBlacklistManager accessTokenBlacklistManager) {
        this.accessTokenBlacklistManager = accessTokenBlacklistManager;
    }

    public boolean isEnabledAccessTokenBlacklist() {
        return enabledAccessTokenBlacklist;
    }

    public void setEnabledAccessTokenBlacklist(boolean enabledAccessTokenBlacklist) {
        this.enabledAccessTokenBlacklist = enabledAccessTokenBlacklist;
    }

    private void checkBlacklistIfEnabled(JwtToken accessToken) {
        if (this.enabledAccessTokenBlacklist && this.accessTokenBlacklistManager.isBlacklisted(accessToken)) {
            throw new AccessTokenBlacklistedException("Access token is blacklisted: " + accessToken.getTokenValue());
        }
    }
}
