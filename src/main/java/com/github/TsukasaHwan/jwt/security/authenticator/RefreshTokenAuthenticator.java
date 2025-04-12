package com.github.TsukasaHwan.jwt.security.authenticator;

import com.github.TsukasaHwan.jwt.core.JwtToken;
import com.github.TsukasaHwan.jwt.core.JwtTokenType;
import com.github.TsukasaHwan.jwt.exception.RefreshTokenRevokedException;
import com.github.TsukasaHwan.jwt.security.token.RefreshTokenRevokeManager;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @author Teamo
 * @since 2025/4/7
 */
public class RefreshTokenAuthenticator extends AbstractTokenAuthenticator {

    private RefreshTokenRevokeManager refreshTokenRevokeManager;

    private boolean enabledRefreshTokenRevoke = false;

    public RefreshTokenAuthenticator(UserDetailsService userDetailsService) {
        super(userDetailsService);
    }

    @Override
    protected JwtTokenType getTokenType() {
        return JwtTokenType.REFRESH_TOKEN;
    }

    @Override
    public Authentication authenticate(HttpServletRequest request, JwtToken token) {
        if (!isRefreshPath(request)) {
            return null;
        }

        checkRefreshTokenIfEnabled(token.getTokenValue());

        return doAuthenticate(request, token);
    }

    public RefreshTokenRevokeManager getRefreshTokenRevokeManager() {
        return refreshTokenRevokeManager;
    }

    public void setRefreshTokenRevokeManager(RefreshTokenRevokeManager refreshTokenRevokeManager) {
        this.refreshTokenRevokeManager = refreshTokenRevokeManager;
    }

    public boolean isEnabledRefreshTokenRevoke() {
        return enabledRefreshTokenRevoke;
    }

    public void setEnabledRefreshTokenRevoke(boolean enabledRefreshTokenRevoke) {
        this.enabledRefreshTokenRevoke = enabledRefreshTokenRevoke;
    }

    private void checkRefreshTokenIfEnabled(String refreshToken) {
        if (this.enabledRefreshTokenRevoke && this.refreshTokenRevokeManager.isRevoked(refreshToken)) {
            throw new RefreshTokenRevokedException("Refresh token has been revoked: " + refreshToken);
        }
    }
}
