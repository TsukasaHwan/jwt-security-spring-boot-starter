package io.github.tsukasahwan.jwt.security.authenticator;

import io.github.tsukasahwan.jwt.core.JwtGrantType;
import io.github.tsukasahwan.jwt.core.JwtToken;
import io.github.tsukasahwan.jwt.exception.RefreshTokenRevokedException;
import io.github.tsukasahwan.jwt.security.token.RefreshTokenRevokeManager;
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
    protected JwtGrantType getGrantType() {
        return JwtGrantType.REFRESH_TOKEN;
    }

    @Override
    public Authentication authenticate(HttpServletRequest request, JwtToken token) {
        if (!isRefreshPath(request)) {
            return null;
        }

        checkRefreshTokenIfEnabled(token);

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

    private void checkRefreshTokenIfEnabled(JwtToken refreshToken) {
        if (this.enabledRefreshTokenRevoke && this.refreshTokenRevokeManager.isRevoked(refreshToken)) {
            throw new RefreshTokenRevokedException("Refresh token has been revoked: " + refreshToken.getTokenValue());
        }
    }
}
