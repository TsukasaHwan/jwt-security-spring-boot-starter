package io.github.tsukasahwan.jwt.security.authentication;

import io.github.tsukasahwan.jwt.core.Jwt;
import io.github.tsukasahwan.jwt.core.JwtClaimsSet;
import io.github.tsukasahwan.jwt.core.JwtGrantType;
import io.github.tsukasahwan.jwt.core.JwtToken;
import io.github.tsukasahwan.jwt.exception.InvalidTokenException;
import io.github.tsukasahwan.jwt.security.token.AccessTokenBlacklistManager;
import io.github.tsukasahwan.jwt.security.token.RefreshTokenRevokeManager;
import io.github.tsukasahwan.jwt.util.JwtUtils;

import java.util.Objects;

/**
 * @author Teamo
 * @since 2025/4/11
 */
public class DefaultJwtAuthenticationManager implements JwtAuthenticationManager {

    private boolean enabledRefreshTokenRevoke = false;

    private boolean enabledAccessTokenBlacklist = false;

    private RefreshTokenRevokeManager refreshTokenRevokeManager;

    private AccessTokenBlacklistManager accessTokenBlacklistManager;

    @Override
    public Jwt login(String subject) {
        JwtToken refreshToken = JwtUtils.refreshToken(subject);

        this.saveRefreshTokenIfEnabledRevoke(refreshToken);

        return this.create(JwtUtils.accessToken(subject), refreshToken);
    }

    @Override
    public Jwt login(JwtClaimsSet accessClaims, JwtClaimsSet refreshClaims) {
        this.validateClaims(accessClaims, refreshClaims);

        JwtToken refreshJwtToken = JwtUtils.token(refreshClaims);

        this.saveRefreshTokenIfEnabledRevoke(refreshJwtToken);

        return this.create(JwtUtils.token(accessClaims), refreshJwtToken);
    }

    @Override
    public Jwt refresh(String subject, JwtToken refreshToken) {
        this.validateTokenSubject(subject, refreshToken);

        this.revokeRefreshTokenIfEnabled(refreshToken);

        JwtToken newRefreshJwtToken = JwtUtils.refreshToken(subject);
        this.saveRefreshTokenIfEnabledRevoke(newRefreshJwtToken);

        JwtToken newAccessJwtToken = JwtUtils.accessToken(subject);
        return this.create(newAccessJwtToken, newRefreshJwtToken);
    }

    @Override
    public Jwt refresh(JwtClaimsSet accessClaims, JwtClaimsSet refreshClaims, JwtToken refreshToken) {
        this.validateClaims(accessClaims, refreshClaims);
        this.validateTokenSubject(accessClaims.getSubject(), refreshToken);

        this.revokeRefreshTokenIfEnabled(refreshToken);

        JwtToken newRefreshToken = JwtUtils.token(refreshClaims);
        this.saveRefreshTokenIfEnabledRevoke(newRefreshToken);

        JwtToken newAccessToken = JwtUtils.token(accessClaims);
        return this.create(newAccessToken, newRefreshToken);
    }

    @Override
    public void logout(String subject, JwtToken accessToken) {
        this.validateTokenSubject(subject, accessToken);

        this.revokeAllRefreshTokenIfEnabled(subject);
        this.addAccessTokenToBlacklistIfEnabled(accessToken);
    }

    private void validateClaims(JwtClaimsSet accessClaims, JwtClaimsSet refreshClaims) {
        if (accessClaims == null) {
            throw new IllegalArgumentException("AccessToken cannot be null");
        }
        if (refreshClaims == null) {
            throw new IllegalArgumentException("RefreshToken cannot be null");
        }

        if (!accessClaims.getGrantType().equals(JwtGrantType.ACCESS_TOKEN)) {
            throw new InvalidTokenException(String.format("Access token type mismatch (expected: %s, actual: %s)",
                    JwtGrantType.ACCESS_TOKEN,
                    accessClaims.getGrantType()));
        }
        if (!refreshClaims.getGrantType().equals(JwtGrantType.REFRESH_TOKEN)) {
            throw new InvalidTokenException(String.format("Refresh token type mismatch (expected: %s, actual: %s)",
                    JwtGrantType.REFRESH_TOKEN,
                    refreshClaims.getGrantType()));
        }

        String accessSubject = accessClaims.getSubject();
        String refreshSubject = refreshClaims.getSubject();
        if (!Objects.equals(accessSubject, refreshSubject)) {
            String message = String.format(
                    "Token subjects mismatch (Access token subject: %s, Refresh token subject: %s)",
                    accessSubject,
                    refreshSubject
            );
            throw new InvalidTokenException(message);
        }
    }

    /**
     * 验证用户主体与令牌中的主体标识是否匹配
     *
     * @param subject 用户主体标识（不可为null）
     * @param token   需要验证的令牌（不可为null）
     * @throws IllegalArgumentException 当主体或令牌为null时抛出
     * @throws InvalidTokenException    当主体不匹配时抛出
     */
    private void validateTokenSubject(String subject, JwtToken token) {
        if (subject == null) {
            throw new IllegalArgumentException("Subject cannot be null");
        }
        if (token == null) {
            throw new IllegalArgumentException("Token cannot be null");
        }
        String tokenSubject = token.getSubject();
        if (!Objects.equals(subject, tokenSubject)) {
            String grantType = token.getGrantType().getValue();
            String message = String.format(
                    "Subject mismatch (Provided: %s, Token subject: %s, Grant type: '%s')",
                    subject,
                    tokenSubject,
                    grantType
            );
            throw new InvalidTokenException(message);
        }
    }

    /**
     * 创建{@link Jwt}
     *
     * @param accessToken  访问令牌
     * @param refreshToken 刷新令牌
     * @return {@link Jwt}
     */
    private Jwt create(JwtToken accessToken, JwtToken refreshToken) {
        return Jwt.builder()
                .accessToken(accessToken.getTokenValue())
                .refreshToken(refreshToken.getTokenValue())
                .expiresIn(accessToken.getExpiresAt().toEpochMilli())
                .build();
    }

    public boolean isEnabledRefreshTokenRevoke() {
        return enabledRefreshTokenRevoke;
    }

    public void setEnabledRefreshTokenRevoke(boolean enabledRefreshTokenRevoke) {
        this.enabledRefreshTokenRevoke = enabledRefreshTokenRevoke;
    }

    public boolean isEnabledAccessTokenBlacklist() {
        return enabledAccessTokenBlacklist;
    }

    public void setEnabledAccessTokenBlacklist(boolean enabledAccessTokenBlacklist) {
        this.enabledAccessTokenBlacklist = enabledAccessTokenBlacklist;
    }

    public RefreshTokenRevokeManager getRefreshTokenRevokeManager() {
        return refreshTokenRevokeManager;
    }

    public void setRefreshTokenRevokeManager(RefreshTokenRevokeManager refreshTokenRevokeManager) {
        this.refreshTokenRevokeManager = refreshTokenRevokeManager;
    }

    public AccessTokenBlacklistManager getAccessTokenBlacklistManager() {
        return accessTokenBlacklistManager;
    }

    public void setAccessTokenBlacklistManager(AccessTokenBlacklistManager accessTokenBlacklistManager) {
        this.accessTokenBlacklistManager = accessTokenBlacklistManager;
    }

    /**
     * 当启用刷新令牌撤销功能时，保存指定的刷新令牌以备后续撤销
     *
     * @param refreshToken 需要保存的刷新令牌
     *                     仅在启用刷新令牌撤销功能时执行实际存储操作
     */
    private void saveRefreshTokenIfEnabledRevoke(JwtToken refreshToken) {
        if (this.enabledRefreshTokenRevoke) {
            this.refreshTokenRevokeManager.save(refreshToken);
        }
    }

    /**
     * 当启用刷新令牌撤销功能时，撤销指定的刷新令牌
     *
     * @param refreshToken 需要撤销的刷新令牌
     *                     仅在启用刷新令牌撤销功能时执行实际撤销操作
     */
    private void revokeRefreshTokenIfEnabled(JwtToken refreshToken) {
        if (this.enabledRefreshTokenRevoke) {
            this.refreshTokenRevokeManager.revoke(refreshToken);
        }
    }

    /**
     * 当启用刷新令牌撤销功能时，撤销指定主体关联的所有刷新令牌
     *
     * @param subject 用户主体标识符（通常为用户名）
     *                用于查找并撤销该用户关联的所有刷新令牌
     *                仅在启用刷新令牌撤销功能时执行实际批量撤销操作
     */
    private void revokeAllRefreshTokenIfEnabled(String subject) {
        if (this.enabledRefreshTokenRevoke) {
            this.refreshTokenRevokeManager.revokeAll(subject);
        }
    }

    /**
     * 当启用访问令牌黑名单功能时，将指定的访问令牌加入黑名单
     *
     * @param accessToken 需要加入黑名单的访问令牌
     *                    仅在启用访问令牌黑名单功能时执行实际添加操作
     */
    private void addAccessTokenToBlacklistIfEnabled(JwtToken accessToken) {
        if (this.enabledAccessTokenBlacklist) {
            this.accessTokenBlacklistManager.addToBlacklist(accessToken);
        }
    }
}
