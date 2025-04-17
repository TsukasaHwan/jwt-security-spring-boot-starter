package io.github.tsukasahwan.jwt.security.authentication;

import io.github.tsukasahwan.jwt.core.Jwt;
import io.github.tsukasahwan.jwt.core.token.AccessToken;
import io.github.tsukasahwan.jwt.core.token.GenericJwtToken;
import io.github.tsukasahwan.jwt.core.token.RefreshToken;
import io.github.tsukasahwan.jwt.exception.InvalidTokenException;
import io.github.tsukasahwan.jwt.security.token.AccessTokenBlacklistManager;
import io.github.tsukasahwan.jwt.security.token.RefreshTokenRevokeManager;
import io.github.tsukasahwan.jwt.util.JwtUtils;

import java.time.Instant;
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
        String refreshTokenValue = JwtUtils.refreshToken(subject);

        saveRefreshTokenIfEnabledRevoke(refreshTokenValue);

        return create(JwtUtils.accessToken(subject), refreshTokenValue);
    }

    @Override
    public Jwt login(AccessToken accessToken, RefreshToken refreshToken) {
        validateToken(accessToken, refreshToken);

        String refreshTokenValue = JwtUtils.refreshToken(refreshToken);

        saveRefreshTokenIfEnabledRevoke(refreshTokenValue);

        return create(JwtUtils.accessToken(accessToken), refreshTokenValue);
    }

    @Override
    public Jwt refresh(String subject, String refreshTokenValue) {
        validateTokenSubject(subject, refreshTokenValue);

        revokeRefreshTokenIfEnabled(refreshTokenValue);

        String newRefreshToken = JwtUtils.refreshToken(subject);
        saveRefreshTokenIfEnabledRevoke(newRefreshToken);

        String newAccessToken = JwtUtils.accessToken(subject);
        return create(newAccessToken, newRefreshToken);
    }

    @Override
    public Jwt refresh(AccessToken accessToken, RefreshToken refreshToken, String refreshTokenValue) {
        validateToken(accessToken, refreshToken);
        validateTokenSubject(accessToken.getSubject(), refreshTokenValue);

        revokeRefreshTokenIfEnabled(refreshTokenValue);

        String newRefreshToken = JwtUtils.refreshToken(refreshToken);
        saveRefreshTokenIfEnabledRevoke(newRefreshToken);

        String newAccessToken = JwtUtils.accessToken(accessToken);
        return create(newAccessToken, newRefreshToken);
    }

    @Override
    public void logout(String subject, String accessTokenValue) {
        validateTokenSubject(subject, accessTokenValue);

        revokeAllRefreshTokenIfEnabled(subject);
        addAccessTokenToBlacklistIfEnabled(accessTokenValue);
    }

    /**
     * 验证访问令牌和刷新令牌的有效性
     *
     * @param accessToken  需要验证的访问令牌对象（不可为null）
     * @param refreshToken 需要验证的刷新令牌对象（不可为null）
     * @throws IllegalArgumentException 当任一令牌参数为null时抛出
     * @throws InvalidTokenException    当令牌主题不一致时抛出
     */
    private void validateToken(AccessToken accessToken, RefreshToken refreshToken) {
        if (accessToken == null) {
            throw new IllegalArgumentException("AccessToken cannot be null");
        }
        if (refreshToken == null) {
            throw new IllegalArgumentException("RefreshToken cannot be null");
        }
        String accessSubject = accessToken.getSubject();
        String refreshSubject = refreshToken.getSubject();
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
     * @param subject    用户主体标识（不可为null）
     * @param tokenValue 需要验证的令牌字符串（不可为null）
     * @throws IllegalArgumentException 当主体或令牌值为null时抛出
     * @throws InvalidTokenException    当令牌解析失败或主体不匹配时抛出
     */
    private void validateTokenSubject(String subject, String tokenValue) {
        if (subject == null) {
            throw new IllegalArgumentException("Subject cannot be null");
        }
        if (tokenValue == null) {
            throw new IllegalArgumentException("Token value cannot be null");
        }
        GenericJwtToken genericJwtToken = JwtUtils.parseToken(tokenValue).getGenericJwtToken();
        String tokenSubject = genericJwtToken.getSubject();
        if (!Objects.equals(subject, tokenSubject)) {
            String tokenType = genericJwtToken.getTokenType().getValue();
            String message = String.format(
                    "Subject mismatch (Provided: %s, Token subject: %s, Token type: '%s')",
                    subject,
                    tokenSubject,
                    tokenType
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
    private Jwt create(String accessToken, String refreshToken) {
        Instant expiresAt = JwtUtils.parseToken(accessToken)
                .getGenericJwtToken()
                .getExpiresAt();
        return Jwt.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(expiresAt.toEpochMilli())
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
     * @param refreshTokenValue 需要保存的刷新令牌字符串值
     *                          仅在启用刷新令牌撤销功能时执行实际存储操作
     */
    private void saveRefreshTokenIfEnabledRevoke(String refreshTokenValue) {
        if (this.enabledRefreshTokenRevoke) {
            this.refreshTokenRevokeManager.save(refreshTokenValue);
        }
    }

    /**
     * 当启用刷新令牌撤销功能时，撤销指定的刷新令牌
     *
     * @param refreshTokenValue 需要撤销的刷新令牌字符串值
     *                          仅在启用刷新令牌撤销功能时执行实际撤销操作
     */
    private void revokeRefreshTokenIfEnabled(String refreshTokenValue) {
        if (this.enabledRefreshTokenRevoke) {
            this.refreshTokenRevokeManager.revoke(refreshTokenValue);
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
     * @param accessTokenValue 需要加入黑名单的访问令牌字符串值
     *                         仅在启用访问令牌黑名单功能时执行实际添加操作
     */
    private void addAccessTokenToBlacklistIfEnabled(String accessTokenValue) {
        if (this.enabledAccessTokenBlacklist) {
            this.accessTokenBlacklistManager.addToBlacklist(accessTokenValue);
        }
    }
}
