package io.github.tsukasahwan.jwt.security.token;

import io.github.tsukasahwan.jwt.core.JwtToken;

/**
 * @author Teamo
 * @since 2025/4/11
 */
public interface RefreshTokenRevokeManager {

    /**
     * 保存刷新令牌
     *
     * @param refreshToken 刷新令牌
     */
    void save(JwtToken refreshToken);

    /**
     * 刷新令牌是否已被撤销
     *
     * @param refreshToken 刷新令牌
     * @return true 表示已被撤销
     */
    boolean isRevoked(JwtToken refreshToken);

    /**
     * 撤销刷新令牌
     *
     * @param refreshToken 刷新令牌
     */
    void revoke(JwtToken refreshToken);

    /**
     * 撤销指定主题的所有刷新令牌
     *
     * @param subject 主题（通常为用户名）
     */
    void revokeAll(String subject);
}
