package io.github.tsukasahwan.jwt.security.authentication;

import io.github.tsukasahwan.jwt.core.Jwt;
import io.github.tsukasahwan.jwt.core.token.AccessToken;
import io.github.tsukasahwan.jwt.core.token.RefreshToken;

/**
 * @author Teamo
 * @since 2025/4/11
 */
public interface JwtAuthenticationManager {

    /**
     * 登录
     *
     * @param subject 主体（通常为用户名）
     * @return {@link Jwt}
     */
    Jwt login(String subject);

    /**
     * 登录
     *
     * @param accessToken  {@link AccessToken}
     * @param refreshToken {@link RefreshToken}
     * @return {@link Jwt}
     */
    Jwt login(AccessToken accessToken, RefreshToken refreshToken);

    /**
     * 刷新
     *
     * @param subject           主体（通常为用户名）
     * @param refreshTokenValue 刷新令牌值
     * @return {@link Jwt}
     */
    Jwt refresh(String subject, String refreshTokenValue);

    /**
     * 刷新
     *
     * @param accessToken       访问令牌
     * @param refreshToken      刷新令牌
     * @param refreshTokenValue 刷新令牌值
     * @return {@link Jwt}
     */
    Jwt refresh(AccessToken accessToken, RefreshToken refreshToken, String refreshTokenValue);

    /**
     * 注销
     *
     * @param subject          主体（通常为用户名）
     * @param accessTokenValue 访问令牌值
     */
    void logout(String subject, String accessTokenValue);
}
