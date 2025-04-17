package io.github.tsukasahwan.jwt.security.authentication;

import io.github.tsukasahwan.jwt.core.Jwt;
import io.github.tsukasahwan.jwt.core.JwtClaimsSet;
import io.github.tsukasahwan.jwt.core.JwtToken;

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
     * @param accessClaims  {@link JwtClaimsSet} 访问声明值
     * @param refreshClaims {@link JwtClaimsSet} 刷新声明值
     * @return {@link Jwt}
     */
    Jwt login(JwtClaimsSet accessClaims, JwtClaimsSet refreshClaims);

    /**
     * 刷新
     *
     * @param subject      主体（通常为用户名）
     * @param refreshToken 刷新令牌
     * @return {@link Jwt}
     */
    Jwt refresh(String subject, JwtToken refreshToken);

    /**
     * 刷新
     *
     * @param accessClaims  {@link JwtClaimsSet} 访问声明值
     * @param refreshClaims {@link JwtClaimsSet} 刷新声明值
     * @param refreshToken  刷新令牌
     * @return {@link Jwt}
     */
    Jwt refresh(JwtClaimsSet accessClaims, JwtClaimsSet refreshClaims, JwtToken refreshToken);

    /**
     * 注销
     *
     * @param subject     主体（通常为用户名）
     * @param accessToken 访问令牌
     */
    void logout(String subject, JwtToken accessToken);
}
