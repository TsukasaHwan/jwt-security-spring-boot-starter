package io.github.tsukasahwan.jwt.util;

import io.github.tsukasahwan.jwt.config.properties.JwtSecurityProperties;
import io.github.tsukasahwan.jwt.core.AbstractToken;
import io.github.tsukasahwan.jwt.core.JwtClaimsNames;
import io.github.tsukasahwan.jwt.core.JwtToken;
import io.github.tsukasahwan.jwt.core.JwtTokenType;
import io.github.tsukasahwan.jwt.core.token.AccessToken;
import io.github.tsukasahwan.jwt.core.token.GenericJwtToken;
import io.github.tsukasahwan.jwt.core.token.RefreshToken;
import io.github.tsukasahwan.jwt.filter.JwtAuthenticationFilter;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.jackson.io.JacksonDeserializer;
import io.jsonwebtoken.jackson.io.JacksonSerializer;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.Assert;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

/**
 * @author Teamo
 * @since 2023/3/26
 */
public class JwtUtils {

    private static final char TOKEN_CONNECTOR_CHAT = ' ';

    private static JwtSecurityProperties properties;

    public JwtUtils(JwtSecurityProperties properties) {
        JwtUtils.properties = properties;
    }

    /**
     * 生成访问令牌
     *
     * @param subject 主题（通常为用户名）
     * @return 访问令牌
     */
    public static String accessToken(String subject) {
        Assert.hasText(subject, "'subject' must not be empty");
        AccessToken accessToken = AccessToken.builder()
                .subject(subject)
                .build();
        return accessToken(accessToken);
    }

    /**
     * 生成访问令牌
     *
     * @param accessToken {@link AccessToken}
     * @return 访问令牌
     */
    public static String accessToken(AccessToken accessToken) {
        return token(accessToken, properties.getExpiresIn());
    }

    /**
     * 生成刷新令牌
     *
     * @param subject 主题（通常为用户名）
     * @return 刷新令牌
     */
    public static String refreshToken(String subject) {
        Assert.hasText(subject, "'subject' must not be empty");
        RefreshToken refreshToken = RefreshToken.builder()
                .subject(subject)
                .build();
        return refreshToken(refreshToken);
    }

    /**
     * 生成刷新令牌
     *
     * @param refreshToken {@link RefreshToken}
     * @return 刷新令牌
     */
    public static String refreshToken(RefreshToken refreshToken) {
        return token(refreshToken, properties.getRefreshTokenExpiresIn());
    }

    /**
     * 生成自定义令牌
     * 如果为刷新令牌则使用刷新令牌配置的过期时间，否则使用令牌配置的过期时间
     *
     * @param genericJwtToken {@link GenericJwtToken}
     * @return 令牌
     */
    public static String token(GenericJwtToken genericJwtToken) {
        Assert.notNull(genericJwtToken, "'token' must not be null");
        Map<String, Object> claims = genericJwtToken.getClaims();
        JwtTokenType tokenType = (JwtTokenType) claims.get(JwtClaimsNames.GRANT_TYPE);
        if (JwtTokenType.REFRESH_TOKEN.equals(tokenType)) {
            return token(genericJwtToken, properties.getRefreshTokenExpiresIn());
        }
        return token(genericJwtToken, properties.getExpiresIn());
    }

    /**
     * 解析令牌
     *
     * @param token 令牌
     * @return {@link JwtToken}
     */
    public static JwtToken parseToken(String token) {
        Assert.hasText(token, "'token' must not be empty");
        Jws<Claims> jws = Jwts.parser()
                .json(new JacksonDeserializer<>())
                .verifyWith(properties.getSecret().getPublicKey())
                .clockSkewSeconds(properties.getAllowedClockSkew().getSeconds())
                .build()
                .parseSignedClaims(token);

        return JwtToken.withTokenValue(token)
                .jws(jws)
                .build();
    }

    /**
     * 提取令牌
     *
     * @param token 令牌
     * @return 不带前缀的令牌，如果入参为 null 则返回 null，
     * 如果未配置前缀则返回原值，如果前缀不匹配则返回 null 否则返回去除前缀后的令牌
     */
    public static String extractToken(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }
        String tokenPrefix = getTokenPrefix();
        if (tokenPrefix == null) {
            return token;
        }
        if (!token.startsWith(tokenPrefix)) {
            return null;
        }
        return token.substring(tokenPrefix.length()).trim();
    }

    /**
     * 获取指定请求的令牌
     *
     * @param request HTTP请求
     * @return 去除前缀后的令牌
     */
    public static String getTokenValue(HttpServletRequest request) {
        Assert.notNull(request, "HttpServletRequest must not be null");
        String token = request.getHeader(getTokenHeader());
        return extractToken(token);
    }

    /**
     * 获取当前请求的令牌
     *
     * @return 去除前缀后的令牌
     */
    public static String getTokenValue() {
        return getTokenValue(WebUtils.getRequest());
    }

    /**
     * 获取指定请求的声明
     *
     * @param request HTTP请求
     * @return {@link JwtToken}
     */
    public static JwtToken getJwtToken(HttpServletRequest request) {
        Assert.notNull(request, "HttpServletRequest must not be null");
        JwtToken jwtToken = (JwtToken) request.getAttribute(JwtAuthenticationFilter.JWT_TOKEN);
        if (jwtToken == null) {
            jwtToken = parseToken(getTokenValue(request));
            request.setAttribute(JwtAuthenticationFilter.JWT_TOKEN, jwtToken);
        }
        return jwtToken;
    }

    /**
     * 获取当前请求的JWT令牌
     *
     * @return {@link JwtToken}
     */
    public static JwtToken getJwtToken() {
        return getJwtToken(WebUtils.getRequest());
    }

    /**
     * 获取当前请求的声明值
     *
     * @param name      声明名称
     * @param claimType 声明类型
     * @param <T>       声明类型
     * @return 声明值
     */
    public static <T> T getTokenClaimValue(String name, Class<T> claimType) {
        Assert.notNull(name, "Name must not be null");
        Assert.notNull(claimType, "Claim type must not be null");
        Claims currentClaims = getJwtToken().getJws().getPayload();
        return JsonUtil.convertValue(currentClaims.get(name), claimType);
    }

    /**
     * 获取令牌请求标头
     *
     * @return 令牌请求标头
     */
    public static String getTokenHeader() {
        return properties.getHeader();
    }

    /**
     * 获取令牌前缀
     *
     * @return 令牌前缀
     */
    public static String getTokenPrefix() {
        return properties.getTokenPrefix() != null ? properties.getTokenPrefix() + TOKEN_CONNECTOR_CHAT : null;
    }

    // -----------------------PRIVATE STATIC METHOD-----------------------

    /**
     * 生成令牌
     *
     * @param token     {@link AbstractToken}
     * @param expiresIn 过期时间
     * @return 令牌
     */
    private static String token(AbstractToken token, Duration expiresIn) {
        Assert.notNull(token, "'token' must not be null");
        Instant now = Instant.now();
        JwtBuilder jwtBuilder = Jwts.builder()
                .json(new JacksonSerializer<>())
                .header()
                .add(token.getHeader())
                .and()
                .claims(token.getClaims())
                .issuedAt(Date.from(now))
                .signWith(properties.getSecret().getPrivateKey());

        if (expiresIn != null) {
            jwtBuilder.expiration(Date.from(now.plus(expiresIn)));
        }

        return jwtBuilder.compact();
    }

}
