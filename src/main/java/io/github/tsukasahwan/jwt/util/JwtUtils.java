package io.github.tsukasahwan.jwt.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.tsukasahwan.jwt.config.properties.JwtSecurityProperties;
import io.github.tsukasahwan.jwt.core.JwtClaimNames;
import io.github.tsukasahwan.jwt.core.JwtClaimsSet;
import io.github.tsukasahwan.jwt.core.JwtGrantType;
import io.github.tsukasahwan.jwt.core.JwtToken;
import io.github.tsukasahwan.jwt.exception.ExpiredJwtException;
import io.github.tsukasahwan.jwt.exception.InvalidTokenException;
import io.github.tsukasahwan.jwt.filter.JwtAuthenticationFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Teamo
 * @since 2023/3/26
 */
public class JwtUtils {

    private static final char TOKEN_CONNECTOR_CHAT = ' ';

    private static final String DECODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to decode the Jwt: %s";

    private static final String ENCODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to encode the Jwt: %s";

    private static final JWSHeader DEFAULT_JWS_HEADER = new JWSHeader.Builder(JWSAlgorithm.RS256)
            .type(JOSEObjectType.JWT)
            .build();

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
    public static JwtToken accessToken(String subject) {
        Assert.hasText(subject, "'subject' must not be empty");
        Instant now = Instant.now();
        JwtClaimsSet accessClaims = JwtClaimsSet
                .withGrantType(JwtGrantType.ACCESS_TOKEN)
                .id(IdUtils.simpleUUID())
                .subject(subject)
                .issuedAt(now)
                .expiresAt(now.plus(properties.getExpiresIn()))
                .build();
        return token(accessClaims);
    }

    /**
     * 生成刷新令牌
     *
     * @param subject 主题（通常为用户名）
     * @return 刷新令牌
     */
    public static JwtToken refreshToken(String subject) {
        Assert.hasText(subject, "'subject' must not be empty");
        Instant now = Instant.now();
        JwtClaimsSet refreshClaims = JwtClaimsSet
                .withGrantType(JwtGrantType.REFRESH_TOKEN)
                .id(IdUtils.simpleUUID())
                .subject(subject)
                .issuedAt(now)
                .expiresAt(now.plus(properties.getRefreshTokenExpiresIn()))
                .build();
        return token(refreshClaims);
    }

    /**
     * 生成令牌
     *
     * @param claims 声明
     * @return 令牌
     */
    public static JwtToken token(JwtClaimsSet claims) {
        JwtClaimsSet checkedClaims = check(claims);
        String tokenValue = serialize(checkedClaims);
        return JwtToken.withTokenValue(tokenValue)
                .claims(c -> c.putAll(checkedClaims.getClaims()))
                .build();
    }

    /**
     * 解析令牌
     *
     * @param token 令牌
     * @return {@link JwtToken}
     */
    public static JwtToken parseToken(String token) {
        Assert.hasText(token, "'token' must not be empty");

        JWSObject jwsObject = parse(token);

        verify(jwsObject);

        JwtToken jwtToken = JwtToken.withTokenValue(token)
                .claims(c -> c.putAll(convert(jwsObject)))
                .build();

        validateJwtToken(jwtToken);

        return jwtToken;
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
        Map<String, Object> claims = getJwtToken().getClaims();
        return JsonUtil.convertValue(claims.get(name), claimType);
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

    private static String serialize(JwtClaimsSet claims) {
        Assert.notNull(claims, "claims must not be null");
        JWTClaimsSet jwtClaimsSet = convert(claims);

        SignedJWT signedJwt = new SignedJWT(DEFAULT_JWS_HEADER, jwtClaimsSet);
        JWSSigner jwsSigner = new RSASSASigner(properties.getSecret().getPrivateKey());
        try {
            signedJwt.sign(jwsSigner);
        } catch (JOSEException e) {
            throw new InvalidTokenException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
                    "Failed to sign the JWT -> " + e.getMessage()), e);
        }

        return signedJwt.serialize();
    }

    private static JwtClaimsSet check(JwtClaimsSet claims) {
        JwtClaimsSet.Builder from = JwtClaimsSet.from(claims);

        // check expiresAt
        Instant expiresAt = claims.getExpiresAt();
        if (expiresAt == null) {
            JwtGrantType grantType = claims.getGrantType();
            if (JwtGrantType.REFRESH_TOKEN.equals(grantType)) {
                from.expiresAt(Instant.now().plus(properties.getRefreshTokenExpiresIn()));
            } else {
                from.expiresAt(Instant.now().plus(properties.getExpiresIn()));
            }
        }

        // check jti
        String id = claims.getId();
        if (!StringUtils.hasText(id)) {
            from.id(IdUtils.simpleUUID());
        }

        return from.build();
    }

    private static JWTClaimsSet convert(JwtClaimsSet claims) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

        String subject = claims.getSubject();
        if (StringUtils.hasText(subject)) {
            builder.subject(subject);
        }

        Instant expiresAt = claims.getExpiresAt();
        if (expiresAt != null) {
            builder.expirationTime(Date.from(expiresAt));
        }

        Instant issuedAt = claims.getIssuedAt();
        if (issuedAt != null) {
            builder.issueTime(Date.from(issuedAt));
        }

        String jwtId = claims.getId();
        if (StringUtils.hasText(jwtId)) {
            builder.jwtID(jwtId);
        }

        Map<String, Object> customClaims = new HashMap<>();
        claims.getClaims().forEach((name, value) -> {
            if (!JWTClaimsSet.getRegisteredNames().contains(name)) {
                customClaims.put(name, value);
            }
        });
        if (!customClaims.isEmpty()) {
            customClaims.forEach(builder::claim);
        }

        return builder.build();
    }

    private static Map<String, Object> convert(JWSObject jwsObject) {
        Map<String, Object> claims = jwsObject.getPayload().toJSONObject();
        if (claims.containsKey(JwtClaimNames.IAT)) {
            claims.put(JwtClaimNames.IAT, Instant.ofEpochSecond((Long) claims.get(JwtClaimNames.IAT)));
        }
        if (claims.containsKey(JwtClaimNames.EXP)) {
            claims.put(JwtClaimNames.EXP, Instant.ofEpochSecond((Long) claims.get(JwtClaimNames.EXP)));
        }
        if (claims.containsKey(JwtClaimNames.GRANT_TYPE)) {
            claims.put(JwtClaimNames.GRANT_TYPE, JsonUtil.convertValue(claims.get(JwtClaimNames.GRANT_TYPE), JwtGrantType.class));
        }
        return claims;
    }

    private static JWSObject parse(String token) {
        JWSObject jwsObject;
        try {
            jwsObject = JWSObject.parse(token);
        } catch (Exception e) {
            if (e instanceof ParseException) {
                throw new InvalidTokenException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE,
                        "Malformed token"), e);
            }
            throw new InvalidTokenException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE,
                    e.getMessage()), e);
        }
        return jwsObject;
    }

    private static void verify(JWSObject jwsObject) {
        JWSVerifier jwsVerifier = new RSASSAVerifier(properties.getSecret().getPublicKey());

        boolean verify;
        try {
            verify = jwsObject.verify(jwsVerifier);
        } catch (JOSEException | IllegalStateException e) {
            throw new InvalidTokenException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE,
                    e.getMessage()), e);
        }

        if (!verify) {
            throw new InvalidTokenException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE,
                    "Invalid JWT signature"));
        }
    }

    private static void validateJwtToken(JwtToken jwtToken) {
        if (jwtToken.getGrantType() == null) {
            throw new InvalidTokenException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE,
                    "Missing required claim: grant_type"));
        }
        Instant expiresAt = jwtToken.getExpiresAt();
        if (expiresAt != null && expiresAt.isBefore(Instant.now())) {
            throw new ExpiredJwtException("JWT expired at: " + expiresAt);
        }
    }

}
