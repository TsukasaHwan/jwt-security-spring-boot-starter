package io.github.tsukasahwan.jwt.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpHeaders;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;

/**
 * JWT安全配置属性类
 *
 * <p>通过 {@code @ConfigurationProperties("jwt.security")} 绑定配置文件参数，
 * 用于集中管理JWT认证相关的各项配置。</p>
 *
 * @author Teamo
 * @since 2023/3/14
 */
@ConfigurationProperties("jwt.security")
public class JwtSecurityProperties {

    /**
     * Token自定义请求头
     */
    private String header = HttpHeaders.AUTHORIZATION;

    /**
     * Token前缀
     */
    private String tokenPrefix;

    /**
     * Token过期时间（默认30分钟）
     */
    private Duration expiresIn = Duration.ofMinutes(30L);

    /**
     * RefreshToken过期时间（默认15天）
     */
    private Duration refreshTokenExpiresIn = Duration.ofDays(15L);

    /**
     * RefreshToken资源路径
     */
    private String refreshTokenPath;

    /**
     * 是否启用基于@RefreshTokenApi注解的配置
     * 启用后，refreshTokenPath配置将失效，改为动态使用@RefreshTokenApi注解映射的端点路径
     */
    private Boolean enabledRefreshTokenApiAnnotation;

    /**
     * 允许匿名访问的资源路径
     */
    private List<String> permitAllPaths = List.of("/error");

    /**
     * 密钥配置
     */
    private Secret secret = new Secret();

    /**
     * 令牌安全配置
     */
    private TokenSecurity tokenSecurity = new TokenSecurity();

    public static class TokenSecurity {

        /**
         * 是否启用令牌安全配置
         */
        private Boolean enabled = false;

        /**
         * 存储类型
         */
        private StorageType storageType;

        /**
         * 刷新令牌撤销配置
         */
        private RefreshTokenRevoke refreshTokenRevoke = new RefreshTokenRevoke();

        /**
         * 访问令牌黑名单配置
         */
        private AccessTokenBlacklist accessTokenBlacklist = new AccessTokenBlacklist();

        public Boolean getEnabled() {
            return enabled;
        }

        public void setEnabled(Boolean enabled) {
            this.enabled = enabled;
        }

        public StorageType getStorageType() {
            return storageType;
        }

        public void setStorageType(StorageType storageType) {
            this.storageType = storageType;
        }

        public RefreshTokenRevoke getRefreshTokenRevoke() {
            return refreshTokenRevoke;
        }

        public void setRefreshTokenRevoke(RefreshTokenRevoke refreshTokenRevoke) {
            this.refreshTokenRevoke = refreshTokenRevoke;
        }

        public AccessTokenBlacklist getAccessTokenBlacklist() {
            return accessTokenBlacklist;
        }

        public void setAccessTokenBlacklist(AccessTokenBlacklist accessTokenBlacklist) {
            this.accessTokenBlacklist = accessTokenBlacklist;
        }

        public enum StorageType {

            /**
             * 使用Redis存储RevokedRefreshToken
             */
            REDIS,

            /**
             * 使用内存存储RevokedRefreshToken
             */
            CAFFEINE

        }

        public static class RefreshTokenRevoke {

            /**
             * 是否启用刷新令牌撤销功能
             */
            private Boolean enabled = false;

            private String keyPrefix = "jwt:refresh_token:";

            public String getKeyPrefix() {
                return keyPrefix;
            }

            public void setKeyPrefix(String keyPrefix) {
                this.keyPrefix = keyPrefix;
            }

            public Boolean getEnabled() {
                return enabled;
            }

            public void setEnabled(Boolean enabled) {
                this.enabled = enabled;
            }
        }

        public static class AccessTokenBlacklist {

            /**
             * 是否启用访问令牌黑名单功能
             */
            private Boolean enabled = false;

            private String keyPrefix = "jwt:access_token:blacklist:";

            public String getKeyPrefix() {
                return keyPrefix;
            }

            public void setKeyPrefix(String keyPrefix) {
                this.keyPrefix = keyPrefix;
            }

            public Boolean getEnabled() {
                return enabled;
            }

            public void setEnabled(Boolean enabled) {
                this.enabled = enabled;
            }
        }
    }

    public static class Secret {

        /**
         * JWT签名算法类型（默认RS256）
         */
        private AlgorithmType algorithm = AlgorithmType.RS256;

        /**
         * RSA公钥，支持 classpath: xxx.pub
         */
        private RSAPublicKey publicKey;

        /**
         * RSA私钥，支持 classpath: xxx.key
         */
        private RSAPrivateKey privateKey;

        /**
         * HMAC密钥，当algorithm为HS256时必填
         */
        private String hmacSecret;

        /**
         * JWT签名算法类型枚举
         */
        public enum AlgorithmType {
            /**
             * RSA非对称加密算法（使用SHA-256哈希）
             */
            RS256,

            /**
             * HMAC对称加密算法（使用SHA-256哈希）
             */
            HS256
        }

        public AlgorithmType getAlgorithm() {
            return algorithm;
        }

        public void setAlgorithm(AlgorithmType algorithm) {
            this.algorithm = algorithm;
        }

        public RSAPublicKey getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(RSAPublicKey publicKey) {
            this.publicKey = publicKey;
        }

        public RSAPrivateKey getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(RSAPrivateKey privateKey) {
            this.privateKey = privateKey;
        }

        public String getHmacSecret() {
            return hmacSecret;
        }

        public void setHmacSecret(String hmacSecret) {
            this.hmacSecret = hmacSecret;
        }
    }

    public String getHeader() {
        return header;
    }

    public void setHeader(String header) {
        this.header = header;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }

    public Duration getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(Duration expiresIn) {
        this.expiresIn = expiresIn;
    }

    public Duration getRefreshTokenExpiresIn() {
        return refreshTokenExpiresIn;
    }

    public void setRefreshTokenExpiresIn(Duration refreshTokenExpiresIn) {
        this.refreshTokenExpiresIn = refreshTokenExpiresIn;
    }

    public String getRefreshTokenPath() {
        return refreshTokenPath;
    }

    public void setRefreshTokenPath(String refreshTokenPath) {
        this.refreshTokenPath = refreshTokenPath;
    }

    public Boolean getEnabledRefreshTokenApiAnnotation() {
        return enabledRefreshTokenApiAnnotation;
    }

    public void setEnabledRefreshTokenApiAnnotation(Boolean enabledRefreshTokenApiAnnotation) {
        this.enabledRefreshTokenApiAnnotation = enabledRefreshTokenApiAnnotation;
    }

    public List<String> getPermitAllPaths() {
        return permitAllPaths;
    }

    public void setPermitAllPaths(List<String> permitAllPaths) {
        this.permitAllPaths = permitAllPaths;
    }

    public Secret getSecret() {
        return secret;
    }

    public void setSecret(Secret secret) {
        this.secret = secret;
    }

    public TokenSecurity getTokenSecurity() {
        return tokenSecurity;
    }

    public void setTokenSecurity(TokenSecurity tokenSecurity) {
        this.tokenSecurity = tokenSecurity;
    }
}
