package io.github.tsukasahwan.jwt.security.token;

/**
 * @author Teamo
 * @since 2025/4/11
 */
public interface AccessTokenBlacklistManager {

    /**
     * 将访问令牌添加到黑名单中
     *
     * @param accessToken 访问令牌
     */
    void addToBlacklist(String accessToken);

    /**
     * 检查访问令牌是否在黑名单中
     *
     * @param accessToken 访问令牌
     * @return 如果访问令牌在黑名单中，则返回true，否则返回false
     */
    boolean isBlacklisted(String accessToken);
}
