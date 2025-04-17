package io.github.tsukasahwan.jwt.core;

/**
 * @author Teamo
 * @since 2025/4/6
 */
public final class JwtClaimsNames {

    /**
     * {@code jti} - JWT ID声明为JWT提供唯一标识符
     */
    public static final String JTI = "jti";

    /**
     * {@code sub} - 主题声明标识作为JWT主题的主体
     */
    public static final String SUB = "sub";

    /**
     * {@code iat} - 在索赔处发出的索赔确定了JWT的发出时间
     */
    public static final String IAT = "iat";

    /**
     * {@code exp} - 过期时间声明标识过期时间，在该过期时间或之后，不得接受JWT进行处理
     */
    public static final String EXP = "exp";

    /**
     * {@code grant_type} - 授权类型
     */
    public static final String GRANT_TYPE = "grant_type";

}
