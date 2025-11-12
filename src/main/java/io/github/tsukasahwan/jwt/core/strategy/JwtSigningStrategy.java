package io.github.tsukasahwan.jwt.core.strategy;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;

/**
 * @author Teamo
 * @since 2025/11/12
 */
public interface JwtSigningStrategy {

    /**
     * 创建JWS头部
     *
     * @return JWS头部
     */
    JWSHeader createJWSHeader();

    /**
     * 创建签名器
     *
     * @return 签名器
     */
    JWSSigner createSigner();

    /**
     * 创建验证器
     *
     * @return 验证器
     */
    JWSVerifier createVerifier();
}
