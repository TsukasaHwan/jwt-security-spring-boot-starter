package io.github.tsukasahwan.jwt.core;

import java.time.Instant;
import java.util.Map;

/**
 * @author Teamo
 * @since 2025/4/6
 */
public interface JwtClaimAccessor {

    Map<String, Object> getClaims();

    default String getId() {
        return (String) getClaims().get(JwtClaimNames.JTI);
    }

    default String getSubject() {
        return (String) getClaims().get(JwtClaimNames.SUB);
    }

    default Instant getIssuedAt() {
        return (Instant) getClaims().get(JwtClaimNames.IAT);
    }

    default Instant getExpiresAt() {
        return (Instant) getClaims().get(JwtClaimNames.EXP);
    }
}
