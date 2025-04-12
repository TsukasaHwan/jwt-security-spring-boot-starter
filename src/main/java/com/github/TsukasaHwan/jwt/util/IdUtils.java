package com.github.TsukasaHwan.jwt.util;

import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

/**
 * @author Teamo
 * @since 2025/4/9
 */
public class IdUtils {

    /**
     * 使用加密的本地线程伪随机数生成器生成该 UUID。
     *
     * @return 随机生成的 {@code UUID}
     */
    public static UUID fastUUID() {
        ThreadLocalRandom random = ThreadLocalRandom.current();
        return new UUID(random.nextLong(), random.nextLong());
    }

    /**
     * 简化的UUID，去掉了横线，使用性能更好的ThreadLocalRandom生成UUID
     *
     * @return 简化的UUID，去掉了横线
     */
    public static String simpleUUID() {
        return fastUUID().toString().replace("-", "");
    }
}
