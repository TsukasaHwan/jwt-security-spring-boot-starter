package com.github.TsukasaHwan.jwt.support;

import java.time.Duration;

/**
 * @author Teamo
 * @since 2025/4/11
 */
public class CaffeineExpireValue<T> {

    private T value;

    private Duration ttl;

    public T getValue() {
        return value;
    }

    public void setValue(T value) {
        this.value = value;
    }

    public Duration getTtl() {
        return ttl;
    }

    public void setTtl(Duration ttl) {
        this.ttl = ttl;
    }
}
