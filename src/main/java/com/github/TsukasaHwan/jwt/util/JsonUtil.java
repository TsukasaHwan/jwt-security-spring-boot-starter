package com.github.TsukasaHwan.jwt.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Jackson工具类
 *
 * @author Teamo
 */
public class JsonUtil {

    private static final Logger log = LoggerFactory.getLogger(JsonUtil.class);

    /**
     * 将对象序列化成json字符串
     *
     * @param value javaBean
     * @param <T>   T 泛型标记
     * @return jsonString json字符串
     */
    public static <T> String toJson(T value) {
        try {
            return getInstance().writeValueAsString(value);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    /**
     * 将json字符串转成对象
     *
     * @param json      json字符串
     * @param valueType 对象类型
     * @param <T>       泛型标记
     * @return 转换后的对象
     */
    public static <T> T fromJson(String json, Class<T> valueType) {
        try {
            return getInstance().readValue(json, valueType);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    /**
     * jackson 的类型转换
     *
     * @param fromValue   来源对象
     * @param toValueType 转换的类型
     * @param <T>         泛型标记
     * @return 转换结果
     */
    public static <T> T convertValue(Object fromValue, Class<T> toValueType) {
        return getInstance().convertValue(fromValue, toValueType);
    }

    public static ObjectMapper getInstance() {
        return JacksonHolder.INSTANCE;
    }

    private static class JacksonHolder {
        private static final ObjectMapper INSTANCE = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }
}
