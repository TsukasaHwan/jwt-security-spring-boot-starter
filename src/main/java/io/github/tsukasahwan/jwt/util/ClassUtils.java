package io.github.tsukasahwan.jwt.util;

import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.method.HandlerMethod;

import java.lang.annotation.Annotation;

/**
 * @author Teamo
 * @since 2025/4/7
 */
public class ClassUtils {

    /**
     * 获取Annotation
     *
     * @param handlerMethod  HandlerMethod
     * @param annotationType 注解类
     * @param <A>            泛型标记
     * @return {Annotation}
     */
    public static <A extends Annotation> A getAnnotation(HandlerMethod handlerMethod, Class<A> annotationType) {
        A annotation = handlerMethod.getMethodAnnotation(annotationType);
        if (null != annotation) {
            return annotation;
        }
        Class<?> beanType = handlerMethod.getBeanType();
        return AnnotatedElementUtils.findMergedAnnotation(beanType, annotationType);
    }

}
