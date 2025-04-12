package io.github.tsukasahwan.jwt.security.authenticator;

import io.github.tsukasahwan.jwt.annotation.RefreshTokenApi;
import io.github.tsukasahwan.jwt.config.properties.JwtSecurityProperties;
import io.github.tsukasahwan.jwt.core.JwtToken;
import io.github.tsukasahwan.jwt.core.JwtTokenType;
import io.github.tsukasahwan.jwt.support.PathPatternRequestMatcher;
import io.github.tsukasahwan.jwt.util.ClassUtils;
import io.github.tsukasahwan.jwt.util.JwtUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.condition.PathPatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.RequestMethodsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @author Teamo
 * @since 2025/4/7
 */
public abstract class AbstractTokenAuthenticator implements InitializingBean, ApplicationContextAware {

    protected ApplicationContext context;

    protected final UserDetailsService userDetailsService;

    private static volatile PathPatternRequestMatcher sharedRefreshTokenMatcher;

    private static final AtomicBoolean INIT_FLAG = new AtomicBoolean(false);

    protected AbstractTokenAuthenticator(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    protected abstract JwtTokenType getTokenType();

    public abstract Authentication authenticate(HttpServletRequest request, JwtToken token);

    @Override
    public void afterPropertiesSet() throws Exception {
        if (INIT_FLAG.compareAndSet(false, true)) {
            JwtSecurityProperties properties = context.getBean(JwtSecurityProperties.class);

            if (properties.getEnabledRefreshTokenApiAnnotation()) {
                if (sharedRefreshTokenMatcher != null) {
                    return;
                }
                RequestMappingHandlerMapping handlerMapping = context.getBean(RequestMappingHandlerMapping.class);
                List<RequestMappingInfo> refreshTokenApiMapping = handlerMapping.getHandlerMethods().entrySet()
                        .stream()
                        .filter(entry -> Objects.nonNull(ClassUtils.getAnnotation(entry.getValue(), RefreshTokenApi.class)))
                        .map(Map.Entry::getKey)
                        .toList();

                Assert.state(refreshTokenApiMapping.size() < 2, "@RefreshTokenApi annotation can only be used once on a method");

                if (refreshTokenApiMapping.isEmpty()) {
                    return;
                }
                RequestMappingInfo requestMappingInfo = refreshTokenApiMapping.get(0);
                String path = extractPathFromRequestMapping(requestMappingInfo);
                RequestMethodsRequestCondition methodsCondition = requestMappingInfo.getMethodsCondition();
                Optional<RequestMethod> requestMethodOpt = methodsCondition.getMethods().stream().findFirst();
                requestMethodOpt.ifPresentOrElse(
                        requestMethod -> sharedRefreshTokenMatcher = createPathMatcher(requestMethod.asHttpMethod(), path),
                        () -> sharedRefreshTokenMatcher = createPathMatcher(null, path)
                );
            } else {
                sharedRefreshTokenMatcher = createPathMatcher(null, properties.getRefreshTokenPath());
            }
        }
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.context = applicationContext;
    }

    protected boolean isRefreshPath(HttpServletRequest request) {
        return sharedRefreshTokenMatcher != null &&
               sharedRefreshTokenMatcher.matches(request);
    }

    protected Authentication doAuthenticate(HttpServletRequest request, JwtToken jwtToken) {
        String authToken = jwtToken.getTokenValue();
        String username = jwtToken.getJws().getPayload().getSubject();
        SecurityContext securityContext = SecurityContextHolder.getContext();
        if (username != null && securityContext.getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            if (validateToken(authToken, userDetails.getUsername())) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, authToken, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                return authentication;
            }
        }
        return null;
    }

    private PathPatternRequestMatcher createPathMatcher(HttpMethod httpMethod, String refreshTokenPath) {
        return Optional.ofNullable(refreshTokenPath)
                .map(path -> PathPatternRequestMatcher.withDefaults().matcher(httpMethod, path))
                .orElse(null);
    }

    private String extractPathFromRequestMapping(RequestMappingInfo requestMappingInfo) {
        PathPatternsRequestCondition pathPatternsCondition = requestMappingInfo.getPathPatternsCondition();
        if (pathPatternsCondition == null) {
            PatternsRequestCondition patternsRequestCondition = requestMappingInfo.getPatternsCondition();
            if (patternsRequestCondition == null) {
                return null;
            }
            return patternsRequestCondition.getPatterns().stream().findFirst().orElse(null);
        } else {
            return pathPatternsCondition.getFirstPattern().getPatternString();
        }
    }

    private boolean validateToken(String token, String subject) {
        if (token == null || subject == null) {
            return false;
        }
        final String tokenSubject = JwtUtils.parseToken(token).getJws().getPayload().getSubject();
        return (tokenSubject != null && tokenSubject.equals(subject));
    }
}
