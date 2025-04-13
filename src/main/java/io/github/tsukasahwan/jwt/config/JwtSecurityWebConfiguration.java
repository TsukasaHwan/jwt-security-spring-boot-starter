package io.github.tsukasahwan.jwt.config;

import io.github.tsukasahwan.jwt.config.properties.JwtSecurityProperties;
import io.github.tsukasahwan.jwt.config.token.TokenSecurityConfiguration;
import io.github.tsukasahwan.jwt.filter.JwtAuthenticationFilter;
import io.github.tsukasahwan.jwt.security.authenticator.TokenAuthenticatorRegistry;
import io.github.tsukasahwan.jwt.security.context.TransmittableThreadLocalSecurityContextHolderStrategy;
import io.github.tsukasahwan.jwt.support.PathPatternRequestMatcher;
import io.github.tsukasahwan.jwt.util.ClassUtils;
import io.github.tsukasahwan.jwt.util.JwtUtils;
import jakarta.annotation.security.PermitAll;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.mvc.condition.PathPatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * @author Teamo
 * @since 2023/03/14
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(JwtSecurityProperties.class)
@EnableMethodSecurity(securedEnabled = true)
@Import({JwtSecurityCoreConfiguration.class, TokenSecurityConfiguration.class})
public class JwtSecurityWebConfiguration {

    private final JwtSecurityProperties jwtSecurityProperties;

    private final UserDetailsService userDetailsService;

    private final TokenAuthenticatorRegistry tokenAuthenticatorRegistry;

    private UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource;

    private AuthenticationSuccessHandler authenticationSuccessHandler;

    private AuthenticationEntryPoint authenticationEntryPoint;

    private AccessDeniedHandler accessDeniedHandler;

    private ApplicationContext context;

    public JwtSecurityWebConfiguration(JwtSecurityProperties jwtSecurityProperties,
                                       UserDetailsService userDetailsService,
                                       TokenAuthenticatorRegistry tokenAuthenticatorRegistry) {
        this.jwtSecurityProperties = jwtSecurityProperties;
        this.userDetailsService = userDetailsService;
        this.tokenAuthenticatorRegistry = tokenAuthenticatorRegistry;
    }

    @Autowired(required = false)
    public void setUrlBasedCorsConfigurationSource(UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource) {
        this.urlBasedCorsConfigurationSource = urlBasedCorsConfigurationSource;
    }

    @Autowired
    public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
        this.authenticationSuccessHandler = authenticationSuccessHandler;
    }

    @Autowired
    public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Autowired
    public void setAccessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
        this.accessDeniedHandler = accessDeniedHandler;
    }

    @Autowired
    public void setApplicationContext(ApplicationContext context) {
        this.context = context;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http.sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(AbstractHttpConfigurer::disable)
            .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
            .logout(AbstractHttpConfigurer::disable);
        // @formatter:on
        this.applyPermitPathsIfAvailable(http);
        this.applyJwtSecurity(http);
        this.applyCorsIfAvailable(http);
        return http.build();
    }

    @Bean
    @SuppressWarnings("InstantiationOfUtilityClass")
    public JwtUtils jwtUtils() {
        // Need to use JwtSecurityProperties, so register a bean
        JwtSecurityProperties.Secret secret = jwtSecurityProperties.getSecret();
        Assert.notNull(secret.getPublicKey(), "RSAPublicKey must not be null");
        Assert.notNull(secret.getPrivateKey(), "RSAPrivateKey must not be null");

        return new JwtUtils(jwtSecurityProperties);
    }

    private void applyPermitPathsIfAvailable(HttpSecurity http) throws Exception {
        List<PathPatternRequestMatcher> requestMatchers =
                this.jwtSecurityProperties.getPermitAllPaths().stream()
                        .distinct()
                        .map(path -> PathPatternRequestMatcher.withDefaults().matcher(path))
                        .toList();
        http.authorizeHttpRequests(authorize -> {
            if (!requestMatchers.isEmpty()) {
                authorize.requestMatchers(requestMatchers.toArray(PathPatternRequestMatcher[]::new))
                        .permitAll();
            }
            List<PathPatternRequestMatcher> permitAllMatcher = extractPermitAllAnnotationPath();
            permitAllMatcher.removeIf(matcher -> requestMatchers.stream().anyMatch(p -> p.equals(matcher)));
            if (!permitAllMatcher.isEmpty()) {
                authorize.requestMatchers(permitAllMatcher.toArray(PathPatternRequestMatcher[]::new))
                        .permitAll();
            }
            authorize.anyRequest().authenticated();
        });
    }

    private void applyJwtSecurity(HttpSecurity http) throws Exception {
        AuthenticationFailureHandler authenticationFailureHandler = new AuthenticationEntryPointFailureHandler(this.authenticationEntryPoint);
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(
                this.tokenAuthenticatorRegistry, authenticationSuccessHandler,
                authenticationFailureHandler);
        // @formatter:off
        http
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .userDetailsService(this.userDetailsService)
            .exceptionHandling((exceptions) -> exceptions
                    .authenticationEntryPoint(this.authenticationEntryPoint)
                    .accessDeniedHandler(this.accessDeniedHandler)
            )
            .securityContext((securityContextConfigurer) -> {
                SecurityContextHolder.setStrategyName(TransmittableThreadLocalSecurityContextHolderStrategy.class.getName());
                SecurityContextHolderStrategy securityContextHolderStrategy = new TransmittableThreadLocalSecurityContextHolderStrategy();
                RequestAttributeSecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();
                securityContextRepository.setSecurityContextHolderStrategy(securityContextHolderStrategy);
                securityContextConfigurer.securityContextRepository(securityContextRepository);
            });
        // @formatter:on
    }

    private void applyCorsIfAvailable(HttpSecurity http) throws Exception {
        if (this.urlBasedCorsConfigurationSource == null) {
            return;
        }
        String header = this.jwtSecurityProperties.getHeader();
        this.urlBasedCorsConfigurationSource.getCorsConfigurations().forEach((s, configuration) -> {
            List<String> allowedHeaders = configuration.getAllowedHeaders();
            if (allowedHeaders == null) {
                allowedHeaders = new ArrayList<>(1);
            }
            if (!allowedHeaders.contains(header)) {
                allowedHeaders.add(header);
            }
            configuration.setAllowedHeaders(allowedHeaders);
        });

        http.cors(cors -> cors.configurationSource(urlBasedCorsConfigurationSource));
    }

    private List<PathPatternRequestMatcher> extractPermitAllAnnotationPath() {
        List<PathPatternRequestMatcher> matchers = new ArrayList<>(16);
        RequestMappingHandlerMapping mapping = this.context.getBean(RequestMappingHandlerMapping.class);
        mapping.getHandlerMethods().forEach((requestMappingInfo, handlerMethod) -> {
            if (requestMappingInfo == null ||
                ClassUtils.getAnnotation(handlerMethod, PermitAll.class) == null) {
                return;
            }

            // Handle different path matching strategies
            Set<String> patterns = new LinkedHashSet<>(16);
            PathPatternsRequestCondition pathPatternsCondition = requestMappingInfo.getPathPatternsCondition();
            if (pathPatternsCondition == null) {
                PatternsRequestCondition patternsRequestCondition = requestMappingInfo.getPatternsCondition();
                if (patternsRequestCondition == null) {
                    return;
                }
                patterns.addAll(patternsRequestCondition.getPatterns());
            } else {
                patterns.addAll(pathPatternsCondition.getPatternValues());
            }

            requestMappingInfo.getMethodsCondition().getMethods().forEach(requestMethod -> {
                HttpMethod httpMethod = HttpMethod.valueOf(requestMethod.name());

                patterns.forEach(pattern -> matchers.add(PathPatternRequestMatcher.withDefaults().matcher(httpMethod, pattern)));
            });
        });
        return matchers;
    }
}
