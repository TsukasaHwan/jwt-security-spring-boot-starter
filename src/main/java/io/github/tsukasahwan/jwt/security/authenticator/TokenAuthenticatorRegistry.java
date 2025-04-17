package io.github.tsukasahwan.jwt.security.authenticator;

import io.github.tsukasahwan.jwt.core.JwtGrantType;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Teamo
 * @since 2025/4/7
 */
public class TokenAuthenticatorRegistry implements InitializingBean, ApplicationContextAware {

    private Map<JwtGrantType, AbstractTokenAuthenticator> authenticatorMap;

    private ApplicationContext context;

    @Override
    public void afterPropertiesSet() throws Exception {
        Map<String, AbstractTokenAuthenticator> beansOfType = context.getBeansOfType(AbstractTokenAuthenticator.class);
        if (beansOfType.isEmpty()) {
            throw new IllegalStateException("No token authenticator implementations found. "
                                            + "Please ensure proper configuration of AbstractTokenAuthenticator subclasses");
        }
        this.authenticatorMap = new HashMap<>(16);
        beansOfType.values().forEach(authenticator -> {
            JwtGrantType type = authenticator.getGrantType();
            if (type == null) {
                throw new IllegalStateException(
                        String.format("Authenticator %s improperly implements getGrantType() - must return non-null JwtTokenType",
                                authenticator.getClass().getSimpleName())
                );
            }
            if (this.authenticatorMap.containsKey(type)) {
                throw new IllegalStateException(
                        String.format("Duplicate grant type authenticator found for [%s] - Existing: %s, Conflicting: %s",
                                type.getValue(),
                                authenticatorMap.get(type).getClass().getSimpleName(),
                                authenticator.getClass().getSimpleName())
                );
            }
            this.authenticatorMap.put(type, authenticator);
        });
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.context = applicationContext;
    }

    public AbstractTokenAuthenticator getTokenAuthenticator(JwtGrantType grantType) {
        if (authenticatorMap == null || authenticatorMap.isEmpty()) {
            throw new IllegalStateException("Token authenticator registry not initialized - ensure Spring context initialization is complete");
        }

        if (grantType == null) {
            throw new IllegalArgumentException("grantType parameter cannot be null when retrieving authenticator");
        }

        AbstractTokenAuthenticator authenticator = authenticatorMap.get(grantType);
        if (authenticator == null) {
            throw new UnsupportedOperationException(
                    String.format("Unsupported grant type: %s. Registered types: %s",
                            grantType.getValue(),
                            String.join(", ", authenticatorMap.keySet().stream()
                                    .map(JwtGrantType::getValue)
                                    .toList()))
            );
        }
        return authenticatorMap.get(grantType);
    }
}
