package com.github.TsukasaHwan.jwt.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Abstract authentication filter base class
 *
 * <p>Extends Spring Web's OncePerRequestFilter, provides common JWT authentication workflow,
 * includes injection of success/failure handlers and authentication template methods.</p>
 *
 * @author Teamo
 * @since 2025/4/3
 */
public abstract class AbstractAuthenticationFilter extends OncePerRequestFilter {

    /**
     * AuthenticationSuccessHandler
     */
    protected final AuthenticationSuccessHandler successHandler;

    /**
     * AuthenticationFailureHandler
     */
    protected final AuthenticationFailureHandler failureHandler;

    protected AbstractAuthenticationFilter(AuthenticationSuccessHandler successHandler, AuthenticationFailureHandler failureHandler) {
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
    }

    @Override
    @SuppressWarnings("NullableProblems")
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            beforeAuthentication(request);
            Authentication authentication = attemptAuthentication(request, response);
            if (authentication == null) {
                filterChain.doFilter(request, response);
                return;
            }
            successfulAuthentication(request, response, filterChain, authentication);
        } catch (Exception e) {
            unsuccessfulAuthentication(request, response, e);
        }
    }

    /**
     * Pre-authentication processing method (can be overridden by subclasses)
     *
     * @param request HTTP request object
     */
    protected void beforeAuthentication(HttpServletRequest request) {
        // do nothing
    }

    /**
     * Concrete authentication logic implementation (abstract method)
     *
     * @param request  HTTP request
     * @param response HTTP response
     * @return Authentication result
     */
    protected abstract Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response);

    /**
     * Handles successful authentication
     *
     * @param request        HTTP request
     * @param response       HTTP response
     * @param chain          Filter chain
     * @param authentication Authentication result
     */
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authentication) throws IOException, ServletException {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        this.successHandler.onAuthenticationSuccess(request, response, chain, authentication);
    }

    /**
     * Authentication failure handling (abstract method)
     *
     * @param request  HTTP request
     * @param response HTTP response
     * @param e        Exception
     * @throws ServletException ServletException
     * @throws IOException      IOException
     */
    protected abstract void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, Exception e)
            throws ServletException, IOException;
}
