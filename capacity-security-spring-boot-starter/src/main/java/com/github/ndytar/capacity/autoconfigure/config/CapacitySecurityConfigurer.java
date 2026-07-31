package com.github.ndytar.capacity.autoconfigure.config;

import com.github.ndytar.capacity.auth.CapacityAuthManager;
import com.github.ndytar.capacity.chaine.CapacityFilter;
import com.github.ndytar.capacity.exception.CapacityAccessDeniedHandler;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@SpringBootApplication(exclude = { UserDetailsServiceAutoConfiguration.class })// optionnel
public class CapacitySecurityConfigurer
        extends AbstractHttpConfigurer<CapacitySecurityConfigurer, HttpSecurity> {

    private CapacityFilter capacityFilter;
    private CapacityAuthManager capacityAuthManager;

    // Constructeur vide, utilisé par la méthode statique
    public CapacitySecurityConfigurer() {
    }

    @Override
    public void init(HttpSecurity http) {
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);

        this.capacityFilter = context.getBean(CapacityFilter.class);
        this.capacityAuthManager = context.getBean(CapacityAuthManager.class);
        AccessDeniedHandler handler = context.getBean(CapacityAccessDeniedHandler.class);

        http.exceptionHandling(e -> e.accessDeniedHandler(handler))
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .anonymous(AbstractHttpConfigurer::disable);

    }

    @Override
    public void configure(HttpSecurity http)  {
        http.addFilterBefore(capacityFilter, UsernamePasswordAuthenticationFilter.class);
    }



    // La méthode statique qui rend le DSL naturel
    public static CapacitySecurityConfigurer capacitySecurity() {
        return new CapacitySecurityConfigurer();
    }
    public AuthorizationManager<RequestAuthorizationContext> authManager() {
        return new LazyAuthorizationManager(() -> this.capacityAuthManager);
    }

}
