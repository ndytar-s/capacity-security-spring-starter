package com.ndytar.reveseEngineering.config;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.AuthenticationEntryPoint;

@Configuration
public class CapacityAuthenticationEntryPoint {
    @Bean(name = "capacityAuthEntryPoint")
    public AuthenticationEntryPoint capacityAuthenticationEntryPoint() {
        return (request, response, exception) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write(exception.getMessage());
        };
    }
}
