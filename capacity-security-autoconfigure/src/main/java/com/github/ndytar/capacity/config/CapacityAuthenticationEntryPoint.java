package com.github.ndytar.capacity.config;

import  com.github.ndytar.capacity.exception.InvalidTokenException;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import tools.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.Map;

@AutoConfiguration
public class CapacityAuthenticationEntryPoint {

    @Bean(name = "capacityAuthEntryPoint")
    public AuthenticationEntryPoint capacityAuthenticationEntryPoint(ObjectMapper objectMapper) {
        return (request, response, exception) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            String errorCode = resolveErrorCode(exception);

            Map<String, String> body = new LinkedHashMap<>();
            body.put("error", errorCode);
            body.put("message", exception.getMessage());

            objectMapper.writeValue(response.getWriter(), body);
        };
    }

    private String resolveErrorCode(AuthenticationException exception) {
        if (exception instanceof InvalidTokenException) {
            return "INVALID_TOKEN";
        }
        return "AUTHENTICATION_FAILED";
    }
}