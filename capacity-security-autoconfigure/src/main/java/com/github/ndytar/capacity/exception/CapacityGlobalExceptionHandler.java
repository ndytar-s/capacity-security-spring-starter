package com.github.ndytar.capacity.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class CapacityGlobalExceptionHandler {

    @ExceptionHandler(RedisUnavailableException.class)
    public ResponseEntity<?> handleRedisUnavailable(RedisUnavailableException e) {
        return build(HttpStatus.SERVICE_UNAVAILABLE, "REDIS_UNAVAILABLE", "Security service Redis unavailable");
    }

    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<?> handleSecurityException(SecurityException e) {
        return build(HttpStatus.UNAUTHORIZED, "AUTHENTICATION_FAILED", e.getMessage());
    }

    @ExceptionHandler(CapacityDeniedException.class)
    public ResponseEntity<?> handleCapacityDenied(CapacityDeniedException e) {
        return build(HttpStatus.FORBIDDEN, "ACCESS_DENIED", e.getMessage());
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<?> handleInvalideToken(InvalidTokenException e) {
        return build(HttpStatus.NOT_ACCEPTABLE, "INVALID_TOKEN", e.getMessage());
    }

    @ExceptionHandler(ApiValidationException.class)
    public ResponseEntity<?> handleApiValidation(ApiValidationException e) {
        return build(e.getStatus(), e.getStatus().name(), e.getMessage());
    }

    private ResponseEntity<?> build(HttpStatusCode status, String errorCode, String message) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("error", errorCode);
        body.put("message", message);
        return ResponseEntity.status(status).body(body);
    }
}