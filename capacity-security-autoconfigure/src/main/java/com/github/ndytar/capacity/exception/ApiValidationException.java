package com.github.ndytar.capacity.exception;

import org.springframework.http.HttpStatus;

public class ApiValidationException extends RuntimeException {
    private final HttpStatus status;

    public ApiValidationException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
