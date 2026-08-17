package com.github.ndytar.capacity.exception;

import org.springframework.security.core.AuthenticationException;


public class InvalidTokenException extends AuthenticationException {

    private final String errorCode;

    public InvalidTokenException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
