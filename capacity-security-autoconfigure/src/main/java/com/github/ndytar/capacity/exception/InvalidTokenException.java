package com.github.ndytar.capacity.exception;

import org.springframework.security.core.AuthenticationException;

public class InvalidTokenException extends AuthenticationException {
    public InvalidTokenException(String message, Throwable cause) {super(message, cause);
    }
}
