package com.github.ndytar.capacity.exception;

import lombok.Getter;
import org.springframework.security.core.AuthenticationException;

@Getter
public class InvalidTokenException extends AuthenticationException {

    private final String errorCode;

    public InvalidTokenException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

}
