package com.github.ndytar.capacity.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class ApiValidationException extends RuntimeException {
    private final HttpStatus status;

    public ApiValidationException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

}
