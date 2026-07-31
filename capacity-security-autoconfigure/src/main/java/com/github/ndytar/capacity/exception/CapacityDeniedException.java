package com.github.ndytar.capacity.exception;

import org.springframework.security.access.AccessDeniedException;

public class CapacityDeniedException extends AccessDeniedException {

    public CapacityDeniedException(String message) {
        super(message);
    }
}