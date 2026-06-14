package com.github.ndytar.capacity.auth;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Collections;


public class CapacityAuth extends AbstractAuthenticationToken {

    private final String token;
    private final String resourceAutorisee;

    public CapacityAuth(String token, String resourceAutorisee) {
        super(Collections.emptyList());
        this.token            = token;
        this.resourceAutorisee = resourceAutorisee;
        setAuthenticated(true);  // manquait
    }

    public String getResourceAutorisee() { return resourceAutorisee; }

    @Override
    public Object getCredentials() { return token; }

    @Override
    public Object getPrincipal() { return token; }
}
