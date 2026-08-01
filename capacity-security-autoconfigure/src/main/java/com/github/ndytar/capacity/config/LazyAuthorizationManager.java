package com.github.ndytar.capacity.config;

import com.github.ndytar.capacity.auth.CapacityAuthManager;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.function.Supplier;

public class LazyAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final Supplier<CapacityAuthManager> supplier;

    public LazyAuthorizationManager(Supplier<CapacityAuthManager> supplier) {
        this.supplier = supplier;
    }

    @Override
    public @Nullable AuthorizationResult authorize(Supplier<? extends @Nullable Authentication> authentication, RequestAuthorizationContext object) {
        return supplier.get().authorize(authentication, object);
    }
}
