package com.github.ndytar.capacity.auth;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import java.util.function.Supplier;


public class CapacityAuthManager implements AuthorizationManager<RequestAuthorizationContext>  {

    private static final Logger log = LoggerFactory.getLogger(CapacityAuthManager.class);
    @Override
    public @Nullable
    AuthorizationResult authorize(Supplier<? extends @Nullable Authentication> authentication, RequestAuthorizationContext object) {
       Authentication auth = authentication.get();// car Authentication est deja injectee dans SecurityContext
        log.info("Type auth reçu : {}", auth != null ? auth.getClass().getSimpleName() : "null");


       if (!(auth instanceof CapacityAuth capacityAuth)) {
           log.info("Acces refuse, pas de CapacityAuth");
           return new AuthorizationDecision(false);
       }
       String urlDemandee = object.getRequest().getRequestURI();
       String urlAutorise = capacityAuth.getResourceAutorisee();//Dans filter, on a construit le capacityAuth avec la resource extraite via le token
       boolean acceAutorise = urlDemandee.equals(urlAutorise);
        log.warn("Url demande : {}, UrlAutorise: {}, AccesAutorise: {}", urlDemandee, urlAutorise, acceAutorise);
        return new AuthorizationDecision(acceAutorise);
    }
}
