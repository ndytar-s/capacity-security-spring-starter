package com.github.ndytar.capacity.auth;

import com.github.ndytar.capacity.annotation.AllowedIp;
import com.github.ndytar.capacity.annotation.OneTimeAccess;
import com.github.ndytar.capacity.exception.CapacityDeniedException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.function.Supplier;

@Component
public class CapacityAuthManager
        implements AuthorizationManager<RequestAuthorizationContext> {

    private static final Logger log = LoggerFactory.getLogger(CapacityAuthManager.class);

    private Deduiction deduiction;
    private RequestMappingHandlerMapping handlerMapping;

    public CapacityAuthManager(Deduiction deduiction, RequestMappingHandlerMapping handlerMapping) {
        this.deduiction = deduiction;
        this.handlerMapping = handlerMapping;
    }

    @Override
    public AuthorizationResult authorize(
            Supplier<? extends Authentication> authSupplier,
            RequestAuthorizationContext context) {

        Authentication auth = authSupplier.get();
        assert context != null;
        String path = context.getRequest().getRequestURI();


        if (!(auth instanceof CapacityAuth capacityAuth)) {

            throw new CapacityDeniedException("Access denied: instance not capacity");
        }

    // JOKER * : court-circuite tout
            if (capacityAuth.getActions().contains("*")) {
                log.info("Joker * : accès total autorisé");
                return new AuthorizationDecision(true);
            }
        HttpServletRequest request = context.getRequest();

        try {
            // récupérer le handler de la requête
            HandlerExecutionChain chain  = handlerMapping.getHandler(request);
            if (chain == null) {
                throw new CapacityDeniedException("URL does not exist, you have no right to attempt : "+ request.getRequestURI());
            }
            // vérifier que c'est bien un HandlerMethod
            if (!(chain.getHandler() instanceof HandlerMethod)) {
                throw new CapacityDeniedException("Handler not recognized for: "+ request.getRequestURI());

            }

            HandlerMethod handler = (HandlerMethod) chain.getHandler();

            // 1. vérifier IP
            if (!verifierIp(capacityAuth, request, handler)) {
                throw new CapacityDeniedException("Unauthorized IP: "+ capacityAuth.getAllowedIp());

            }

            // 2. déduire le scope requis
            String scopeRequis = deduiction.deduireScope(handler);
            log.info("Scope requis : {}", scopeRequis);

            // 3. vérifier que le token couvre le scope
            if (!deduiction.scopeCouvre(capacityAuth.getResourceScope(),
                    request.getRequestURI(), scopeRequis)) {

                throw new CapacityDeniedException("Scope not allowed: Capacity= "+ capacityAuth.getResourceScope()+", required= "+scopeRequis);

            }

            // 4. déduire l'action requise
            String actionRequise = deduiction.deduireAction(handler, request);
            log.info("Action requise : {}", actionRequise);
            log.info("Action aquise : {}", capacityAuth.getActions());

            // 5. vérifier que le token a l'action
            if (!capacityAuth.getActions().contains(actionRequise)) {
                throw new CapacityDeniedException("Action not authorized: Action acquired = "+capacityAuth.getActions()+", Action required = "+actionRequise);

            }

            // 6. vérifier @OneTimeAccess
            if (!verifierOneTime(capacityAuth, handler)) {
                throw new CapacityDeniedException("One-time capacity required: "+ capacityAuth.isOneTime());

            }

            log.info("Accès autorisé : scope={}, action={}",
                    scopeRequis, actionRequise);
            return new AuthorizationDecision(true);

        } catch (NoHandlerFoundException e) {

            throw  new CapacityDeniedException("No endpoints found for :"+ request.getRequestURI());
        } catch (CapacityDeniedException e) {
            throw e;

        } catch (Exception e) {
            log.error("Erreur : {}", e.getMessage());
            throw  new CapacityDeniedException("Error :"+ e.getMessage());

        }
    }


    // vérifier @AllowedIp
    private boolean verifierIp(CapacityAuth auth,
                               HttpServletRequest request,
                               HandlerMethod handler) {

        AllowedIp allowedIp = handler.getMethodAnnotation(AllowedIp.class);
        if (allowedIp != null) {
            String pattern = allowedIp.value().replace("*", ".*");
            return request.getRemoteAddr().matches(pattern);
        }

        // vérifier aussi l'IP dans le token
        if (auth.getAllowedIp() != null) {
            return auth.getAllowedIp().equals(request.getRemoteAddr());
        }

        return true; // pas de restriction IP
    }

    // vérifier @OneTimeAccess
    private boolean verifierOneTime(CapacityAuth auth, HandlerMethod handler) {
        OneTimeAccess oneTime = handler.getMethodAnnotation(OneTimeAccess.class);
        if (oneTime != null && !auth.isOneTime()) {
            return false; // token one-time requis mais token normal fourni
        }
        return true;
    }


}
