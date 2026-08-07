package com.github.ndytar.capacity.auth;

import com.github.ndytar.capacity.annotation.OneTimeAccess;
import com.github.ndytar.capacity.exception.CapacityDeniedException;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.function.Supplier;

public class CapacityAuthManager
        implements AuthorizationManager<RequestAuthorizationContext> {


    private Deduiction deduiction;
    private RequestMappingHandlerMapping handlerMapping;
    private IpAuthorizationChecker ipAuthorizationChecker;
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

        // === INTERCEPTER LE FORWARD D'ERREUR ===
        // Quand Spring forward vers /error (404, exception...), on autorise
        // pour laisser le BasicErrorController retourner la VRAIE erreur.
        HttpServletRequest request = context.getRequest();
        if (request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI) != null) {
            return new AuthorizationDecision(true);
        }
        if (!(auth instanceof CapacityAuth capacityAuth)) {

            throw new CapacityDeniedException("Access denied: instance not capacity");
        }

    // JOKER * : court-circuite tout
            if (capacityAuth.getActions().contains("*")) {
                return new AuthorizationDecision(true);
            }

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

            if (!ipAuthorizationChecker.verifierIp(request, handler)) {
                throw new CapacityDeniedException("Unauthorized IP access to this resource.");
            }

            // 2. déduire le scope requis

            String scopeRequis = deduiction.deduireScope(handler, request);
            // 3. vérifier que le token couvre le scope
            if (!deduiction.scopeCouvre(capacityAuth.getResourceScope(),
                    request.getRequestURI(), scopeRequis)) {

                throw new CapacityDeniedException("Scope not allowed: Capacity= "+ capacityAuth.getResourceScope()+", required= "+scopeRequis);

            }

            // 4. déduire l'action requise
            String actionRequise = deduiction.deduireAction(handler, request);

            // 5. vérifier que le token a l'action
            if (!capacityAuth.getActions().contains(actionRequise)) {
                throw new CapacityDeniedException("Action not authorized: Action acquired = "+capacityAuth.getActions()+", Action required = "+actionRequise);

            }

            // 6. vérifier @OneTimeAccess
            if (!verifierOneTime(capacityAuth, handler)) {
                throw new CapacityDeniedException("One-time capacity required: "+ capacityAuth.isOneTime());

            }

            return new AuthorizationDecision(true);

        } catch (NoHandlerFoundException e) {

            throw  new CapacityDeniedException("No endpoints found for :"+ request.getRequestURI());
        } catch (CapacityDeniedException e) {
            throw e;

        } catch (Exception e) {
            throw  new CapacityDeniedException("Error :"+ e.getMessage());

        }
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
