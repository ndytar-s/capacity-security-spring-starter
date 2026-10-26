package com.github.ndytar.capacity.auth;


import com.github.ndytar.capacity.annotation.OneTimeAccess;
import com.github.ndytar.capacity.annotation.SubjectId;
import com.github.ndytar.capacity.audit.AuditCollector;
import com.github.ndytar.capacity.chaine.CapacityFilter;
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

import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;

/**
 * MODIFICATION PAR RAPPORT À L'ORIGINAL :
 * - La déduction scope/action via handlerMapping + Deduiction reste
 *   strictement inchangée.
 * - Les étapes 3 à 6 (scopeCouvre, vérif action, one-time, audit) ne sont
 *   plus faites ici en interne : elles sont déléguées à CapacityDecision,
 *   partagée avec la voie agentic (CapacityAwareToolCallback).
 * - Nouveau : si la requête porte l'attribut PRECOMPUTED_CAPACITY_LIST
 *   (posé par CapacityFilter pour les routes /agent/**), la résolution se
 *   fait parmi cette liste au lieu du CapacityAuth unique du
 *   SecurityContextHolder.
// */


/**
 * MODIFICATION PAR RAPPORT À L'ORIGINAL :
 * - La déduction scope/action via handlerMapping + Deduiction reste
 *   strictement inchangée.
 * - Les étapes 3 à 6 (scopeCouvre, vérif action, one-time, audit) ne sont
 *   plus faites ici en interne : elles sont déléguées à CapacityDecision,
 *   partagée avec la voie agentic (CapacityAwareToolCallback).
 * - Nouveau : si la requête porte l'attribut PRECOMPUTED_CAPACITY_LIST
 *   (posé par CapacityFilter pour les routes /agent/**), la résolution se
 *   fait parmi cette liste au lieu du CapacityAuth unique du
 *   SecurityContextHolder.
 */
public class CapacityAuthManager implements AuthorizationManager<RequestAuthorizationContext> {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(CapacityAuthManager.class);

    private final Deduiction deduiction;
    private final RequestMappingHandlerMapping handlerMapping;
    private final IpAuthorizationChecker ipAuthorizationChecker;
    private final AuditCollector auditCollector;
    private final CapacityDecision capacityDecision;

    public CapacityAuthManager(
            Deduiction deduiction,
                               RequestMappingHandlerMapping handlerMapping,
                               IpAuthorizationChecker ipAuthorizationChecker,
                               AuditCollector auditCollector,
                               CapacityDecision capacityDecision
    ) {
        this.deduiction = deduiction;
        this.handlerMapping = handlerMapping;
        this.ipAuthorizationChecker = ipAuthorizationChecker;
        this.auditCollector = auditCollector;
        this.capacityDecision = capacityDecision;
    }

    @Override
    @SuppressWarnings("unchecked")
    public AuthorizationResult authorize(Supplier<? extends Authentication> authSupplier,
                                         RequestAuthorizationContext context) {

        HttpServletRequest request = context.getRequest();

        // forward d'erreur Spring : inchangé
        if (request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI) != null) {
            return new AuthorizationDecision(true);
        }

        try {
            HandlerExecutionChain chain = handlerMapping.getHandler(request);
            if (chain == null) {
                throw new CapacityDeniedException("URL does not exist, you have no right to attempt : " + request.getRequestURI());
            }
            if (!(chain.getHandler() instanceof HandlerMethod)) {
                throw new CapacityDeniedException("Handler not recognized for: " + request.getRequestURI());
            }
            HandlerMethod handler = (HandlerMethod) chain.getHandler();

            if (!ipAuthorizationChecker.verifierIp(request, handler)) {
                throw new CapacityDeniedException("Unauthorized IP access to this resource.");
            }

            String scopeRequis = deduiction.deduireScope(handler, request);
            String actionRequise = deduiction.deduireAction(handler, request);

            // une méthode qui déclare @SubjectId n'accepte que des capacités personnelles,
            // et une méthode sans @SubjectId refuse les capacités personnelles
            boolean sujetRequis = Arrays.stream(handler.getMethodParameters())
                    .anyMatch(p -> p.hasParameterAnnotation(SubjectId.class));

            Object listAttr = request.getAttribute(CapacityFilter.ATTR_CAPACITY_LIST);

            CapacityAuth capacityAuth;
            if (listAttr instanceof List<?> liste) {
                capacityAuth = capacityDecision.resoudre((List<CapacityAuth>) liste,
                        request.getRequestURI(), scopeRequis, actionRequise, sujetRequis);
            } else {
                Authentication auth = authSupplier.get();
                if (!(auth instanceof CapacityAuth single)) {
                    throw new CapacityDeniedException("Access denied: instance not capacity");
                }
                capacityAuth = capacityDecision.resoudre(List.of(single),
                        request.getRequestURI(), scopeRequis, actionRequise, sujetRequis);
            }

            // @OneTimeAccess : vérification spécifique au handler REST,
            // reste ici car propre à cette voie (annotation sur HandlerMethod)
            if (!verifierOneTime(capacityAuth, handler)) {
                throw new CapacityDeniedException("One-time capacity required: " + capacityAuth.isOneTime());
            }

            return new AuthorizationDecision(true);

        } catch (NoHandlerFoundException e) {
            throw new CapacityDeniedException("No endpoints found for :" + request.getRequestURI());
        } catch (CapacityDeniedException e) {
            throw e;
        } catch (Exception e) {
            log.error("Erreur : {}", e.getMessage());
            throw new CapacityDeniedException("Error :" + e.getMessage());
        }
    }

    private boolean verifierOneTime(CapacityAuth auth, HandlerMethod handler) {
        OneTimeAccess oneTime = handler.getMethodAnnotation(OneTimeAccess.class);
        if (oneTime != null && !auth.isOneTime()) {
            return false;
        }
        return true;
    }
}
