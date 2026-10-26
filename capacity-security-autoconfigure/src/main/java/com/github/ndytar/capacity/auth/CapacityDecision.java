package com.github.ndytar.capacity.auth;

import com.github.ndytar.capacity.agentic.AmbiguousCapacityScopeException;
import com.github.ndytar.capacity.audit.AuditCollector;
import com.github.ndytar.capacity.audit.AuditEvent;
import com.github.ndytar.capacity.audit.AuditResult;
import com.github.ndytar.capacity.exception.CapacityDeniedException;
import com.github.ndytar.capacity.jwt_macaroons.MacaroonService;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Décide si une capacité, parmi une liste détenue, couvre un scope et une
 * action demandés. Ne connaît ni HandlerMethod, ni handlerMapping, ni
 * Spring AI : elle reçoit des chaînes déjà déterminées par l'appelant.
 *
 * - Voie REST classique (CapacityAuthManager) : scopeRequis/actionRequise
 *   viennent de Deduiction.deduireScope/deduireAction(handler, request).
 * - Voie agentic (CapacityAwareToolCallback) : ils viennent directement de
 *   RequiresCapacity.resourcePattern()/actions() du tool.
 *
 * NOTE D'IMPLÉMENTATION : macaroonService.revokeMacaroon(...) suppose la
 * signature déjà utilisée dans CapacityFilter.essayerMacaroon (revocation
 * par token sérialisé). À vérifier contre la signature réelle de
 * MacaroonService dans votre lib.
 */


/**
 * Décide si une capacité, parmi une liste détenue, couvre un scope et une
 * action demandés. Ne connaît ni HandlerMethod, ni handlerMapping, ni Spring AI.
 *
 * INVARIANT SUJET (nouveau) :
 *   - une méthode qui déclare @SubjectId (sujetRequis = true) n'accepte QUE des
 *     capacités personnelles ;
 *   - une méthode sans @SubjectId (sujetRequis = false) REFUSE les capacités
 *     personnelles.
 * Une capacité personnelle ne peut donc jamais ouvrir un endpoint ou un tool qui
 * ne reçoit pas l'identifiant injecté : le développeur ne peut pas "oublier" de
 * filtrer par sujet sans que le framework ne le refuse.
 *
 * ADAPTER : isPersonnel() doit correspondre au getter réel de ton CapacityAuth.
 * ADAPTER : macaroonService.revokeMacaroon(...) suppose la signature utilisée
 * dans CapacityFilter.essayerMacaroon.
 */
public class CapacityDecision {

    private final Deduiction deduiction;
    private final MacaroonService macaroonService;
    private final AuditCollector auditCollector;

    public CapacityDecision(Deduiction deduiction,
                            MacaroonService macaroonService,
                            AuditCollector auditCollector) {
        this.deduiction = deduiction;
        this.macaroonService = macaroonService;
        this.auditCollector = auditCollector;
    }

    /** Méthode sans @SubjectId. */
    public boolean couvre(List<CapacityAuth> capacites, String urlOuPattern,
                          String scopeRequis, String actionRequise) {
        return couvre(capacites, urlOuPattern, scopeRequis, actionRequise, false);
    }

    /**
     * Vérification PURE, sans effet de bord (pas de révocation, pas d'audit).
     * Sert au filtrage de visibilité des tools : on ne consomme jamais une
     * capacité one-time juste pour décider d'un affichage.
     */
    public boolean couvre(List<CapacityAuth> capacites, String urlOuPattern,
                          String scopeRequis, String actionRequise, boolean sujetRequis) {
        List<CapacityAuth> candidates = filtrerSujet(capacites, sujetRequis);

        boolean joker = candidates.stream().anyMatch(c -> c.getActions().contains("*"));
        if (joker) return true;

        return candidates.stream()
                .anyMatch(c -> deduiction.scopeCouvre(c.getResourceScope(), urlOuPattern, scopeRequis)
                        && c.getActions().contains(actionRequise));
    }

    /** Méthode sans @SubjectId. */
    public CapacityAuth resoudre(List<CapacityAuth> capacites, String urlOuPattern,
                                 String scopeRequis, String actionRequise) {
        return resoudre(capacites, urlOuPattern, scopeRequis, actionRequise, false);
    }

    /**
     * @param capacites     capacités détenues, déjà validées cryptographiquement
     * @param urlOuPattern  URL réelle (voie REST) ou resourcePattern du tool (voie agentic)
     * @param scopeRequis   scope requis
     * @param actionRequise action requise
     * @param sujetRequis   true si la méthode ou le tool déclare un paramètre @SubjectId
     */
    public CapacityAuth resoudre(List<CapacityAuth> capacites,
                                 String urlOuPattern,
                                 String scopeRequis,
                                 String actionRequise,
                                 boolean sujetRequis) {

        List<CapacityAuth> candidates = filtrerSujet(capacites, sujetRequis);

        // joker * : court-circuite tout, comme dans CapacityAuthManager aujourd'hui
        List<CapacityAuth> jokers = candidates.stream()
                .filter(c -> c.getActions().contains("*"))
                .toList();
        if (!jokers.isEmpty()) {
            CapacityAuth match = jokers.get(0);
            auditCollector.record(new AuditEvent(Instant.now(), "*", scopeRequis,
                    "uuid: " + match.getUuid(), AuditResult.SUCCESS, "Joker action"));
            return match;
        }

        List<CapacityAuth> matches = candidates.stream()
                .filter(c -> deduiction.scopeCouvre(c.getResourceScope(), urlOuPattern, scopeRequis))
                .filter(c -> c.getActions().contains(actionRequise))
                .collect(Collectors.toList());

        if (matches.isEmpty()) {
            auditCollector.record(new AuditEvent(Instant.now(), actionRequise, scopeRequis,
                    "uuid: n/a", AuditResult.DENIED,
                    "Aucune capacité ne couvre ce scope/action (sujetRequis=" + sujetRequis + ")"));
            throw new CapacityDeniedException(
                    "Aucune capacité ne couvre : scope=" + scopeRequis + ", action=" + actionRequise
                            + ", sujetRequis=" + sujetRequis);
        }
        if (matches.size() > 1) {
            auditCollector.record(new AuditEvent(Instant.now(), actionRequise, scopeRequis,
                    "uuid: n/a", AuditResult.DENIED, "Scopes ambigus"));
            throw new AmbiguousCapacityScopeException(
                    "Scopes ambigus pour : scope=" + scopeRequis + ", action=" + actionRequise);
        }

        CapacityAuth match = matches.get(0);

        if (match.isOneTime() && !estUnJwt((String) match.getCredentials())) {
            // révocation différée jusqu'ici : seuls les macaroons sont révoqués ainsi
            macaroonService.revokeMacaroon((String) match.getCredentials());
        }

        auditCollector.record(new AuditEvent(Instant.now(), actionRequise,
                "Capacity=" + match.getResourceScope() + ", required=" + scopeRequis,
                "uuid: " + match.getUuid(), AuditResult.SUCCESS,
                "Action authorized : " + match.getActions() + ", required : " + actionRequise));

        return match;
    }

    private List<CapacityAuth> filtrerSujet(List<CapacityAuth> capacites, boolean sujetRequis) {
        return capacites.stream()
                .filter(c -> c.isPersonnel() == sujetRequis)
                .toList();
    }

    private boolean estUnJwt(String token) {
        return token != null && !token.isEmpty() && token.split("\\.").length == 3;
    }
}