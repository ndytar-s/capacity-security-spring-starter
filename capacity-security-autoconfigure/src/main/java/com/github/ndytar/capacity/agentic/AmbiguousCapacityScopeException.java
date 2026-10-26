package com.github.ndytar.capacity.agentic;


import com.github.ndytar.capacity.exception.CapacityDeniedException;

/**
 * Levée quand plus d'une capacité, parmi celles détenues, couvre le même
 * scope+action demandé. Signale un défaut de conception (patterns de scope
 * qui se recouvrent), jamais résolu par combinaison : on refuse, on ne
 * choisit pas à la place du développeur.
 */
public class AmbiguousCapacityScopeException extends CapacityDeniedException {

    public AmbiguousCapacityScopeException(String message) {
        super(message);
    }
}