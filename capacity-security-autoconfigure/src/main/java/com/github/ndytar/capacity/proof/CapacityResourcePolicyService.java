package com.github.ndytar.capacity.proof;


import java.util.Map;
import java.util.Set;

public interface CapacityResourcePolicyService {

    /**
     * Évalue si une action est autorisée sur une ressource donnée,
     * compte tenu de l'ensemble des preuves déjà validées pour elle.
     * Ne connaît ni rôle, ni utilisateur : uniquement des principaux preuve.
     */

    Map<String, Set<String>> getAuthorizedScopes(ProofRequest request);

}
