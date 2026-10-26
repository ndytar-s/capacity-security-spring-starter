package com.github.ndytar.capacity.proof;


public interface CapacityProofVerifier {

    /**
     * Vérifie qu'une signature correspond bien à une clé enregistrée
     * pour une ressource donnée, sur un hash donné.
     * Ne renvoie jamais d'identité "utilisateur" : uniquement le résultat
     * de la vérification cryptographique.
     */
    ProofVerificationResult verify(ProofRequest request);
}