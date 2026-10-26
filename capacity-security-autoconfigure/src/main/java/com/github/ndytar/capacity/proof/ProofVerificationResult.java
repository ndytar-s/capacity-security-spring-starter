package com.github.ndytar.capacity.proof;

/***
 *

 * @param resource
 * @param proofPrincipal
 * proofPrincipalId est volontairement scopé à la ressource,
 * pas un identifiant global réutilisable ailleurs. Ça évite qu'on reconstruise un "compte" déguisé.
 */
public record ProofVerificationResult(
        String resource,
        String proofPrincipal  // identifiant minimal de la preuve, ex: hash de la clé publique
) {}
