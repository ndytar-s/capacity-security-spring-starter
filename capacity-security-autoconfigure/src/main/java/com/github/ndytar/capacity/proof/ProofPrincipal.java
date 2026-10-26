package com.github.ndytar.capacity.proof;

public record ProofPrincipal(
        String proofPrincipalId,   // vient de ProofVerificationResult
        String resourceId,         // ressource sur laquelle la preuve est valide
        String proofMode           // ex: "biometric-device", libre, informatif seulement
) {}