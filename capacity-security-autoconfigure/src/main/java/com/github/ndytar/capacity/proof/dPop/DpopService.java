package com.github.ndytar.capacity.proof.dPop;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Map;

public interface DpopService {
    Map<String, Object> buildCnf(String jwkJson);

    DpopProof extractDpopProof(HttpServletRequest request);

    boolean verifySignature(DpopProof proof, String expectedJkt);

    boolean verifyPayload(DpopProof proof, HttpServletRequest request, String capacityToken);
}