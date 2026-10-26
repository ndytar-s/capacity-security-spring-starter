package com.github.ndytar.capacity.customclaims;

import com.github.ndytar.capacity.proof.ProofRequest;
import jakarta.annotation.Nullable;

public interface CustomClaimsService {
    /**
     * Validation de claims ou caveat de capacité est injecté lors d'authentification par signature ou empreinte digitale ou tout autre identité
     * La valeur retournée : La resource/scope et les actions
     * */
   CustomClaims customClaims(@Nullable ProofRequest proofRequest, Object o) ;

    /**
     *
     * @param customClaims
     * @return
     * @throws Exception
     * La verification de claims s'effectue pour cha requet
     *
     */
    boolean verify( CustomClaims customClaims) throws Exception;

}
