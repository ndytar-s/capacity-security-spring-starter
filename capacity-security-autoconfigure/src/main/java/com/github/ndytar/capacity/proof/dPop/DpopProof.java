package com.github.ndytar.capacity.proof.dPop;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;

import java.time.Instant;

public record DpopProof(SignedJWT jwt, JWK jwk, String jti, Instant iat,
                        String htm, String htu, String chash) {}