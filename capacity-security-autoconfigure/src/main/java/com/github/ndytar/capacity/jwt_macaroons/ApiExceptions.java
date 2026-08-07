package com.github.ndytar.capacity.jwt_macaroons;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public final class ApiExceptions {
    private static final Logger log = LoggerFactory.getLogger(ApiExceptions.class);

    private ApiExceptions() {}

    public static ResponseStatusException jwtAbsent() {
        log.warn( "Token JWT not found");
        return new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Token JWT not found"
        );
    }

    public static ResponseStatusException jwtInvalide() {
        //log.warn("Token JWT not valide or expired");
        return new  ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Token / Maccaroon not valide or expired"
        );
    }

    public static ResponseStatusException ressourceInterdite(String ressource) {
        log.warn( "The requested resource:[ {} ] is not authorized by the token", ressource);
        return new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "The requested resource is not authorized by the token"
        );
    }

    public static ResponseStatusException actionInterdite(String action) {
        log.warn(  "Unauthorized action : " + action);

        return new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "Unauthorized action : " + action
        );
    }

    public static ResponseStatusException parametreInvalide(String message) {
        log.warn("Invalid parameter");
        return new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                message
        );
    }

    public static ResponseStatusException erreurServeur(String message) {
        return new ResponseStatusException(
                HttpStatus.INTERNAL_SERVER_ERROR,
                message
        );
    }
}
