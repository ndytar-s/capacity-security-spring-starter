    package com.github.ndytar.capacity.jwt_macaroons;

    import  com.github.ndytar.capacity.exception.ApiValidationException;
    import org.slf4j.Logger;
    import org.slf4j.LoggerFactory;
    import org.springframework.http.HttpStatus;

    public final class ApiExceptions {
        private static final Logger log = LoggerFactory.getLogger(ApiExceptions.class);

        public static ApiValidationException parametreInvalide(String message) {
            log.warn("Invalid parameter: {}", message);
            return new ApiValidationException(HttpStatus.BAD_REQUEST, message);
        }

        public static ApiValidationException jwtAbsent() {
            log.warn( "Token JWT not found");
            return new ApiValidationException(HttpStatus.NOT_FOUND, "Token JWT not found");

        }

        public static ApiValidationException jwtInvalide() {
            //log.warn("Token JWT not valide or expired");
            return new  ApiValidationException(
                    HttpStatus.UNAUTHORIZED,
                    "Token / Maccaroon not valide or expired"
            );
        }

        public static ApiValidationException ressourceInterdite(String ressource) {
            log.warn( "The requested resource:[ {} ] is not authorized by the token", ressource);
            return new ApiValidationException(
                    HttpStatus.FORBIDDEN,
                    "The requested resource is not authorized by the token"
            );
        }

        public static ApiValidationException actionInterdite(String action) {
            log.warn(  "Unauthorized action : " + action);

            return new ApiValidationException(
                    HttpStatus.FORBIDDEN,
                    "Unauthorized action : " + action
            );
        }



        public static ApiValidationException erreurServeur(String message) {
            return new ApiValidationException(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    message
            );
        }
    }
