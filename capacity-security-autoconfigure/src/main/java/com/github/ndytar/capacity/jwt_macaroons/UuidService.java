package com.github.ndytar.capacity.jwt_macaroons;

import  com.github.ndytar.capacity.services.RegistrationTokenService;

import java.util.UUID;


public class UuidService {
    private final RegistrationTokenService registrationToken;

    public UuidService( RegistrationTokenService registrationToken) {
        this.registrationToken = registrationToken;
    }
    /***Pour chaque nouveau tkone on a besoin d'un UUID dans le cas où "Redise" est activé.*
     * Si Possible utiliser le deviceId pour une revocation de tpken et macaroon en cas d'incident.
     */

    public String generer(String deviceId, long dureeMs) {
        String uuid = UUID.randomUUID().toString();
        registrationToken.registerJwt(uuid, deviceId, dureeMs);

        return uuid;
    }
}