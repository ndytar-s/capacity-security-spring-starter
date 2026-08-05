package com.github.ndytar.capacity.jwt_macaroons;

import com.github.ndytar.capacity.register.TokenRedisService;

import java.util.Optional;
import java.util.UUID;


public class UuidService {

    private TokenRedisService tokenRedisService;

    public UuidService(TokenRedisService tokenRedisService) {
        this.tokenRedisService = tokenRedisService;
    }

    /***
     *
     * @param deviceId
     * @param DUREE_MS
     * @return
     *
     * Pour chaque nouveau tkone on a besoin d'un UUID dans le cas où "Redise" est activé.
     * On stocke le UUID, le nom utilisateur et l'identifiant l'appareil.
     * UUID sera utilisé pour la revocation et l'atténuation
     * Nom d'utilisateur sera utilisé pour le refresh token
     */

    public String generer(String prefix, String deviceId, long DUREE_MS) {
        String uuid = UUID.randomUUID().toString();
        tokenRedisService.stocker(prefix, uuid, deviceId, DUREE_MS);
        return uuid;
    }

    // récupérer username depuis uuid
    public Optional<String> getUsername(String prefix, String uuid) {
        return tokenRedisService.getUsernameJwt(prefix, uuid);
    }

    // vérifier si uuid appartient à un username
    public boolean belongsTo(String prefix, String uuid, String username) {
        return getUsername(prefix, uuid)
                .map(u -> u.equals(username))
                .orElse(false);
    }
  public boolean existe(String prefix, String uuid) {
      return tokenRedisService.existe(prefix, uuid);
  }


}