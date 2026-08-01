package com.github.ndytar.capacity.login;


import com.github.ndytar.capacity.aop.OauthUserInfo;
import com.github.ndytar.capacity.aop.SecurityVulnerabilityEvent;
import com.github.ndytar.capacity.aop.VulnerabilityType;
import com.github.ndytar.capacity.capacityModel.CapacityUser;
import com.github.ndytar.capacity.jwt_macaroons.JwtService;
import com.github.ndytar.capacity.jwt_macaroons.RefreshTokenService;
import com.github.ndytar.capacity.jwt_macaroons.TokenResponse;
import com.github.ndytar.capacity.jwt_macaroons.UuidService;
import com.github.ndytar.capacity.properties.CapacityJwtPropertie;
import com.github.ndytar.capacity.properties.CapacityMacaoonPropertie;
import com.github.ndytar.capacity.services.CapacityPolitiqueMappingService;
import com.github.ndytar.capacity.services.CapacityUserService;
import com.github.ndytar.capacity.services.IAuthService;
import com.github.ndytar.capacity.services.SucurityVulnerabilityReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

public class AuthService implements IAuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private CapacityUserService capacityUserService;
    private CapacityPolitiqueMappingService politiqueService;
    private JwtService jwtService;
    private RefreshTokenService refreshTokenService;
    private UuidService uuidService;
    private CapacityJwtPropertie jwtPropertie;
    private CapacityMacaoonPropertie macaoonPropertie;

    //@Value("${capacity.jwt.duree:900000}")
   // private long DUREE_MS;
   // @Value("${capacity.macaroon.redis.enabled}")
   // private boolean redisEnabled;

    private static final String PREFIX_JWT      = "jwt:";
    private static final String PREFIX_REF      = "refresh:";

    PasswordEncoder encoder;
    SucurityVulnerabilityReport vulnerabilityReport;

    public AuthService(CapacityUserService capacityUserService,
                       CapacityPolitiqueMappingService politiqueService, JwtService jwtService,
                       RefreshTokenService refreshTokenService, UuidService uuidService,
                       SucurityVulnerabilityReport vulnerabilityReport,
                       PasswordEncoder encoder,
                       CapacityJwtPropertie jwtPropertie,
                       CapacityMacaoonPropertie macaoonPropertie) {
        this.capacityUserService = capacityUserService;
        this.politiqueService = politiqueService;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.uuidService = uuidService;
        this.vulnerabilityReport = vulnerabilityReport;
        this.encoder = encoder;
        this.jwtPropertie = jwtPropertie;
        this.macaoonPropertie = macaoonPropertie;
    }
    // login
    @Override
    public TokenResponse login(String username, String password, String deviceId) {
//log.info(encoder.encode(password));
        CapacityUser user = capacityUserService
                .findByUsername(username)
                .orElseThrow(() -> {
                    vulnerabilityReport.report(
                            new SecurityVulnerabilityEvent(
                                    VulnerabilityType.NOTFUND,
                                    "Utilisateur inconnu", username, getClass().getSimpleName())
                    );
                    return new RuntimeException("Utilisateur inconnu");
                });

        matches(user.getPassword(), password);

        //log.info("Connexion : {} sur appareil : {}", username, deviceId);
        return genererTokenResponse(user, deviceId);
    }
    @Override
    public TokenResponse login(String username, String deviceId) {

        CapacityUser user = capacityUserService
                .findByUsername(username)
                .orElseThrow(() -> {
                    vulnerabilityReport.report(
                            new SecurityVulnerabilityEvent(
                                    VulnerabilityType.NOTFUND,
                                    "Utilisateur inconnu", username, getClass().getSimpleName())
                    );

                    return new RuntimeException("Utilisateur inconnu");
                });


        log.info("Connexion : {} sur appareil : {}", username, deviceId);
        return genererTokenResponse(user, deviceId);
    }
    // refresh
    @Override
    public TokenResponse refresh(String refreshToken) {

        String username = refreshTokenService.valider(PREFIX_REF, refreshToken)
                .orElseThrow(() ->
                        new RuntimeException("Refresh token invalide"));

        CapacityUser user = capacityUserService
                .findByUsername(username)
                .orElseThrow(() ->
                        new RuntimeException("Utilisateur inconnu"));

        return genererTokenResponse(user, "default");
    }
    /**
     *     génération tokens et stockage de redise
      */
    @Override
    public TokenResponse genererTokenResponse(CapacityUser user, String deviceId) {

        Map<String, Set<String>> politique =
                getPolitiqueFusionnee(user.getRoles());

        Map<String, String> accessTokens = new HashMap<>();
        AtomicReference<String> uuid = new AtomicReference<>("");

            politique.forEach((scope, actions) -> {
                if (macaoonPropertie.isRedis())
                    uuid.set(uuidService.generer(PREFIX_JWT, deviceId, jwtPropertie.getDuration()));
                String token = jwtService.generer(scope, actions, false, null, null, uuid.get());
                accessTokens.put(scope, token);
                log.info("Token généré : scope={}, uuid={}", scope, uuid);
            });


        // refresh token
        if (macaoonPropertie.isRedis())
            uuid.set(uuidService.generer(PREFIX_REF, deviceId, jwtPropertie.getRefduration()));
        String refreshToken = refreshTokenService.generer(
                user.getUsername(), uuid.get());

        return new TokenResponse(
                user.getUsername(),
                user.getRoles().toString(),
                accessTokens,
                refreshToken
        );
    }
    // fusion des politiques
    private Map<String, Set<String>> getPolitiqueFusionnee(List<String> roles) {

        Map<String, Set<String>> fusion = new HashMap<>();

        for (String role : roles) {
            politiqueService.getPolitiqueForRole(role)
                    .forEach((scope, actions) ->
                            fusion.computeIfAbsent(scope, k -> new HashSet<>())
                                    .addAll(actions));
        }

        return fusion;
    }
    @Override
    public TokenResponse processExternalOauthVerification(OauthUserInfo userInfo) {
        System.out.println("\n on genere les capacitys");
       // return new TokenResponse();
        return login(userInfo.getEmail(), null);
    }
    public boolean matches(String rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) { return false; }
        try {
            return encoder.matches(rawPassword, encodedPassword);
        }catch (IllegalArgumentException e) {
            vulnerabilityReport.report(
                    new SecurityVulnerabilityEvent(
                            VulnerabilityType.PAINTEXT_PASSWORD, "Plain text password deteted", "", getClass().getSimpleName())
            );
        }
        return rawPassword.equals(encodedPassword);
    }
}
