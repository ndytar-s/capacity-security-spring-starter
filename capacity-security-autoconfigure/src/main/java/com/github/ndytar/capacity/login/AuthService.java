package com.github.ndytar.capacity.login;

import  com.github.ndytar.capacity.aop.OauthUserInfo;
import  com.github.ndytar.capacity.aop.SecurityVulnerabilityEvent;
import  com.github.ndytar.capacity.aop.VulnerabilityType;
import  com.github.ndytar.capacity.capacityModel.CapacityUser;
import  com.github.ndytar.capacity.exception.ApiValidationException;
import  com.github.ndytar.capacity.jwt_macaroons.*;
import  com.github.ndytar.capacity.properties.CapacityJwtPropertie;
import  com.github.ndytar.capacity.properties.CapacityMacaoonPropertie;
import  com.github.ndytar.capacity.services.CapacityPolitiqueMappingService;
import  com.github.ndytar.capacity.services.CapacityUserService;
import  com.github.ndytar.capacity.services.IAuthService;
import  com.github.ndytar.capacity.services.SucurityVulnerabilityReport;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

public class AuthService implements IAuthService {
    private static final Pattern HASH_PREFIX_PATTERN = Pattern.compile("^\\{.+\\}.*");

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private CapacityUserService capacityUserService;
    private CapacityPolitiqueMappingService politiqueService;
    private JwtService jwtService;
    private RefreshTokenService refreshTokenService;
    private UuidService uuidService;
    private CapacityJwtPropertie jwtPropertie;
    private CapacityMacaoonPropertie macaoonPropertie;
    private ExtractionToken  extractionToken;


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
                       CapacityMacaoonPropertie macaoonPropertie,ExtractionToken extractionToken) {
        this.capacityUserService = capacityUserService;
        this.politiqueService = politiqueService;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.uuidService = uuidService;
        this.vulnerabilityReport = vulnerabilityReport;
        this.encoder = encoder;
        this.jwtPropertie = jwtPropertie;
        this.macaoonPropertie = macaoonPropertie;
        this.extractionToken = extractionToken;
    }
    // login
    @Override
    public TokenResponse login(String username, String password, String deviceId) {
        CapacityUser user = capacityUserService
                .findByUsername(username)
                .orElseThrow(() -> {
                    vulnerabilityReport.report(
                            new SecurityVulnerabilityEvent(
                                    VulnerabilityType.NOTFUND,
                                    "Unknown user!!", username, getClass().getSimpleName())
                    );
                    return new ApiValidationException(HttpStatus.NOT_FOUND,"Unknown user!");
                });


       matches(password, user.getPassword());
       return genererTokenResponse(user, deviceId);

    }

   //Cas auth par OAUTH
    @Override
    public TokenResponse oAuthlogin(String username, String deviceId) {

        CapacityUser user = capacityUserService
                .findByUsername(username)
                .orElseThrow(() -> {
                    vulnerabilityReport.report(
                            new SecurityVulnerabilityEvent(
                                    VulnerabilityType.NOTFUND,
                                    "Unknown user.", username, getClass().getSimpleName())
                    );

                    return new ApiValidationException(HttpStatus.NOT_FOUND,"Unknown user");
                });


        log.info("Connexion : {} sur appareil : {}", username, deviceId);
        return genererTokenResponse(user, deviceId);
    }
    // refresh
    @Override
    public TokenResponse refresh(String refreshToken) {

        String username = getName(refreshToken);
        CapacityUser user = capacityUserService
                .findByUsername(username)
                .orElseThrow(() ->
                        new RuntimeException("Unknown user"));

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
                    uuid.set(uuidService.generer(deviceId, jwtPropertie.getDuration()));
                String token = jwtService.generer(scope, actions, false, deviceId, uuid.get());
                accessTokens.put(scope, token);
            });


        // refresh token
        if (macaoonPropertie.isRedis())
            uuid.set(uuidService.generer(deviceId, jwtPropertie.getRefduration()));
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
    private Map<String, Set<String>> getPolitiqueFusionnee(Set<String> roles) {

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
            return oAuthlogin(userInfo.getEmail(), null);
    }

    public void matches(String rawPassword, String storedPassword) {
        //log.info("rawPasse encode :  {}", encoder.encode(rawPassword));
        if (rawPassword == null || storedPassword == null) {
            throw new ApiValidationException(HttpStatus.UNAUTHORIZED, "Incorrect password");
        }

        boolean hasRecognizedPrefix = HASH_PREFIX_PATTERN.matcher(storedPassword).matches();

        if (!hasRecognizedPrefix) {
            vulnerabilityReport.report(
                    new SecurityVulnerabilityEvent(
                            VulnerabilityType.PAINTEXT_PASSWORD, "Plain text password detected", "", getClass().getSimpleName())
            );
            if (!rawPassword.equals(storedPassword)) {
                throw new ApiValidationException(HttpStatus.UNAUTHORIZED, "Incorrect password");
            }
            return;
        }

        try {
            if (!encoder.matches(rawPassword, storedPassword)) {
                throw new ApiValidationException(HttpStatus.UNAUTHORIZED, "Incorrect password");
            }
        } catch (IllegalArgumentException e) {
            vulnerabilityReport.report(
                    new SecurityVulnerabilityEvent(
                            VulnerabilityType.PAINTEXT_PASSWORD, "Malformed hash detected", "", getClass().getSimpleName())
            );
            throw new ApiValidationException(HttpStatus.UNAUTHORIZED, "Incorrect password");
        }
    }    private String getName(String refreshToken) {
        Claims claims = extractionToken.extractClaims(refreshToken);
        if (!"refresh".equals(claims.get("type"))) {
            return null;
        }

        return claims.getSubject();
    }

}
