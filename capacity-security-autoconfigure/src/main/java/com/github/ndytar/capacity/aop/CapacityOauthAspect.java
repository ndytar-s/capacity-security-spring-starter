package com.github.ndytar.capacity.aop;


import com.github.ndytar.capacity.annotation.CapacityOauth;
import com.github.ndytar.capacity.jwt_macaroons.TokenResponse;
import com.github.ndytar.capacity.login.AuthService;
import com.github.ndytar.capacity.properties.CapacitySecurityAoautProperties;
import com.github.ndytar.capacity.services.ExternalOauthVerifier;
import jakarta.servlet.http.HttpServletRequest;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.Signature;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Arrays;
@Aspect
public class CapacityOauthAspect {

    private final ExternalOauthVerifier externalOauthVerifier;
    private final AuthService authService; // Votre service existant
    private final CapacitySecurityAoautProperties properties;

   
    public CapacityOauthAspect(
            ExternalOauthVerifier externalOauthVerifier, AuthService authService,
            CapacitySecurityAoautProperties properties) {
        this.externalOauthVerifier = externalOauthVerifier;
        this.authService = authService;
        this.properties = properties;
    }

    @Around("@annotation(capacityOauth)")
    public Object handleOauth(ProceedingJoinPoint joinPoint, CapacityOauth capacityOauth) throws Throwable {

        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        HttpServletRequest request = attributes.getRequest();

        String headerName = properties.getHeaderName();
        String prefix = properties.getPrefix();
        String headerValue = request.getHeader(headerName);
        String externalToken = null;

        if (headerValue != null) {
            externalToken = (prefix != null && !prefix.isEmpty() && headerValue.startsWith(prefix))
                    ? headerValue.substring(prefix.length()).trim()
                    : headerValue.trim();
        }

        if (externalToken == null || externalToken.isEmpty()) {
            throw new SecurityException("Jeton d'autorisation introuvable dans l'en-tête : " + headerName);
        }

        OauthUserInfo userInfo = externalOauthVerifier.verify(externalToken);
        TokenResponse tokenResponse = authService.processExternalOauthVerification(userInfo);

        // Injection directe dans les arguments de la methode cible : on remplace
        // le parametre TokenResponse (quelle que soit sa position) par la vraie
        // valeur, AVANT d'appeler proceed(). L'ArgumentResolver devient inutile
        // pour ce champ precis.
        Object[] args = joinPoint.getArgs();
        Object[] nouveauxArgs = Arrays.copyOf(args, args.length);
        Signature signature = joinPoint.getSignature();
        if (signature instanceof MethodSignature methodSignature) {
            Class<?>[] typesParametres = methodSignature.getParameterTypes();
            for (int i = 0; i < typesParametres.length; i++) {
                if (typesParametres[i].equals(TokenResponse.class)) {
                    nouveauxArgs[i] = tokenResponse;
                }
            }
        }

        return joinPoint.proceed(nouveauxArgs);
    }
}
