package com.github.ndytar.capacity.autoconfigure;
import com.github.ndytar.capacity.aop.*;
import com.github.ndytar.capacity.audit.AuditCollector;
import com.github.ndytar.capacity.auth.CapacityAuthManager;
import com.github.ndytar.capacity.auth.CapacityDecision;
import com.github.ndytar.capacity.auth.Deduiction;
import com.github.ndytar.capacity.auth.IpAuthorizationChecker;
import com.github.ndytar.capacity.capacityModel.AbstractPoliticMapping;
import com.github.ndytar.capacity.chaine.CapacityFilter;
import com.github.ndytar.capacity.customclaims.CustomClaimsService;
import com.github.ndytar.capacity.exception.CapacityAccessDeniedHandler;
import com.github.ndytar.capacity.jwt_macaroons.*;
import com.github.ndytar.capacity.login.AuthService;
import com.github.ndytar.capacity.proof.CapacityResourcePolicyService;
import com.github.ndytar.capacity.proof.dPop.DpopService;
import com.github.ndytar.capacity.properties.*;
import com.github.ndytar.capacity.services.*;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.Optional;

import static com.github.ndytar.capacity.config.CapacitySecurityConfigurer.capacitySecurity;

@AutoConfiguration
@ConditionalOnClass(SecurityFilterChain.class)
@EnableConfigurationProperties({
        CapacityJwtPropertie.class,
        CapacityMacaoonPropertie.class,
        CapacitySecurityPropertie.class,
        CapacitySecurityAoautProperties.class,
        CapacityDpopPropertie.class})
public class CapacitySecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public CapacityFilter capacityFilter(
            AuthenticationEntryPoint authenticationEntryPoint,
            ExtractionToken extractionToken,
            MacaroonService macaroonService,
            CapacityMacaoonPropertie macaroonPropertie,
            RequestMappingHandlerMapping handlerMapping,
            CapacityJwtPropertie jwtPropertie,
            @Qualifier("handlerExceptionResolver")
            HandlerExceptionResolver resolver,
            JwtService jwtService,
            CustomClaimsService customClaimes,
            Deduiction deduiction,
            DpopService dpopService,
            CapacityDpopPropertie isDop
    ) {

        // filter.setHEADER(properties.getJwt().getHeaderName());
        return new CapacityFilter(
             authenticationEntryPoint,extractionToken,macaroonService,
                macaroonPropertie,handlerMapping,jwtPropertie,resolver,
                jwtService,customClaimes,deduiction,dpopService,isDop
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public IAuthService authService(
            DpopService dpopService,
            Optional<CapacityUserService> capacityUserService,
            Optional<CapacityPolitiqueMappingService> politiqueService,
            AuditCollector auditCollector,
            JwtService jwtService,
            RefreshTokenService refreshTokenService,
            UuidService uuidService,
            SucurityVulnerabilityReport vulnerabilityReport,
            PasswordEncoder encoder,
            CapacityJwtPropertie jwtPropertie,
            CapacityMacaoonPropertie macaoonPropertie,
            ExtractionToken extractionToken,
            CustomClaimsService customClaimes,
            CapacityResourcePolicyService capacityResourcePolicyService,
            CapacityJwtPropertie capacityJwtPropertie

    ) {
        return new AuthService(
                dpopService, capacityUserService, politiqueService, auditCollector, jwtService,
                 refreshTokenService, uuidService, vulnerabilityReport, encoder, jwtPropertie,
                 macaoonPropertie, extractionToken, customClaimes, capacityResourcePolicyService,
                capacityJwtPropertie
        );
    }

    @Bean @ConditionalOnMissingBean
    public ExtractionToken extractionToken(CapacityJwtPropertie jwtPropertie){
    return new ExtractionToken(jwtPropertie);
    }

    @Bean @ConditionalOnMissingBean public CapacityAccessDeniedHandler capacityAccessDeniedHandler() {
     return new CapacityAccessDeniedHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    public MacaroonService macaroonService(
            CapacityMacaoonPropertie macaoonPropertie,
            CapacityJwtPropertie jwtPropertie,
            ExtractionToken extractionToken, RevocationToken revocationToken,
            RegistrationTokenService registrationToken, Deduiction deduiction
    ) {
        return new MacaroonService(
                macaoonPropertie,
               jwtPropertie,
               extractionToken,  revocationToken,
                 registrationToken,  deduiction
        );
    }


    @Bean
    @ConditionalOnMissingBean
    public RedisTokenStorage redisTokenStorage(  StringRedisTemplate redisTemplate,
                                                 RedisKeys redisKeys){
     return new RedisTokenStorage(redisTemplate,redisKeys);
    }
    @Bean
    @ConditionalOnMissingBean
    public RedisKeys redisKeys() {
    return new RedisKeys();
    }
    @Bean
    @ConditionalOnMissingBean
    public JwtService jwtService(
            CapacityJwtPropertie jwtPropertie,
            RevocationToken revocationToken,
            ExtractionToken extractionToken,
            RegistrationToken registrationToken,
            AuditCollector auditCollector) {
        return new JwtService(
                jwtPropertie,
                 revocationToken,
                extractionToken,
                 registrationToken,
                 auditCollector
        );
    }
    @Bean
    @ConditionalOnMissingBean
    public IpAuthorizationChecker ipAuthorizationChecker(CapacitySecurityPropertie securityProperties){
        return new IpAuthorizationChecker(securityProperties);
    }
    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenService refreshTokenService(CapacityJwtPropertie jwtPropertie) {
        return new RefreshTokenService(jwtPropertie);
    }

    @Bean
    @ConditionalOnMissingBean
    public UuidService uuidService(RegistrationTokenService registrationToken){
     return  new UuidService(registrationToken);
    }
    @Bean
    @ConditionalOnMissingBean
     public RevocationToken revocationToken(TokenStorageService tokenStorage){
      return new RevocationToken(tokenStorage);
    }
    @Bean
    @ConditionalOnMissingBean
    public RegistrationToken registrationToken(TokenStorageService tokenStorageService){
    return new RegistrationToken(tokenStorageService);
    }
    @Bean
    @ConditionalOnMissingBean
    public Deduiction deduiction() {
        return new Deduiction();
    }
    @Bean
    @ConditionalOnMissingBean
    public CapacityAuthManager capacityAuthManager(
            Deduiction deduiction,
            RequestMappingHandlerMapping handlerMapping,
            IpAuthorizationChecker ipAuthorizationChecker,
            AuditCollector auditCollector,
            CapacityDecision capacityDecision
    ) {
        return new CapacityAuthManager(
                deduiction, handlerMapping,
                ipAuthorizationChecker, auditCollector, capacityDecision
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public CapacityDecision capacityDecision(Deduiction deduiction,
                                             MacaroonService macaroonService,
                                             AuditCollector auditCollector){
            return new CapacityDecision( deduiction,
                     macaroonService,
                     auditCollector);
    }
    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain capacityFilterChain(
            HttpSecurity http, CapacityAuthManager capacity)  {

        http.with(capacitySecurity(), Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().access(capacity));

        return http.build();
    }
}