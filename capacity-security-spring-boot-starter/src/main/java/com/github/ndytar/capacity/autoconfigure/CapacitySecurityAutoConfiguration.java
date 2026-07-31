package com.github.ndytar.capacity.autoconfigure;


import com.github.ndytar.capacity.auth.CapacityAuthManager;
import com.github.ndytar.capacity.auth.Deduiction;
import com.github.ndytar.capacity.chaine.CapacityFilter;
import com.github.ndytar.capacity.jwt_macaroons.JwtService;
import com.github.ndytar.capacity.jwt_macaroons.MacaroonService;
import com.github.ndytar.capacity.jwt_macaroons.RefreshTokenService;
import com.github.ndytar.capacity.jwt_macaroons.UuidService;
import com.github.ndytar.capacity.login.AuthService;
import com.github.ndytar.capacity.properties.CapacityJwtPropertie;
import com.github.ndytar.capacity.properties.CapacityMacaoonPropertie;
import com.github.ndytar.capacity.properties.CapacitySecurityPropertie;

import com.github.ndytar.capacity.register.TokenRedisService;
import com.github.ndytar.capacity.services.CapacityPolitiqueMappingService;
import com.github.ndytar.capacity.services.CapacityUserService;
import com.github.ndytar.capacity.services.SecurityAuditReporter;
import com.github.ndytar.capacity.services.SucurityVulnerabilityReport;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import static com.github.ndytar.capacity.autoconfigure.config.CapacitySecurityConfigurer.capacitySecurity;

@AutoConfiguration
@ConditionalOnClass(SecurityFilterChain.class)
@EnableConfigurationProperties({CapacityJwtPropertie.class,
        CapacityMacaoonPropertie.class,
CapacitySecurityPropertie.class})
public class CapacitySecurityAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean
    public CapacityFilter capacityFilter(
            JwtService jwtService,
            MacaroonService macaroonService,
            TokenRedisService tokenRedisService,
            SecurityAuditReporter auditReporter,
            RequestMappingHandlerMapping handlerMapping,
            CapacityJwtPropertie jwtPropertie
    ) {

        CapacityFilter filter = new CapacityFilter(
                jwtService,
                 macaroonService,
                tokenRedisService,
                 auditReporter,
                 handlerMapping,
                 jwtPropertie
        );
       // filter.setHEADER(properties.getJwt().getHeaderName());
        return filter;
    }
    @Bean
    @ConditionalOnMissingBean
    public AuthService authService(CapacityUserService capacityUserService,
                                  CapacityPolitiqueMappingService politiqueService,
                                  JwtService jwtService,
                                  RefreshTokenService refreshTokenService,
                                  UuidService uuidService,
                                  SucurityVulnerabilityReport vulnerabilityReport,
                                  PasswordEncoder encoder,
                                  CapacityJwtPropertie jwtPropertie,
                                  CapacityMacaoonPropertie macaoonProperti) {
        return new AuthService(
              capacityUserService,
               politiqueService,
                jwtService,
                 refreshTokenService,
                 uuidService,
                 vulnerabilityReport,
                 encoder,
                jwtPropertie,
                macaoonProperti
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public MacaroonService macaroonService(UuidService uuidService,
                                           JwtService jwtService,
                                           TokenRedisService tokenRedisService,
                                           CapacityMacaoonPropertie macaoonPropertie,
                                           CapacityJwtPropertie jwtPropertie) {
        return new MacaroonService(
                uuidService,
               jwtService,
                tokenRedisService,
                macaoonPropertie,
                 jwtPropertie
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public TokenRedisService tokenRedisService(StringRedisTemplate redisTemplate,
                                               CapacityJwtPropertie jwtPropertie) {
        return new TokenRedisService(redisTemplate, jwtPropertie);
    }

    @Bean
    @ConditionalOnMissingBean
    public CapacityAuthManager capacityAuthManager(Deduiction deduiction, RequestMappingHandlerMapping handlerMapping) {
        return new CapacityAuthManager(deduiction, handlerMapping);
    }


    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain capacityFilterChain(
            HttpSecurity http, CapacityAuthManager capacity) throws Exception {

        http.with(capacitySecurity(), Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().access(capacity));

        return http.build();
    }
}