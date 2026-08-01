package com.github.ndytar.capacity.autoconfigure;

import com.github.ndytar.capacity.aop.*;
import com.github.ndytar.capacity.login.AuthService;
import com.github.ndytar.capacity.properties.CapacitySecurityAoautProperties;
import com.github.ndytar.capacity.services.ExternalOauthVerifier;
import com.github.ndytar.capacity.services.SecurityAuditReporter;
import com.github.ndytar.capacity.services.SucurityVulnerabilityReport;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

@AutoConfiguration
@ConditionalOnClass(Aspect.class)
@EnableAspectJAutoProxy
public class CapacityAopAutoConfiguration {
    /***
     *
     * @param externalOauthVerifier
     * @param authService
     * @param properties
     * @return
     * @ConditionalOnBean(ExternalOauthVerifier.class) : ce bean ne se crée que si le développeur a lui même déclaré une
     * implémentation de ExternalOauthVerifier dans son propre @Configuration.
     * S'il ne l'a pas fait, CapacityOauthAspect n'est simplement jamais instancié,
     * aucune erreur, la fonctionnalité OAuth reste inactive silencieusement,
     * et le reste du starter (JWT, Macaroon) continue de fonctionner normalement.
     */
    @Bean
    @ConditionalOnBean(ExternalOauthVerifier.class)
    @ConditionalOnMissingBean(CapacityOauthAspect.class)
    public CapacityOauthAspect capacityOauthAspect(
            ExternalOauthVerifier externalOauthVerifier,
            AuthService authService,
            CapacitySecurityAoautProperties properties) {
        return new CapacityOauthAspect(externalOauthVerifier, authService, properties);
    }
    @Bean
    @ConditionalOnMissingBean
    public SecurityAuditAspect securityAuditAspect() {
        return new SecurityAuditAspect();
    }
    @Bean
    @ConditionalOnMissingBean(SecurityAuditReporter.class)//possible personnaliser implementer soit meme
    public SecurityAuditReporter securityAuditReporter(ApplicationEventPublisher publisher) {
        return new SpringSecurityAuditRepoerter(publisher);
    }

    @Bean
    @ConditionalOnMissingBean(SucurityVulnerabilityReport.class)//possible personnaliser implementer soit meme
    public SucurityVulnerabilityReport sucurityVulnerabilityReport(ApplicationEventPublisher publisher) {
        return new SpringSecurityVulnerabilityReporter(publisher);
    }
    @Bean
    @ConditionalOnMissingBean
    public SecurityVulnerabilityAspect securityVulnerabilityAspect() {
        return new SecurityVulnerabilityAspect();
    }
}