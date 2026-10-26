package com.github.ndytar.capacity.autoconfigure;

import com.github.ndytar.capacity.aop.*;
import com.github.ndytar.capacity.audit.*;
import com.github.ndytar.capacity.config.CapacityWebSecurityAutoConfiguration;
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
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

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
     @ConditionalOnMissingBean
     public CapacityWebSecurityAutoConfiguration capacityWebSecurityAutoConfiguration(){
            return new CapacityWebSecurityAutoConfiguration();
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

    @Bean
    @ConditionalOnMissingBean(WebMvcConfigurer.class)
    public WebMvcConfigurer capacityWebMvcConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
                resolvers.add(new TokenResponseArgumentResolver());
            }
        };
    }
    //  -------------------- Audit  -----------------
   @Bean
   @ConditionalOnMissingBean
   @Order(Ordered.HIGHEST_PRECEDENCE)
   public AuditFilter auditFilter(com.github.ndytar.capacity.audit.SecurityAuditReporter reporter){
        return new AuditFilter(reporter);
   }
 @Bean
    @ConditionalOnMissingBean(DefaultAuditCollector.class)
    public DefaultAuditCollector defaultAuditCollector(){
        return new DefaultAuditCollector();
 }
 @Bean
    @ConditionalOnMissingBean(DefaultAuditEventHandler.class)
    public DefaultAuditEventHandler defaultAuditEventHandler(LogAuditSystem logAuditSystem){
        return new DefaultAuditEventHandler( logAuditSystem);
 }
 @Bean
    @ConditionalOnMissingBean
    public SpringSecurityAuditReporter springSecurityAuditReporter(ApplicationEventPublisher publisher ){
        return new SpringSecurityAuditReporter(  publisher);
 }


}