package com.github.ndytar.capacity.config;

import com.github.ndytar.capacity.audit.LogAuditSystem;
import com.github.ndytar.capacity.properties.CapacitySecurityPropertie;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class AuditConfig {

    @Bean
    @ConditionalOnMissingBean(LogAuditSystem.class)
    public LogAuditSystem defaultLogAuditSystem() {
        return new DefaultLogAuditSystem(new CapacitySecurityPropertie());
    }
}
