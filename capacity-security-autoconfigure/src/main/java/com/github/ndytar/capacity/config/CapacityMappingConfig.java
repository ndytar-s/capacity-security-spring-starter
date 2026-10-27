package com.github.ndytar.capacity.config;

import com.github.ndytar.capacity.capacityModel.AbstractPoliticMapping;
import com.github.ndytar.capacity.services.MappingScopeActions;
import com.github.ndytar.capacity.services.PoliticMappingProvider;
import com.github.ndytar.capacity.services.PoliticMappingRepository;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
@AutoConfiguration
public class CapacityMappingConfig {
    @AutoConfiguration(afterName = {
            "org.springframework.boot.data.jpa.autoconfigure.DataJpaRepositoriesAutoConfiguration",
            "org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration"
    })
    @ConditionalOnClass(name = "jakarta.persistence.MappedSuperclass")
    public static class CapacityPoliticMappingAutoConfiguration {

        @Bean
        @ConditionalOnBean(PoliticMappingRepository.class)
        @ConditionalOnMissingBean(PoliticMappingProvider.class)
        PoliticMappingProvider jpaPoliticMappingProvider(
                PoliticMappingRepository<? extends AbstractPoliticMapping> repo) {
            return scope -> repo.findByScope(scope).map(m -> (MappingScopeActions) m);
        }
    }
}
