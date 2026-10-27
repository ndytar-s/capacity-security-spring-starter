package com.github.ndytar.capacity.config;

import com.github.ndytar.capacity.proof.Actions;
import com.github.ndytar.capacity.proof.CapacityResourcePolicyService;
import com.github.ndytar.capacity.proof.ProofRequest;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;
import java.util.Set;

@AutoConfiguration
public class CapacityProofConfiguration {
    @Bean
    @ConditionalOnMissingBean(CapacityResourcePolicyService.class)
    public CapacityResourcePolicyService capacityResourcePolicyService() {

        return new CapacityResourcePolicyService() {
            @Override
            public Map<String, Set<String>> getAuthorizedScopes(ProofRequest request) {
                return Map.of(request.resource(), Actions.get.actions());
            }
        };

    }

}