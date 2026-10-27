package com.github.ndytar.capacity.config;

import com.github.ndytar.capacity.customclaims.CustomClaims;
import com.github.ndytar.capacity.customclaims.CustomClaimsService;
import com.github.ndytar.capacity.proof.ProofRequest;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

@AutoConfiguration

public class DefaultCustomClaimsConfig  {

    @Bean
    @ConditionalOnMissingBean(CustomClaimsService.class)
    public CustomClaimsService customClaimsService() {

        return new CustomClaimsService() {
            @Override
            public CustomClaims customClaims(ProofRequest proofRequest, Object o) {
                return new CustomClaims(Map.of());
            }

            @Override
            public boolean verify(CustomClaims customClaims) throws Exception {
                return true;
            }

        };
    }
}
