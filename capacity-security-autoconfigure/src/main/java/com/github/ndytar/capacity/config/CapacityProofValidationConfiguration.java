package com.github.ndytar.capacity.config;

import com.github.ndytar.capacity.proof.CapacityProofVerifier;
import com.github.ndytar.capacity.proof.CapacityResourcePolicyService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@AutoConfiguration
public class CapacityProofValidationConfiguration {

    @Bean
    public ApplicationRunner capacityProofPairingCheck(
            ObjectProvider<CapacityProofVerifier> verifierProvider,
            ObjectProvider<CapacityResourcePolicyService> policyProvider) {

        return args -> {
            boolean hasVerifier = verifierProvider.getIfAvailable() != null;
            boolean hasPolicy = policyProvider.getIfAvailable() != null;

            if (hasVerifier != hasPolicy) {
                throw new IllegalStateException(
                        "Configuration incomplète du chemin preuve : CapacityProofVerifier et "
                                + "CapacityResourcePolicyService doivent être fournis ensemble. "
                                + "Présent : verifier=" + hasVerifier + ", policyService=" + hasPolicy);
            }
        };
    }
}
