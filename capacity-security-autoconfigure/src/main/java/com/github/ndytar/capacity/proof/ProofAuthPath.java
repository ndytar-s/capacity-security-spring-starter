package com.github.ndytar.capacity.proof;

public final class ProofAuthPath {

    private final CapacityResourcePolicyService policyService;

    public ProofAuthPath( CapacityResourcePolicyService policyService) {

        this.policyService = policyService;
    }


    public CapacityResourcePolicyService policyService() {
        return policyService;
    }
}