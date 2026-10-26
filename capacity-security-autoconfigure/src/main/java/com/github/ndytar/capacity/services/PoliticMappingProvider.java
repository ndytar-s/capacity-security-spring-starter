package com.github.ndytar.capacity.services;

import java.util.Optional;

public interface PoliticMappingProvider {
    Optional<MappingScopeActions> find(String scope);
}