package com.github.ndytar.capacity.login;


import com.github.ndytar.capacity.services.CapacityPolitiqueMappingService;
import com.github.ndytar.capacity.services.MappingScopeActions;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

//@Component
public class DynamicPoliticMappingService implements CapacityPolitiqueMappingService {

    // Une fonction que le développeur fournira pour charger ses propres données brutes
    private final Function<String, Collection<? extends MappingScopeActions>> datasourceProvider;

    public DynamicPoliticMappingService(Function<String, Collection<? extends MappingScopeActions>> datasourceProvider) {
        this.datasourceProvider = datasourceProvider;
    }

    @Override
    public Map<String, Set<String>> getPolitiqueForRole(String role) {
        // La logique complexe de transformation reste chez vous, masquée pour lui
        Collection<? extends MappingScopeActions> data = datasourceProvider.apply(role);
        if (data == null) {
            return Collections.emptyMap();
        }

        return data.stream()
                .collect(Collectors.toMap(
                        MappingScopeActions::getScopeName,
                        MappingScopeActions::getActionsSet,
                        (existing, replacement) -> {
                            existing.addAll(replacement);
                            return existing;
                        }
                ));
    }
}
