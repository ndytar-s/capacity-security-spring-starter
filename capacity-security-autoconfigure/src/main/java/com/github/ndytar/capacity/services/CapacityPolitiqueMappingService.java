package com.github.ndytar.capacity.services;

import java.util.Map;
import java.util.Set;

// Dans le starter : interface que le dev doit implémenter
public interface CapacityPolitiqueMappingService {
    Map<String, Set<String>> getPolitiqueForRole(String role);
}
