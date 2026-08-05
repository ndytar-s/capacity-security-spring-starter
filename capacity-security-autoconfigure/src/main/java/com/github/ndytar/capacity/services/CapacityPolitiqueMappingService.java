package com.github.ndytar.capacity.services;

import java.util.Map;
import java.util.Set;

public interface CapacityPolitiqueMappingService {
    Map<String, Set<String>> getPolitiqueForRole(String role);
}
