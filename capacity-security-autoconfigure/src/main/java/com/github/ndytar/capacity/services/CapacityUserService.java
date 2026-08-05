package com.github.ndytar.capacity.services;


import com.github.ndytar.capacity.capacityModel.CapacityUser;

import java.util.Optional;

/**
 * Optionnel, user peut configuer lui meme et retiurner le resultat souhaite
 */
public interface CapacityUserService {
    Optional<CapacityUser> findByUsername(String username);
}

