package com.github.ndytar.capacity.services;


import com.github.ndytar.capacity.capacityModel.CapacityUser;

import java.util.Optional;

// Interface starter
public interface CapacityUserService {
    Optional<CapacityUser> findByUsername(String username);
}

