package com.github.ndytar.capacity.services;

import com.github.ndytar.capacity.capacityModel.AbstractPoliticMapping;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

import java.util.Optional;

@NoRepositoryBean
public interface PoliticMappingRepository<T extends AbstractPoliticMapping>
        extends JpaRepository<T, Long> {
    Optional<T> findByScope(String scope);
}