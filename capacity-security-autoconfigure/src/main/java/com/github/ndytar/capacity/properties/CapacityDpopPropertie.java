package com.github.ndytar.capacity.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "capacity.dpop")
public class CapacityDpopPropertie {
   boolean active=false;
    private List<String> algorithms = List.of("ES256"); // défaut
    public List<String> getAlgorithms() { return algorithms; }
    public void setAlgorithms(List<String> a) { this.algorithms = a; }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }
}
