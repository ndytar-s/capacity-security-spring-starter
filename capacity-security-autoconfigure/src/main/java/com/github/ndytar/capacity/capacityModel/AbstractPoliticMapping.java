package com.github.ndytar.capacity.capacityModel;


import com.github.ndytar.capacity.services.MappingScopeActions;
import jakarta.persistence.*;
import org.springframework.data.annotation.Id;

import java.util.HashSet;
import java.util.Set;

@MappedSuperclass
public abstract class AbstractPoliticMapping implements MappingScopeActions {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "politique_roles", joinColumns = @JoinColumn(name = "politique_id"))
    @Column(name = "role_name")
    private Set<String> role = new HashSet<>();

    @Column(nullable = false)
    private String scope;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "politique_action", joinColumns = @JoinColumn(name = "politique_id"))
    @Column(name = "action")
    private Set<String> actions = new HashSet<>();

    protected AbstractPoliticMapping() {}
    protected AbstractPoliticMapping(String scope, Set<String> role, Set<String> actions) {
        this.scope = scope; this.role = role; this.actions = actions;
    }

    @Override public String getScopeName() { return scope; }
    @Override public Set<String> getActionsSet() { return actions; }
    public Set<String> getRole() { return role; }
}
