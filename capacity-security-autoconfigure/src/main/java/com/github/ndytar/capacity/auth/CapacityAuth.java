package com.github.ndytar.capacity.auth;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.Set;
import java.util.stream.Collectors;

public class CapacityAuth extends AbstractAuthenticationToken {

    private final String      token;
    private final String      resourceScope;
    private final Set<String> actions;
    private final boolean     oneTime;

    private final String      uuid;

    public CapacityAuth(String token, String resourceScope,
                        Set<String> actions, boolean oneTime,
                       String uuid) {
        super(actions.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList()));
        this.token         = token;
        this.resourceScope = resourceScope;
        this.actions       = actions;
        this.oneTime       = oneTime;

        this.uuid           = uuid;
        setAuthenticated(true);
    }

    public String      getResourceScope() { return resourceScope; }
    public Set<String> getActions()       { return actions; }
    public boolean     isOneTime()        { return oneTime; }
    public String      getUuid()           { return uuid; }

    @Override
    public Object getCredentials() { return token; }

    @Override
    public Object getPrincipal()   { return token; }
}
