package com.github.ndytar.capacity.capacityModel;

import java.util.Set;

public class CapacityUser {

    private String       username;
    private String       password;
    private Set<String> roles;

    public CapacityUser(String username, String password,
                        Set<String> roles) {
        this.username = username;
        this.password = password;
        this.roles    = roles;
    }

    public String       getUsername() { return username; }
    public String       getPassword() { return password; }
    public Set<String> getRoles()    { return roles; }
}
