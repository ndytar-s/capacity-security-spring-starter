package com.github.ndytar.capacity.capacityModel;


import java.util.Set;

public class CapacityUser {
    private Long id;
    private String       username;
    private String       password;
    private Set<String> roles;

    public CapacityUser(String username, String password,
                        Set<String> roles, Long id) {
        this.username = username;
        this.password = password;
        this.roles    = roles;
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String       getUsername() { return username; }
    public String       getPassword() { return password; }
    public Set<String> getRoles()    { return roles; }
}
