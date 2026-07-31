package com.github.ndytar.capacity.capacityModel;


import java.util.List;

public class CapacityUser {

    private String       username;
    private String       password;
    private List<String> roles;

    public CapacityUser(String username, String password,
                        List<String> roles) {
        this.username = username;
        this.password = password;
        this.roles    = roles;
    }

    public String       getUsername() { return username; }
    public String       getPassword() { return password; }
    public List<String> getRoles()    { return roles; }
}
