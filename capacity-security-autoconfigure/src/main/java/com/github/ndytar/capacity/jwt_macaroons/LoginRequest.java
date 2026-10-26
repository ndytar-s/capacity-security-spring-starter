package com.github.ndytar.capacity.jwt_macaroons;


public class LoginRequest {

    private String username;
    private String password;
    private Object jwk ;  // optionnel

    public String getUsername()           { return username; }
    public void   setUsername(String u)   { this.username = u; }
    public String getPassword()           { return password; }
    public void   setPassword(String p)   { this.password = p; }

    public Object getJwk() {
        return jwk;
    }

    public void setJwk(Object jwk) {
        this.jwk = jwk;
    }
}
