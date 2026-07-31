package com.github.ndytar.capacity.login;


public class LoginRequest {

    private String username;
    private String password;
    private String deviceId = "default";  // optionnel

    public String getUsername()           { return username; }
    public void   setUsername(String u)   { this.username = u; }
    public String getPassword()           { return password; }
    public void   setPassword(String p)   { this.password = p; }
    public String getDeviceId()           { return deviceId; }
    public void   setDeviceId(String d)   { this.deviceId = d; }
}
