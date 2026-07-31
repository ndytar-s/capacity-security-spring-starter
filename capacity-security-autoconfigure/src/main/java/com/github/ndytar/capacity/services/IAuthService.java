package com.github.ndytar.capacity.services;


import com.github.ndytar.capacity.aop.OauthUserInfo;
import com.github.ndytar.capacity.capacityModel.CapacityUser;
import com.github.ndytar.capacity.jwt_macaroons.TokenResponse;

public interface IAuthService {
  public TokenResponse login(String username, String password, String deviceId);
  public TokenResponse login(String username, String deviceId);
  public TokenResponse refresh(String refreshToken);
  public TokenResponse genererTokenResponse(CapacityUser user, String deviceId);
  public TokenResponse processExternalOauthVerification(OauthUserInfo userInfo);
}
