package com.coffee.coffeeservice.util;

import lombok.experimental.UtilityClass;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@UtilityClass
public class PasswordUtil {

  private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

  public String hashPassword(String password) {
    return encoder.encode(password);
  }

  public boolean matches(String password, String hashedPassword) {
    return encoder.matches(password, hashedPassword);
  }
}