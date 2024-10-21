package com.coffee.coffeeservice.common.annotation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PasswordValidator implements ConstraintValidator<ValidPassword, String> {

  @Override
  public boolean isValid(String s, ConstraintValidatorContext constraintValidatorContext) {

    if (s == null) {
      return true;
    }
    return s.length() >= 8;
  }
}
