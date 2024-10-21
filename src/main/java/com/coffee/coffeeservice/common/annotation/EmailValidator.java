package com.coffee.coffeeservice.common.annotation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class EmailValidator implements ConstraintValidator<ValidEmail, String> {

  @Override
  public boolean isValid(String s, ConstraintValidatorContext constraintValidatorContext) {

    if (s == null) {
      return true;
    }
    return s.matches("^[\\w-.]+@([\\w-]+.)+[\\w-]{2,4}$");
  }
}
