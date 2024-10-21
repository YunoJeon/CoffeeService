package com.coffee.coffeeservice.common.annotation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Constraint(validatedBy = PasswordValidator.class)
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidPassword {

  String message() default "비밀번호는 최소 8자 이상으로 이루어져 있어야 합니다.";
  Class<?>[] groups() default {};
  Class<? extends Payload>[] payload() default {};

}
