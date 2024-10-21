package com.coffee.coffeeservice.common.annotation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Constraint(validatedBy = PhoneValidator.class)
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidPhone {

  String message() default "대한민국 전화번호 형식에 맞게 입력해주세요.";
  Class<?>[] groups() default {};
  Class<? extends Payload>[] payload() default {};

}
