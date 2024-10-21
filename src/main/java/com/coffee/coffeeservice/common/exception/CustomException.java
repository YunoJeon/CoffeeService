package com.coffee.coffeeservice.common.exception;

import com.coffee.coffeeservice.common.type.ErrorCode;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class CustomException extends RuntimeException{

  private final ErrorCode errorCode;
}