package com.coffee.coffeeservice.common.type;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ErrorCode {

  ALREADY_EXISTS_USER("ALREADY_EXISTS_USER", "등록된 계정이 존재합니다."),
  ALREADY_VERIFY("ALREADY_VERIFY", "승인이 완료된 이메일 입니다."),
  NOT_FOUND_USER("NOT_FOUND_USER", "계정을 찾지 못했습니다."),
  MAIL_ERROR("MAIL_ERROR", "메일 전송 중 오류가 발생했습니다."),
  ;

  private final String code;
  private final String message;

}