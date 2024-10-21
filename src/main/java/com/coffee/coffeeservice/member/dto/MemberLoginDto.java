package com.coffee.coffeeservice.member.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class MemberLoginDto {

  @Email(message = "이메일 형식이 아닙니다.")
  @NotEmpty(message = "이메일은 필수 입력사항 입니다.")
  private String email;

  @NotEmpty(message = "비밀번호는 필수 입력사항 입니다.")
  @Size(min = 8, message = "비밀번호는 최소 8자 이상으로 이루어져 있어야 합니다.")
  private String password;
}