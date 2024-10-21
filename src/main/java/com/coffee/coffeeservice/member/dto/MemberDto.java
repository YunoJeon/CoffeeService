package com.coffee.coffeeservice.member.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class MemberDto {

  @NotEmpty(message = "이름은 필수 입력사항 입니다.")
  @Size(max = 50)
  private String memberName;

  @NotEmpty(message = "휴대폰번호는 필수 입력사항 입니다.")
  @Pattern(regexp = "01(?:0|1|[6-9])[.-]?(\\d{3}|\\d{4})[.-]?(\\d{4})$", message = "대한민국 전화번호 형식에 맞게 입력해주세요.")
  private String phone;

  @NotEmpty(message = "비밀번호는 필수 입력사항 입니다.")
  @Size(min = 8, message = "비밀번호는 최소 8자 이상으로 이루어져 있어야 합니다.")
  private String password;

  @Email(message = "이메일 형식이 아닙니다.")
  @NotEmpty(message = "이메일은 필수 입력사항 입니다.")
  private String email;

  @NotEmpty(message = "주소는 필수 입력사항 입니다.")
  private String address;

}