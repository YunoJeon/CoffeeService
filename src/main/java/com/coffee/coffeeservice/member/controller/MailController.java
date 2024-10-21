package com.coffee.coffeeservice.member.controller;

import com.coffee.coffeeservice.member.service.MailService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class MailController {

  private final MailService mailService;

  @GetMapping("/verify")
  public ResponseEntity<String> verify(@RequestParam String email) {

    mailService.verifyEmail(email);

    return ResponseEntity.ok("이메일 인증이 완료되었습니다.");
  }
}