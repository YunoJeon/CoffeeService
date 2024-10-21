package com.coffee.coffeeservice.member.controller;

import com.coffee.coffeeservice.member.dto.MemberDto;
import com.coffee.coffeeservice.member.service.MemberService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/members")
public class MemberController {

  private final MemberService memberService;

  @PostMapping
  public ResponseEntity<Void> addMember(@RequestBody @Valid MemberDto memberDto) {

    memberService.addMember(memberDto);

    return ResponseEntity.status(HttpStatus.CREATED).build();
  }
}