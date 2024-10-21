package com.coffee.coffeeservice.member.controller;

import com.coffee.coffeeservice.member.dto.MemberDto;
import com.coffee.coffeeservice.member.dto.MemberLoginDto;
import com.coffee.coffeeservice.member.dto.MemberUpdateDto;
import com.coffee.coffeeservice.member.service.MemberService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
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

  @PostMapping("/login")
  public ResponseEntity<String> login(@RequestBody @Valid MemberLoginDto memberLoginDto) {

    String token = memberService.login(memberLoginDto.getEmail(), memberLoginDto.getPassword());

    return ResponseEntity.ok(token);
  }

  @GetMapping("/{email}")
  public ResponseEntity<MemberDto> getMember(@PathVariable String email,
      @RequestHeader("AUTH-TOKEN") String token) {

    MemberDto memberDto = memberService.getMember(email, token);

    return ResponseEntity.ok(memberDto);
  }

  @PatchMapping("/{email}")
  public ResponseEntity<Void> updateMember(@PathVariable String email,
      @RequestHeader("AUTH-TOKEN") String token,
      @RequestBody @Valid MemberUpdateDto memberUpdateDto) {

    memberService.updateMember(email, token, memberUpdateDto);

    return ResponseEntity.noContent().build();
  }
}