package com.coffee.coffeeservice.member.service;

import static com.coffee.coffeeservice.common.type.ErrorCode.ALREADY_EXISTS_USER;
import static com.coffee.coffeeservice.common.type.ErrorCode.LOGIN_ERROR;
import static com.coffee.coffeeservice.common.type.ErrorCode.NOT_FOUND_USER;
import static com.coffee.coffeeservice.common.type.ErrorCode.NOT_MATCH_TOKEN;
import static com.coffee.coffeeservice.common.type.ErrorCode.WRONG_PASSWORD;
import static com.coffee.coffeeservice.member.type.RoleType.BUYER;

import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.coffee.coffeeservice.common.exception.CustomException;
import com.coffee.coffeeservice.member.dto.MemberDto;
import com.coffee.coffeeservice.member.dto.MemberUpdateDto;
import com.coffee.coffeeservice.member.entity.Member;
import com.coffee.coffeeservice.member.repository.MemberRepository;
import com.coffee.coffeeservice.util.JwtUtil;
import com.coffee.coffeeservice.util.PasswordUtil;
import java.time.LocalDateTime;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService {

  private final MemberRepository memberRepository;

  private final MailService mailService;

  private final JwtUtil jwtUtil;

  public void addMember(MemberDto memberDto) {

    Optional<Member> optionalMember = memberRepository.findByEmail(memberDto.getEmail());
    if (optionalMember.isPresent()) {
      throw new CustomException(ALREADY_EXISTS_USER);
    }

    String encodePassword = PasswordUtil.hashPassword(memberDto.getPassword());

    Member member = Member.builder()
        .memberName(memberDto.getMemberName())
        .phone(memberDto.getPhone())
        .email(memberDto.getEmail())
        .password(encodePassword)
        .address(memberDto.getAddress())
        .role(BUYER)
        .build();

    memberRepository.save(member);

    mailService.sendEmail(memberDto.getEmail());
  }

  public String login(String email, String password) {

    Member member = memberRepository.findByEmail(email).orElse(null);

    if (member == null || !PasswordUtil.matches(password, member.getPassword())
        || member.getCertificationAt() == null) {
      throw new CustomException(LOGIN_ERROR);
    }

    return jwtUtil.generateToken(email);
  }

  public MemberDto getMember(String email, String token) {

    Member member = memberRepository.findByEmail(email)
        .orElseThrow(() -> new CustomException(NOT_FOUND_USER));

    try {
      jwtUtil.validateToken(token);
    } catch (SignatureVerificationException e) {
      throw new CustomException(NOT_MATCH_TOKEN);
    }

    return MemberDto.builder()
        .memberName(member.getMemberName())
        .phone(member.getPhone())
        .email(member.getEmail())
        .address(member.getAddress())
        .build();
  }

  public void updateMember(String email, String token, MemberUpdateDto memberUpdateDto) {

    Member member = memberRepository.findByEmail(email).orElseThrow(() -> new CustomException(NOT_FOUND_USER));

    try {
      jwtUtil.validateToken(token);
    } catch (SignatureVerificationException e) {
      throw new CustomException(NOT_MATCH_TOKEN);
    }

    if (!PasswordUtil.matches(memberUpdateDto.getCurrentPassword(), member.getPassword())) {
      throw new CustomException(WRONG_PASSWORD);
    }

    if (memberUpdateDto.getPhone() != null) {
      member.setPhone(memberUpdateDto.getPhone());
      member.setUpdatedAt(LocalDateTime.now());
    }

    if (memberUpdateDto.getEmail() != null && !member.getEmail().equals(memberUpdateDto.getEmail())) {
      if (memberRepository.existsByEmail(memberUpdateDto.getEmail())) {
        throw new CustomException(ALREADY_EXISTS_USER);
      }
      member.setEmail(memberUpdateDto.getEmail());
      member.setUpdatedAt(LocalDateTime.now());
    }

    if (memberUpdateDto.getAddress() != null) {
      member.setAddress(memberUpdateDto.getAddress());
      member.setUpdatedAt(LocalDateTime.now());
    }

    if (memberUpdateDto.getPassword() != null) {
      member.setPassword(PasswordUtil.hashPassword(memberUpdateDto.getPassword()));
      member.setUpdatedAt(LocalDateTime.now());
    }
    memberRepository.save(member);
  }
}