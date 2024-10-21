package com.coffee.coffeeservice.member.service;

import static com.coffee.coffeeservice.common.type.ErrorCode.ALREADY_VERIFY;
import static com.coffee.coffeeservice.common.type.ErrorCode.MAIL_ERROR;
import static com.coffee.coffeeservice.common.type.ErrorCode.NOT_FOUND_USER;

import com.coffee.coffeeservice.common.exception.CustomException;
import com.coffee.coffeeservice.member.entity.Member;
import com.coffee.coffeeservice.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MailService {

  private final JavaMailSender mailSender;

  private final MemberRepository memberRepository;

  public void sendEmail(String email) {

    Member member = memberRepository.findByEmail(email).orElseThrow(() -> new CustomException(NOT_FOUND_USER));

    if (member.getCertificationAt() != null) {
      throw new CustomException(ALREADY_VERIFY);
    }

    String subject = "C.R 회원가입 인증 이메일";
    String text = "회원가입을 위한 인증을 완료하려면 아래 링크를 클릭해 주세요: \n" +
        "http://localhost:8080/verify?email=" + email;

    SimpleMailMessage message = new SimpleMailMessage();
    message.setTo(email);
    message.setSubject(subject);
    message.setText(text);

    try {
      mailSender.send(message);
    } catch (MailException e) {
      throw new CustomException(MAIL_ERROR);
    }
  }

  public void verifyEmail(String email) {

    Member member = memberRepository.findByEmail(email).orElseThrow(() -> new CustomException(NOT_FOUND_USER));

    if (member.getCertificationAt() != null) {
      throw new CustomException(ALREADY_VERIFY);
    }

    member.certify();
    memberRepository.save(member);
  }
}