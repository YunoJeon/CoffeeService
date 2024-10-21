package service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.coffee.coffeeservice.common.exception.CustomException;
import com.coffee.coffeeservice.member.entity.Member;
import com.coffee.coffeeservice.member.repository.MemberRepository;
import com.coffee.coffeeservice.member.service.MailService;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

@ExtendWith(MockitoExtension.class)
class MailServiceTest {

  @Mock
  private JavaMailSender mailSender;

  @Mock
  private MemberRepository memberRepository;

  @InjectMocks
  private MailService mailService;

  @Test
  void send_Email() {
    // given
    String email = "@coffee@gmail.com";
    String subject = "C.R 회원가입 인증 이메일";
    String text = "회원가입을 위한 인증을 완료하려면 아래 링크를 클릭해 주세요: \n" +
        "http://localhost:8080/verify?email=" + email;
    // when
    Member member = Member.builder()
        .email(email)
        .build();
    when(memberRepository.findByEmail(email)).thenReturn(Optional.of(member));

    mailService.sendEmail(email);
    // then
    ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(
        SimpleMailMessage.class);
    verify(mailSender).send(messageCaptor.capture());

    SimpleMailMessage capturedMessage = messageCaptor.getValue();
    assertEquals(email, Objects.requireNonNull(capturedMessage.getTo())[0]);
    assertEquals(subject, capturedMessage.getSubject());
    assertEquals(text, capturedMessage.getText());
  }

  @Test
  void already_Verified_Email() {
    // given
    String email = "coffee@gmail.com";
    Member verifiedMember = Member.builder()
        .email(email)
        .certificationAt(LocalDateTime.now())
        .build();

    when(memberRepository.findByEmail(email)).thenReturn(Optional.of(verifiedMember));
    // when, then
    CustomException e = assertThrows(CustomException.class, () ->
        mailService.sendEmail(email));

    assertEquals("ALREADY_VERIFY", e.getErrorCode().getCode());
    assertEquals("승인이 완료된 이메일 입니다.", e.getErrorCode().getMessage());
  }

  @Test
  void verify_New_Email() {
    // given
    String email = "coffee@gmail.com";
    Member newMember = Member.builder()
        .email(email)
        .build();

    when(memberRepository.findByEmail(email)).thenReturn(Optional.of(newMember));
    // when
    mailService.verifyEmail(email);
    // then
    assertNotNull(newMember.getCertificationAt());
    verify(memberRepository).save(newMember);
  }
}