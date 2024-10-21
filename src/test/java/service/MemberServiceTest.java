package service;

import static com.coffee.coffeeservice.common.type.ErrorCode.ALREADY_EXISTS_USER;
import static com.coffee.coffeeservice.common.type.ErrorCode.LOGIN_ERROR;
import static com.coffee.coffeeservice.member.type.RoleType.BUYER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.coffee.coffeeservice.common.exception.CustomException;
import com.coffee.coffeeservice.member.dto.MemberDto;
import com.coffee.coffeeservice.member.entity.Member;
import com.coffee.coffeeservice.member.repository.MemberRepository;
import com.coffee.coffeeservice.member.service.MailService;
import com.coffee.coffeeservice.member.service.MemberService;
import com.coffee.coffeeservice.util.JwtUtil;
import com.coffee.coffeeservice.util.PasswordUtil;
import java.time.LocalDateTime;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class MemberServiceTest {

  @InjectMocks
  private MemberService memberService;

  @Mock
  private MemberRepository memberRepository;

  @Mock
  private MailService mailService;

  @Mock
  private JwtUtil jwtUtil;

  private MemberDto memberDto;

  @BeforeEach
  void setUp() {
    memberDto = MemberDto.builder()
        .memberName("홍길동")
        .phone("010-1234-5678")
        .email("coffee@gmail.com")
        .password("12345678")
        .address("none")
        .build();
  }

  @Test
  void addMember_Success() {
    // given
    when(memberRepository.findByEmail(memberDto.getEmail())).thenReturn(Optional.empty());
    when(memberRepository.save(any(Member.class))).thenAnswer(
        invocation -> invocation.getArgument(0));
    // when
    memberService.addMember(memberDto);
    // then
    ArgumentCaptor<Member> memberCaptor = ArgumentCaptor.forClass(Member.class);
    verify(memberRepository).save(memberCaptor.capture());
    Member member = memberCaptor.getValue();

    assertEquals(memberDto.getMemberName(), member.getMemberName());
    assertEquals(memberDto.getPhone(), member.getPhone());
    assertEquals(memberDto.getEmail(), member.getEmail());
    assertNotEquals(memberDto.getPassword(), member.getPassword());
    assertEquals(BUYER, member.getRole());
    assertNull(member.getCertificationAt());

    verify(mailService).sendEmail(memberDto.getEmail());
  }

  @Test
  void addMember_Failure_UserAlreadyExists() {
    // given
    when(memberRepository.findByEmail(memberDto.getEmail())).thenReturn(Optional.of(new Member()));
    // when
    CustomException e = assertThrows(CustomException.class,
        () -> memberService.addMember(memberDto));
    // then
    assertEquals(ALREADY_EXISTS_USER, e.getErrorCode());

    verify(memberRepository, never()).save(any(Member.class));
    verify(mailService, never()).sendEmail(anyString());
  }

  @Test
  void addMember_Success_HashesPasswordCorrectly() {
    // given
    when(memberRepository.findByEmail(memberDto.getEmail())).thenReturn(Optional.empty());
    when(memberRepository.save(any(Member.class))).thenAnswer(
        invocation -> invocation.getArgument(0));
    try (MockedStatic<PasswordUtil> mockedStatic = mockStatic(PasswordUtil.class)) {
      String hashedPassword = "hashedPassword";
      mockedStatic.when(() -> PasswordUtil.hashPassword(anyString())).thenReturn(hashedPassword);
      // when
      memberService.addMember(memberDto);
      // then
      ArgumentCaptor<Member> memberCaptor = ArgumentCaptor.forClass(Member.class);
      verify(memberRepository).save(memberCaptor.capture());
      Member member = memberCaptor.getValue();

      assertNotEquals(memberDto.getPassword(), member.getPassword());
      assertEquals(hashedPassword, member.getPassword());
      assertEquals(memberDto.getEmail(), member.getEmail());
    }
  }

  @Test
  void login_success() {
    // given
    String email = "coffee@gmail.com";
    String password = "12345678";
    Member member = new Member();
    member.setEmail(email);
    member.setPassword(PasswordUtil.hashPassword(password));
    member.setCertificationAt(LocalDateTime.now());

    when(memberRepository.findByEmail(email)).thenReturn(Optional.of(member));
    when(jwtUtil.generateToken(email)).thenReturn("token");
    // when
    String token = memberService.login(email, password);
    // then
    assertEquals("token", token);
  }

  @Test
  void login_Failure_InvalidEmail() {
    // given
    String email = "coffee@gmail.com";
    String password = "12345678";

    when(memberRepository.findByEmail(email)).thenReturn(Optional.empty());
    // when
    CustomException e = assertThrows(CustomException.class,
        () -> memberService.login(email, password));
    // then
    assertEquals(LOGIN_ERROR, e.getErrorCode());
  }

  @Test
  void login_Failure_InvalidPassword() {
    // given
    String email = "coffee@gmail.com";
    String password = "123456789";
    Member member = new Member();
    member.setEmail(email);
    member.setPassword(PasswordUtil.hashPassword("12345678"));
    member.setCertificationAt(LocalDateTime.now());

    when(memberRepository.findByEmail(email)).thenReturn(Optional.of(member));
    // when
    CustomException e = assertThrows(CustomException.class,
        () -> memberService.login(email, password));
    // then
    assertEquals(LOGIN_ERROR, e.getErrorCode());
  }

  @Test
  void login_Failure_NotCertified() {
    // given
    String email = "coffee@gmail.com";
    String password = "12345678";
    Member member = new Member();
    member.setEmail(email);
    member.setPassword(PasswordUtil.hashPassword(password));

    when(memberRepository.findByEmail(email)).thenReturn(Optional.of(member));

    // when
    CustomException e = assertThrows(CustomException.class,
        () -> memberService.login(email, password));
    // then
    assertEquals(LOGIN_ERROR, e.getErrorCode());
  }
}