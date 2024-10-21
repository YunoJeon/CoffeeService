package com.coffee.coffeeservice.configuration;

import java.util.Properties;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

@Configuration
@RequiredArgsConstructor
public class MailConfig {

  private static final String MAIL_SMTP_AUTH = "mail.smtp.auth";
  private static final String MAIL_SMTP_STARTTLS_ENABLE = "mail.smtp.starttls.enable";
  private static final String MAIL_DEBUG = "mail.smtp.debug";
  private static final String MAIL_CONNECTION_TIMEOUT = "mail.connectiontimeout";

  @Value("${spring.mail.host}")
  private String host;

  @Value("${spring.mail.username}")
  private String username;

  @Value("${spring.mail.password}")
  private String password;

  @Value("${spring.mail.port}")
  private int port;

  @Value("${spring.mail.properties.mail.smtp.auth}")
  private boolean auth;

  @Value("${spring.mail.properties.mail.smtp.debug}")
  private boolean debug;

  @Value("${spring.mail.properties.mail.smtp.connectiontimeout}")
  private int connectionTimeout;

  @Value("${spring.mail.properties.mail.starttls.enable}")
  private boolean startTlsEnable;

  @Bean
  public JavaMailSender javaMailSender() {
    JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
    mailSender.setHost(host);
    mailSender.setPort(port);
    mailSender.setUsername(username);
    mailSender.setPassword(password);

    Properties properties = mailSender.getJavaMailProperties();
    properties.put(MAIL_SMTP_AUTH, auth);
    properties.put(MAIL_SMTP_STARTTLS_ENABLE, startTlsEnable);
    properties.put(MAIL_DEBUG, debug);
    properties.put(MAIL_CONNECTION_TIMEOUT, connectionTimeout);

    mailSender.setJavaMailProperties(properties);
    mailSender.setDefaultEncoding("UTF-8");

    return mailSender;
  }
}