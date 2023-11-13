package com.example.restservice;

import java.util.Collections;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
public class UserController {
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    // 회원가입
    @PostMapping("/join")
    public Long join(@RequestBody Map<String, String> user) {
        return userRepository.save(Users.builder()
            .email(user.get("email"))
            .pwd(passwordEncoder.encode(user.get("password")))
            .roles(Collections.singletonList("ROLE_USER")) // 최초 가입시 USER 로 설정
            .build()).getId();
    }

    UserService memberService;

    // 로그인
    @PostMapping("/login")
    public String login(@RequestBody Map<String, String> user) {
        Users member = userRepository.findByEmail(user.get("email"))
            .orElseThrow(() -> new IllegalArgumentException("가입되지 않은 E-MAIL 입니다."));
        if (!passwordEncoder.matches(user.get("password"), member.getPassword())) {
            throw new IllegalArgumentException("잘못된 비밀번호입니다.");
        }
        return jwtTokenProvider.createToken(member.getUsername(), member.getRoles());
    }

    private final SocialLoginService socialLoginService;
    
    //https://velog.io/@yaaloo/Security-JWT-%EB%A1%9C%EC%BB%AC-%EC%86%8C%EC%85%9C-%EB%A1%9C%EA%B7%B8%EC%9D%B8-%ED%8A%9C%ED%86%A0%EB%A6%AC%EC%96%BC#socialloginservice
    // 소셜로그인 참고자료
    @PostMapping("/social/{provider}")
    public ResponseEntity<JwtDto> socialSignIn(@PathVariable String provider, String code) {
        SignUpForm signUpForm = socialLoginService.signIn(provider, code);
        Users member;
        try {
            member = userRepository.findByEmail(signUpForm.getEmail()).orElseThrow(() -> new UsernameNotFoundException("일치하는 정보가 없습니다."));
        } catch(UsernameNotFoundException e) {
            member = userRepository.save(Users.builder()
                .email(signUpForm.getEmail())
                // .name(signUpForm.getName())
                .roles(Collections.singletonList("ROLE_USER"))
                .build());
        }
        return ResponseEntity.ok(memberService.socialSignIn(signUpForm));
	}
}
