package com.example.restservice;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;   
     private final JwtTokenProvider jwtIssuer;


    public JwtDto socialSignIn(SignUpForm form) {
        Users member;
        try {
            member = getMemberByEmail(form.getEmail());
        }catch (UsernameNotFoundException e) {
            member = userRepository.save(Users.builder()
                .email(form.getEmail())
                // .name(form.getName())
                .memberRole(MemberRole.USER)
                .provider(MemberProvider.KAKAO)
                .build());
        }

        return jwtIssuer.createToken_(member.getEmail(), member.getMemberRole().name());
    }


    private Users getMemberByEmail(String email) {
        return userRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("일치하는 정보가 없습니다."));
    }
}
