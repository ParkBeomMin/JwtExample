package com.example.restservice;

import java.util.Base64;
import java.util.Date;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component
public class JwtTokenProvider {
    private String secretKey = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz";

    // 토큰 유효시간 30분
    private long tokenValidTime = 30 * 60 * 1000L;

    // 이건 어떤거지?
    private final UserDetailsService userDetailsService;

    // 객체 초기화, secretKey를 Base64로 인코딩한다.
    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    // JWT 토큰 생성
    // JWT 토큰을 생성하기 위해선, 토큰에 담길 정보와 만료시간, 그리고 서명할 때 사용할 secret값이 필요하다.
    // JWT 토큰을 생성하는 메서드는 아래와 같다.
    //
    // 1. JWT payload에 저장될 정보는 claim이라고 부른다.   
    // 2. claim은 key / value 쌍으로 저장되며, 여러개의 claim을 넣을 수 있다.
    // 3. JWT는 JSON 객체를 사용하여 claim을 저장한다.
    // 4. JWT payload에 저장되는 정보의 한 조각을 claim이라고 부른다.
    // 5. claim은 name / value 쌍으로 이루어져 있으며, claim에는 여러가지 종류가 있다.
    // 6. claim의 종류는 registered, public, private이 있다.
    // 7. registered claim은 이미 정해진 claim으로 선택적으로 사용할 수 있다.
    // 8. public claim은 충돌이 방지된 이름을 가지고 있어야 한다.
    // 9. private claim은 충돌이 방지된 이름을 가지고 있어야 한다.
    // 10. JWT payload에는 여러개의 claim을 넣을 수 있다.
    public String createToken(String userPk, List<String> roles) {
        Claims claims = Jwts.claims().setSubject(userPk); // JWT payload에 저장되는 정보단위
        claims.put("roles", roles); // 정보는 key / value 쌍으로 저장된다.
        Date now = new Date();
        return Jwts.builder()
            .setClaims(claims) // 정보 저장
            .setIssuedAt(now) // 토큰 발행 시간 정보
            .setExpiration(new Date(now.getTime() + tokenValidTime)) // set Expire Time
            .signWith(SignatureAlgorithm.HS256, secretKey) // 사용할 암호화 알고리즘과 signature에 들어갈 secret값 세팅
            .compact();
    } 

    // JWT 토큰에서 인증 정보 조회
    // JWT 토큰에서 인증 정보를 조회하는 메서드는 아래와 같다.
    //
    // 1. JWT 토큰을 파싱하여, payload에 저장된 정보를 꺼낸다.
    // 2. payload에서 꺼낸 정보를 이용해 User 객체를 만들어서 리턴한다.
    // 3. User 객체를 만들 때, username, password, authorities를 넣어준다.
    // 4. authorities는 JWT 토큰에서 꺼낸 roles 정보를 이용한다.
    // 5. roles 정보는 List<String> 형태로 저장되어 있으며, 이를 이용해 SimpleGrantedAuthority 객체를 만들어 authorities에 넣어준다.
    // 6. SimpleGrantedAuthority 객체는 권한을 나타낼 때 사용한다.
    // 7. SimpleGrantedAuthority 객체를 만들 때, 권한 코드를 "ROLE_"로 시작해야 한다.
    // 8. JWT 토큰에서 꺼낸 roles 정보는 "ROLE_"로 시작하지 않으므로, 이를 추가해준다.
    // 9. JWT 토큰에서 꺼낸 roles 정보는 List<String> 형태이므로, 이를 Stream으로 변환한 뒤, map을 이용해 SimpleGrantedAuthority 객체로 변환한다.
    // 10. 변환된 Stream은 collect(Collectors.toList())를 이용해 List<SimpleGrantedAuthority> 형태로 변환한다.
    // 11. 변환된 List<SimpleGrantedAuthority>를 User 객체를 만들 때 넣어준다.
    public Authentication getAuthentication(String token) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(this.getUserPk(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    // 토큰에서 회원 정보 추출
    public String getUserPk(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }
    
    // Request의 Header에서 token 값을 가져옵니다. "X-AUTH-TOKEN" : "TOKEN값'
    public String resolveToken(HttpServletRequest request) {
        return request.getHeader("X-AUTH-TOKEN");
    }

    // 토큰의 유효성 + 만료일자 확인
    public boolean validateToken(String jwtToken) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken);
            return !claims.getBody().getExpiration().before(new Date()); // 토큰이 만료되었는지 확인
        } catch (Exception e) {
            return false;
        }
    }

}
