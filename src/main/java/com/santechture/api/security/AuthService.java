package com.santechture.api.security;


import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import com.santechture.api.dto.GeneralResponse;
import com.santechture.api.dto.admin.AdminDto;
import com.santechture.api.entity.Admin;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;



import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

@Service
@Log4j2
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authManager;

    private final HttpServletRequest httpRequest;

    private final JwtTokenUtil jwtTokenUtil;

    public ResponseEntity<JwtAuthResponse> login(String login, String password) {
        Authentication authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(login, password));

        log.debug("Valid userDetails credentials.");

        Admin admin = (Admin) authentication.getPrincipal();

        SecurityContextHolder.getContext().setAuthentication(authentication);
        log.debug("SecurityContextHolder updated. [login={}]", login);


        String accessTokenId = UUID.randomUUID().toString();
        String accessToken = JwtTokenUtil.generateToken(login, accessTokenId);
        log.info("Access token created. [tokenId={}]", accessTokenId);

        return new JwtAuthResponse().response(admin.getUsername(), admin.getAdminId(), accessToken, HttpStatus.OK);
    }


}