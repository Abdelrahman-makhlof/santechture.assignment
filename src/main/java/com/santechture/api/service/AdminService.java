package com.santechture.api.service;

import com.santechture.api.dto.GeneralResponse;
import com.santechture.api.dto.admin.AdminDto;
import com.santechture.api.entity.Admin;
import com.santechture.api.exception.BusinessExceptions;
import com.santechture.api.repository.AdminRepository;
import com.santechture.api.validation.LoginRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AdminService implements UserDetailsService {


    private final AdminRepository adminRepository;

    private final BCryptPasswordEncoder passwordEncoder;


    public ResponseEntity<GeneralResponse> login(LoginRequest request) throws BusinessExceptions {

        Admin admin = adminRepository.findByUsernameIgnoreCase(request.getUsername());


        if (Objects.isNull(admin) || !this.passwordEncoder.matches(request.getPassword(), admin.getPassword())) {


            throw new BusinessExceptions("login.credentials.not.match");
        }

        return new GeneralResponse().response(new AdminDto(admin));
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Admin admin = adminRepository.findByUsernameIgnoreCase(username);
        if (admin == null)
            throw new UsernameNotFoundException("User name not found..!");


        return admin;
    }


}
