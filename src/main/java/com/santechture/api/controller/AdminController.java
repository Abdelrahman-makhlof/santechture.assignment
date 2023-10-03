package com.santechture.api.controller;


import com.santechture.api.dto.GeneralResponse;
import com.santechture.api.exception.BusinessExceptions;
import com.santechture.api.security.AuthService;
import com.santechture.api.security.JwtAuthResponse;
import com.santechture.api.service.AdminService;
import com.santechture.api.validation.LoginRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "admin")
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;
    private final AuthService authService;


    @PostMapping
    public ResponseEntity<JwtAuthResponse> login(@RequestBody LoginRequest request) throws BusinessExceptions {
        return authService.login(request.getUsername(),request.getPassword());
    }


}
