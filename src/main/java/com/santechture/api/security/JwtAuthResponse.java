package com.santechture.api.security;

import com.santechture.api.dto.GeneralResponse;
import com.santechture.api.dto.admin.AdminDto;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.io.Serializable;

@Data
@NoArgsConstructor
public class JwtAuthResponse implements Serializable {

    private Integer adminId;

    private String username;

    private String token;

    public ResponseEntity<JwtAuthResponse> response(String name, Integer id, String token,HttpStatus status) {

        this.username = name;
        this.adminId=id;
        this.token= token;

        return new ResponseEntity<JwtAuthResponse>(this, status);

    }
}
