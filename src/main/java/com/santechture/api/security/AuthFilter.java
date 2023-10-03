package com.santechture.api.security;

import com.santechture.api.entity.Admin;
import com.santechture.api.service.AdminService;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

@Log4j2
public class AuthFilter extends OncePerRequestFilter {

    @Autowired
    private AdminService adminService;

    @Autowired
    private JwtTokenUtil tokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final String jwtTokenHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        log.info("Path is >> " + request.getRequestURL());
        final SecurityContext securityContext = SecurityContextHolder.getContext();

        if (jwtTokenHeader != null && securityContext.getAuthentication() == null) {
            String jwtToken = jwtTokenHeader.substring("Bearer ".length());
            if (tokenUtil.validateToken(jwtToken, request)) {
                String username = tokenUtil.getUserNameFromToken(jwtToken);
                if (username != null) {
                    Admin userDetails = (Admin) adminService.loadUserByUsername(username);
                    if (tokenUtil.isTokenValid(jwtToken, userDetails)) {
                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            }
        }

        filterChain.doFilter(request, response);
    }

    protected boolean isSwaggerUrl(String url) {
        if (url.contains("swagger") || url.contains("api-docs") || url.contains("configuration/ui") || url.contains("webjars/")
                || url.contains("swagger-resources") || url.contains("configuration/security") || url.contains("actuator")) {
            return true;
        } else {
            return false;
        }

    }

}
