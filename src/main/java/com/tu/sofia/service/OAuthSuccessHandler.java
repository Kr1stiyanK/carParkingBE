package com.tu.sofia.service;

import com.tu.sofia.dto.UserRegistrationDTO;
import com.tu.sofia.model.UserEntity;
import com.tu.sofia.utils.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuthSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final JwtUtil jwtTokenProvider;

    private final UserEntityService userEntityService;

    public OAuthSuccessHandler(JwtUtil jwtTokenProvider, UserEntityService userEntityService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.userEntityService = userEntityService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        if (authentication instanceof OAuth2AuthenticationToken oAuth2AuthenticationToken) {
            UserRegistrationDTO registrationDTO = new UserRegistrationDTO()
                    .setEmail(oAuth2AuthenticationToken.getPrincipal().getAttribute("email").toString())
                    .setName(oAuth2AuthenticationToken.getPrincipal().getAttribute("name").toString())
                    .setPassword("1234");
            UserEntity user = this.userEntityService.createGoogleCustomer(registrationDTO);
            String token = this.jwtTokenProvider.generateToken(user.getEmail(), user.getId());
            Cookie jwtCookie = new Cookie("jwtToken", token);
            jwtCookie.setHttpOnly(false);
            jwtCookie.setSecure(false);
            jwtCookie.setPath("/");
            response.addCookie(jwtCookie);
            response.sendRedirect("http://localhost:4200/profile");
        }
        super.onAuthenticationSuccess(request, response, authentication);
    }

    @Override
    public void setRequestCache(RequestCache requestCache) {
        super.setRequestCache(requestCache);
    }


}
