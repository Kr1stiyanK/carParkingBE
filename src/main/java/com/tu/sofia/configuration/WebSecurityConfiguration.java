package com.tu.sofia.configuration;

import com.tu.sofia.filter.JwtFilter;
import com.tu.sofia.service.OAuthSuccessHandler;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import jakarta.servlet.http.Cookie;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@CrossOrigin(origins = "*")
public class WebSecurityConfiguration {

    @Autowired
    @Lazy
    private JwtFilter jwtFilter;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity security,
                                                   OAuthSuccessHandler oAuthSuccessHandler) throws Exception {
        security
                .csrf().disable()
                .authorizeHttpRequests().requestMatchers("/register", "/login", "/api/guest/check-availability", "/api/guest/quick-booking").permitAll().and()
                .authorizeHttpRequests().requestMatchers("/oauth2/**").permitAll().and()
                .authorizeHttpRequests().requestMatchers("/api/logout").permitAll().and()
                .authorizeHttpRequests().requestMatchers("/api/**").authenticated()
                .anyRequest().authenticated()
                .and()
                .logout((logout) -> logout
                        .logoutUrl("/api/logout").permitAll()
                        .clearAuthentication(true)
                        .invalidateHttpSession(true)
                        .logoutSuccessHandler((request, response, authentication) -> {
                            if (authentication != null) {
                                request.getSession().invalidate();
                            }
                            Cookie jsessionidCookie = new Cookie("JSESSIONID", null);
                            jsessionidCookie.setHttpOnly(false);
                            jsessionidCookie.setSecure(false);
                            jsessionidCookie.setMaxAge(0);
                            jsessionidCookie.setPath("/");
                            response.addCookie(jsessionidCookie);

                            Cookie jwtTokenCookie = new Cookie("jwtToken", null);
                            jwtTokenCookie.setHttpOnly(false);
                            jwtTokenCookie.setSecure(false);
                            jwtTokenCookie.setMaxAge(0);
                            jwtTokenCookie.setPath("/");
                            response.addCookie(jwtTokenCookie);


                            response.setStatus(HttpServletResponse.SC_OK);
                        })
                )
                .oauth2Login()
                .successHandler(oAuthSuccessHandler)
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .cors();

        return security.build();
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH"));
        configuration.setAllowedHeaders(Arrays.asList("authorization", "content-type", "x-auth-token"));
        configuration.setExposedHeaders(Arrays.asList("x-auth-token"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
