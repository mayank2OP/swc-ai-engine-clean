package com.icar.swc.config;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.icar.swc.entity.User;
import com.icar.swc.repository.UserRepository;
import com.icar.swc.security.JwtAuthFilter;
import com.icar.swc.security.JwtService;

@Configuration
public class SecurityConfig {

    private final JwtService jwtService;
    private final JwtAuthFilter jwtAuthFilter;
    private final UserRepository userRepository;

    @Value("${frontend.url}")
    private String frontendUrl;

    public SecurityConfig(
            JwtService jwtService,
            JwtAuthFilter jwtAuthFilter,
            UserRepository userRepository
    ) {
        this.jwtService = jwtService;
        this.jwtAuthFilter = jwtAuthFilter;
        this.userRepository = userRepository;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
            // ✅ ENABLE CORS
            .cors(cors -> {})

            // ✅ STATELESS JWT
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // ✅ ROUTES
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/",
                    "/auth/**",
                    "/oauth2/**",
                    "/login/oauth2/**",
                    "/error"
                ).permitAll()
                .anyRequest().authenticated()
            )

            // ✅ GOOGLE OAUTH
            .oauth2Login(oauth ->
                oauth.successHandler(this::googleSuccessHandler)
            )

            // ✅ JWT FILTER
            .addFilterBefore(
                jwtAuthFilter,
                UsernamePasswordAuthenticationFilter.class
            );

        return http.build();
    }

    // ================= GOOGLE SUCCESS HANDLER =================
    private void googleSuccessHandler(
            HttpServletRequest request,
            HttpServletResponse response,
            org.springframework.security.core.Authentication authentication
    ) throws IOException {

        OAuth2User oauthUser =
                (OAuth2User) authentication.getPrincipal();

        String email = oauthUser.getAttribute("email");

        User user = userRepository.findByUsername(email)
                .orElseGet(() -> {
                    User u = new User();
                    u.setUsername(email);
                    u.setPassword("OAUTH2_USER");
                    u.setRole("USER");
                    u.setProvider("GOOGLE");
                    return userRepository.save(u);
                });

        String token = jwtService.generateToken(user.getUsername());

        response.sendRedirect(
                frontendUrl + "/oauth-success?token=" + token
        );
    }
}
