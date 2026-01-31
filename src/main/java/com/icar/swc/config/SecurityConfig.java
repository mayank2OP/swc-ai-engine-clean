package com.icar.swc.config;

import java.io.IOException;
import java.time.LocalDateTime;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

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

    // 🔴 CHANGE THIS TO YOUR VERCEL URL
    private static final String FRONTEND_URL =
            "https://swc-ai-engine-clean.vercel.app";

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
            // ✅ STATELESS (JWT)
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // ✅ ROUTE RULES
            .authorizeHttpRequests(auth -> auth
                // PUBLIC ROUTES
                .requestMatchers(
                    "/",
                    "/login",
                    "/register",
                    "/auth/**",
                    "/oauth2/**",
                    "/login/oauth2/**",
                    "/error"
                ).permitAll()

                // PUBLIC APIs (your choice)
                .requestMatchers("/api/**").permitAll()

                // EVERYTHING ELSE PROTECTED
                .anyRequest().authenticated()
            )

            // ✅ GOOGLE LOGIN
            .oauth2Login(oauth2 -> oauth2
                .successHandler(this::googleSuccessHandler)
            )

            // ✅ JWT FILTER (must be AFTER permit rules)
            .addFilterBefore(
                jwtAuthFilter,
                UsernamePasswordAuthenticationFilter.class
            )

            // ✅ LOGOUT
            .logout(logout -> logout
                .logoutSuccessUrl(FRONTEND_URL + "/login")
                .permitAll()
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
        u.setPassword(null);
        u.setProvider("GOOGLE");
        u.setRole("USER");
        return userRepository.save(u); // createdAt set automatically
    });

        String token = jwtService.generateToken(user.getUsername());

        // ✅ REDIRECT BACK TO FRONTEND WITH JWT
        response.sendRedirect(
            FRONTEND_URL + "/oauth-success?token=" + token
        );
    }
}
