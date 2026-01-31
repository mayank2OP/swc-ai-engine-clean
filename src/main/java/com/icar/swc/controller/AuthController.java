package com.icar.swc.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.icar.swc.dto.AuthRequest;
import com.icar.swc.dto.AuthResponse;
import com.icar.swc.entity.User;
import com.icar.swc.repository.UserRepository;
import com.icar.swc.security.JwtService;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserRepository userRepo;
    private final PasswordEncoder encoder;
    private final JwtService jwtService;

    public AuthController(UserRepository userRepo,
                          PasswordEncoder encoder,
                          JwtService jwtService) {
        this.userRepo = userRepo;
        this.encoder = encoder;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AuthRequest req) {
        if (userRepo.findByUsername(req.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("User already exists");
        }

        User user = new User();
        user.setUsername(req.getUsername());
        user.setPassword(encoder.encode(req.getPassword()));

        userRepo.save(user);
        return ResponseEntity.ok("Registered successfully");
    }

   @PostMapping("/login")
public ResponseEntity<?> login(@RequestBody AuthRequest req) {

    User user = userRepo.findByUsername(req.getUsername())
            .orElseThrow(() ->
                    new org.springframework.security.authentication.BadCredentialsException(
                            "Invalid username or password"
                    )
            );

    if (!encoder.matches(req.getPassword(), user.getPassword())) {
        throw new org.springframework.security.authentication.BadCredentialsException(
                "Invalid username or password"
        );
    }

    String token = jwtService.generateToken(user.getUsername());
    return ResponseEntity.ok(new AuthResponse(token));
}
