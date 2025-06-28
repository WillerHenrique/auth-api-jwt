package com.auth.apijwt.controller;

import com.auth.apijwt.dto.AuthRequest;
import com.auth.apijwt.dto.AuthResponse;
import com.auth.apijwt.entity.User;
import com.auth.apijwt.security.JwtService;
import com.auth.apijwt.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;

    public AuthController(UserService userService, JwtService jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AuthRequest request) {
        try {
            User user = userService.registerUser(request.getUsername(), request.getPassword());
            String token = jwtService.generateToken(user.getUsername(), user.getRoles());
            return ResponseEntity.ok(new AuthResponse(token));
        } catch (RuntimeException ex) {
            return ResponseEntity.badRequest().body(ex.getMessage());
        }
    }

    @PostMapping("/login")
public ResponseEntity<?> login(@RequestBody AuthRequest request) {
    return userService.findByUsername(request.getUsername())
            .filter(user -> userService.checkPassword(request.getPassword(), user.getPassword()))
            .<ResponseEntity<?>>map(user -> {
                String token = jwtService.generateToken(user.getUsername(), user.getRoles());
                return ResponseEntity.ok(new AuthResponse(token));
            })
            .orElseGet(() -> ResponseEntity.status(401).body("Usuário ou senha inválidos"));
}

}
