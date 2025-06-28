package com.auth.apijwt;

import com.auth.apijwt.controller.AuthController;
import com.auth.apijwt.dto.AuthRequest;
import com.auth.apijwt.dto.AuthResponse;
import com.auth.apijwt.entity.User;
import com.auth.apijwt.security.JwtService;
import com.auth.apijwt.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.ResponseEntity;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthApiJwtApplicationTests {

    private UserService userService;
    private JwtService jwtService;
    private AuthController authController;

    @BeforeEach
    void setUp() {
        userService = mock(UserService.class);
        jwtService = mock(JwtService.class);
        authController = new AuthController(userService, jwtService);
    }

    @Test
    void testLoginSuccess() {
        // Simulando entrada
        AuthRequest request = new AuthRequest("testuser", "123456");

        // Simulando usuário no banco
        User user = new User();
        user.setUsername("testuser");
        user.setPassword("encodedPassword"); // Simulado, não precisa bater com a real
        user.setRoles(Set.of("USER"));

        // Mockando comportamento
        when(userService.findByUsername("testuser")).thenReturn(Optional.of(user));
        when(userService.checkPassword("123456", "encodedPassword")).thenReturn(true);
        when(jwtService.generateToken("testuser", user.getRoles())).thenReturn("fake-jwt-token");

        // Executando
        ResponseEntity<?> response = authController.login(request);

        // Verificando
        assertEquals(200, response.getStatusCode().value()
);
        assertTrue(response.getBody() instanceof AuthResponse);
        assertEquals("fake-jwt-token", ((AuthResponse) response.getBody()).getToken());
    }

    @Test
    void testLoginFail_InvalidCredentials() {
        AuthRequest request = new AuthRequest("testuser", "wrongpassword");

        User user = new User();
        user.setUsername("testuser");
        user.setPassword("encodedPassword");
        user.setRoles(Set.of("USER"));

        when(userService.findByUsername("testuser")).thenReturn(Optional.of(user));
        when(userService.checkPassword("wrongpassword", "encodedPassword")).thenReturn(false);

        ResponseEntity<?> response = authController.login(request);

        assertEquals(401, response.getStatusCode().value()
);
        assertEquals("Usuário ou senha inválidos", response.getBody());
    }

    @Test
    void testLoginFail_UserNotFound() {
        AuthRequest request = new AuthRequest("naoexiste", "123456");

        when(userService.findByUsername("naoexiste")).thenReturn(Optional.empty());

        ResponseEntity<?> response = authController.login(request);

        assertEquals(401, response.getStatusCode().value()
);
        assertEquals("Usuário ou senha inválidos", response.getBody());
    }
}
