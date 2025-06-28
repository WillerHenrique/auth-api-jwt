package com.auth.apijwt.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.Set;

@Entity
@Table(name = "app_user")  // Renomeando a tabela para evitar conflito com palavra reservada
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    @Id 
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> roles;
}
