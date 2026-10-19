package com.innoboard.authservice.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "users_credentials")
@Getter
@Setter
@NoArgsConstructor
public class UserCredentials extends Auditable {

    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private String userId;

    @Column(name="login", nullable = false, length = 100)
    private String login;

    @Column(name = "password_hash", nullable = false, length = 100)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(name="role",nullable = false, length = 20)
    private Role role;

    @Column(name="active", nullable = false)
    private boolean active =true;

}
