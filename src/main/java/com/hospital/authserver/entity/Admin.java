package com.hospital.authserver.entity;
import jakarta.persistence.*;
import lombok.Data;

@Data

@Entity
@Table(name = "admin")
public class Admin {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    @OneToOne
    @JoinColumn(name = "user_id")
    private User user;
}