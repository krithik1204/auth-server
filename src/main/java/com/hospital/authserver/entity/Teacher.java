package com.hospital.authserver.entity;
import jakarta.persistence.*;

@Entity
@Table(name = "teachers")
public class Teacher {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String employeeId;

    @OneToOne
    @JoinColumn(name = "user_id")
    private User user;
}