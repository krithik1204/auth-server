package com.hospital.authserver.entity;
import jakarta.persistence.*;
import java.time.LocalDate;

@Entity
@Table(name = "students")
public class Student {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    private String className;
    @Column
    private String section;
    @Column(unique = true, nullable = false)
    private String student_id;

    @OneToOne
    @JoinColumn(name = "user_id")
    private User user;
}