package com.college.authserver.entity;


import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "menus")
public class Menu {
@Id
@GeneratedValue(strategy = GenerationType.IDENTITY)
private Long id;
private String name;
private String path;
private String icon;
@ManyToOne
@JoinColumn(name = "role_id")
private Role role;
@ManyToOne
@JoinColumn(name = "parent_id")
private Menu parent;
}
