package com.college.authserver.entity;

import java.util.List;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "roles")
public class Role {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id; // PRINCIPAL, ADMIN, HOD, FACULTY, STUDENT
	private String name;
	private String description;
	@OneToMany(mappedBy = "role", cascade = CascadeType.ALL)
	private List<Menu> menus;
}
