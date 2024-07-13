# Implementar JWT en un Proyecto de Microservicios con Spring Boot

## 1. Introducción

### ¿Qué es JWT?
JWT (JSON Web Token) es un estándar abierto para la creación de tokens de acceso que permiten la comunicación segura entre dos partes. Los tokens JWT son compactos, seguros y auto-contenidos, lo que los hace ideales para su uso en escenarios de autenticación y autorización en aplicaciones web y servicios distribuidos.

### Importancia de la seguridad en microservicios
En un entorno de microservicios, la seguridad es crucial debido a la naturaleza distribuida de las aplicaciones. Implementar JWT permite asegurar que cada solicitud a un microservicio esté autenticada y autorizada, garantizando que solo los usuarios y servicios legítimos tengan acceso a los recursos.

## 2. Requisitos Previos

### Instalación de Java y Spring Boot

Antes de comenzar con la implementación de JWT en un proyecto de microservicios con Spring Boot, es necesario asegurarse de tener instalados los siguientes componentes:

1. **Java Development Kit (JDK)**: Se recomienda tener la versión 11 o superior.
2. **Spring Boot**: Spring Boot simplifica la creación de aplicaciones basadas en Spring al proporcionar una configuración y una estructura predeterminadas.

### Creación de un Nuevo Proyecto Spring Boot

Vamos a crear un nuevo proyecto Spring Boot desde cero utilizando Spring Initializr.

1. **Ir a Spring Initializr**: [https://start.spring.io/](https://start.spring.io/)
2. **Configurar el proyecto**:
    - **Project**: Maven Project
    - **Language**: Java
    - **Spring Boot**: 3.3.1 (o la versión más reciente)
    - **Project Metadata**:
        - **Group**: com.isabosdev
        - **Artifact**: template_jwt_H2
        - **Name**: template_jwt_H2
        - **Package name**: com.isabosdev.template_jwt_H2
        - **Packaging**: Jar
        - **Java**: 17

3. **Agregar Dependencias**:
    - **Spring Web**: Para crear aplicaciones web, incluyendo RESTful.
    - **Spring Security**: Para manejar la seguridad.
    - **Spring Data JPA**: Para interactuar con la base de datos.
    - **H2 Database**: Base de datos en memoria para pruebas (opcional).

4. **Generar el Proyecto**: Hacer clic en "Generate" para descargar el proyecto.

### Dependencias Necesarias en `pom.xml`

Abrir el archivo `pom.xml` del proyecto generado y agregar las siguientes dependencias si no se agregaron automáticamente:

```xml
<dependencies>

    <!-- Spring Boot Starter Data JPA -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    
    <!-- Spring Boot Starter Security -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    
    <!-- Spring Boot Starter Web -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- H2 Database (para pruebas) -->
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <scope>runtime</scope>
    </dependency>

   <!-- JWT (https://github.com/auth0/java-jwt) -->
   <dependency>
         <groupId>com.auth0</groupId>
         <artifactId>java-jwt</artifactId>
         <version>4.4.0</version>
   </dependency>
</dependencies>
```

Estas dependencias incluyen todo lo necesario para comenzar con un proyecto Spring Boot que utiliza JWT para la autenticación y autorización.

---
## 3. Configuración del Proyecto

### Estructura del Proyecto

A continuación se presenta la estructura básica de un proyecto Spring Boot para implementar JWT:

```
jwt-demo/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/
│   │   │       └── isabosdev/
│   │   │           └── template_jwt_H2/
│   │   │               ├── controller/
│   │   │               ├── model/
│   │   │               ├── repository/
│   │   │               ├── security/
│   │   │               └── service/
|   |   |               └── util/
│   │   └── resources/
│   │       ├── application.properties
│   │       └── static/
│   │           └── index.html
├── pom.xml
└── README.md
```

- **controller/**: Contendrá los controladores REST.
- **model/**: Contendrá las clases de entidad.
- **repository/**: Contendrá las interfaces de repositorio JPA.
- **security/**: Contendrá las clases relacionadas con la seguridad (configuración, filtros, utilidades).
- **service/**: Contendrá las clases de servicio.
- **resources/**: Contendrá los archivos de configuración y recursos estáticos.
- **util/**: Contendrá las clases de ayuda

### Archivos de Configuración (`application.properties`)

Abrir el **archivo** `application.properties` en `src/main/resources/` y agregar las siguientes configuraciones básicas:

```properties
# Configuración de la base de datos H2
spring.datasource.url=jdbc:h2:mem:testdb
spring.datasource.driverClassName=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=password
spring.h2.console.enabled=true

# JPA
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true

# Configuración de seguridad (opcional)
jwt.secret=miSecretKey
jwt.expiration=3600000
```

- **spring.datasource.url**: URL de conexión a la base de datos H2.
- **spring.datasource.driverClassName**: Controlador de la base de datos H2.
- **spring.datasource.username y spring.datasource.password**: Credenciales de la base de datos.
- **spring.h2.console.enabled**: Habilita la consola H2 para acceder a la base de datos en memoria.
- **spring.jpa.hibernate.ddl-auto**: Configuración de Hibernate para crear/actualizar las tablas automáticamente.
- **spring.jpa.show-sql**: Muestra las consultas SQL en la consola.
- **jwt.secret**: Clave secreta para firmar los tokens JWT.
- **jwt.expiration**: Tiempo de expiración del token en milisegundos.

Con estos archivos y configuraciones, ya hemos sentado las bases de nuestro proyecto.

---

## 4. Creación del Modelo de Usuario

En este paso, vamos a definir la entidad de Usuario y su correspondiente repositorio para interactuar con la base de datos.

### Entidad Usuario

Crear una **clase** `User` en el **paquete** `model`:

```java
package com.isabosdev.template_jwt_H2.model;

import javax.persistence.*;

@Entity
@Table(name = "users")
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true)
    private String username;
    
    @Column(nullable = false)
    private String password;
    
    @Column(nullable = false)
    private String role;

    // Getters and setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
```

- **@Entity**: Marca la clase como una entidad JPA.
- **@Table(name = "users")**: Define el nombre de la tabla en la base de datos.
- **@Id**: Marca el campo `id` como la clave primaria.
- **@GeneratedValue(strategy = GenerationType.IDENTITY)**: Especifica que el valor del `id` será generado automáticamente.
- **@Column**: Especifica que los campos `username`, `password` y `role` son columnas en la tabla `users`.

### Repositorio de Usuario

Crear una **interfaz** `UserRepository` en el paquete `repository`:

```java
package com.isabosdev.template_jwt_H2.repository;

import com.example.jwtdemo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
```

- **@Repository**: Marca la interfaz como un repositorio de Spring.
- **JpaRepository<User, Long>**: Extiende la interfaz `JpaRepository` para la entidad `User` con la clave primaria de tipo `Long`.
- **Optional<User> findByUsername(String username)**: Método para encontrar un usuario por su nombre de usuario.

Con esto, hemos definido el modelo de usuario y el repositorio correspondiente para interactuar con la base de datos.

---

## 5. Servicio de Usuario

En este paso, vamos a crear el servicio para gestionar usuarios y la implementación de `UserDetailsService` que es necesaria para la integración con Spring Security. Además, configuraremos un bean de `PasswordEncoder` necesario para encriptar las contraseñas de los usuarios.

#### Configuración del PasswordEncoder

Primero, definimos un bean de `PasswordEncoder` en una clase de configuración.

Crear una **clase** `PasswordConfig` en el **paquete** `security`:

```java
package com.isabosdev.template_jwt_H2.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

- **@Configuration**: Indica que esta clase es una configuración de Spring.
- **@Bean**: Define un bean de `PasswordEncoder` que estará disponible en el contexto de la aplicación.

#### Servicio para Gestionar Usuarios

Crear una **clase** `UserService` en el **paquete** `service`:

```java
package com.isabosdev.template_jwt_H2.service;

import com.isabosdev.template_jwt_H2.model.User;
import com.isabosdev.template_jwt_H2.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public User saveUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }
}
```

- **@Service**: Marca la clase como un servicio de Spring.
- **@Autowired**: Inyección de dependencias para `UserRepository` y `PasswordEncoder`.
- **findByUsername(String username)**: Método para buscar un usuario por su nombre de usuario.
- **saveUser(User user)**: Método para guardar un usuario, encriptando su contraseña antes de guardarla.

#### Implementación de UserDetailsService

Crear una clase `CustomUserDetailsService` que implementa `UserDetailsService` en el paquete `service`:

```java
package com.isabosdev.template_jwt_H2.service;

import com.isabosdev.template_jwt_H2.model.User;
import com.isabosdev.template_jwt_H2.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
        
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), 
                Collections.singletonList(new SimpleGrantedAuthority(user.getRole())));
    }
}
```

- **@Service**: Marca la clase como un servicio de Spring.
- **@Autowired**: Inyección de dependencias para `UserRepository`.
- **loadUserByUsername(String username)**: Método para cargar un usuario por su nombre de usuario, lanzando una excepción si no se encuentra.
- **org.springframework.security.core.userdetails.User**: Clase de Spring Security que representa al usuario, incluyendo su nombre de usuario, contraseña y roles.

Con esto, hemos creado el servicio de usuario, la implementación de `UserDetailsService` para integrarlo con Spring Security y la configuración del `PasswordEncoder` necesario para encriptar las contraseñas de los usuarios. 

---

## 6. Controlador de Autenticación

En este paso, vamos a crear un controlador para manejar el login y el registro de usuarios. Este controlador tendrá endpoints para validar credenciales y registrar nuevos usuarios. Además, crearemos la clase `JwtUtil` necesaria para la generación de tokens JWT y la configuración de `AuthenticationManager`.

### Clase JwtUtil

Primero, vamos a crear la **clase** `JwtUtil` en el **paquete** `util`:

```java
package com.isabosdev.template_jwt_H2.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    public String generateToken(UserDetails userDetails) {
        Algorithm algorithm = Algorithm.HMAC512(secret);
        return JWT.create()
                .withSubject(userDetails.getUsername())
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + expiration))
                .sign(algorithm);
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        try {
            Algorithm algorithm = Algorithm.HMAC512(secret);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withSubject(userDetails.getUsername())
                    .build();
            verifier.verify(token);
            return true;
        } catch (JWTVerificationException exception) {
            return false;
        }
    }

    public String extractUsername(String token) {
        return decodeToken(token).getSubject();
    }

    public Date extractExpiration(String token) {
        return decodeToken(token).getExpiresAt();
    }

    private DecodedJWT decodeToken(String token) {
        Algorithm algorithm = Algorithm.HMAC512(secret);
        JWTVerifier verifier = JWT.require(algorithm).build();
        return verifier.verify(token);
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
}
```

- **@Component**: Marca la clase como un componente de Spring.
- **@Value**: Inyecta valores de configuración desde `application.properties`.

### Configuración de Seguridad

Vamos a configurar `AuthenticationManager` y otros aspectos de seguridad en una clase de configuración.

Crear una **clase** `SecurityConfig` en el **paquete** `security`:

```java
package com.isabosdev.template_jwt_H2.security;

import com.isabosdev.template_jwt_H2.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
           .authorizeHttpRequests(auth -> auth
               .requestMatchers("/auth/**").permitAll()
               .anyRequest().authenticated()
           )
           .sessionManagement(session -> session
               .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
           );
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
```

- **@Configuration**: Indica que esta clase es una configuración de Spring.
- **@EnableWebSecurity**: Habilita la seguridad web de Spring.
- **SecurityFilterChain**: Configura el filtro de seguridad de Spring.
- **requestMatchers**: Método actualizado para definir las reglas de autorización.
- **csrf(csrf -> csrf.disable())**: Nueva forma de deshabilitar CSRF.

#### Endpoints para Login y Registro

Crear una **clase** `AuthController` en el **paquete** `controller`:

```java
package com.isabosdev.template_jwt_H2.controller;

import com.isabosdev.template_jwt_H2.model.User;
import com.isabosdev.template_jwt_H2.service.UserService;
import com.isabosdev.template_jwt_H2.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody User user) throws AuthenticationException {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
        );

        final UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        final String token = jwtUtil.generateToken(userDetails);

        Map<String, String> response = new HashMap<>();
        response.put("token", token);

        return response;
    }

    @PostMapping("/register")
    public Map<String, String> register(@RequestBody User user) {
        User newUser = userService.saveUser(user);

        final UserDetails userDetails = userDetailsService.loadUserByUsername(newUser.getUsername());
        final String token = jwtUtil.generateToken(userDetails);

        Map<String, String> response = new HashMap<>();
        response.put("token", token);

        return response;
    }
}
```

- **@RestController**: Marca la clase como un controlador REST.
- **@RequestMapping("/auth")**: Define la ruta base para los endpoints de autenticación.
- **@PostMapping("/login)**: Endpoint para el login. Autentica al usuario y genera un token JWT.
- **@PostMapping("/register)**: Endpoint para el registro. Guarda al nuevo usuario y genera un token JWT.
- **authenticationManager.authenticate(...)**: Autentica al usuario usando `AuthenticationManager`.
- **userDetailsService.loadUserByUsername(...)**: Carga los detalles del usuario usando `UserDetailsService`.
- **jwtUtil.generateToken(...)**: Genera un token JWT usando `JwtUtil`.


Con esto, hemos creado el controlador de autenticación con endpoints para login y registro, la clase `JwtUtil` para manejar los tokens JWT y la configuración de seguridad para `AuthenticationManager`. 

---

### 7. Intercepción de Solicitudes

En este paso, vamos a configurar un filtro JWT para interceptar y validar las solicitudes HTTP. Este filtro garantizará que solo las solicitudes con un token JWT válido puedan acceder a los recursos protegidos.

#### Filtros de JWT

Crear una clase `JwtRequestFilter` en el paquete `security`:

```java
package com.isabosdev.template_jwt_H2.security;

import com.isabosdev.template_jwt_H2.service.CustomUserDetailsService;
import com.isabosdev.template_jwt_H2.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

       final String requestTokenHeader = request.getHeader("Authorization");

       String username = null;
       String jwtToken = null;

       // JWT Token está en el formato "Bearer token". Remover el prefijo "Bearer" y obtener el token
       if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
          jwtToken = requestTokenHeader.substring(7);
          try {
             username = jwtUtil.extractUsername(jwtToken);
          } catch (IllegalArgumentException e) {
             System.out.println("Unable to get JWT Token");
          } catch (JWTVerificationException e) {
             System.out.println("JWT Token has expired");
          }
       } else {
          logger.warn("JWT Token does not begin with Bearer String");
       }

       // Una vez tenemos el token validamos y autenticamos
       if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
          UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
          // Si el token es válido, configure Spring Security para manualmente configurar la autenticación
          if (jwtUtil.validateToken(jwtToken, userDetails)) {
             UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                     new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
             usernamePasswordAuthenticationToken
                     .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
             SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
          }
       }
       chain.doFilter(request, response);
    }
}
```

- **@Component**: Marca la clase como un componente de Spring.
- **doFilterInternal(...)**: Método que intercepta las solicitudes HTTP.
   - **requestTokenHeader = request.getHeader("Authorization")**: Obtiene el encabezado `Authorization` de la solicitud.
   - **jwtToken = requestTokenHeader.substring(7)**: Extrae el token JWT del encabezado.
   - **username = jwtUtil.extractUsername(jwtToken)**: Extrae el nombre de usuario del token JWT.
   - **if (jwtUtil.validateToken(jwtToken, userDetails))**: Valida el token JWT.
   - **UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken**: Crea un objeto de autenticación para el usuario validado.
   - **SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken)**: Establece la autenticación en el contexto de seguridad de Spring.

### Configuración de Seguridad

En este paso, ya hemos configurado la seguridad para usar `SecurityFilterChain` en lugar de `WebSecurityConfigurerAdapter`. Asegurémonos de que `JwtRequestFilter` esté registrado en el flujo de filtros de seguridad.

#### Integración del Filtro en la Cadena de Seguridad

Ya hemos creado la **clase** `JwtRequestFilter` y la hemos configurado en la **clase** `SecurityConfig`. Ahora, revisemos que todo esté correctamente configurado y cómo funciona en conjunto

```java
package com.isabosdev.template_jwt_H2.security;

import com.isabosdev.template_jwt_H2.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
           .authorizeHttpRequests(auth -> auth
               .requestMatchers("/auth/**").permitAll()
               .anyRequest().authenticated()
           )
           .sessionManagement(session -> session
               .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
           );
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
```

- **http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class)**: Registra `JwtRequestFilter` antes del filtro de autenticación de Spring Security.


Con esto, hemos creado un filtro para interceptar y validar las solicitudes con JWT, y hemos configurado la seguridad para usar `SecurityFilterChain` y manejar el filtro JWT.

---

## 9. Pruebas del Proyecto

En este paso, vamos a probar los endpoints de autenticación y los endpoints protegidos para asegurarnos de que todo funcione correctamente.

### Pruebas de los Endpoints de Autenticación

1. **Registro de Usuario**

   Primero, probaremos el endpoint de registro para crear un nuevo usuario. Usaremos una herramienta como Postman para enviar solicitudes HTTP.

   **Solicitud HTTP:**
   - Método: POST
   - URL: `http://localhost:8080/auth/register`
   - Cuerpo (JSON):
     ```json
     {
         "username": "testuser",
         "password": "testpassword",
         "role": "ROLE_USER"
     }
     ```

   **Respuesta Esperada:**
   - Código de estado: 200 OK
   - Cuerpo (JSON):
     ```json
     {
         "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0dXNlciIsImlhdCI6MTcyMDg5OTk2OSwiZXhwIjoxNzIwOTAzNTY5fQ.rc5ujtK-SQWcNDEaQ4n0VuHdQTBw7T4VuPCKb0EgPJ878ZbmLMRlyAnkpXqemCHA1dKnIv7erxLbTUZemQ3U7Q"
     }
     ```

2. **Inicio de Sesión**

   Ahora, probaremos el endpoint de login para autenticar al usuario y obtener un token JWT.

   **Solicitud HTTP:**
   - Método: POST
   - URL: `http://localhost:8080/auth/login`
   - Cuerpo (JSON):
     ```json
     {
         "username": "testuser",
         "password": "testpassword"
     }
     ```

   **Respuesta Esperada:**
   - Código de estado: 200 OK
   - Cuerpo (JSON):
     ```json
     {
         "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0dXNlciIsImlhdCI6MTcyMDkwMDA4MSwiZXhwIjoxNzIwOTAzNjgxfQ.xotgMiiVBk0qyjMcVW98inxqpWpwQOSSckrQ2kUiBARY9aSf25GnavLA2i9MNvIpoHGvdyg80h1DaP-2SjOmyw"
     }
     ```

#### Pruebas de los Endpoints Protegidos

1. **Endpoint Protegido**

   Crearemos un controlador adicional para probar los endpoints protegidos. Crear una clase `TestController` en el paquete `controller`:

   ```java
   package com.isabosdev.template_jwt_H2.controller;

   import org.springframework.web.bind.annotation.GetMapping;
   import org.springframework.web.bind.annotation.RequestMapping;
   import org.springframework.web.bind.annotation.RestController;

   @RestController
   @RequestMapping("/api")
   public class TestController {

       @GetMapping("/protected")
       public String protectedEndpoint() {
           return "Este es un endpoint protegido.";
       }
   }
   ```

   - **@RestController y @RequestMapping("/api")**: Define un controlador REST con una ruta base `/api`.
   - **@GetMapping("/protected")**: Define un endpoint GET protegido en `/api/protected`.

2. **Acceso al Endpoint Protegido**

   Intentaremos acceder al endpoint protegido sin un token JWT.

   **Solicitud HTTP:**
   - Método: GET
   - URL: `http://localhost:8080/api/protected`

   **Respuesta Esperada:**
   - Código de estado: 403 Forbidden (o 401 Unauthorized)

   Ahora, intentaremos acceder al endpoint protegido con un token JWT válido.

   **Solicitud HTTP:**
   - Método: GET
   - URL: `http://localhost:8080/api/protected`
   - Encabezado:
      - `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...` (token obtenido en el paso anterior)

   **Respuesta Esperada:**
   - Código de estado: 200 OK
   - Cuerpo: `Este es un endpoint protegido.`

### Resumen

- **Registro de Usuario**: Creación de un nuevo usuario y generación de un token JWT.
- **Inicio de Sesión**: Autenticación de un usuario existente y obtención de un token JWT.
- **Endpoint Protegido**: Acceso a un endpoint protegido, primero sin un token (esperando un error) y luego con un token válido (esperando éxito).

Con esto, hemos realizado pruebas completas de los endpoints de autenticación y los endpoints protegidos. 

---


