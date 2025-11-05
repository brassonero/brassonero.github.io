## Análisis Detallado de Problemas de Seguridad

### ID 1: Verificación de permisos de aplicación después de validar JWT
**❌ PARCIALMENTE IMPLEMENTADO**

**Ubicación del problema:**
- **Archivo:** `TokenController.java`
- **Método:** `getToken()` (líneas 30-62)

**Problema específico:**
```java
// Solo valida credenciales del cliente, NO verifica permisos específicos de API
if (registeredClient == null ||
    !registeredClient.getClientSecret().equals("{noop}" + request.getClientSecret())) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid client credentials");
}
```

**Falta implementar:**
- No hay verificación de scopes contra los endpoints específicos
- No existe validación de que el cliente tenga permisos para APIs específicas
- El JWT se genera con todos los scopes del cliente sin validación adicional

---

### ID 2: Restricción de autenticación usuario/contraseña para información sensible
**❌ NO IMPLEMENTADO**

**Ubicación del problema:**
- **Archivo:** `SecurityConfig.java`
- **Método:** `userDetailsService()` (líneas 97-104)

```java
@Bean
UserDetailsService userDetailsService() {
    UserDetails userDetails = User.withUsername("user")
            .password("{noop}user") // ⚠️ Permite acceso sin restricción de sensibilidad
            .authorities("ROLE_USER")
            .build();
    return new InMemoryUserDetailsManager(userDetails);
}
```

**Problemas identificados:**
1. No hay clasificación de APIs (sensible vs no sensible)
2. No existe lógica para rechazar solicitudes a datos sensibles con autenticación básica
3. El `TokenController` no valida el tipo de autenticación usado

---

### ID 3: Autenticación mediante certificado para información sensible
**❌ NO IMPLEMENTADO**

**Ubicación del problema:**
- **Archivo:** `TokenController.java` (línea 42-45)
- **Archivo:** `SecurityConfig.java`

```java
// TokenController.java - Solo acepta CLIENT_SECRET_BASIC
OAuth2ClientAuthenticationToken authenticationToken = new OAuth2ClientAuthenticationToken(
        registeredClient,
        ClientAuthenticationMethod.CLIENT_SECRET_BASIC, // ⚠️ Solo método básico
        registeredClient.getClientSecret()
);
```

**Falta completamente:**
- No hay configuración de SSL mutual (mTLS)
- No existe soporte para `ClientAuthenticationMethod.TLS_CLIENT_AUTH`
- No hay validación de certificados X.509

---

### ID 4: Implementación del parámetro nonce para prevenir ataques replay
**❌ NO IMPLEMENTADO**

**Ubicación del problema:**
- **Archivo:** `TokenController.java`
- **Método:** `getToken()` (líneas 49-57)

```java
JwtClaimsSet claims = JwtClaimsSet.builder()
        .issuer("https://localhost:9054")
        .subject(request.getClientId())
        .audience(List.of("api-gateway", "resource-server"))
        .issuedAt(now)
        .expiresAt(expiresAt)
        .claim("scope", String.join(" ", registeredClient.getScopes()))
        // ⚠️ FALTA: .claim("nonce", generateNonce())
        // ⚠️ FALTA: .claim("jti", UUID.randomUUID().toString())
        .build();
```

**Problemas:**
1. No hay generación de nonce
2. No hay almacenamiento de nonces usados
3. No hay validación contra replay attacks
4. Falta el claim "jti" (JWT ID) único

---

### ID 5: No configurar scope default de OAuth 2.0
**✅ CUMPLE**

**Verificación correcta en:**
- **Archivo:** `TokenController.java` (línea 56)
- Los scopes se toman explícitamente del cliente registrado sin defaults

---

## Problemas Adicionales de Seguridad Críticos

### 1. CSRF Deshabilitado
**Archivo:** `SecurityConfig.java` (línea 77)
```java
.csrf(AbstractHttpConfigurer::disable); // ⚠️ CRÍTICO: CSRF deshabilitado
```

### 2. Contraseñas sin encriptar
**Archivo:** `SecurityConfig.java` (línea 99)
```java
.password("{noop}user") // ⚠️ Sin encriptación
```

### 3. CORS permite todos los orígenes
**Archivo:** `WebConfig.java` (línea 11)
```java
.allowedOrigins("*") // ⚠️ Acepta cualquier origen
```

### 4. Issuer hardcodeado
**Archivo:** `TokenController.java` (línea 50)
```java
.issuer("https://localhost:9054") // ⚠️ Debería ser configurable
```

### 5. Secretos en código
**Archivo:** `TokenController.java` (línea 36)
```java
!registeredClient.getClientSecret().equals("{noop}" + request.getClientSecret())
// ⚠️ Comparación de secretos vulnerable a timing attacks
```

### 6. Falta el repositorio CyberArk
**Archivo:** `CcpRegisteredClientRepository.java` - **NO PROPORCIONADO**
- Este archivo es crítico pero no fue compartido
- Sin él, no se puede validar la integración con CyberArk

**Recomendación urgente:** Implementar todos los controles de seguridad faltantes antes de pasar a producción.