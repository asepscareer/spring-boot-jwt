package code.storm.controllers;

import code.storm.models.ERole;
import code.storm.models.RefreshToken;
import code.storm.models.Role;
import code.storm.payload.request.LoginRequest;
import code.storm.payload.request.SignupRequest;
import code.storm.payload.response.MessageResponse;
import code.storm.payload.response.UserInfoResponse;
import code.storm.repositories.RoleRepository;
import code.storm.repositories.UserRepository;
import code.storm.security.RefreshTokenService;
import code.storm.security.UserDetailsImpl;
import code.storm.security.jwt.JwtUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    AuthenticationManager authenticationManager;
    @Mock
    UserRepository userRepository;
    @Mock
    RoleRepository roleRepository;
    @Mock
    PasswordEncoder encoder;
    @Mock
    JwtUtils jwtUtils;
    @Mock
    RefreshTokenService refreshTokenService;

    private AuthController controller;

    private final UserDetailsImpl fakeUserDetail =
            new UserDetailsImpl(1L, "asep", "asep@mail.com", "password",
                    Collections.singletonList(new SimpleGrantedAuthority("admin")));
    private final Object principal = "asep";

    @Mock
    private Authentication fakeAuth;


    @BeforeEach
    void init() {
        controller = new AuthController(
                authenticationManager,
                userRepository,
                roleRepository,
                encoder,
                jwtUtils,
                refreshTokenService
        );
    }

    // Register Username Exist
    @Test
    void shouldReturnUsernameExist() {

        SignupRequest req = new SignupRequest();
        req.setUsername("asepsaputra");

        when(userRepository.existsByUsername(eq(req.getUsername())))
                .thenReturn(true);

        ResponseEntity<?> actual = controller.registerUser(req);

        assertEquals(400, actual.getStatusCodeValue());

        MessageResponse expectedResp = new MessageResponse("Error: Username is already taken!");
        assertEquals(expectedResp, actual.getBody());
    }

    // Register Email Exist
    @Test
    void shouldReturnEmailExist() {

        SignupRequest req = new SignupRequest();
        req.setEmail("asepsaputra@gmail.com");

        when(userRepository.existsByEmail(eq(req.getEmail())))
                .thenReturn(true);

        ResponseEntity<?> actual = controller.registerUser(req);

        assertEquals(400, actual.getStatusCodeValue());

        MessageResponse expectedResp = new MessageResponse("Error: Email is already in use!");
        assertEquals(expectedResp, actual.getBody());
    }

    // Register User Role is Not Found
    @Test
    void shouldRoleNotFound() {
        SignupRequest req = new SignupRequest();
        req.setUsername("asepsaputra");
        req.setEmail("asepsaputra@gmail.com");
        req.setPassword("asepsaputra");

        Throwable throwable = catchThrowable(() -> controller.registerUser(req));
        assertThat(throwable)
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Error: Role is not found.");

    }

    @Test
    void shouldRoleDefaultIsUser() {
        SignupRequest req = new SignupRequest();
        req.setUsername("asepsaputra");
        req.setEmail("asepsaputra@gmail.com");
        req.setPassword("asepsaputra");

        Set<Role> roles = new HashSet<>();
        roles.add(new Role(ERole.ROLE_USER));
        assertEquals(1, roles.size());
    }

        // AthenticateUser method
    @Test
    void shouldReturnUserInfo() {
        LoginRequest req = new LoginRequest();
        req.setUsername("asep");
        req.setPassword("password");

        UserInfoResponse expectedResp = new UserInfoResponse(1L, req.getUsername(), fakeUserDetail.getEmail(), Collections.singletonList("admin"));


        // Misalkan berhasil autentikasi
        doReturn(fakeAuth).when(authenticationManager).
                authenticate(any(UsernamePasswordAuthenticationToken.class));


        doReturn(fakeUserDetail).when(fakeAuth).getPrincipal();

        // Misalkan jwt utils berhasil generate jwt cookie
        ResponseCookie fakeJwtCookie = ResponseCookie.from("token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
                .path("/api").maxAge(24 * 60 * 60).httpOnly(true).build();

        doReturn(fakeJwtCookie)
                .when(jwtUtils)
                .generateJwtCookie(any(UserDetailsImpl.class));

        // Misalkan berhasil create refresh token
        String tokenValue = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
        RefreshToken fakeRefreshToken = mock(RefreshToken.class);
        when(fakeRefreshToken.getToken()).thenReturn(tokenValue);
        doReturn(fakeRefreshToken)
                .when(refreshTokenService)
                .createRefreshToken(fakeUserDetail.getId());

        ResponseCookie fakeRefreshJwtCookie = ResponseCookie.from("refresh-token", tokenValue)
                .path("/api/refreshtoken").maxAge(24 * 60 * 60).httpOnly(true).build();
        doReturn(fakeRefreshJwtCookie)
                .when(jwtUtils)
                .generateRefreshJwtCookie(any(String.class));
        // ResponseEntity<UserInfoResponse> resp = ResponseEntity.ok(expectedResp);
        ResponseEntity<UserInfoResponse> actual = controller.authenticateUser(req);
        List<String> setCookieHeader = actual.getHeaders().get("Set-Cookie");

        assertEquals(200, actual.getStatusCodeValue());
        assertEquals(2, setCookieHeader.size());
        assertEquals(expectedResp, actual.getBody());

    }

    // LogoutUser method
    void logoutMethod() {
        ResponseCookie fakeJwtCookie = ResponseCookie.from("fakeJwtCookie", null)
                .path("/api").build();
        doReturn(fakeJwtCookie)
                .when(jwtUtils)
                .getCleanJwtCookie();

        ResponseCookie fakeJwtRefreshCookie = ResponseCookie.from("fakeJwtRefreshCookie", null)
                .path("/api/auth/refreshtoken").build();
        doReturn(fakeJwtRefreshCookie)
                .when(jwtUtils)
                .getCleanJwtRefreshCookie();

        MessageResponse expectedResp = new MessageResponse("You've been signed out!");
        ResponseEntity<MessageResponse> actual = controller.logoutUser();
        List<String> setCookieHeader = actual.getHeaders().get("Set-Cookie");
    }

    @Test
    @DisplayName("Logout itu harusnya menghapus data refresh token si user dari DB untuk user yang bukan anonim")
    void logoutShouldDeleteRefreshTokenForNonAnonymousUser() {
        when(fakeAuth.getPrincipal())
                .thenReturn(fakeUserDetail);

        SecurityContext securityContext = Mockito.mock(SecurityContext.class);
        Mockito.when(securityContext
                .getAuthentication())
                .thenReturn(fakeAuth);
        SecurityContextHolder.setContext(securityContext);

        logoutMethod();

        Mockito.verify(refreshTokenService,
                times(1))
                .deleteByUserId(any(Long.class));

    }

    @Test()
    @DisplayName("Logout itu harusnya tidak melakukan apa2 terkait refresh token untuk user yang anonim")
    void logoutShouldNotDeleteRefreshTokenForAnonymousUser() {
        when(fakeAuth.getPrincipal())
                .thenReturn("anonymousUser");

        SecurityContext securityContext = Mockito.mock(SecurityContext.class);
        Mockito.when(securityContext
                .getAuthentication())
                .thenReturn(fakeAuth);
        SecurityContextHolder.setContext(securityContext);
        logoutMethod();

        Mockito.verify(refreshTokenService,
                times(0))
                .deleteByUserId(any(Long.class));

    }


    @Test
    void shouldFailedIfAuthenticationFailed() {
        LoginRequest req = new LoginRequest();
        req.setUsername("asep");
        req.setPassword("password");
        doThrow(new RuntimeException("Kamu tidak dikenali"))
                .when(authenticationManager)
                .authenticate(any(UsernamePasswordAuthenticationToken.class));
        assertThrows(RuntimeException.class, () -> controller.authenticateUser(req));
    }

}
