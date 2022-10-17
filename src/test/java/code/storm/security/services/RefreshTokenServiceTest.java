package code.storm.security.services;


import code.storm.models.RefreshToken;
import code.storm.models.User;
import code.storm.repositories.RefreshTokenRepository;
import code.storm.repositories.UserRepository;
import code.storm.security.RefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private UserRepository userRepository;

    private RefreshTokenService service;

    @BeforeEach
    void init() {
        service = new RefreshTokenService(
                1L,
                refreshTokenRepository,
                userRepository
        );
    }

    @Test
    void deleteByUserId() {
        User person = new User(1L, "asepsaputra");
        Mockito.when(userRepository
                .findById(any(Long.class)))
                .thenReturn(Optional.of(person));
//        Mockito.when(userRepository.findById(eq(person.getId()))).thenReturn(Optional.of(person));
        when(refreshTokenRepository.deleteByUser(Mockito.any(User.class)))
                .thenReturn(1);
        service.deleteByUserId(person.getId());

        verify(refreshTokenRepository, times(1)).deleteByUser(person);
    }

    @Test
    void findByToken() {
        RefreshToken refreshToken = mock(RefreshToken.class);

        when(refreshToken.getToken())
                .thenReturn("token-test");

        service.findByToken(refreshToken.getToken());

        verify(refreshTokenRepository, times(1))
                .findByToken(refreshToken.getToken());
    }

}
