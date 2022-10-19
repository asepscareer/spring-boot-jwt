package code.storm.repositories;

import code.storm.models.RefreshToken;
import code.storm.models.User;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@SpringBootTest
class RefreshTokenRepositoryTest {

    @Autowired
    private RefreshTokenRepository repository;

    @Autowired
    private UserRepository userRepository;

    @Test
    void deleteByUser() {

        User person = new User(
                "asepsaputra",
                "asep@gmail.com",
                "asepsaputra");

        userRepository.save(person);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setId(1L);
        refreshToken.setUser(person);
        refreshToken.setExpiryDate(Instant.now());
        refreshToken.setToken(UUID.randomUUID().toString());
        repository.save(refreshToken);
        repository.deleteByUser(person);

        Optional<RefreshToken> deletedRefreshToken = repository.findById(1L);

        Assertions.assertEquals(Optional.empty(),deletedRefreshToken);

    }
}

