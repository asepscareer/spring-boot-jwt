package code.storm.repositories;

import code.storm.models.RefreshToken;
import code.storm.models.User;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Description;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.time.Instant;
import java.util.Optional;

@ExtendWith(SpringExtension.class)
@DataJpaTest
class RefreshTokenRepositoryTest {

    @Autowired
    private RefreshTokenRepository repository;

    @Autowired
    private UserRepository userRepository;

    private User person;

    @BeforeEach
    void saveData() {
        person = new User(
                "adirafinance",
                "adirafinance@gmail.com",
                "adirafinance");
        userRepository.save(person);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setId(1L);
        refreshToken.setUser(person);
        refreshToken.setExpiryDate(Instant.now());
        refreshToken.setToken("token-test");
        repository.save(refreshToken);
    }

    @AfterEach
    void deleteData() {
        repository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Find By Token")
    @Description("Refresh Token Find By Token")
    void findByToken() {

        Optional<RefreshToken> foundRefreshToken = repository
                .findByToken("token-test");

        Assertions.assertTrue(foundRefreshToken.isPresent());

    }

    @Test
    @DisplayName("Delete By User")
    @Description("Refresh Token Delete By User")
    void deleteByUser() {

        repository.deleteByUser(person);

        Optional<RefreshToken> deletedRefreshToken = repository.findById(1L);

        Assertions.assertEquals(Optional.empty(), deletedRefreshToken);

    }



}

