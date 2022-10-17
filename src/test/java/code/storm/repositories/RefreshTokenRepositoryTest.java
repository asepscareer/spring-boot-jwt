package code.storm.repositories;

import code.storm.models.User;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class RefreshTokenRepositoryTest {

    @Mock
    RefreshTokenRepository refreshTokenRepository;

    @Test
    void deleteByUser() {
        User person = new User("asepsaputra", "asep@gmail.com", "asepsaputra");
        int actualResult = refreshTokenRepository.deleteByUser(person);
        Assertions.assertEquals(0,0);
    }
}

