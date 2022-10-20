package code.storm.repositories;

import code.storm.models.User;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.Optional;

@ExtendWith(SpringExtension.class)
@DataJpaTest
public class UserRepositoryTest {

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
    }

    @AfterEach
    void deleteData() {
        userRepository.deleteAll();
    }

    @Test
    void findByUsername() {
        Optional<User> opt = userRepository.
                findByUsername(person.getUsername());
        Assertions.assertNotNull(opt);
    }

    @Test
    void existsByUsername() {
        Boolean checkUsername = userRepository
                .existsByUsername("adirafinance");
        Assertions.assertTrue(checkUsername);
    }

    @Test
    void existsByEmail() {
        Boolean checkEmail = userRepository
                .existsByEmail("adirafinance@gmail.com");
        Assertions.assertTrue(checkEmail);
    }

}
