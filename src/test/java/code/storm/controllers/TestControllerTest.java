package code.storm.controllers;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class TestControllerTest {

    private TestController controller;

    @BeforeEach
    void init() {
        controller = new TestController();
    }

    @Test
    void testAllAccess() {
        Assertions.assertEquals("Public Content.", controller.allAccess());
    }

    @Test
    void testUserAccess() {
        Assertions.assertEquals("User Content.", controller.userAccess());
    }


    @Test
    void testModeratorAccess() {
        Assertions.assertEquals("Moderator Board.", controller.moderatorAccess());
    }


    @Test
    void testAdminAccess() {
        Assertions.assertEquals("Admin Board.", controller.adminAccess());
    }
    


}
