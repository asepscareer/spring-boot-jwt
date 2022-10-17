package code.storm;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class CobaTest {

    @Test
    void testFactorial() throws Exception {
        try {
            System.out.println("Start Test");
            int factorial = Coba.factorial(3);
            Assertions.assertEquals(6, factorial);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

}
