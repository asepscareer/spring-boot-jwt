package code.storm;

import code.storm.models.ERole;
import code.storm.models.Role;
import code.storm.repositories.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SpringBootJWTApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringBootJWTApplication.class, args);
	}

	@Bean
	CommandLineRunner startUp(RoleRepository roleRepository){
		return args -> {
			roleRepository.save(new Role(ERole.ROLE_USER));
			roleRepository.save(new Role(ERole.ROLE_ADMIN));
			roleRepository.save(new Role(ERole.ROLE_MODERATOR));
		};
	}


}
