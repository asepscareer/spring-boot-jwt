package code.storm.payload.response;

import java.util.List;
import java.util.Objects;

public class UserInfoResponse {
	private Long id;
	private String username;
	private String email;
	private List<String> roles;

	public UserInfoResponse(Long id, String username, String email, List<String> roles) {
		this.id = id;
		this.username = username;
		this.email = email;
		this.roles = roles;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public List<String> getRoles() {
		return roles;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		UserInfoResponse that = (UserInfoResponse) o;
		return Objects.equals(id, that.id) && Objects.equals(username, that.username) && Objects.equals(email, that.email) && Objects.equals(roles, that.roles);
	}

	@Override
	public int hashCode() {
		return Objects.hash(id, username, email, roles);
	}

	@Override
	public String toString() {
		return "UserInfoResponse{" +
				"id=" + id +
				", username='" + username + '\'' +
				", email='" + email + '\'' +
				", roles=" + roles +
				'}';
	}
}
