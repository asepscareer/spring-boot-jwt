package code.storm.payload.response;


import java.util.Objects;

public class MessageResponse {
	private String message;

	public MessageResponse(String message) {
	    this.message = message;
	  }

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		MessageResponse that = (MessageResponse) o;
		return Objects.equals(message, that.message);
	}

	@Override
	public int hashCode() {
		return Objects.hash(message);
	}

	@Override
	public String toString() {
		return "MessageResponse{" +
				"message='" + message + '\'' +
				'}';
	}
}
