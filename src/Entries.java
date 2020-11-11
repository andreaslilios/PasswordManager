
import java.io.Serializable;

public class Entries implements Serializable {

    private String domain;
    private String username;
    private String password;
    private String comment;

    public Entries(String domain, String username, String password, String comment) {

        this.domain = domain;
        this.username = username;
        this.password = password;
        this.comment = comment;

    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getDomain() {
        return domain;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getPassword() {
        return password;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public String getComment() {
        return comment;
    }

    public String toString() {
        return "Domain:{" + domain + "}," + "Username:{" + username + "}," + "Password:{" + password + "}," + "Comment:{" + comment + "}";
    }

}
