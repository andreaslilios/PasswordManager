
import java.io.File;
import java.io.Serializable;
import java.security.cert.X509Certificate;


public class User implements Serializable 
{
    
    private String name;
    private String surname;
    private String email;
    private String username;
    private String authHash;

    
    
    public User(String Username)
    {
        this.username=username;
    }
    
    
    public User(String name, String surname, String email, String username) {
        this.name = name;
        this.surname = surname;
        this.email = email;
        this.username = username;
    }
    
    public String getAuthHash() {
        return authHash;
    }

    public void setAuthHash(String authHash) {
        this.authHash = authHash;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
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

    
    
}
