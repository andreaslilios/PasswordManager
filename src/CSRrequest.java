
import java.security.Key;
import java.security.KeyPair;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;


public class CSRrequest 
{
    
    private PKCS10CertificationRequest request;
    private KeyPair UsersKeyPair;
    
    
    public CSRrequest(PKCS10CertificationRequest request,KeyPair UsersKeyPair)
    {
        
       
       this.request=request;
       this.UsersKeyPair=UsersKeyPair;
       
      
    }
    
    
    //getters

    public PKCS10CertificationRequest getRequest() {
        return request;
    }

    public KeyPair getUsersKeyPair() {
        return UsersKeyPair;
    }
  
    //stters

    public void setRequest(PKCS10CertificationRequest request) {
        this.request = request;
    }

    public void setUsersKeyPair(KeyPair UsersKeyPair) {
        this.UsersKeyPair = UsersKeyPair;
    }
    
    
    //toString

    @Override
    public String toString() {
        return "CSRrequest{" + "request=" + request + ", UsersKeyPair=" + UsersKeyPair + '}';
    }
    
    
}
