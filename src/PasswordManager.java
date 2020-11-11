
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V1CertificateGenerator;


public class PasswordManager 
{
  
    public static X509Certificate createUserCert(PKCS10CertificationRequest csr)
    {
        X509Certificate UserCert=null;
        
        return UserCert;
    }
    
    public static void main(String[] args) throws KeyStoreException 
    {
        
      //Register r=new Register();  
      StartLogin a =new StartLogin();
        
        
        if (Security.getProvider("BC") == null){
            System.out.println("Bouncy Castle provider is NOT available");
        }
        else{
            System.out.println("Bouncy Castle provider is available");
        }
        
      
       
        
    }

        
}
    

