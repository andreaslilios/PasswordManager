
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

public class DhmiourgiaX509 implements Serializable {

    private int Version1;
    private String Version3;
    private KeyPair keyPair1;
    private X509Certificate cert;
    

    
    //Telika xreiasthke enas akoma constructor o opoios xreiazetai gia thn klash register wste na dhmiourgeite mono mia fora to CAcert
    // kai tis upoloipes na pernete apo to KeyStore. Ousiastika meta thn prwth fora tis epomenes to kanoume load apo to Keystore kai 
    //kaloume ton en logw constructor wste na valoyme to CAcert mesa se ena antikeimeno DhmiourgiaX509 gia logous sumvatothtas me ta alla
    // kommatia kwdika pou exoume grapsei
    public DhmiourgiaX509(X509Certificate CA)
    {
        cert=CA;
        
    }
    
    //o prwtos Constructor tha dhmiourgei Pistopoihtiko X509 version 1 apo BouncyCastle selfsigned gia thn CA
    // kai o deuteros tha dhmiourgei Version 3 X509 pistopoihtiko gia tous Users
    public DhmiourgiaX509(int Version1) {

        //dhmiourgia pistopoihtikou
        SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy");
        try {

            // dhmiourgia  key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            keyPairGenerator.initialize(2048, new SecureRandom());
            keyPair1 = keyPairGenerator.generateKeyPair();

            // dhmiourgia pistopoihtikou authypografou gia  thn efarmogh
            // H efarmogh tha einai CA ara tha pame se version1 tou X509 apo Bouncycastle
            String string_date = "24/05/2017";

                Date d = sdf.parse(string_date);
                long temp = d.getTime();
            
            

            Date start_date = new Date(24/05/2017);  // hmeromhnia  arxhs pistopoihtikou

            String dt;
            Calendar c = Calendar.getInstance();
            c.setTime(start_date);
            c.add(Calendar.YEAR, 1); //diarkeia zwhs enas xronos gia thn CA
            dt = sdf.format(c.getTime());

            Date end_date = sdf.parse(dt);    //hmeromhnia lhkshs pistopoihtikou

            
            BigInteger serialNumber = new BigInteger(Long.toString(temp));     // serial number for certificate

            //allazei o generator analoga to eidos toy pistopoihtikou
            X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();

            X500Principal dnName = new X500Principal("CN=PASSWORD MANAGER");

            certGen.setSerialNumber(serialNumber);
            certGen.setIssuerDN(dnName);

            certGen.setNotBefore(start_date);
            certGen.setNotAfter(end_date);
            certGen.setSubjectDN(dnName);
            certGen.setPublicKey(keyPair1.getPublic());
            certGen.setSignatureAlgorithm("SHA1withRSA");
            cert = certGen.generate(keyPair1.getPrivate(), "BC");

             //dhmiourgia Keystore
            //Arxika dhmiourgw to arxeio kai tis roes tou
            //kai sth sunexeia to keystore kai to gemizw
            File usr_dir = new File("Application");
            if (!usr_dir.exists()) {

                if (usr_dir.mkdir()) {

                    System.out.println("Directory is created!");
                } else {
                    System.out.println("Failed to create directory!");
                }
            }
            
            
            
            File file = new File("Application\\CA.bks");
            

            FileOutputStream os = new FileOutputStream(file);
            
            String password = "password";
            char[] pass = password.toCharArray();

            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = cert;
            
            
            KeyStore keyStore = KeyStore.getInstance("BKS", "BC");
           
            FileInputStream fin=null;
            keyStore.load(fin, "password".toCharArray());

            Key prkey = keyPair1.getPrivate();

            System.out.println("TO PRIVATE KEY ths CA einai: \n");
            System.out.println(keyPair1.getPrivate().toString());
            
            System.out.println("TO CA CERTIFICATE EINAI: \n");
            System.out.println(cert);
            //apothikeuw to private key
            //kai to certificate(to opoio exw valei ston pinaka chain)
            
            
//            keyStore.setKeyEntry("apo", prkey,"password".toCharArray(), chain);
//
//            keyStore.store(os,"password".toCharArray());
            
            os.flush();
            os.close();
          

        } catch (ParseException ex) {
            Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateEncodingException ex) {
            Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalStateException ex) {
            Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {

        } catch (FileNotFoundException ex) {
            Logger.getLogger(DhmiourgiaX509.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(DhmiourgiaX509.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(DhmiourgiaX509.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(DhmiourgiaX509.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    //dhmiourgia 2ou Constructor gia version 3 pistopoihtiko gia tous users ths efarmoghs
    //tha ginei xrhsh diaforetikou generator
    //O constructor tha pernei ws parametrous ena string , to pistopoihtiko ths Arxhs pou tha exei ftiaxtei prwta me ton 1o constructor
    // kai ena Certification Request apo to xrhsth pros thn efarmogh
    public DhmiourgiaX509(String Version3, DhmiourgiaX509 CAcert, CSRrequest requestCSR) {
        SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy");

        try {

                    // To Key pair kai to Principal tha ta pernei apo th klash Register kai einai tou xrhsth
            PublicKey UsersPublickey = requestCSR.getUsersKeyPair().getPublic();

            long temp = System.currentTimeMillis();

            Date start_date = new Date(temp);  // hmeromhnia  arxhs pistopoihtikou

            String dt;
            Calendar c = Calendar.getInstance();
            c.setTime(start_date);
            c.add(Calendar.MONTH, 6); //diarkeia zwhs 6 mhnwn gia ton user
            dt = sdf.format(c.getTime());

            Date end_date = sdf.parse(dt);    //hmeromhnia lhkshs pistopoihtikou

            BigInteger serialNumber = new BigInteger(Long.toString(temp));     // serial number for certificate

            PrivateKey caKey = CAcert.keyPair1.getPrivate();

            X509Certificate caCert = CAcert.getCert();

            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            X500Principal subjectName = new X500Principal(requestCSR.getRequest().getSubject().toString());

//                    vazw ta stoixeia sto pistopoihtiko me xrhsh set methodwn
            certGen.setSerialNumber(serialNumber);
            certGen.setIssuerDN(caCert.getSubjectX500Principal());
            certGen.setNotBefore(start_date);
            certGen.setNotAfter(end_date);

            certGen.setSubjectDN(subjectName);
            certGen.setPublicKey(UsersPublickey);
            certGen.setSignatureAlgorithm(requestCSR.getRequest().getSignatureAlgorithm().getAlgorithm().toString());

                //Valame to klasiko to extension pou xrhsimopoieitai wste 
            certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));

            //telikh kataskeyh certificate
            cert = certGen.generate(CAcert.keyPair1.getPrivate(), "BC");  // note: private key of CA

                //    System.out.println(cert);
        } catch (ParseException ex) {
            Logger.getLogger(DhmiourgiaX509.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DhmiourgiaX509.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(DhmiourgiaX509.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateEncodingException ex) {
            Logger.getLogger(DhmiourgiaX509.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalStateException ex) {
            Logger.getLogger(DhmiourgiaX509.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(DhmiourgiaX509.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(DhmiourgiaX509.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateParsingException ex) {
            Logger.getLogger(DhmiourgiaX509.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    //getters
    public KeyPair getKeyPair1() {
        return keyPair1;
    }

    public X509Certificate getCert() {
        return cert;
    }

}
