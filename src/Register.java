
import java.awt.Color;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.Certificate;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.Signer;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import static org.bouncycastle.asn1.x500.style.RFC4519Style.c;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import static org.bouncycastle.asn1.x509.ObjectDigestInfo.publicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.PSSSignatureSpi.SHA1withRSA;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import sun.security.pkcs10.PKCS10;
import sun.security.pkcs12.PKCS12KeyStore;

public class Register extends JFrame {

    public Register() {
        JLabel TitleLabel, NameLabel, SurnameLabel, UsernameLabel, PasswordLabel, EmailLabel, l8;
        JTextField NameText, SurnameText, UsernameText, EmailText;
        JButton REGbutton;
        JPasswordField PassField;

        setVisible(true);
        setSize(600, 400);
        setLayout(null);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setTitle("User Registration");

        TitleLabel = new JLabel("<HTML><B><U>Fill out the form</U></B></HTML>");

        TitleLabel.setFont(new Font("Serif", Font.BOLD, 20));

        NameLabel = new JLabel("Name:");
        SurnameLabel = new JLabel("Surname:");
        UsernameLabel = new JLabel("Username:");
        PasswordLabel = new JLabel("Master password:");
        EmailLabel = new JLabel("Email:");

        NameText = new JTextField();
        SurnameText = new JTextField();
        UsernameText = new JTextField();
        PassField = new JPasswordField();
        EmailText = new JTextField();

        REGbutton = new JButton("Register");

        TitleLabel.setBounds(80, 30, 400, 30);
        NameLabel.setBounds(80, 70, 200, 30);
        SurnameLabel.setBounds(80, 110, 200, 30);
        UsernameLabel.setBounds(80, 150, 200, 30);
        PasswordLabel.setBounds(80, 190, 200, 30);

        EmailLabel.setBounds(80, 230, 200, 30);

        NameText.setBounds(300, 70, 200, 30);
        SurnameText.setBounds(300, 110, 200, 30);
        PassField.setBounds(300, 190, 200, 30);
        UsernameText.setBounds(300, 150, 200, 30);
        EmailText.setBounds(300, 230, 200, 30);

        REGbutton.setBounds(80, 300, 100, 30);
        REGbutton.setBackground(Color.blue);
        REGbutton.setForeground(Color.white);
        setLocationRelativeTo(null);

        add(TitleLabel);
        add(NameLabel);
        add(NameText);
        add(SurnameText);
        add(SurnameLabel);
        add(UsernameLabel);
        add(UsernameText);
        add(EmailLabel);
        add(EmailText);
        add(PassField);
        add(PasswordLabel);

        add(REGbutton);

        //kwdikas tou koympiou pou oloklhrwnei to registration sto susthma
        REGbutton.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent e) {

                    
                try {
                    
                    File UsersFile = new File("Users\\Xristes.txt");
                    
                    //an yparxei to Users File shmainei oti exei ginei toulaxiston 1 kataxwrish ara mono tote exei nohma
                    // na koitaksw gia monadikothta tou username
                    if (UsersFile.exists())
                    {
                        
                        //elegxw an o xrhsths einai monadikos me th methodo pou exw ulopoihsei
                        boolean CheckResult=CheckUniqueUsername(UsernameText.getText());
                        
                        //an einai true shmainei oti uparxei xrhsths me idio username hdh sto susthma
                        if(CheckResult==true)
                        {
                            
                            JOptionPane.showMessageDialog(null, "Το username που δώσατε χρησιμοποιείται ήδη!!", "Already existing user",1); 
                            
                        }
                        else //alliws an den uparxei tha proxwraei kanonika h diadikasia kataxwrhshs
                        {
                            
                            
                            //dhmiourgia pistopoihtikou efarmoghs CA dhmiourgw ksana to idio antikeimeno alla h hmeromhnia ekdoshs einai
                            //idia epomenws o xronos lhkshs threitai
                            DhmiourgiaX509 CAcert = new DhmiourgiaX509(1);
                           
                            
                            
                            
//                            KeyStore keyStore = KeyStore.getInstance("BKS", "BC");
//                            keyStore.load(new FileInputStream("CA.bks"), "password".toCharArray());
//
//                           
//                            X509Certificate[] chain = (X509Certificate[]) keyStore.getCertificateChain("apo");
//                            
//                            X509Certificate CAcert=chain[0];

                            




                            // dhmiourgia  key pair gia ton user (gia to pistopoihtiko tou)
                            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
                            keyPairGenerator.initialize(2048, new SecureRandom());
                            KeyPair keyPair1 = keyPairGenerator.generateKeyPair();
                            

                            //Akolouthei h diadikasia CSR tou aithmatos gia upografh  apo to user sthn efarmogh
                            // h efarmogh afou eksetasei to aithma tha upograpsei me to private key ths
                            PKCS10CertificationRequestBuilder builder1 = new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=User V3 Certificate"), keyPair1.getPublic());

                            JcaContentSignerBuilder signerbuilder2 = new JcaContentSignerBuilder("SHA1withRSA");

                            ContentSigner signer = signerbuilder2.build(keyPair1.getPrivate());

                            org.bouncycastle.pkcs.PKCS10CertificationRequest csr = builder1.build(signer);

                            CSRrequest requestCSR = new CSRrequest(csr, keyPair1);

                            System.out.println("USERS CSR REQUEST \n ");
                            
                            System.out.println(csr);
                            
                            //dhmiourgia Certificate tou xrhsth me vash to aithma pou prohghthike
                            DhmiourgiaX509 UserCert = new DhmiourgiaX509("version3",CAcert, requestCSR);

                            System.out.println(" Users Certificate \n ");
                            System.out.println(UserCert);
                            
                            //dhmiourgia user tha kratame sto antikeimeno tupou user oles tis plhrofories ektos apo to password
                         
                            User userRoot = new User(UsernameText.getText(), SurnameText.getText(), EmailText.getText(), UsernameText.getText());

                            
                            String skey = generateStrongPasswordHash(new String(PassField.getPassword()),UsernameText.getText());
                            String authHash = generateStrongPasswordHash2(skey, new String(PassField.getPassword()));

                            System.out.println("Dhmiourgia SKEY \n");
                            System.out.println(skey);
                            
                            System.out.println("Dhmiourgia authHash \n");
                            System.out.println(authHash);
                            
                            
                            //setarw to authHash ston user
                            userRoot.setAuthHash(authHash);
                            
                            
                            //Apothikeuw ton user se ena arxeio xrhstwn
                            //epeidh Den einai o prwtos xrhsths pou exei mpei sto file xrhsimopoiw thn klash pou exw dhmiourghsei wste
                            //na kleithei h reset kai na  mhn exw provlhma me to prwto antikeimeno
                            
                            HelpObjectOutputStream oos2 = new HelpObjectOutputStream(new FileOutputStream(UsersFile, true));
                        
                            oos2.writeObject(userRoot);
                            oos2.flush();
                            oos2.close();
                            
                            
                            String usernam = UsernameText.getText();
                            String finalName = usernam + ".cer";
                            
                            
                            //kanw export ta kleidia tou xrhsth
                            File UsersKeys = new File("Users\\UsersKeys" + usernam+".txt");
                            FileOutputStream sf = new FileOutputStream(UsersKeys);
                            ObjectOutputStream of = new ObjectOutputStream(sf);

                            of.writeObject(keyPair1.getPublic().toString() + "\n");
                            of.flush();

                            of.writeObject(keyPair1.getPrivate().toString() + "\n");
                            of.flush();

                            of.close();


                            
                            File file2 = new File("Users\\X509Certificates\\" + finalName);

                            FileOutputStream fout = new FileOutputStream(file2);
                            ObjectOutputStream oos3 = new ObjectOutputStream(fout);
                            oos3.writeObject(UserCert);
                            oos3.flush();
                            oos3.close();
                            
                            
                            File theDir = new File("Application\\" + usernam);

                            // if the directory does not exist, create it
                            if (!theDir.exists()) 
                            {
                                System.out.println("creating directory: " + theDir.getName());
                                boolean result = false;

                                try {
                                    theDir.mkdir();
                                    result = true;
                                } catch (SecurityException se) {
                                    //handle it
                                }
                                if (result) {
                                    System.out.println("DIR created");
                                }
                            }
                            
                        }
                       dispose(); 
                        
                        
                    }
                    else //an o fakelos den uparxei tote tha proxwraei h diadikasia gia ton prwto xrhsth tou susthmatos mas
                    {

                        //dhmiourgia pistopoihtikou efarmoghs CA
                        DhmiourgiaX509 CAcert = new DhmiourgiaX509(1);

                        // dhmiourgia  key pair gia ton user (gia to pistopoihtiko tou)
                        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
                        keyPairGenerator.initialize(2048, new SecureRandom());
                        KeyPair keyPair1 = keyPairGenerator.generateKeyPair();
                        
                        

                        //Akolouthei h diadikasia CSR tou aithmatos gia upografh  apo to user sthn efarmogh
                        // h efarmogh afou eksetasei to aithma tha upograpsei me to private key ths
                        PKCS10CertificationRequestBuilder builder1 = new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=User V3 Certificate"), keyPair1.getPublic());

                        JcaContentSignerBuilder signerbuilder2 = new JcaContentSignerBuilder("SHA1withRSA");

                        ContentSigner signer = signerbuilder2.build(keyPair1.getPrivate());

                        org.bouncycastle.pkcs.PKCS10CertificationRequest csr = builder1.build(signer);

                        CSRrequest requestCSR = new CSRrequest(csr, keyPair1);

                        System.out.println(" USERS CSR REQUEST CREATED ");
                        
                        //dhmiourgia Certificate tou xrhsth me vash to aithma pou prohghthike
                        DhmiourgiaX509 UserCert = new DhmiourgiaX509("version3", CAcert, requestCSR);

                        System.out.println("Users Certificate Created");
                        
                        
                        //dhmiourgia user tha kratame sto antikeimeno tupou user oles tis plhrofories ektos apo to password
                        User userRoot = new User(UsernameText.getText(), SurnameText.getText(), EmailText.getText(), UsernameText.getText());

                        String skey = generateStrongPasswordHash(new String(PassField.getPassword()), UsernameText.getText());
                        
                        String authHash = generateStrongPasswordHash2(skey, new String(PassField.getPassword()));

                        
                        System.out.println("Dhmiourgia SKEY \n");
                        System.out.println(skey);
                        System.out.println("Dhmiourgia authHash \n");
                        System.out.println(authHash);
                        
                        
                        //setarw to authHash ston user
                        userRoot.setAuthHash(authHash);

                        
                        //Diadikasia dhmiourgias fakelou o opoios tha periexei ta pistopoihtika olwn twn xrhstwn gia authentication
                        File usr = new File("Users");
                        if (!usr.exists()) {

                            if (usr.mkdir()) {

                                System.out.println("Directory is created!");
                            } else {
                                System.out.println("Failed to create directory!");
                            }
                        }

                        File file = new File("Users\\X509Certificates");
                        if (!file.exists()) {

                            if (file.mkdir()) {

                                System.out.println("Directory is created! \n");
                            } else {
                                System.out.println("Failed to create directory! \n");
                            }
                        }
                        
                        //vazw to xrhsth sto file xrhstwn pou tous krataw olous
                        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(UsersFile));

                        oos.writeObject(userRoot);
                        oos.flush();
                        oos.close();

                        
                       
                        
                        
                        
                        //gia na dwsw to katallhlo onoma sto pistopoithko tou xrhsth
                        String usernam = UsernameText.getText();
                        String finalName = usernam + ".cer";
                        
                        
                        //kanw export ta kleidia tou xrhsth
                        File UsersKeys=new File("Users\\UsersKeys"+usernam+".txt");
                        FileOutputStream sf=new FileOutputStream(UsersKeys);
                        ObjectOutputStream of=new ObjectOutputStream(sf);
                        
                        of.writeObject(keyPair1.getPublic().toString()+"\n");
                        of.flush();
                        
                        of.writeObject(keyPair1.getPrivate().toString()+"\n");
                        of.flush();
                        
                        of.close();
                        
                        

                        File file2 = new File("Users\\X509Certificates\\" + finalName);

                        FileOutputStream fout = new FileOutputStream(file2);
                        ObjectOutputStream oos3 = new ObjectOutputStream(fout);
                        
                        
                        String password = "password";
                        char[] pass = password.toCharArray();

                        X509Certificate[] chain = new X509Certificate[1];
                        chain[0] = UserCert.getCert();

                        KeyStore keyStore = KeyStore.getInstance("BKS", "BC");

                        
                        FileInputStream fin=null;
                        keyStore.load(fin, "password".toCharArray());

                        Key prkey = keyPair1.getPrivate();

                        //apothikeuw to private key
                        //kai to certificate(to opoio exw valei ston pinaka chain)
                        
                        
//                        keyStore.setKeyEntry("apo", prkey, "password".toCharArray(), chain);
//
//                        keyStore.store(oos3, "password".toCharArray());

                        oos3.flush();
                        oos3.close();

                        //dhmiourgia tou fakelou tou xrhsth sthn efarmogh
                        File theDir = new File("Application\\" + usernam);

                            // if the directory does not exist, create it
                            if (!theDir.exists()) 
                            {
                                System.out.println("creating directory: " + theDir.getName()+"\n");
                                boolean result = false;

                                try {
                                    theDir.mkdir();
                                    repaint();
                                    result = true;
                                } catch (SecurityException se) {
                                    //handle it
                                }
                                if (result) {
                                    System.out.println("DIR created \n");
                                }
                            }
                            dispose();
                    }
                    
                    
                } catch (FileNotFoundException ex) {
                    Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchProviderException ex) {
                    Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
                } catch (OperatorCreationException ex) {
                    Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidKeySpecException ex) {
                    Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
                } catch (KeyStoreException ex) {
                    Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
                }catch (CertificateException ex) {
                    Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
                }
//
//                    File userfile = new File(usernam + "keystore.bks");
//
//                    FileOutputStream os = new FileOutputStream(file);
//
//                    KeyStore keyStore = KeyStore.getInstance("RSAkey");
//                    InputStream is = null;
//                    keyStore.load(is, "password".toCharArray());
//
//                    String password = "password";
//                    char[] pass = password.toCharArray();
//
//                    Key prkey = keyPair1.getPrivate();
//                    Key pbkey = keyPair1.getPublic();
//
//                    keyStore.setKeyEntry("rsakey", pbkey.getEncoded(), null);
//                    keyStore.setKeyEntry("rsakey", prkey.getEncoded(), null);
//                    keyStore.store(os, "password".toCharArray());
//                    os.close();
//                    System.out.println(file.toString());
                
                  
             

//
//                    File userfile = new File(usernam + "keystore.bks");
//
//                    FileOutputStream os = new FileOutputStream(file);
//
//                    KeyStore keyStore = KeyStore.getInstance("RSAkey");
//                    InputStream is = null;
//                    keyStore.load(is, "password".toCharArray());
//
//                    String password = "password";
//                    char[] pass = password.toCharArray();
//
//                    Key prkey = keyPair1.getPrivate();
//                    Key pbkey = keyPair1.getPublic();
//
//                    keyStore.setKeyEntry("rsakey", pbkey.getEncoded(), null);
//                    keyStore.setKeyEntry("rsakey", prkey.getEncoded(), null);
//                    keyStore.store(os, "password".toCharArray());
//                    os.close();
//                    System.out.println(file.toString());

                

            }
        }
     );

   }

    //Methodos pou pernei ws parametro to Password kai to Username kai dhmiourgei to SKEY
    private static String generateStrongPasswordHash(String password, String username) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //   int iterations = 1000;
        int iterations = 2000;

        char[] chars = password.toCharArray();
        //byte[] salt = getSalt();
        byte[] salt = username.getBytes();
        String onoma;

        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64);

        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return toHex(hash);
    }

    //Methodos pou pernei ws parametro to SKEY kai to Password kai dhmiourgei to authHash
    private static String generateStrongPasswordHash2(String SKEY, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        int iterations = 1000;

        char[] chars = SKEY.toCharArray();
        //byte[] salt = getSalt();
        byte[] salt = password.getBytes();
        String onoma;

        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64);

        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return toHex(hash);
    }

    //Methodos pou metatrepei to kleidi se string wste na mas  vohthisei stous elegxous
    private static String toHex(byte[] array) throws NoSuchAlgorithmException {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }
    
    
    private static boolean CheckUniqueUsername(String username)
    {
        boolean flag=false;
        
        try
        {
            
        
        
        //Elegxos gia to username tou xrhsth wste na einai monadiko 
                    File checkFile=new File("Users\\Xristes.txt");
                            
                    ObjectInputStream stream0=new ObjectInputStream(new FileInputStream(checkFile));
                    
                    
                    User TestUser=null;
                   
                    
                    while (!stream0.equals(null))
                    {
                       TestUser=(User)stream0.readObject();
                     
                       
                        if (TestUser.getUsername().equalsIgnoreCase(username))
                        {
                            
                            flag=true;
                            stream0.close();
                            break;
                        }
                       
                       
                        
                    }
                    stream0.close();
                    
             System.out.println("return "+flag);       
        return flag;
            
      } catch (FileNotFoundException ex) {
            Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            System.out.println("Registration completed");            
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(Register.class.getName()).log(Level.SEVERE, null, ex);
        }

        return flag;
    }
    
    
}
