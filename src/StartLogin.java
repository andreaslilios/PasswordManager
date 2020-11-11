import org.bouncycastle.jcajce.provider.keystore.bc.BcKeyStoreSpi;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.image.BufferedImage;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.imageio.ImageIO;
import javax.swing.*;
import static javax.swing.JFrame.EXIT_ON_CLOSE;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemReader;

public class StartLogin {

    private X509Certificate cer;
    private String root;
    private static String skey1;
    private static int count=0;
    private static int timeDelay=0;
    
    public StartLogin() {
        JFrame frame1 = new JFrame("Password Manager");

        frame1.setVisible(true);

        GridLayout g2 = new GridLayout(1, 2);

        frame1.setLayout(g2);

        frame1.setDefaultCloseOperation(EXIT_ON_CLOSE);

        JPanel panel1 = new JPanel();
        panel1.setLayout(null);

        panel1.setBackground(Color.WHITE);

        //taktopoiw ta components sto panel1
        JLabel label = new JLabel("<HTML><B><U>LOGIN</U></B></HTML>");
        label.setFont(new Font("Serif", Font.PLAIN, 20));
        label.setBounds(160, 10, 400, 50);

        JLabel UsernameLabel = new JLabel("Username: ");
        UsernameLabel.setBounds(30, 70, 200, 30);

        JTextField text1 = new JTextField();
        text1.setBounds(100, 70, 200, 30);

        JLabel PassLabel = new JLabel("Password: ");
        PassLabel.setBounds(30, 110, 200, 30);

        JPasswordField text2 = new JPasswordField();
        text2.setBounds(100, 110, 200, 30);

        JButton LoginButton = new JButton("Login");
        LoginButton.setBounds(150, 190, 100, 30);

        JLabel registration = new JLabel("For registration click here: ");
        registration.setBounds(10, 270, 200, 30);

        JButton RegButton = new JButton("Register");
        RegButton.setBounds(180, 270, 100, 30);

        JLabel choosFile = new JLabel("Upload certicate: ");
        choosFile.setBounds(10, 150, 200, 30);
        JButton UpButton = new JButton("Choose File");
        UpButton.setBounds(150, 150, 100, 30);

        JTextField Uptext = new JTextField();
        Uptext.setBounds(80, 75, 205, 35);

        panel1.add(label);
        panel1.add(UsernameLabel);
        panel1.add(text1);
        panel1.add(PassLabel);
        panel1.add(text2);

        panel1.add(LoginButton);

        panel1.add(LoginButton);

        panel1.add(registration);
        panel1.add(RegButton);
        panel1.add(UpButton);
        panel1.add(choosFile);

        //dhmiourgia 2ou panell
        JPanel p2 = new JPanel();

        ImageIcon image = new ImageIcon("hackers_security_password-100004008-orig.jpg");

        JLabel l1 = new JLabel(image);

        p2.add(l1);

        frame1.add(panel1);
        frame1.add(p2);

        //dinw tis teleutaies ruthmiseis sto frame
        frame1.setSize(800, 350);
        frame1.setLocationRelativeTo(null);
        
        UpButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {

               

                try
                {    
                
                    JFileChooser chooser = new JFileChooser();
                    chooser.showOpenDialog(null);
                    File f = chooser.getSelectedFile();
                    
                    FileInputStream fis = new FileInputStream(f);
                    ObjectInputStream oo = new ObjectInputStream(fis);

                    CertificateFactory cf = CertificateFactory.getInstance("X.509");

                    System.out.println("---");

                    X509Certificate x509 = null;
                    
                    while (oo.available()>0) {
                    // x509 = (X509Certificate) cf.generateCertificate(oo);
               
                    }

                     System.out.println(x509);
                  
                    cer=x509;
                    
                    
                  
                   
                
                   
                    
               

                }catch (FileNotFoundException ex) {
                    Logger.getLogger(StartLogin.class.getName()).log(Level.SEVERE, null, ex);
                } catch (CertificateException ex) {
                    Logger.getLogger(StartLogin.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(StartLogin.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });

        RegButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Register a = new Register();
            }
        });

        LoginButton.addActionListener(new ActionListener() {
            
                   
            public void actionPerformed(ActionEvent e) 
            {
                
               try {
                    
                    // pernw apo ta grafika ta stoixeia tou xrhsth username kai password kai dhmiourgw Skey kai auth hash me th xrhsh
                    //twn methodwn pou exoume dhmiourghsei
                    String MasterPassword = new String(text2.getPassword());
                    String username = text1.getText();
                    

                    String skey = generateStrongPasswordHash(MasterPassword, username);
                    String authHash = generateStrongPasswordHash2(skey, MasterPassword);
                    
                    
                   System.out.println("Dhmiourgia SKEY \n");
                   System.out.println(skey);
                   System.out.println("Dhmiourgia authHash \n");
                   System.out.println(authHash);

                    //ta xreiazomai wste na dwthoun ws parametroi gia thn dhmiourgia ths MainPage tou kathe xrhsth
                    root=username;
                    skey1=skey;
                                     

                    boolean checkHashAndName = AuthenticationHashAndLogin(authHash, username);
                    
                    //tha parw apo to keystore to pistopoihtiko ths CA wste na mporw na kanw verify toy xrhsth
                               
                        
//                   KeyStore keyStore = KeyStore.getInstance("BKS","BC");
//                   keyStore.load(new FileInputStream("Application\\CA_keystore.bks"), "password".toCharArray());
//
//                   String apo="apo";
//                   X509Certificate[] certChain = (X509Certificate[]) keyStore.getCertificateChain(apo);
//                   X509Certificate CAcert=certChain[0];                   
                    
                    //boolean checkCert = AuthenticationCert(cer,username,CAcert);
                    
                    boolean checkCert=true;
                    
                    //An enas apo tous duo elegxous eite tou certificate eite tou LoginName kai Hash einai false tote: 

                    if (checkCert == false || checkHashAndName==false) 
                    {
                        ImageIcon icon = new ImageIcon("STOPentry.jpeg");
                        JOptionPane.showMessageDialog(null, "Δοκιμάστε ξανά Λαθος κωδικός ή username!", "Failed Login",1,icon);

                        //elegxw ta attempts pou ginontai an enas xrhsths kanei 10 to programma kleinei
                        count++;

                        if (count > 10) {
                            System.exit(0);
                        }
                        
                        
                      //Otan pragmatopoieitai apotyxhmeno login tha uparxei xronokathysterhsh
                
                       TimeUnit.SECONDS.sleep(timeDelay);
                       
                       timeDelay=timeDelay+2;
                        
                    }
                    else if(checkHashAndName == true && checkCert == true)
                    {
                        MainPage p1 = new MainPage(root,skey1);
                        frame1.dispose();
                                
                    }
  
               
                       
                       
                
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(StartLogin.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidKeySpecException ex) {
                    Logger.getLogger(StartLogin.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InterruptedException ex) {
                    Logger.getLogger(StartLogin.class.getName()).log(Level.SEVERE, null, ex);
                }
                
            }
        });

    }

    private static String generateStrongPasswordHash(String password, String username) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //   int iterations = 1000;
        int iterations = 2000;

        char[] chars = password.toCharArray();
        //byte[] salt = getSalt();
        byte[] salt = username.getBytes();
        String onoma;

//        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64 * 8);
        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64);

        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return toHex(hash);
    }

    private static String generateStrongPasswordHash2(String password, String username) throws NoSuchAlgorithmException, InvalidKeySpecException {
        int iterations = 1000;
        //  int iterations = 2000;

        char[] chars = password.toCharArray();
        //byte[] salt = getSalt();
        byte[] salt = username.getBytes();
        String onoma;

//        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64 * 8);
        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64);

        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return toHex(hash);
    }

    private static byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

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

    private static boolean validatePassword(String originalPassword, String storedPassword) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String[] parts = storedPassword.split(":");
        int iterations = Integer.parseInt(parts[0]);
        byte[] salt = fromHex(parts[1]);
        //byte[] salt = fromHex(username);
        byte[] hash = fromHex(parts[2]);

//   PBEKeySpec spec = new PBEKeySpec(originalPassword.toCharArray(), salt, iterations, hash.length * 8);
        PBEKeySpec spec = new PBEKeySpec(originalPassword.toCharArray(), salt, iterations, hash.length * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] testHash = skf.generateSecret(spec).getEncoded();

        int diff = hash.length ^ testHash.length;
        for (int i = 0; i < hash.length && i < testHash.length; i++) {
            diff |= hash[i] ^ testHash[i];
        }
        return diff == 0;
    }

    private static byte[] fromHex(String hex) throws NoSuchAlgorithmException {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;

    }

    //tha dexetai username kai authHash kai tha elegxei an uparxoun sto authentication file dhladh sto arxeio users pou exoume
    private static boolean AuthenticationHashAndLogin(String LoginAuthHash, String LoginUsername)
    {
            
        boolean result = false;

        //trexw to arxeio kai kanw elegxous an uparxei se kapoio antikeimeno user idio authHash kai username me auta pou edwse o xrhsths
        try {

            //ksekinaw ton prwto elegxo gia username kai authHash
            File UsersFile = new File("Users\\Xristes.txt");

            ObjectInputStream in1 = new ObjectInputStream(new FileInputStream(UsersFile));

            User tempUser = null;

            while (!in1.equals(null)) 
            {
                
                tempUser = (User) in1.readObject();
                   
                if (tempUser.getAuthHash().equalsIgnoreCase(LoginAuthHash) && (tempUser.getUsername().equalsIgnoreCase(LoginUsername))) 
                {
                   
                    
                    result=true;
                    break;
                }
            }

            //kleinw tis roes tou arxeiou Users
            in1.close();
         
         
          return result;  
          
        } catch (IOException ex) {
            System.out.println("Failed Login Attempt");
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(StartLogin.class.getName()).log(Level.SEVERE, null, ex);
        }  
        
        return result;
    }
    
    
    private static boolean AuthenticationCert(X509Certificate LoginCert, String LoginUsername,X509Certificate CAcert) {
        //ksekinaw ton deutero elegxo gia to pistopoihtiko

        boolean result=false;
        
        String finalName = LoginUsername + ".cer";
        File CertificatesFile = new File("Users\\X509Certificates\\" + finalName);

        try {

            FileInputStream stream = new FileInputStream(CertificatesFile);

            ObjectInputStream in2 = new ObjectInputStream(stream);

            DhmiourgiaX509 tempCert = null;

            while (!in2.equals(null)) 
            {

                tempCert = (DhmiourgiaX509) in2.readObject();

                tempCert.getCert().checkValidity();

                tempCert.getCert().verify(CAcert.getPublicKey());
                
            }

            in2.close();

           

            System.out.println(result);
            
            return result;
            
        } catch (CertificateException ex) {
            Logger.getLogger(StartLogin.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(StartLogin.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(StartLogin.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(StartLogin.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(StartLogin.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(StartLogin.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(StartLogin.class.getName()).log(Level.SEVERE, null, ex);
        }

        return result;
    }
         

       
}


