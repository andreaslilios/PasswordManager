

import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.List;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OptionalDataException;
import java.security.Key;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import static javax.swing.JFrame.EXIT_ON_CLOSE;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import static javax.swing.WindowConstants.DISPOSE_ON_CLOSE;
import static jdk.nashorn.internal.parser.TokenType.EOF;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class MainPage extends JFrame {

    private String username1;     //το username
    private String skey1;        //και το συμμετρικο κλειδι που υπολογίζω στην StartLogin
    private String domain2;     //Εδω τα 4 
    private String username2;  //χαρακτηριστικα της καθε
    private String password2; //εγγραφης στο 
    private String comment2; //αρχειο του καθε χρηστη
    private ArrayList<Entries> list = new ArrayList<Entries>(); // αποθηκευω τις εγγραφες στο αρχειο ως αντικειμενα Entries  
    private ArrayList<Entries> listb = new ArrayList<Entries>();// και τις επεξεργαζομαι μεσω αυτων των λιστων
    private ArrayList<String> encryptedText = new ArrayList<String>();//επιλεγω να κρυπτογραφησω-αποκρυπτογραφησω στις εγγραφες
    private ArrayList<String> decryptedText = new ArrayList<String>();//ενα-ενα τα χαρακτηριστικα τους μεσω λιστων
    //Με λιγα λογια, οι list,listb περιεχουν τις εγγραφες του αρχειου ως αντικειμενα 
    // και οι encryptedText,decryptedText τα πεδια τους 

    public MainPage(String username1, String skey1) {

        this.username1 = username1;
        this.skey1 = skey1;
        // Εδω αποθηκευεται το εκαστοτε directory 
        File file = new File("Application\\" + username1 + "\\Entries.txt");

        setTitle("Password Manager");
        JPanel panel1;
        JPanel panel2;

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setVisible(true);
        GridLayout grid = new GridLayout(1, 2);

        panel1 = new JPanel();
        panel1.setLayout(null);
        panel2 = new JPanel();
        //Τα κουμπια για τις 4 λειτουργιες
        JButton neosKwdikos = new JButton("New Code");
        JButton CryptDecrypt = new JButton("Encryption/Decryption");
        JButton tropopoihsh = new JButton("Modify Code");
        JButton diagrafi = new JButton("Delete Code");

        ImageIcon image = new ImageIcon("pm.png");
        JLabel fwto = new JLabel(image);
        JLabel sxolia = new JLabel("<HTML><B>Choose the sevrice you want</B></HTML>");
        sxolia.setFont(new Font("serif", Font.PLAIN, 20));

        JLabel welcome = new JLabel("<HTML><B>Welcome " + username1 + ",</B></HTML>");
        JButton logout = new JButton("Log Out");
        logout.setBounds(10, 370, 80, 25);
        welcome.setBounds(10, 5, 200, 15);
        sxolia.setBounds(120, 40, 400, 30);
        neosKwdikos.setBounds(125, 100, 230, 30);
        CryptDecrypt.setBounds(125, 150, 230, 30);
        tropopoihsh.setBounds(125, 200, 230, 30);
        diagrafi.setBounds(125, 250, 230, 30);

        panel1.add(welcome);
        panel1.add(sxolia);
        panel1.add(neosKwdikos);
        panel1.add(CryptDecrypt);
        panel1.add(tropopoihsh);
        panel1.add(diagrafi);
        panel1.add(logout);
        panel2.add(fwto);
        setLayout(grid);
        add(panel1);
        add(panel2);
        setSize(1000, 450);
        setLocationRelativeTo(null);
// 1η λειτουργια : ΕΙΣΑΓΩΓΗ ΚΩΔΙΚΟΥ 
        neosKwdikos.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent e) {

                JFrame frame1 = new JFrame("Password Manager");
                frame1.setVisible(true);
                GridLayout g2 = new GridLayout(1, 2);
                frame1.setLayout(g2);
                frame1.setDefaultCloseOperation(DISPOSE_ON_CLOSE);
                JPanel panel1;
                JPanel panel2;
                panel1 = new JPanel();
                panel1.setLayout(null);
                panel2 = new JPanel();
                JLabel domain = new JLabel("Domain");
                domain.setBounds(10, 70, 100, 30);
                JTextField dmn = new JTextField();
                dmn.setBounds(10, 100, 100, 30);
                JLabel username = new JLabel("Username");
                username.setBounds(160, 70, 100, 30);
                JTextField usrnm = new JTextField();
                usrnm.setBounds(160, 100, 100, 30);
                JLabel password = new JLabel("Password");
                password.setBounds(310, 70, 100, 30);
                JTextField passwd = new JTextField();
                passwd.setBounds(310, 100, 100, 30);
                JLabel comment = new JLabel("Comment");
                comment.setBounds(460, 70, 100, 30);
                JTextField cmmnt = new JTextField();
                cmmnt.setBounds(460, 100, 100, 30);
                JButton ok = new JButton("Commit entry");
                ok.setBounds(210, 180, 150, 35);

                panel1.add(domain);
                panel1.add(dmn);
                panel1.add(username);
                panel1.add(usrnm);
                panel1.add(password);
                panel1.add(passwd);
                panel1.add(comment);
                panel1.add(cmmnt);
                panel1.add(ok);
                frame1.add(panel1);
                frame1.setSize(590, 300);
                frame1.setLocationRelativeTo(null);

                ok.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {

                        frame1.dispose();
                        String domain2 = dmn.getText();
                        System.out.println(domain2);
                        String username2 = usrnm.getText();
                        String password2 = passwd.getText();
                        String comment2 = cmmnt.getText();

                        ObjectOutputStream out = null;
                        FileOutputStream out2;

                        try {

                            // ελεγχος εγκυροτητας για το αν υπαρχει directory χρηστη
                            if (file.exists()) {
                                HelpObjectOutputStream out3 = new HelpObjectOutputStream(new FileOutputStream(file, true));
                                // κρυπτογραφω 1-1 τα πεδια της εγγραφης
                                encryptedText.add(encrypt(domain2, skey1));
                                encryptedText.add(encrypt(username2, skey1));
                                encryptedText.add(encrypt(password2, skey1));
                                encryptedText.add(encrypt(comment2, skey1));
                                //τα τοποθετω σε αντικειμενο
                                Entries a = new Entries(encryptedText.get(0), encryptedText.get(1), encryptedText.get(2), encryptedText.get(3));
                                // γραφω αρχειο αντικειμενων (περναω 1-1 τις εγγραφες)
                                out3.writeObject(a);
                                out3.flush();
                                out3.close();
                                //αδειαζω την λιστα σε περιπτωση κρατησης στοιχειων του χρηστη
                                encryptedText.clear();
                                JFrame frame = new JFrame("JOptionPane showMessageDialog example");
                                JOptionPane.showMessageDialog(frame, "Insert Succesfull!", "New Code", JOptionPane.INFORMATION_MESSAGE);

                            } else {
                                File file = new File("Application\\" + username1 + "\\Entries.txt");
                                out2 = new FileOutputStream(file);
                                out = new ObjectOutputStream(out2);
                                encryptedText.add(encrypt(domain2, skey1));
                                encryptedText.add(encrypt(username2, skey1));
                                encryptedText.add(encrypt(password2, skey1));
                                encryptedText.add(encrypt(comment2, skey1));
                                Entries a = new Entries(encryptedText.get(0), encryptedText.get(1), encryptedText.get(2), encryptedText.get(3));
                                out.writeObject(a);
                                out.flush();
                                out.close();
                                encryptedText.clear();
                                JFrame frame = new JFrame("JOptionPane showMessageDialog example");
                                JOptionPane.showMessageDialog(frame, "Insert Succesfull!", "New Code", JOptionPane.INFORMATION_MESSAGE);
                            }

                        } catch (IOException ex) {
                            Logger.getLogger(MainPage.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (Exception ex) {
                            Logger.getLogger(MainPage.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }

                });

            }
        });
// 2η λειτουργια : ΔΙΑΓΡΑΦΗ ΚΩΔΙΚΟΥ-ΕΓΓΡΑΦΗΣ
        diagrafi.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {

                JFrame frame2 = new JFrame("Delete Password");
                frame2.setVisible(true);

                setLayout(new FlowLayout());

                JPanel panel = new JPanel();
                panel.setLayout(null);
                JLabel domainLabel = new JLabel("Give the domain of your password");
                JTextField domainField = new JTextField();
                JButton domainButton = new JButton("OK");
                domainLabel.setBounds(150, 20, 200, 60);
                domainField.setBounds(170, 80, 150, 30);
                domainButton.setBounds(190, 130, 100, 30);
                panel.add(domainLabel);
                panel.add(domainField);
                panel.add(domainButton);
                frame2.add(panel);
                frame2.setSize(500, 300);
                frame2.setLocationRelativeTo(null);
                domainButton.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {

                        frame2.dispose();
                        try {
                            //καθε φορα αδειαζω τις λιστες για πιθανη κρατηση στοιχειων απο προηγουμενη λειτουργια
                            list.clear();
                            listb.clear();
                            //πεδιο εισαγωγης κριτηριου για διαγραφη εγγραφης-κωδικου
                            String domainDelete = domainField.getText();
                            FileInputStream fis = new FileInputStream("Application\\" + username1 + "\\Entries.txt");
                            ObjectInputStream ois = null;

                            if (fis.available() != 0) {
                                ois = new ObjectInputStream(fis);
                            }
                            Entries a = null;
                            //ανοιγω το αρχειο για να διαβασω τις εγγραφες
                            while (ois != null && fis.available() != 0) {
                                //τις αποθηκευω ξανα σε αντικειμενο 1-1 και μετα σε λιστα, για επεξεργασια                                
                                a = (Entries) ois.readObject();
                                list.add(a);
                            }
                            ois.close();
                            //διαγραφω τον directory αφου θα υποστει επεξεργασια και το ξαναφτιαχνω μετα,με νεα δεδομενα
                            file.delete();
                            for (int i = 0; i < list.size(); i++) {
                                try {
                                    //αφου πηρα τις εγγραφες,τις αποκρυπτογραφω για να βρω ποια χρειαζεται επεξεργασια
                                    //1-1 τα πεδια, τα αποθηκευω σε αντικειμενο και τα προσθετω σε λιστα
                                    decryptedText.add(decrypt(list.get(i).getDomain(), skey1));
                                    decryptedText.add(decrypt(list.get(i).getUsername(), skey1));
                                    decryptedText.add(decrypt(list.get(i).getPassword(), skey1));
                                    decryptedText.add(decrypt(list.get(i).getComment(), skey1));
                                    Entries b = new Entries(decryptedText.get(0), decryptedText.get(1), decryptedText.get(2), decryptedText.get(3));
                                    listb.add(b);
                                    decryptedText.clear();
                                } catch (Exception ex) {
                                    Logger.getLogger(MainPage.class.getName()).log(Level.SEVERE, null, ex);
                                }

                            }
                            //Διαγραφη καταλληλης εγγραφης:συγκρινοντας βασει κριτηριου
                            for (int i = 0; i < listb.size(); i++) {
                                if (listb.get(i).getDomain().equals(domainDelete)) {
                                     JFrame frame = new JFrame("JOptionPane showMessageDialog example");
                                    JOptionPane.showMessageDialog(frame, "Delete Succesfull!", "Delete Code", JOptionPane.INFORMATION_MESSAGE);
                                    listb.remove(i);
                                }
                                else{
                                    //JFrame frame = new JFrame("JOptionPane showMessageDialog example");
                                    JOptionPane.showMessageDialog(null, "Wrong Domain!", "Delete Code", JOptionPane.INFORMATION_MESSAGE);
                                    
                                }
                            }
                            // η listb πλεον, ειναι το νεο περιεχομενο του directory
                            ObjectOutputStream out = null;
                            FileOutputStream out2;

                            try {
                                if (file.exists()) {
                                    HelpObjectOutputStream out3 = new HelpObjectOutputStream(new FileOutputStream(file, true));
                                    list.clear();
                                    // περναω 1-1 τις εγγραφες στο αρχειο, αφου τις κρυπτογραφησω ξανα
                                    //οπως νωριτερα
                                    for (int i = 0; i < listb.size(); i++) {
                                        encryptedText.add(encrypt(listb.get(i).getDomain(), skey1));
                                        encryptedText.add(encrypt(listb.get(i).getUsername(), skey1));
                                        encryptedText.add(encrypt(listb.get(i).getPassword(), skey1));
                                        encryptedText.add(encrypt(listb.get(i).getComment(), skey1));
                                        Entries c = new Entries(encryptedText.get(0), encryptedText.get(1), encryptedText.get(2), encryptedText.get(3));
                                        list.add(c);
                                        encryptedText.clear();
                                    }
                                    for (int i = 0; i < list.size(); i++) {
                                        out3.writeObject(list.get(i));
                                        out3.flush();
                                    }
                                    out3.close();
                                   

                                } else {
                                    File file = new File("Application\\" + username1 + "\\Entries.txt");
                                    out2 = new FileOutputStream(file);
                                    out = new ObjectOutputStream(out2);
                                    list.clear();
                                    for (int i = 0; i < listb.size(); i++) {
                                        encryptedText.add(encrypt(listb.get(i).getDomain(), skey1));
                                        encryptedText.add(encrypt(listb.get(i).getUsername(), skey1));
                                        encryptedText.add(encrypt(listb.get(i).getPassword(), skey1));
                                        encryptedText.add(encrypt(listb.get(i).getComment(), skey1));
                                        Entries c = new Entries(encryptedText.get(0), encryptedText.get(1), encryptedText.get(2), encryptedText.get(3));
                                        list.add(c);
                                        encryptedText.clear();
                                    }
                                    for (int i = 0; i < list.size(); i++) {
                                        out.writeObject(list.get(i));
                                        out.flush();
                                    }
                                    out.close();
                                    JFrame frame = new JFrame("JOptionPane showMessageDialog example");
                                    JOptionPane.showMessageDialog(frame, "Delete Succesfull!", "Delete Code", JOptionPane.INFORMATION_MESSAGE);
                                }
                            } catch (IOException ex) {
                                System.out.println(" eimai to 1");;
                            } catch (Exception ex) {
                                Logger.getLogger(MainPage.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        } catch (FileNotFoundException ex) {
                            System.out.println(" eimai to 2");
                        } catch (IOException ex) {
                            Logger.getLogger(MainPage.class.getName()).log(Level.SEVERE, null, ex);

                        } catch (ClassNotFoundException ex) {
                            Logger.getLogger(MainPage.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                });
            }
        });
// 3η λειτουργια : ΤΡΟΠΟΠΟΙΗΣΗ ΚΩΔΙΚΟΥ
        tropopoihsh.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {

                JFrame frame2 = new JFrame("Modify Password");
                frame2.setVisible(true);
                setLayout(new FlowLayout());
                JPanel panel = new JPanel();
                panel.setLayout(null);
                JLabel domainLabel = new JLabel("Give the domain of your password");
                JTextField domainField = new JTextField();
                domainLabel.setBounds(150, 20, 200, 60);
                domainField.setBounds(170, 80, 150, 30);
                panel.add(domainLabel);
                panel.add(domainField);

                JLabel codeLabel = new JLabel("Give new password");
                JTextField codeField = new JTextField();
                JButton codeButton = new JButton("OK");
                codeLabel.setBounds(180, 100, 200, 60);
                codeField.setBounds(170, 150, 150, 30);
                codeButton.setBounds(190, 200, 100, 30);
                panel.add(codeLabel);
                panel.add(codeField);
                panel.add(codeButton);
                frame2.add(panel);
                frame2.setSize(500, 300);
                frame2.setLocationRelativeTo(null);
                codeButton.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        frame2.dispose();
                        try {
                            list.clear();
                            listb.clear();
                            // πεδιο1: το κριτηριο
                            // πεδιο2: ο νεος κωδικος της εγγραφης
                            String domainD = domainField.getText();
                            String newcode = codeField.getText();
                            FileInputStream fis = new FileInputStream("Application\\" + username1 + "\\Entries.txt");
                            ObjectInputStream ois = null;

                            if (fis.available() != 0) {
                                ois = new ObjectInputStream(fis);
                            }
                            //διαβαζω ξανα το αρχειο και παιρνω τα αντικειμενα σε μια λιστα αφου θα 
                            //πρεπει να πειραξω παλι το περιεχομενο του directory
                            Entries a = null;
                            while (ois != null && fis.available() != 0) {
                                a = (Entries) ois.readObject();
                                list.add(a);
                            }
                            ois.close();
                            //ξαναδιαγραφω τον φακελο αφου χρειαζεται παλι επεξεργασια περιεχομενου και
                            //το παλιο δεν μου χρειαζεται αφου μολις το πηρα σε λιστα
                            file.delete();
                            for (int i = 0; i < list.size(); i++) {
                                try {
                                    //αποκρυπτογραφω το παλιο περιεχομενο 1-1 πεδια εγγραφης και τα προσθετω
                                    //σε λιστα αντικειμενων
                                    decryptedText.add(decrypt(list.get(i).getDomain(), skey1));
                                    decryptedText.add(decrypt(list.get(i).getUsername(), skey1));
                                    decryptedText.add(decrypt(list.get(i).getPassword(), skey1));
                                    decryptedText.add(decrypt(list.get(i).getComment(), skey1));
                                    Entries b = new Entries(decryptedText.get(0), decryptedText.get(1), decryptedText.get(2), decryptedText.get(3));
                                    listb.add(b);
                                    decryptedText.clear();
                                } catch (Exception ex) {
                                    Logger.getLogger(MainPage.class.getName()).log(Level.SEVERE, null, ex);
                                }

                            }
                            //αλλαγη κωδικου δημιουργωντας νεα εγγραφη με νεο κωδικο
                            //και αφαιρωντας την παλια
                            for (int i = 0; i < listb.size(); i++) {
                                if (listb.get(i).getDomain().equals(domainD)) {
                                    Entries b = new Entries(listb.get(i).getDomain(), listb.get(i).getUsername(), newcode, listb.get(i).getComment());
                                    listb.add(b);
                                    listb.remove(i);
                                    JFrame frame = new JFrame("JOptionPane showMessageDialog example");
                                    JOptionPane.showMessageDialog(frame, "Modification Succesfull!", "Edit Code", JOptionPane.INFORMATION_MESSAGE);
                                }
                                else{
                                    JOptionPane.showMessageDialog(null, "Wrong Domain!", "Edit Code", JOptionPane.INFORMATION_MESSAGE);
                                }
                            }
                            ObjectOutputStream out = null;
                            FileOutputStream out2;
                            try {
                                //ελεγχος για το αν υπαρχει ο εκαστοτε directory
                                if (file.exists()) {
                                    HelpObjectOutputStream out3 = new HelpObjectOutputStream(new FileOutputStream(file, true));
                                    //δεν ξεχναω να ανανεωσω τηνλιστα για τυχον αποθηκευση προηγουμενων δεδομενων
                                    list.clear();
                                    //κρυπτογραφω τις νεες εγγραφες(1-1 τα πεδια)και τις αποθηκευω σε νεα λιστα 
                                    for (int i = 0; i < listb.size(); i++) {
                                        encryptedText.add(encrypt(listb.get(i).getDomain(), skey1));
                                        encryptedText.add(encrypt(listb.get(i).getUsername(), skey1));
                                        encryptedText.add(encrypt(listb.get(i).getPassword(), skey1));
                                        encryptedText.add(encrypt(listb.get(i).getComment(), skey1));
                                        Entries c = new Entries(encryptedText.get(0), encryptedText.get(1), encryptedText.get(2), encryptedText.get(3));
                                        list.add(c);
                                        encryptedText.clear();
                                    }
                                    //περναω τις εγγραφες στο αρχειο
                                    for (int i = 0; i < list.size(); i++) {
                                        out3.writeObject(list.get(i));
                                        out3.flush();
                                    }
                                    out3.close();
                                    

                                } else {
                                    File file = new File("Application\\" + username1 + "\\Entries.txt");
                                    out2 = new FileOutputStream(file);
                                    out = new ObjectOutputStream(out2);
                                    list.clear();
                                    for (int i = 0; i < listb.size(); i++) {
                                        encryptedText.add(encrypt(listb.get(i).getDomain(), skey1));
                                        encryptedText.add(encrypt(listb.get(i).getUsername(), skey1));
                                        encryptedText.add(encrypt(listb.get(i).getPassword(), skey1));
                                        encryptedText.add(encrypt(listb.get(i).getComment(), skey1));
                                        Entries c = new Entries(encryptedText.get(0), encryptedText.get(1), encryptedText.get(2), encryptedText.get(3));
                                        list.add(c);
                                        encryptedText.clear();
                                    }
                                    for (int i = 0; i < list.size(); i++) {
                                        out.writeObject(list.get(i));
                                        out.flush();
                                    }
                                    out.close();
                                    
                                }
                            } catch (IOException ex) {
                                Logger.getLogger(MainPage.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (Exception ex) {
                                Logger.getLogger(MainPage.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        } catch (FileNotFoundException ex) {
                            Logger.getLogger(MainPage.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (IOException ex) {
                            Logger.getLogger(MainPage.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (ClassNotFoundException ex) {
                            Logger.getLogger(MainPage.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                });

            }

        });
        // 4η λειτουργεια : ΚΡΥΠΤΟΓΡΑΦΗΣΗ/ΑΠΟΚΡΥΠΤΟΓΡΑΦΗΣΗ ΕΓΓΡΑΦΗΣ
        CryptDecrypt.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {

                JFrame frame2 = new JFrame("Code Presentation");
                frame2.setVisible(true);
                setLayout(new FlowLayout());
                JPanel panel = new JPanel();
                panel.setLayout(null);
                JLabel domainLabel = new JLabel("Give the domain of the password");
                JTextField domainField = new JTextField();
                JButton domainButton = new JButton("Encrypt/Decrypt");
                domainLabel.setBounds(120, 20, 200, 60);
                domainField.setBounds(140, 80, 150, 30);
                domainButton.setBounds(140, 130, 150, 30);
                panel.add(domainLabel);
                panel.add(domainField);
                panel.add(domainButton);

                frame2.add(panel);
                frame2.setSize(450, 300);
                frame2.setLocationRelativeTo(null);
                domainButton.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        frame2.dispose();
                        try {
                            //κριτηριο για το ποια εγγραφη θελω να εμφανισω
                            String domain = domainField.getText();
                            list.clear();
                            listb.clear();
                            FileInputStream fis = new FileInputStream("Application\\" + username1 + "\\Entries.txt");
                            ObjectInputStream ois = null;
                            if (fis.available() != 0) {
                                ois = new ObjectInputStream(fis);
                            }
                            //διαβαζω το αρχειο και παιρνω το περιεχομενο σε μια λιστα αντικειμενων
                            Entries a = null;
                            while (ois != null && fis.available() != 0) {
                                a = (Entries) ois.readObject();
                                list.add(a);
                                System.out.println(list);
                            }
                            ois.close();
                            //file.delete();
                            //αποκρυπτογραφω τις εγγραφες 
                            for (int i = 0; i < list.size(); i++) {
                                try {
                                    decryptedText.add(decrypt(list.get(i).getDomain(), skey1));
                                    decryptedText.add(decrypt(list.get(i).getUsername(), skey1));
                                    decryptedText.add(decrypt(list.get(i).getPassword(), skey1));
                                    decryptedText.add(decrypt(list.get(i).getComment(), skey1));
                                    Entries b = new Entries(decryptedText.get(0), decryptedText.get(1), decryptedText.get(2), decryptedText.get(3));
                                    listb.add(b);
                                    decryptedText.clear();
                                } catch (Exception ex) {
                                    Logger.getLogger(MainPage.class.getName()).log(Level.SEVERE, null, ex);
                                }
                            }
                            //αφου βρω ποια εγγραφη χρειαζομαι την εμφανιζω
                            for (int i = 0; i < listb.size(); i++) {
                                if (listb.get(i).getDomain().equals(domain)) {
                                    JFrame frame = new JFrame("JOptionPane showMessageDialog example");
                                    JOptionPane.showMessageDialog(frame, listb.get(i) + "'.", "Encrypt/Decrypt", JOptionPane.INFORMATION_MESSAGE);
                                }
                                else{
                                    JFrame frame = new JFrame("JOptionPane showMessageDialog example");
                                    JOptionPane.showMessageDialog(frame,"Wrong Domain!","Encrypt/Decrypt", JOptionPane.INFORMATION_MESSAGE);
                                }
                            }
                        } catch (Exception ex) {
                            Logger.getLogger(MainPage.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                });
            }
        });
        // 5η λειτουργεια : ΑΠΟΣΥΝΔΕΣΗ ΧΡΗΣΤΗ
        logout.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {

                dispose();
                new StartLogin();
            }
        });
    }

    // ΕΔΩ ΚΡΥΠΤΟΓΡΑΦΩ ΤΙΣ ΕΓΓΡΑΦΕΣ ΧΡΗΣΙΜΟΙΩΝΤΑΣ ΤΙΣ ΕΓΓΡΑΦΕΣ, ΤΟ ΣΥΜΜΕΤΡΙΚΟ ΚΛΕΙΔΙ ΠΟΥ ΠΡΟΚΥΠΤΕΙ ΑΠ'ΤΟ LogIn 
    //KAΙ ΤΟΝ ΑΛΓΟΡΙΘΜΟ ΚΡΥΠΤΟΓΡΑΦΗΣΗΣ AES-128 bits
    public static String encrypt(String plainText, String skey) throws Exception {
        String algorithm = "AES";
        Cipher chiper = Cipher.getInstance(algorithm);
        SecretKeySpec aesKey = new SecretKeySpec(skey.getBytes(), "AES");
        chiper.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encVal = chiper.doFinal(plainText.getBytes("UTF-8"));
        String encryptedValue = new BASE64Encoder().encode(encVal);
        return encryptedValue;
    }

    // ΕΔΩ ΑΠΟΚΡΥΠΤΟΓΡΑΦΩ ΤΙΣ ΕΓΓΡΑΦΕΣ ΧΡΗΣΙΜΟΙΩΝΤΑΣ ΤΙΣ ΕΓΓΡΑΦΕΣ(ΣΕ ΚΡΥΠΤΟΓΡΑΦΗΜΕΝΗ ΜΟΡΦΗ), 
    //ΤΟ ΣΥΜΜΕΤΡΙΚΟ ΚΛΕΙΔΙ ΠΟΥ ΠΡΟΚΥΠΤΕΙ ΑΠ'ΤΟ LogIn 
    //KAΙ ΤΟΝ ΑΛΓΟΡΙΘΜΟ ΚΡΥΠΤΟΓΡΑΦΗΣΗΣ AES-128 bits
    public static String decrypt(String encryptedText, String skey) throws Exception {
        String algorithm = "AES";
        Cipher chiper = Cipher.getInstance(algorithm);
        SecretKeySpec aesKey = new SecretKeySpec(skey.getBytes(), "AES");
        chiper.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedText);
        byte[] decValue = chiper.doFinal(decordedValue);
        String decryptedValue = new String(decValue);
        return decryptedValue;
    }
}
