/*

ePassLeser v0.1

dient zum Auslesen des Gesichtsbildes per BAC
aus einem elektronischen Reisepass
oder Aufenthaltstitel


QnD-Implementierung

=============================================

Copyright (C) 2014  Adrian Krohn
E-mail: adk@toppoint.de

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/

import java.util.List;
import java.util.Formatter;
import java.util.Random;
import java.lang.System;
import java.lang.Integer;
import java.io.*; //evtl. ausdünnen
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.smartcardio.*;



class ePassLeser {
  public static int AnzahlTerminals = 0;
  public static int TerminalAktiv = -1;
  public static long ssc_lsb = 0 ;
  public static String ssc_msb = "";

  public static String calcSHA1(String data) {
    /*
    MessageDigest md = null;
    try {
      md = MessageDigest.getInstance("SHA-1");
    }catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    return new String(ByteToHex(md.digest(data.getBytes("UTF-8"))));
    */
    String result = "";
    try {
      MessageDigest hash = MessageDigest.getInstance("SHA-1");
      hash.reset();
      hash.update(ConvertHexString(data));
      result = ByteToHex(hash.digest());
    }catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    return result;
  }
  public static String calcSHA1_String(String data) {
    /*
    MessageDigest md = null;
    try {
      md = MessageDigest.getInstance("SHA-1");
    }catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    return new String(ByteToHex(md.digest(data.getBytes("UTF-8"))));
    */
    String result = "";
    try {
      MessageDigest hash = MessageDigest.getInstance("SHA-1");
      hash.reset();
      hash.update(data.getBytes("UTF-8"));
      result = ByteToHex(hash.digest());
    }catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }catch (UnsupportedEncodingException e) {
      e.printStackTrace();
    }
    return result;
  }
  public static String AdjustParity(String data) {
    byte[] b = ConvertHexString(data);
    for (int j = 0; j < b.length; j++) {
      int z = 0;
      for (int i = 0; i < 7; i++) {
        if ((b[j]&(0x02 <<i)) != 0) {
          z++;
        }
        b[j] &= 0xFE;
        if ((z%2) == 0) {
          b[j] |= 0x01;
        }
      }
    }
    return ByteToHex(b);
  }

  public static byte[] ConvertHexString(String data) {
      int s = data.length();
      int z = 0;
      byte[] b = new byte[s/2];
      for (int i = 0; i < s; i+=2) {
        b[z] = (byte) Integer.parseInt(data.substring(i, i+2),16);
        z++;

      }
      return b;
  }
  public static byte[] ShortToByte(short[] data) {
      int s = data.length;
      byte[] b = new byte[s];
      for (int i = 0; i < s; i++) {
        b[i] = (byte) data[i];
      }
      return b;
  }

  public static String ByteToHex(byte[] data) {

    Formatter formatter = new Formatter();
    for (byte b : data) {
      formatter.format("%02x", b);
    }
    String result = formatter.toString();
    formatter.close();
    return result;

  }

  public static String xor(String d1, String d2) {

      byte[] b1 = ConvertHexString(d1);
      byte[] b2 = ConvertHexString(d2);
      int s = b1.length;

      if (s != b2.length)
        return "";

      byte[] b = new byte[s];
      for (int i = 0; i < s; i++) {
        b[i] = (byte) (b1[i] ^ b2[i]);
      }
      return ByteToHex(b);
  }


  public static int listCounted() {
    TerminalFactory factory = TerminalFactory.getDefault();
    try {
      List<CardTerminal> terminals = factory.terminals().list();
      int index = 0;
      for (CardTerminal terminal : terminals) {
        System.out.println("Nummer: "+(index+1));
        System.out.println("Terminal: "+terminal.getName());
        System.out.println("Karte vorhanden: "+terminal.isCardPresent());
        System.out.println("-------------------------------");
        index++;
      }
      AnzahlTerminals = index;
      return terminals.size();
    }catch(CardException e) {
      e.printStackTrace();
    }
    return 0;
  }

  public static String getSSC() {
    String tmp = Long.toString(ssc_lsb,16);

    while (tmp.length() < 8) {
      tmp = "0" + tmp;
    }
    return ssc_msb + tmp;
  }

  public static void increaseSSC() {
    ssc_lsb++;
  }

  public static String padding(String msg) {
    msg += "80";
    while ((msg.length() % 16) != 0) { //Länge soll n*8bytes sein
      msg += "00";
    }
    return msg;
  }

  public static String trim(String msg) {
    int l = msg.length();
    while (!(msg.endsWith("80")) && (l > 2)) {
      msg = msg.substring(0,l-2);
      l -= 2;
    }
    msg = msg.substring(0,l-2);

    return msg;
  }

  public static String mac(String key, String data) {
    String cc = "0000000000000000";

    MAC mac1 = new MAC(key);
    MAC mac2 = new MAC(key.substring(16,32));

    int i = 0;

    while (i < (data.length())) {
      cc = xor(cc,data.substring(i,i+16));
      cc = mac1.encrypt(cc);
      i += 16;
    }
    cc = mac2.decrypt(cc);
    cc = mac1.encrypt(cc);
    return cc;
  }

  public static String securemessage(String K_enc, String K_mac, String cla, String ins, String p1, String p2, String lc, String msg, String le) {
    Encrypter tdes = new Encrypter(K_enc);

    cla = xor("0C",cla);

    String cmd_header = cla + ins + p1 + p2;
    msg = padding(msg);

    String l = "";
    String do87 = "";
    String do97 = "";


    if (lc != "") {
      l = Integer.toString(((msg.length()/2)+1),16);
      while (l.length() < 2) {
        l = "0" + l;
      }
      do87 = "87" + l + "01" + tdes.encrypt(msg);
    }


    if (le != "") {
      l = Integer.toString((le.length()/2),16);
      while (l.length() < 2) {
        l = "0" + l;
      }
      do97 = "97"+ l + le;
    }

    String M = padding(cmd_header) + do87 + do97;
    //System.out.println("M: "+M);

    increaseSSC();

    String N = padding(getSSC() + M);

    //System.out.println("N: "+N);

    //System.out.println("SSC: "+getSSC());

    String cc = mac(K_mac, N);

    //System.out.println("CC: "+cc);

    String do8e = "8E08" + cc;

    l = Integer.toString((do87 + do97 + do8e).length()/2,16);
    while (l.length() < 2) {
       l = "0" + l;
    }
    return cmd_header + l + do87 + do97 + do8e + "00";
  }
  public static String unsecuremessage(String K_enc, String K_mac, ResponseAPDU r) {
    String radpu = ByteToHex(r.getBytes());
    String lc = "";
    String msg= "";
    int l = 0;
    Encrypter tdes = new Encrypter(K_enc);

    //System.out.println("R: "+radpu.substring(0,2));
    if (radpu.substring(0,2).startsWith("87")) {
      //System.out.println("R:   "+radpu);
      lc = radpu.substring(2,4);
      l = Integer.parseInt(lc, 16)*2;
      msg = radpu.substring(6,l+4);
      //System.out.println("MSG: "+msg);
      msg = tdes.decrypt(msg);

      //System.out.println("MSGdc: "+msg);
      msg = trim(msg);
      System.out.println("Data: "+msg);
    }
    return msg;

  }
  public static void selectReader() {
    listCounted();
    System.out.println("Bitte Lesegerät auswählen: ");

    BufferedReader input = new BufferedReader(new InputStreamReader(System.in));

    int auswahl = 0;
    try {
      auswahl = input.read() - 49;
    }catch (IOException e) {
      e.printStackTrace();
    }
    if (auswahl >= AnzahlTerminals) {
      System.out.println("Ungültige Auswahl!");
      return;
    }
    TerminalAktiv = auswahl;
  }
  public static void connectCard() throws CardException {
    CardTerminal terminal = TerminalFactory.getDefault().terminals().list().get(TerminalAktiv);


    BufferedReader input = new BufferedReader(new InputStreamReader(System.in));

    //String mrz1 = "";
    String mrz2 = "";
    String idno = "";
    String bday = "";
    String expi = "";

    /*System.out.println("Bitte Zeile 1 von MRZ eingegen: ");
    try {
      mrz1 = input.readLine();
    }catch (IOException e) {
      e.printStackTrace();
    }*/

    /*
    System.out.println("Bitte Zeile 2 von MRZ eingegen: ");
    try {
      mrz2 = input.readLine();
    }catch (IOException e) {
      e.printStackTrace();
    }
    */
    System.out.println("Bitte Kartennummer (9-stellig) + Prüfziffer eingeben: ");
    try {
      idno = input.readLine();
    }catch (IOException e) {
      e.printStackTrace();
    }
    System.out.println("Bitte Geburtstag (JJMMTT) + Prüfziffer eingeben: ");
    try {
      bday = input.readLine();
    }catch (IOException e) {
      e.printStackTrace();
    }
    System.out.println("Bitte Ablaufdatum (JJMMTT) + Prüfziffer eingeben: ");
    try {
      expi = input.readLine();
    }catch (IOException e) {
      e.printStackTrace();
    }
    //System.out.println(mrz1);
    //System.out.println(mrz2);

    //String mrz_info = mrz2.substring(0,10) + mrz2.substring(13,20) + mrz2.substring(21,28);

    String mrz_info = idno.toUpperCase() + bday + expi;


    System.out.println(mrz_info);
    System.out.println(calcSHA1_String(mrz_info));
    mrz_info = calcSHA1_String(mrz_info);
    mrz_info = mrz_info.substring(0,32);
    System.out.println(mrz_info);

    System.out.println("Warte auf Karte...");
    while (!terminal.isCardPresent()) {
      //sleep...
    }
    System.out.println("Karte gefunden!");
    Card card = terminal.connect("T=1");
    System.out.println("Card Info: "+card.toString());
    System.out.println("Card Protokoll: "+card.getProtocol());
    ATR atr = card.getATR();
    System.out.println("ART: "+ByteToHex(atr.getBytes()));
    System.out.println("ART Historical Bytes: "+ByteToHex(atr.getHistoricalBytes()));


    String K_seed = mrz_info;


    String c = "00000001";

    String D = K_seed + c;


    String H = calcSHA1(D);

    String K_a_enc = H.substring(0,16);
    String K_b_enc = H.substring(16,32);

    //System.out.println("K_a: "+K_a);
    K_a_enc = AdjustParity(K_a_enc);
    //System.out.println("K_a: "+K_a);
    //System.out.println("K_b: "+K_b);
    K_b_enc = AdjustParity(K_b_enc);
    //System.out.println("K_b: "+K_b);

    //System.out.println("SHA1(D): "+H);

    c = "00000002";
    D = K_seed + c;
    H = calcSHA1(D);

    String K_a_mac = H.substring(0,16);
    String K_b_mac = H.substring(16,32);
    K_a_mac = AdjustParity(K_a_mac);
    K_b_mac = AdjustParity(K_b_mac);



    String K_enc = K_a_enc + K_b_enc;
    String K_mac = K_a_mac + K_b_mac;

    CardChannel channel = card.getBasicChannel();

    CommandAPDU cmd = new CommandAPDU(ConvertHexString("00A4040C07A0000002471001"));
    ResponseAPDU r = channel.transmit(cmd);
    System.out.println("Select P.App.: "+ByteToHex(r.getBytes()));


    cmd = new CommandAPDU(ConvertHexString("0084000008"));
    r = channel.transmit(cmd);
    String rand_icc = ByteToHex(r.getBytes()).substring(0,16);
    System.out.println("R: "+rand_icc);

    //Random randgen = new Random();
    //String rand_ifd = ...

    String rand_ifd = "781723860C06C226"; //das ist eine Zufallszahl!
    String K_ifd = "0B795240CB7049B01C19B33E32804F0B";

    String S = rand_ifd + rand_icc + K_ifd;
    System.out.println("S:     "+S);

    Encrypter tdes = new Encrypter(K_enc);
    String E = tdes.encrypt(S);
    System.out.println("E:     "+E);


    E = padding(E);

    String M  = mac(K_mac, E);

    System.out.println("M:     "+M);

    String cmd_data = "0082000028" + E.substring(0,64) + M + "28";
    System.out.println("CMD:   "+cmd_data);

    cmd = new CommandAPDU(ConvertHexString(cmd_data));
    r = channel.transmit(cmd);

    E = ByteToHex(r.getBytes());

    System.out.println("Res:   "+E);
    E = E.substring(0,64);

    S = tdes.decrypt(E);

    String K_icc = S.substring(32,64);
    System.out.println("K_icc:  "+K_icc);

    K_seed = xor(K_icc,K_ifd);

    H = calcSHA1(K_seed+"00000001");

    K_a_enc = H.substring(0,16);
    K_b_enc = H.substring(16,32);

    H = calcSHA1(K_seed+"00000002");

    K_a_mac = H.substring(0,16);
    K_b_mac = H.substring(16,32);

    K_enc = K_a_enc + K_b_enc;
    K_mac = K_a_mac + K_b_mac;


    ssc_msb = rand_icc.substring(8,16);
    ssc_lsb = Long.parseLong(rand_ifd.substring(8,16),16);

    //SSC = Long.parseLong(rand_icc.substring(8,16) + rand_ifd.substring(8,16),16);

    cmd_data = securemessage(K_enc, K_mac, "00", "A4", "02", "0C", "02", "0102", ""); //datengruppe 2 (bild)
    System.out.println("APDU: "+cmd_data);
    cmd = new CommandAPDU(ConvertHexString(cmd_data));
    r = channel.transmit(cmd);
    String rapdu = ByteToHex(r.getBytes());
    System.out.println("RAPDU: "+rapdu);
    increaseSSC();

    cmd_data = securemessage(K_enc, K_mac, "00", "B0", "00", "00", "", "", "04"); //lese 4 bytes
    System.out.println("APDU: "+cmd_data);
    cmd = new CommandAPDU(ConvertHexString(cmd_data));
    r = channel.transmit(cmd);
    rapdu = ByteToHex(r.getBytes());
    System.out.println("RAPDU: "+rapdu);
    increaseSSC();
    rapdu = unsecuremessage(K_enc, K_mac, r);
    int le = Integer.parseInt(rapdu.substring(4,8),16); //Anzahl Bytes der Datengruppe
    System.out.println("L: "+le);
    int z = 0x04;
    String data = "";
    while (z < le) {
      String offset = Integer.toString(z,16);
      while (offset.length() < 4) {
        offset = "0" + offset;
      }

      int l = 64;
      if ((le-z) < 64) {
        l = le-z;
      }

      String ll = Integer.toString(l,16);
      while (ll.length() < 2) {
        ll = "0" + ll;
      }
      cmd_data = securemessage(K_enc, K_mac, "00", "B0", offset.substring(0,2), offset.substring(2,4), "", "", ll);
      //System.out.println("APDU: "+cmd_data);
      cmd = new CommandAPDU(ConvertHexString(cmd_data));
      r = channel.transmit(cmd);
      increaseSSC();
      //rapdu = ByteToHex(r.getBytes());
      data += unsecuremessage(K_enc, K_mac, r);

      //System.out.println("z: "+z+" ("+offset+"), l: "+l+" (ll: "+ll+"), l(r): "+r.getBytes().length);
      z += l;
    }
    //System.out.println("Data: "+data);


    boolean found = false; //CBEFF Decoding
    while (!found) {
      if (!data.startsWith("7f60")) {
        data = data.substring(2, data.length());
      }else {
        found = true;
        data = data.substring(4, data.length());
      }
    }
    found = false;
    while (!found) {
      if (!data.startsWith("5f2e")) {
        data = data.substring(2, data.length());
      }else {
        found = true;
        data = data.substring(102, data.length());
      }
    }


    FileOutputStream fos = null;
    try {
      fos = new FileOutputStream("bild.jp2");
      fos.write(ConvertHexString(data));
    } catch (IOException e) {
      e.printStackTrace();
    } finally {
      if (fos != null) try {fos.close();} catch (IOException e) {}
    }
    //byte[] image = ConvertHexString(data);

    System.out.println("Bild erfolgreich gespeichert!");


  }

  public static void main(String[] args) {

System.out.println("ePassLeser version 0.1, Copyright (C) 2014 Adrian Krohn");
System.out.println("");
System.out.println("ePassLeser comes with ABSOLUTELY NO WARRANTY; for details see the file COPYING.");
System.out.println("This is free software, and you are welcome to redistribute it");
System.out.println("under certain conditions; see also the file COPYING.");
System.out.println("====================================================");

    selectReader();
    try {
      connectCard();
    }catch (Exception e) {
      e.printStackTrace();
    }
  }
}
