package tomcathoneypot;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.net.Socket;
import java.time.ZoneId;
import java.time.ZonedDateTime;

/**
 *
 * @author Tanya Peddi, Krutika Patil, Uma VadiveLakshmanan, Jonathan Frazier
 */
public class ConnectionLog {

    // IP Address of the client
    private String sourceIPAddr = null;
    // Port Number of the client
    private int sourcePort = 0;
    // IP Address of the Tomcat Honeypot
    private String destIPAddr = null;
    // Port Number of the Tomcat Honeypot
    private int destPort = 0;
    //BufferedWriter used to write entries into log file
    private BufferedWriter bufferedWriter;
    // date object used to store date and time of network connection to honeypot
    private String date;

    /**
     * ConnectionLog Constructor that creates the Connection log file and adds a
     * header line to the beginning of the log file
     */
    public ConnectionLog() {

        try {
            File file = new File("ConnectionLog.txt");
            if (!file.exists()) {
                file.createNewFile();
                bufferedWriter = new BufferedWriter(new FileWriter(file.getAbsoluteFile(), true));
                bufferedWriter.write("Date/Time, Local IP Addr, Local Port Number, Remote IP Addr, Remote Port Number");
                bufferedWriter.flush();
            }
            bufferedWriter = new BufferedWriter(new FileWriter(file.getAbsoluteFile(), true));

        } catch (Exception e) {
            System.out.println("Error in Connectionlog Consturctor: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Method that logs each network connection to a log file. The information
     * logged is the current date/time of the connection, Honeypot IP address,
     * Honeypot port number, Attacker IP address, and Attacker port number
     *
     * @param connection Socket on which the current network connection is
     * stored
     * @throws FileNotFoundException
     * @throws IOException
     */
    public void writeLogEntry(Socket connection) throws FileNotFoundException, IOException {
        sourceIPAddr = connection.getInetAddress().toString();
        sourcePort = connection.getPort();
        destIPAddr = connection.getLocalAddress().toString();
        destPort = connection.getLocalPort();
        date = java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneId.of("UTC")));
        String entry = date + ", " + destIPAddr + ", " + destPort + ", " + sourceIPAddr + ", " + sourcePort;
        bufferedWriter.newLine();
        bufferedWriter.write(entry);
        bufferedWriter.flush();

    }

}
