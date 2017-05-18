/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tomcathoneypot;

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
public class InteractionLog {
    
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
     * InteractionLog Constructor that creates the Interaction log file and adds a 
     * header line to the beginning of the log file
     */
    public InteractionLog() {
        try {
            File file = new File("InteractionLog.txt");
            if (!file.exists())
            {
                file.createNewFile();
                bufferedWriter = new BufferedWriter(new FileWriter(file.getAbsoluteFile(), true));
                bufferedWriter.write("Date/Time, Local IP Addr, Local Port Number, Remote IP Addr, Remote Port Number, Request/Command");
                bufferedWriter.flush();
            }
            bufferedWriter = new BufferedWriter(new FileWriter(file.getAbsoluteFile(), true));
            
        } catch (Exception e) {
            System.out.println("Error in InteractionLog Constructor: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Method to write the client request to the Honeypot to the current log file
     * @param connection Socket on which the current network connection is stored
     * @param request String representing client HTTP request to Honeypot
     * @throws FileNotFoundException
     * @throws IOException 
     */
    public void writeRequestEntry(Socket connection, String request) throws FileNotFoundException, IOException {
        sourceIPAddr = connection.getInetAddress().toString();
        sourcePort = connection.getPort();
        destIPAddr = connection.getLocalAddress().toString();
        destPort = connection.getLocalPort();
        date = java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneId.of("GMT")));
        request = request;
        String entry = date + ", " + destIPAddr + ", " + destPort + ", " + sourceIPAddr + ", " + sourcePort + ", " + request;
        bufferedWriter.newLine();
        bufferedWriter.write(entry);
        bufferedWriter.flush();
        

    }
    
    /**
     * Method to write the Honeypots response back to the client to the log file
     * @param connection Socket on which the current network connection is stored
     * @param request String representing client HTTP request to Honeypot
     * @throws FileNotFoundException
     * @throws IOException 
     */
    public void writeResponseEntry(Socket connection, String request) throws FileNotFoundException, IOException {
        sourceIPAddr = connection.getLocalAddress().toString();
        sourcePort = connection.getLocalPort();
        destIPAddr = connection.getInetAddress().toString();
        destPort = connection.getPort();
        date = java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneId.of("GMT")));
        request = request.replaceAll("\\n", " ");
        String entry = date + ", " + destIPAddr + ", " + destPort + ", " + sourceIPAddr + ", " + sourcePort + ", " + request;
        bufferedWriter.newLine();
        bufferedWriter.write(entry);
        bufferedWriter.flush();
        
    }
    
    
    
}
