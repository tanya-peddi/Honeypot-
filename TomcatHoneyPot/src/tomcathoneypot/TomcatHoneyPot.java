/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tomcathoneypot;

import java.io.DataOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.ZoneId;
import java.time.ZonedDateTime;

/**
 *
 * @author Tanya Peddi, Krutika Patil, Uma VadiveLakshmanan, Jonathan Frazier
 */
public class TomcatHoneyPot {

    // server socket on which Tomcat Honeypot listens for network connections
    ServerSocket tomcatHoney;
    // log file to record all network connections to the Tomcat Honeypot
    ConnectionLog connectionLog;
    // denied users log file
    DeniedUsers dUsers;
    String forbiddenHeader;

    /**
     * Constructor for TomcatHoneyPot application
     */
    public TomcatHoneyPot() {
        tomcatHoney = null;
        connectionLog = new ConnectionLog();
        dUsers = new DeniedUsers();

        try {
            tomcatHoney = new ServerSocket(8080);
        } catch (Exception e) {
            e.getMessage();
        }
        while (true) {
            try {

                Socket tomcatConnection = tomcatHoney.accept();
                //DeniedUsers dUsers = new DeniedUsers();
                String ipAddress = tomcatConnection.getInetAddress().toString();
                // Check if IP Address is blacklisted due to previously having uploaded a file to honeypot
                // If IP address not black listed process request
                if (!(dUsers.readLogEntry(ipAddress))) {
                    connectionLog.writeLogEntry(tomcatConnection);
                    TomcatHoneypotHTTPHandler tomcat = new TomcatHoneypotHTTPHandler(tomcatConnection);
                    Thread tomcathoneypot = new Thread(tomcat);
                    tomcathoneypot.start();
                // If IP address is black list send back 403 Forbidden http response    
                } else {
                    DataOutputStream tomcatResponse = new DataOutputStream(tomcatConnection.getOutputStream());
                    tomcatForbidenResponse();
                    tomcatResponse.writeBytes(forbiddenHeader);
                    tomcatResponse.flush();
                    tomcatResponse.close();
                    
                }

            } catch (Exception e) {
                System.out.println("Error in TomcatHoneyPot constructor: " + e.getMessage());
                e.printStackTrace();
            }
        }

    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // create new Tomcat Honeypot instance
        new TomcatHoneyPot();

    }

    private void tomcatForbidenResponse() {

        String server = "Server: Apache-Coyote/1.1";
        String contenttype = "Content-Type: txt/html;charset=UTF-8";
        String date = java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneId.of("GMT")));
        String connection = "Connection: close";
        String httpVersion = "HTTP/1.1";
        String httpCode = "403";
        String httpCodeDesc = "Forbidden";
        

        forbiddenHeader = httpVersion + " ";
        forbiddenHeader = forbiddenHeader + httpCode + " ";
        forbiddenHeader = forbiddenHeader + httpCodeDesc + "\r\n";
        forbiddenHeader = forbiddenHeader + contenttype + "\r\n";
        forbiddenHeader = forbiddenHeader + server + "\r\n";
        forbiddenHeader = forbiddenHeader + date + "\r\n";
        forbiddenHeader = forbiddenHeader + connection + "\r\n";
        forbiddenHeader = forbiddenHeader + "\r\n";

    }

}
