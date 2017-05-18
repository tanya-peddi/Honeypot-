/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tomcathoneypot;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Locale;

/**
 *
 * @author Tanya Peddi, Krutika Patil, Uma VadiveLakshmanan, Jonathan Frazier
 */
public class TomcatHoneypotHTTPHandler extends Thread implements Runnable {

    // request stores the HTTP header of the request sent to the tomcat server
    private String request;
    // headaer stores the HTTP header of the HTTP response that will be sent to the client
    private String header;
    // tomcatSocket socket one which honeypot interacts with client
    private Socket tomcatSocket;
    // log file that records requests to the honeypot and the honeypot's responses back to the server
    private InteractionLog interactionlog;
    // String object that contains the username:password
    private String authorization;
    // boolean to indicate whether current connection has authenticated
    private boolean authorized = false;
    // string that contains the username of the client attempting to connect to the Tomcat Honeypot
    private String username = null;
    // string that contains the password of the client attempting to connect to the Tomcat Honeypot
    private String password = null;
    // string that stores the user name to authenticate to the Tomcat HoneyPot
    private String authuser = "tomcat";
    // string that stores the password to authenticate to the Tomcat HoneyPot
    private String authpass = "tomcat";
    // string that stores the Attackers IPAddr and port number
    private String attackerIP = null;
    // string that stores the time of the Attacker's request
    private String attackerRequestTime = null;
    private String uploadFileName = null;

    public TomcatHoneypotHTTPHandler(Socket socket) {
        tomcatSocket = socket;

    }

    /**
     * Method to get the currently stored request header of the current HTTP
     * request
     *
     * @return String request representing the request header of the current
     * HTTP Request
     */
    public String getRequest() {
        return request;
    }

    /**
     * Method to the HTTP header for the HTTP response that the honey pot will
     * send back to the client
     *
     * @return header string object that contains the HTTP header for the HTTP
     * response back to the client
     */
    public String getHeader() {
        return header;
    }

    /**
     * Method that runs the honeypot thread
     */
    public void run() {
        BufferedReader tomcatInput = null;
        DataOutputStream tomcatResponse = null;
        String messageOut = null;
        try {
            interactionlog = new InteractionLog();

            tomcatInput = new BufferedReader(new InputStreamReader(tomcatSocket.getInputStream()));
            //request = tomcatInput.readLine();
            //System.out.println(request);
            attackerIP = tomcatSocket.getInetAddress().toString().replaceAll("[/.]", "_");

            attackerRequestTime = java.time.format.DateTimeFormatter.ofPattern("yyyyMMddhhmmsszzz").format(ZonedDateTime.now(ZoneId.of("UTC")));
            System.out.println(attackerIP);
            System.out.println(attackerRequestTime);
            uploadFileName = attackerRequestTime + attackerIP;

            request = readRequest(tomcatInput);

            interactionlog.writeRequestEntry(tomcatSocket, request);

            this.authenticate();

            if (authorized) {
                tomcatResponse = new DataOutputStream(tomcatSocket.getOutputStream());
                messageOut = header + "\r\n" + tomcatCommandResponse(request, tomcatSocket) + "\r\n";
                tomcatResponse.writeBytes(messageOut);
                tomcatResponse.flush();
                //tomcatResponse.close();
                interactionlog.writeResponseEntry(tomcatSocket, header);

                //tomcatInput.close();
            }
            tomcatSocket.close();

        } catch (Exception e) {
            System.out.println("Error in Run method: " + e);
            e.printStackTrace();
        }

    }

    /**
     * Method that authenticates a user on the Tomcat Honeypot. The
     * authentication is very simplistic and is used to encourage someone
     * attacking the honeypot to attempt to guess the password. As the password
     * guesses are recorded in the interaction log file, this provides a record
     * of known passwords
     *
     * 
     */
    public void authenticate() {
        try {
            int condition = 1;
            
            if (authuser.equals("") || authpass.equals(""))
            {
                condition = 1;
            }
            
            if (authuser.equals(null))
            { 
                condition = 1;
            }
            if (authpass.equals(null))
            {
                condition = 1;
            }
            if (!(authuser.equals(username)) || !(authpass.equals(password))) {

                condition = 1;
            }
            if ((authuser.equals(username)) && (authpass.equals(password)))
            {
                condition = 2;
            }
            
            switch (condition) {
                case 1:
                    header = tomcatAuthResponse(request);
                    DataOutputStream tomcatResponse = new DataOutputStream(tomcatSocket.getOutputStream());
                    String messageOut = header;
                    tomcatResponse.writeBytes(messageOut);
                    tomcatResponse.flush();
                    tomcatResponse.close();
                    interactionlog.writeResponseEntry(tomcatSocket, header);
                    break;
                case 2:
                    header = tomcatHTTPResponse(request);
                    authorized = true;
                    break;
            }
        } catch (Exception e) {
            System.out.println("Error in authenticate method: " + e.getMessage());
            e.printStackTrace();
        }

    }

    /**
     * Method to return a properly formated 401 - Unauthorized HTTP header which
     * in turn will be sent to the requesting client
     *
     * @param request string object containing HTTP request from client
     * @return header string object that contains the HTTP response header to be
     * sent to the client
     */
    private String tomcatAuthResponse(String request) {
        String server = "Server: Apache-Coyote/1.1";
        String contenttype = "Content-Type: txt/html;charset=UTF-8";
        String date = java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneId.of("GMT")));
        String connection = "Connection: keep-alive";
        String httpVersion = "HTTP/1.1";
        String httpCode = "401";
        String httpCodeDesc = "Unauthorized";
        String authenticateflag = "WWW-Authenticate: Basic realm=\"/manager/text/\"";

        header = httpVersion + " ";
        header = header + httpCode + " ";
        header = header + httpCodeDesc + "\r\n";
        header = header + contenttype + "\r\n";
        header = header + server + "\r\n";
        header = header + date + "\r\n";
        header = header + authenticateflag + "\r\n";
        header = header + connection + "\r\n";
        header = header + "\r\n";

        return header;
    }

    /**
     * Method to return a properly formatted 200 - OK Http request header
     *
     * @param request string object containing HTTP request from client
     * @return header string object that contains the HTTP response header to be
     * sent to the client
     */
    private String tomcatHTTPResponse(String request) {

        String server = "Server: Apache-Coyote/1.1";
        String contenttype = "Content-Type: txt/html;charset=UTF-8";
        String date = java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneId.of("GMT")));
        String connection = "Connection: close";
        String httpVersion = "HTTP/1.1";
        String httpCode = "200";
        String httpCodeDesc = "OK";

        header = httpVersion + " ";
        header = header + httpCode + " ";
        header = header + httpCodeDesc + "\r\n";
        header = header + contenttype + "\r\n";
        header = header + server + "\r\n";
        header = header + date + "\r\n";
        header = header + connection + "\r\n";
        header = header + "\r\n";

        if (request.contains("/manager/text/deploy")) {
            return header;

        }

        if (request.contains("/manager/text/list")) {
            return header;
        }

        return header;
    }

    /**
     * Method to read the HTTP request from the client and store the request in
     * a String object
     *
     * @param connectionRequest BufferedReader object used to read the client's
     * HTTP request to a String object
     * @return request String object that stores the HTTP request from the
     * client
     */
    public String readRequest(BufferedReader connectionRequest) {

        BufferedReader readRequest = connectionRequest;

        String request = "";

        try {
            String requestInfo;

            while (readRequest.ready()) {

                requestInfo = readRequest.readLine();
                if (requestInfo.equals("\r\n"))
                {
                    break;
                }
                // special case to decode user name and password part of HTTP header
                if (requestInfo.contains("Authorization")) {
                    String[] authorize = requestInfo.split(" ");
                    // decode the user name and password
                    String userpass = new String(Base64.getDecoder().decode(authorize[2]), StandardCharsets.UTF_8);
                    String[] userpass1 = userpass.split(":");
                    username = userpass1[0];
                    System.out.println("username is " + username);
                    
                    if (userpass1.length==1)
                    {
                        password = null;
                    } else {
                        password = userpass1[1];
                    }
                    System.out.println("password is " + password);
                    authorization = "";
                    for (int i = 0; i < 2; i++) {
                        authorization = authorization + authorize[i] + " ";
                    }
                    authorization = authorization + userpass;
                    System.out.println(authorization);
                    request = request + " " + authorization;
                } else {
                    System.out.println(requestInfo);
                    request = request + " " + requestInfo;
                }

            }

        } catch (IOException e) {
            System.out.println("IOException: " + e);
            e.printStackTrace();
        }
        return request;

    }

    /**
     * Method used to emulate the responses and interaction of an actual
     * deployment of Tomcat All responses are scripted as the TomcatHoneypot is
     * a low interaction honeypot
     *
     * @param command String that contains HTTP request from client
     * @param sock Socket on which the tomcat honeypot is running
     * @return response String object that includes proper response from Tomcat
     * version 8.0.38
     */
    protected String tomcatCommandResponse(String command, Socket sock) {

        String response = null;
        if (command.equals("Get /")) {

            String server = "Server: Apache-Tomcat";
            String contenttype = "Content-Type: txt/html;charset=UTF-8";
            String date = java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneId.of("GMT")));
            String connection = "Connection: close";
            String httpVersion = "HTTP/1.1";
            String httpCode = "200";
            String httpCodeDesc = "OK";

            response = httpVersion + " ";
            response = response + httpCode + " ";
            response = response + httpCodeDesc + "\r\n";
            response = response + contenttype + "\r\n";
            response = response + server + "\r\n";
            response = response + date + "\r\n";
            response = response + connection + "\r\n";
            response = response + "\r\n";
            return response;
        } // List Currently Deployed Applications
        else if (command.contains("/manager/text/list")) {
            response = "OK - Listed applications for virtual host localhost\n"
                    + "/webdav:running:0:webdav\n"
                    + "/examples:running:0:examples\n"
                    + "/manager:running:0:manager\n"
                    + "/:running:0:ROOT\n"
                    + "/test:running:0:test##2\n"
                    + "/test:running:0:test##1\n";
            return response;
        } // List Server Info details
        else if (command.contains("/manager/text/serverinfo")) {
            response = "OK - Server info\n"
                    + "Tomcat Version: Apache Tomcat/8.0.38\n"
                    + "OS Name: Linux\n"
                    + "OS Version: 4.8.4-200.fc24.x86_64\n"
                    + "OS Architecture: amd64\n"
                    + "JVM Version: 1.8.0_111-b16\n"
                    + "JVM Vendor: Oracle Corporation\n";
            return response;
        } // List Server Info details
        else if (command.contains("/manager/text/status")) {
            response = "OK - Server info\n"
                    + "Tomcat Version: Apache Tomcat/8.0.38\n"
                    + "OS Name: Linux\n"
                    + "OS Version: 4.8.4-200.fc24.x86_64\n"
                    + "OS Architecture: amd64\n"
                    + "JVM Version: 1.8.0_111-b16\n"
                    + "JVM Vendor: Oracle Corporation\n";
            return response;
        } // list resources
        else if (command.contains("/manager/text/resources")) {
            response = "OK - Listed global resources of all types\n"
                    + "UserDatabase:org.apache.catalina.users.MemoryUserDatabase\n";
            return response;
        } // Session Statistics
        else if (command.contains("/manager/text/sessions?")) {
            String[] path;
            String[] pathAnd;
            path = command.split("=");
            pathAnd = path[1].split(" ");
            response = "OK - Session information for application at context path " + pathAnd[0] + " \n"
                    + "Default maximum session inactive interval 30 minutes\n";
            return response;
        } else if (command.contains("/manager/text/start")) {

            String[] path;
            String[] pathAnd;
            path = command.split("=");
            pathAnd = path[1].split(" ");
            response = "OK - Stared application  at context path " + pathAnd[0] + " \n";
            return response;
        } // Expire an application
        else if (command.contains("/manager/text/expire?")) {
            String[] path;
            String[] pathAnd;
            String[] PathIdle;
            path = command.split("=");
            pathAnd = path[1].split("&");
            PathIdle = path[2].split(" ");
            response = "OK - Session information for application at context path\n" + pathAnd[0]
                    + "Default maximum session inactive interval 30 minutes\n"
                    + ">" + PathIdle[0] + " minutes: 0 sessions were expired";
            return response;
        } // Stop an applications
        else if (command.contains("manager/text/stop")) {
            String[] path;
            String[] pathAnd;
            path = command.split("=");
            pathAnd = path[1].split(" ");
            response = "OK - stopped application  at context path " + pathAnd[0] + " \n";
            return response;
        } // Undelpoy an application
        else if (command.contains("/manager/text/undeploy")) {
            String[] path;
            String[] pathAnd;
            path = command.split("=");
            pathAnd = path[1].split(" ");
            response = "OK - undeployed application  at context path " + pathAnd[0] + " \n";

            return response;
        } //SSL Connector Ciphers
        else if (command.contains("/manager/text/sslConnectorCiphers")) {
            response = "OK - Connector / SSL Cipher information\n "
                    + "Connector[HTTP/1.1-8080]\n"
                    + "SSL is not enabled for this connector\n"
                    + "Connector[AJP/1.3-8009]\n"
                    + "SSL is not enabled for this connector";
            return response;
        } // Save configuration
        else if (command.contains("/manager/text/save")) {
            response = "FAIL - No StoreConfig MBean registered at [Catalina:type=StoreConfig]. Registration is typically performed by the StoreConfigLifecycleListener. \n"
                    + "\n";
            return response;
        }

        String[] path = null;

        if (command.contains("&tag=")) {
            path = command.split("=");
            String[] path2 = path[1].split("&");
            response = "OK - Deployed application at context path " + path2[0];
            return response;
        } else if (command.contains("&war=file")) //done
        {

            path = command.split("=");
            String[] path2 = path[1].split("&");
            response = "OK - Deployed application at context path " + path2[0];
            return response;
        } else if (command.contains("/manager/text/deploy?war=file:")) {
            String[] pathAnd = null;
            path = command.split("=");
            pathAnd = path[1].split(" ");
            response = "OK - Deployed application at context path " + pathAnd[0] + "\n";
            return response;
        } else if (command.contains("/manager/text/deploy")) {
            path = command.split("=");
            String[] path2 = path[1].split(" ");
            int bytesRead;
            int current = 0;
            String attackerIP = sock.getInetAddress().toString().replaceAll("[/.]", "_");
            String attackerUploadTime = java.time.format.DateTimeFormatter.ofPattern("yyyyMMddhhmmsszzz").format(ZonedDateTime.now(ZoneId.of("UTC")));
            String fileName = attackerUploadTime + attackerIP + ".txt";
            System.out.println(fileName);
            File FILE_TO_RECEIVED = new File(fileName);
            int FILE_SIZE = 6022386;
            FileOutputStream fos = null;
            BufferedOutputStream bos = null;

            byte[] mybytearray = new byte[FILE_SIZE];
            try {
                InputStream is = sock.getInputStream();
                fos = new FileOutputStream(FILE_TO_RECEIVED);
                bos = new BufferedOutputStream(fos);

                bytesRead = is.read(mybytearray, 0, mybytearray.length); // read(the array where the bytes are store,the index from where , no. of bytes to be read)
                // returns number of bytes actually read
                current = bytesRead;
                /**
                 * do { bytesRead = is.read(mybytearray, current,
                 * (mybytearray.length - current)); // reading and storing only
                 * upto where the data in file is if (bytesRead >= 0) // will
                 * return -1 if no more bytes to read { current += bytesRead; }
                 * } while (bytesRead > -1);
                 *
                 */
                bos.write(mybytearray, 0, current);
                bos.flush();
                bos.close();
                System.out.println("File " + FILE_TO_RECEIVED + " downloaded (" + current + " bytes read)");

                response = "OK - Deployed application at context path " + path2[0];
                DeniedUsers denieduser = new DeniedUsers();
                denieduser.writeLogEntry(sock);

                return response;

            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
        return response;
    }
}
