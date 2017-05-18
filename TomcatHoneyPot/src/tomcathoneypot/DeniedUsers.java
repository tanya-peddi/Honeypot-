/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tomcathoneypot;
import java.io.BufferedWriter;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.IOException;
import java.net.Socket;
import java.time.ZoneId;
import java.time.ZonedDateTime;
/**
 *
 * @author VP
 */
public class DeniedUsers {
    
      // IP Address of the client
    private String sourceIPAddr = null;
    private BufferedWriter bufferedWriter; 
    private BufferedReader bufferedReader;
    private String date;


    public DeniedUsers() {
        try {
            File file = new File("DeniedUsers.txt");
            if (!file.exists()) {
                file.createNewFile();
                bufferedWriter = new BufferedWriter(new FileWriter(file.getAbsoluteFile(), true));
                bufferedWriter.write("Source_IPAddress");
                bufferedReader = new BufferedReader(new FileReader(file));
                bufferedWriter.flush();
            }
            bufferedWriter = new BufferedWriter(new FileWriter(file.getAbsoluteFile(), true));

        } catch (Exception e) {
            System.out.println("Error in Denied Users Consturctor: " + e.getMessage());
            e.printStackTrace();
        }
        
        
    }
    public void writeLogEntry(Socket connection) throws FileNotFoundException, IOException {
        sourceIPAddr = connection.getInetAddress().toString();
        
        String entry = sourceIPAddr;
        bufferedWriter.newLine();
        bufferedWriter.write(entry);
        bufferedWriter.flush();

    }
    
    public boolean readLogEntry(String ipAddress) throws FileNotFoundException, IOException {
        BufferedReader readlogEntry = new BufferedReader(new FileReader("DeniedUsers.txt"));
        String x = readlogEntry.readLine();
      while(x!= null)
      {
          if(x.contains(ipAddress))
          {
              return true;
          }
          x=readlogEntry.readLine();
      }
      return false;
      
      
        
        

    }
    
    
}
