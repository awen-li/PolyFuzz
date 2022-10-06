package OsJansi;

import org.fusesource.jansi.AnsiColors;
import org.fusesource.jansi.AnsiMode;
import org.fusesource.jansi.AnsiType;
import org.fusesource.jansi.io.AnsiOutputStream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;


import java.io.File;
import java.io.InputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;


import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;



public class OutStream 
{
    public static byte[] ReadBytes (String FName)
    {
        byte[] bytes = null;
        
        try
        {
            File file = new File(FName);
            InputStream insputStream = new FileInputStream(file);

            bytes = new byte[(int) file.length()];
            
            insputStream.read(bytes);
            insputStream.close();
        }
        catch (Exception e) 
        {
            System.out.println (e);
        }

        return bytes;        
    }

    public static void main(String[] args)
    {
        String InFile = args [0];
        byte[] bytes = ReadBytes (InFile);
        if (bytes == null)
        {
            return;
        }
            
        try
        {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final AnsiOutputStream ansiOutput = new AnsiOutputStream(baos, null, AnsiMode.Strip, null, AnsiType.Emulation,
                                                                     AnsiColors.TrueColor, Charset.forName("UTF-8"), null, null, false);

            ansiOutput.write(bytes);
        }
        catch (Exception e) 
        {
            return;
        }
    }
}

