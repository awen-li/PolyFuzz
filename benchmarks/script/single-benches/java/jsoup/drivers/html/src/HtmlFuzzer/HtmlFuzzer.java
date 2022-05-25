package html;

import org.jsoup.Jsoup;

import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

public class HtmlFuzzer 
{
    public static void main(String[] args)
    {
        String InFile = args [0];
            
        try
        {
            File FD = new File (InFile);
            InputStream insputStream = new FileInputStream(FD);

            int length = (int)FD.length();
            byte[] bytes = new byte[length];

            insputStream.read(bytes);
            insputStream.close();

            Jsoup.parse(new String (bytes));
        }
        catch (Exception e) 
        {
            return;
        }
    }
}

