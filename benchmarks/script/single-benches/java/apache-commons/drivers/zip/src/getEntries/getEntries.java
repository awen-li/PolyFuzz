package zip;

import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import java.io.IOException;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

public class getEntries 
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

            new ZipFile(new SeekableInMemoryByteChannel(bytes)).close();
        }
        catch (Exception e) 
        {
            return;
        }
    }
}

