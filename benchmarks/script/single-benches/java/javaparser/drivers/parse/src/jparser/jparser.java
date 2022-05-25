package zip;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseStart;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.Providers;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

public class jparser 
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

            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
            ParserConfiguration parserConfiguration = new ParserConfiguration();
            new JavaParser(parserConfiguration).parse(ParseStart.COMPILATION_UNIT, Providers.provider(byteArrayInputStream, parserConfiguration.getCharacterEncoding()));
        }
        catch (Exception e) 
        {
            return;
        }
    }
}

