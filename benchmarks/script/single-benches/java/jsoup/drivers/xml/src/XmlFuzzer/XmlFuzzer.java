package xml;

import org.jsoup.Jsoup;
import org.jsoup.parser.Parser;
import org.jsoup.nodes.Document;

import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.ByteArrayInputStream;

public class XmlFuzzer 
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

            Parser.unescapeEntities("<<>>>" + Integer.toString (length) + "]]]]", false);

            Document doc1 = Jsoup.parse (new String (bytes), null, Parser.xmlParser());
            doc1.selectFirst("p").wholeText();
            doc1.getElementsByAttribute("x");
            

            Document doc2 = Jsoup.parse(new String (bytes), "", Parser.htmlParser());
            doc2.selectFirst("p").wholeText();
            doc2.getElementsByAttribute("x");
            
        }
        catch (Exception e) 
        {
            return;
        }
    }
}

