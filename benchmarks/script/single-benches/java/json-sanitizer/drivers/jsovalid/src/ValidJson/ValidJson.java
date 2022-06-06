package jsovalid;


import com.google.gson.JsonElement;
import com.google.json.JsonSanitizer;
import com.google.gson.Gson;
import com.google.json.EvalMinifier.NameGenerator;
import com.google.json.EvalMinifier;


import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

public class ValidJson 
{    
    private static Gson gson = new Gson();
    
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

            String sanitize = JsonSanitizer.sanitize(new String (bytes), 10);
            JsonSanitizer.sanitize(sanitize).equals(sanitize);
             new Gson().fromJson(sanitize, JsonElement.class);
             JsonSanitizer.sanitize(new String (bytes), length);

             EvalMinifier.minify(new String (bytes));

             NameGenerator ng = new NameGenerator();
             for (int i = length; --i >= 0;) { ng.next(); }
            
        }
        catch (Exception e) 
        {
            return;
        }
    }
}

