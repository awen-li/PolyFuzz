package JsonReaderDrv;


import java.io.IOException;
import one.nio.serial.*;


public class JsonReaderDrv 
{
    public static void fuzzerTestOneInput(byte[] input)
    {
        try
        {
            if (input.length == 0) return;
            
            byte[] bytes = input;

            JsonReader reader = new JsonReader(bytes);
            Object o1 = reader.readObject();
            String s1 = Json.toJson(o1);
            Object o2 = Json.fromJson(s1);
            String s2 = Json.toJson(o2);
        }
        catch (Exception e) 
        {
            return;
        }      
    }
}

