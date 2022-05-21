package JsonReaderDrv;


import java.io.IOException;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

import one.nio.serial.*;

/*
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
*/


public class JsonReaderDrv 
{
/*
    private static final String sample = "[{\n" +
            "  \"created_at\": \"Thu Jun 22 21:00:00 +0000 2017\",\n" +
            "  \"id\": 877994604561387500,\n" +
            "  \"id_str\": \"877994604561387520\",\n" +
            "  \"text\": \"Creating a Grocery List Manager \\u0026 Display Items https://t.co/xFox12345 #Angular\",\n" +
            "  \"truncated\": false,\n" +
            "  \"entities\": {\n" +
            "    \"hashtags\": [{\n" +
            "      \"text\": \"Angular\",\n" +
            "      \"indices\": [103, 111]\n" +
            "    }],\n" +
            "    \"symbols\": [null],\n" +
            "    \"user_mentions\": [],\n" +
            "    \"urls\": [{\n" +
            "      \"url\": \"https://t.co/xFox12345\",\n" +
            "      \"expanded_url\": \"http://example.com/2sr60pf\",\n" +
            "      \"display_url\": \"example.com/2sr60pf\",\n" +
            "      \"indices\": [79, 102]\n" +
            "    }]\n" +
            "  },\n" +
            "  \"source\": \"<a href=\\\"http://example.com\\\" rel=\\\"nofollow\\\">Some link</a>\",\n" +
            "  \"user\": {\n" +
            "    \"id\": 772682964,\n" +
            "    \"id_str\": \"772682964\",\n" +
            "    \"name\": \"Example JavaScript\",\n" +
            "    \"screen_name\": \"ExampleJS\",\n" +
            "    \"location\": \"Melbourne, Australia\",\n" +
            "    \"description\": \"Keep up with JavaScript tutorials, tips, tricks and articles.\",\n" +
            "    \"url\": \"http://t.co/cCHxxxxx\",\n" +
            "    \"entities\": {\n" +
            "      \"url\": {\n" +
            "        \"urls\": [{\n" +
            "          \"url\": \"http://t.co/cCHxxxxx\",\n" +
            "          \"expanded_url\": \"http://example.com/javascript\",\n" +
            "          \"display_url\": \"example.com/javascript\",\n" +
            "          \"indices\": [0, 22]\n" +
            "        }]\n" +
            "      },\n" +
            "      \"description\": {\n" +
            "        \"urls\": []\n" +
            "      }\n" +
            "    },\n" +
            "    \"protected\": false,\n" +
            "    \"followers_count\": 2145,\n" +
            "    \"friends_count\": 18,\n" +
            "    \"listed_count\": 328,\n" +
            "    \"created_at\": \"Wed Aug 22 02:06:33 +0000 2012\",\n" +
            "    \"favourites_count\": 57,\n" +
            "    \"utc_offset\": 43200,\n" +
            "    \"time_zone\": \"Wellington\"\n" +
            "  }\n" +
            "}]";


    public static void WritOneCase (String Path, String Content)
    {
        try
        {
            Path p = Paths.get(Path);  
            Files.write(p, Content.getBytes());
            System.out.println (Content);
        }
        catch (IOException e) 
        {
            return;
        }
    }
*/

    public static void main(String[] args)
    {
        String InFile = args [0];

        try
        {
            //WritOneCase ("tests/test1", sample);
            
            File FD = new File (InFile);
            InputStream insputStream = new FileInputStream(FD);

            int length = (int)FD.length();
            byte[] bytes = new byte[length];

            insputStream.read(bytes);
            insputStream.close();
                
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

