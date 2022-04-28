package OsJansi;

import org.fusesource.jansi.AnsiColors;
import org.fusesource.jansi.AnsiMode;
import org.fusesource.jansi.AnsiType;
import org.fusesource.jansi.io.AnsiOutputStream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;



public class OutStream 
{
        public static void canHandleSgrsWithMultipleOptions() throws IOException 
        {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final AnsiOutputStream ansiOutput = new AnsiOutputStream(baos, null, AnsiMode.Strip, null, AnsiType.Emulation,
                                                                     AnsiColors.TrueColor, Charset.forName("UTF-8"), null, null, false);
            ansiOutput.write(("\u001B[33mbanana_1  |\u001B[0m 19:59:14.353\u001B[0;38m [debug] A message\u001B[0m\n").getBytes());
            System.out.println(baos.toString());
        }

        public static void main(String[] args)
        {
            try
            {
                canHandleSgrsWithMultipleOptions ();
            }
            catch (IOException e) 
    		{
    			return;
    		}
        }
}

