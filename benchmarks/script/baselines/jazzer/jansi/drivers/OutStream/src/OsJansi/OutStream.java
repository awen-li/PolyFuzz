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
        public static void fuzzerTestOneInput(byte[] input) 
        {
            
            try
            {
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                final AnsiOutputStream ansiOutput = new AnsiOutputStream(baos, null, AnsiMode.Strip, null, AnsiType.Emulation,
                                                                     AnsiColors.TrueColor, Charset.forName("UTF-8"), null, null, false);
                ansiOutput.write(input);
            }
            catch (Exception e) 
            {
                return;
            }
        }
}

