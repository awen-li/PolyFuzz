package ReJansi;

import static org.fusesource.jansi.Ansi.ansi;
import static org.fusesource.jansi.AnsiRenderer.render;
import static org.fusesource.jansi.AnsiRenderer.renderCodes;

public class Render 
{   
        public static void fuzzerTestOneInput(byte[] input) 
        {
            try
            {
                String str = new String(input);
                render(str);
            }
            catch (Exception e) 
            {
        		return;
            }
        }
}

