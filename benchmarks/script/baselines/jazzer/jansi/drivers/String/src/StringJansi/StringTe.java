package StringJansi;

import org.fusesource.jansi.Ansi;

public class StringTe 
{
        public static void fuzzerTestOneInput(byte[] input) 
        {
            byte[] bytes = input;
            int length   = input.length;

            int x,y;
            switch (length)
            {
                case 0:
                case 1:return;
                case 2:
                case 3:x = bytes[0]; y = bytes[1]; break;
                default:
                {
                    x = bytes[0]<<8 | bytes[1];
                    y = bytes[2]<<8 | bytes[3];
                    break;
                }
            }

            try
            {
                Ansi ansi = Ansi.ansi().cursor( x, y).reset();
            }
            catch (Exception e) 
            {
        			return;
            }
        }
}

