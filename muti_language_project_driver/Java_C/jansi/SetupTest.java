
import java.io.PrintStream;
import org.fusesource.jansi.AnsiConsole;
import org.fusesource.jansi.AnsiMode;
import org.fusesource.jansi.Ansi;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class SetupTest {

    public static void fuzzerTestOneInput(FuzzedDataProvider data) 
    {
        String input = data.consumeRemainingAsString();

        print(System.out, input);
        print(System.err, input);
        AnsiConsole.systemInstall();
        print(System.out, input);
        print(System.err, input);
        AnsiConsole.out().setMode(AnsiMode.Strip);
        AnsiConsole.err().setMode(AnsiMode.Strip);
        print(System.out, input);
        print(System.err, input);
        AnsiConsole.systemUninstall();
        print(System.out, input);
        print(System.err, input);
    }

    private static void print(PrintStream stream, String text) {
        int half = text.length() / 2;
        stream.print(text.substring(0, half));
        stream.println(Ansi.ansi().fg(Ansi.Color.GREEN).a(text.substring(half)).reset());
    }

}
