import org.fusesource.jansi.AnsiConsole;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class AnsiConsoleOut {

    public static void fuzzerTestOneInput(FuzzedDataProvider data) 
    {
        String input = data.consumeRemainingAsString(10);
        AnsiConsole.out().println(input);
    }

}
