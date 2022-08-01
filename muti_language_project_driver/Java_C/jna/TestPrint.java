import JNAApiInterface;
import com.sun.jna.Native;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class TestPrint {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {

        String input = data.consumeRemainingAsString();
        JNAApiInterface jnaLib = JNAApiInterface.INSTANCE;
        jnaLib.printf(input);

    }
}
