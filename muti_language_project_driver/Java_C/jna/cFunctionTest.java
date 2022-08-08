
import com.sun.jna.NativeLibrary;
import com.sun.jna.Function;
import com.sun.jna.Platform;

import com.sun.jna.ptr.IntByReference;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class cFunctionTest {


    public static void fuzzerTestOneInput(FuzzedDataProvider data) {

        int input = data.consumeInt();

        IntByReference ibr = new IntByReference(input);

        ibr.toString().split("@");
    
}
    
}
