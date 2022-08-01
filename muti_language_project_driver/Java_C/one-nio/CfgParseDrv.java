package CfgParseDrv;


import java.io.IOException;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;


import one.nio.config.*;


public class CfgParseDrv 
{

    @Config
    public static class TestConfig {
        @Converter(InetAddressConverter.class) InetAddress scalar;

        @Converter(InetAddressConverter.class) InetAddress[] array1;

        @Converter(InetAddressConverter.class) InetAddress[] array2;

        @Converter(InetAddressConverter.class) InetAddress[][] arrayArray1;

        List<@Converter(InetAddressConverter.class) InetAddress>[] arrayList1;

        LinkedList<@Converter(InetAddressConverter.class) InetAddress> list1;

        Set<@Converter(InetAddressConverter.class) InetAddress> set;

        List<List<@Converter(InetAddressConverter.class) InetAddress>> listList1;

        List<@Converter(InetAddressConverter.class) InetAddress[]> listArray1;

        Map<String, @Converter(InetAddressConverter.class) InetAddress> map1;

        ConcurrentHashMap<@Converter(InetAddressConverter.class) InetAddress, String> map2;

        Map<String, List<@Converter(InetAddressConverter.class) InetAddress>> multiMap;

        List<Map<@Converter(InetAddressConverter.class) InetAddress, @Converter(InetAddressConverter.class) InetAddress>> listMap;
    }

    public static class InetAddressConverter {
        public InetAddress convert(String value) throws UnknownHostException {
            return InetAddress.getByName(value);
        }
    }

    private static TestConfig testConfig;

   
    public static void fuzzerTestOneInput(byte[] input)
    {
        try
        {
            if (input.length == 0) return;
            testConfig = ConfigParser.parse(new String(input, "UTF-8"), TestConfig.class);
        }
        catch (Exception e) 
        {
            return;
        }      
    }
}

