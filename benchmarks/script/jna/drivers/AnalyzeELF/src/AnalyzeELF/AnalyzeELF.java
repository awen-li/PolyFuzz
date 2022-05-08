package AnalyzeELF;


import java.io.IOException;
import com.sun.jna.ELFAnalyser;

public class AnalyzeELF 
{
    public static void main(String[] args)
    {
        String InFile = args [0];

        try
        {
            ELFAnalyser.analyse(InFile);
        }
        catch (IOException e) 
        {
            return;
        }
    }
}

