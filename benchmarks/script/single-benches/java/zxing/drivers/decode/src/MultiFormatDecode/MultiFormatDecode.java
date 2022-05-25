package decode;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.BufferedImageLuminanceSource;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.ReaderException;
import com.google.zxing.Result;
import com.google.zxing.common.HybridBinarizer;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import javax.imageio.ImageIO;

import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

public class MultiFormatDecode 
{
    private static MultiFormatReader barcodeReader = new MultiFormatReader();
    
    public static void main(String[] args)
    {
        String InFile = args [0];
            
        try
        {
            File FD = new File (InFile);
            InputStream insputStream = new FileInputStream(FD);

            int length = (int)FD.length();
            byte[] bytes = new byte[length];

            insputStream.read(bytes);
            insputStream.close();
            
            BufferedImage read = ImageIO.read(new ByteArrayInputStream(bytes));
            if (read != null && ((long) read.getHeight()) * ((long) read.getWidth()) <= 10000000) {
                Result decode = barcodeReader.decode(new BinaryBitmap(new HybridBinarizer(new BufferedImageLuminanceSource(read))));
                decode.getText();
                decode.getResultMetadata();
            }
        }
        catch (Exception e) 
        {
            return;
        }
    }
}

