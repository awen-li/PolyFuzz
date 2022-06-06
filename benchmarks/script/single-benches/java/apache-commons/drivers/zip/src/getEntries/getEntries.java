package zip;

import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.ArchiveOutputStream;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
import org.apache.commons.compress.utils.IOUtils;
import java.io.OutputStream;

import java.io.IOException;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.FileNotFoundException;



public class getEntries 
{
    public static final ArchiveStreamFactory factory = ArchiveStreamFactory.DEFAULT;
    public static File archive;
    
    public static void addArchiveEntry(final ArchiveOutputStream out, 
                                              final String filename, 
                                              final File infile) throws IOException, FileNotFoundException 
    {
        final ArchiveEntry entry = out.createArchiveEntry(infile, filename);
        out.putArchiveEntry(entry);
        IOUtils.copy(infile, out);
        out.closeArchiveEntry();
    }
            
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

            String archivename = "archivename.tt";
            archive = File.createTempFile("test", "." + archivename);
            archive.deleteOnExit();
            OutputStream stream = Files.newOutputStream(archive.toPath());
            ArchiveOutputStream out = factory.createArchiveOutputStream(archivename, stream);
            addArchiveEntry (out, "in/0", new File (InFile));
            
            new ZipFile(new SeekableInMemoryByteChannel(bytes)).close();       
        }
        catch (Exception  e) 
        {
            return;
        }
    }
}

