
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;


public class HelpObjectOutputStream extends ObjectOutputStream 
{
    
    public HelpObjectOutputStream(OutputStream out) throws IOException
    {
        super(out);
    } 
       @Override
       protected void writeStreamHeader() throws IOException {
    
         reset();
  
        
    }
    
    
    
    
    
}
