import java.io.*;

public class Cipher{
  public static void main(String []args) throws Throwable{
		
    File f = new File(args[1]);				
    InputStream in = new FileInputStream(f);
    int mode = Integer.parseInt(args[0]);
    byte[] buff = new byte[1];
		int bytesRead = 0;
		ByteArrayOutputStream bao = new ByteArrayOutputStream();
		String cadaux;
		int i = 0;
		
		while((bytesRead = in.read(buff)) != -1) {
			bao.write(buff, 0, bytesRead);
		}
		byte[] data = bao.toByteArray();
		byte[] bmpHeader = getBMPHeader(data);
		int size = getTotal(bmpHeader,2,4);
		int offset = getTotal(bmpHeader,10,4);
		byte[] workData = getData(data,size,offset);
		byte[] header = getHeader(data, offset);
		byte[] cipheredData = new byte[workData.length];
		String m = new String();
		System.out.println("Size:"+size);
		System.out.println("Header: "+header.length);
		System.out.println("Data length:"+workData.length);
		
		
		switch(mode){
			case 1:
				cipheredData = cipherHandlerECB(workData);
				m = "ECB";
			break;
			case 2:
				cipheredData = cipherHandlerCFB(workData);
				m = "CFB";
			break;
			case 3:
				cipheredData = cipherHandlerCBC(workData);
				m = "CBC";
			break;
			case 4:
			cipheredData = cipherHandlerOFB(workData);
				m = "OFB";
			break;
			case 5:
				cipheredData = cipherHandlerECB(workData);
				m = "CTR";
			break;
		}
		
		byte[] finalData = join(header,cipheredData);
		
		save(finalData, m+"_ciphered_"+args[1]);
		
	}
	
	public static byte[] getBMPHeader(byte[] d){
		byte[] bmpHeader = new byte[14];
		System.arraycopy(d,0,bmpHeader,0,14);
		return bmpHeader;
	}
	
	public static byte[] getHeader(byte[] d,int offset){
		int l = offset;
		byte[] header = new byte[l];
		System.arraycopy(d,0,header,0,l);
		return header;
	}
	
	public static byte[] getData(byte[] d,int size, int offset){
		int l = size - offset;
		byte[] data = new byte[l];
		System.arraycopy(d,offset,data,0,l);
		return data;
	}
	
	public static int getTotal(byte[] d,int init,int length){
		String s = new String("");
		for(int i = init; i < (init + length); i++){
			String aux = Integer.toHexString(d[i]);
			s = aux.concat(s);
		}
		int intValue = Integer.parseInt(s, 16); 
		return intValue;
	}
	
	/****************************************************/
	public static byte[] cipherHandlerECB(byte[] data){
		byte[] aux = new byte[8];
		byte[] auxout = new byte[8];
		byte[] out = new byte[data.length];
		for(int i = 0; i < (data.length/8); i++){
			System.arraycopy(data,i*8,aux,0,8);
			auxout = cipherA(aux);
			System.arraycopy(auxout,0,out,i*8,8);
		}
		return out;
	}
	
	public static byte[] cipherHandlerCFB(byte[] data){
		byte[] in = iVector();
		byte[] m = new byte[8];
		byte[] c =  new byte[8];
		byte[] aux = new byte[8];
		byte[] out = new byte[data.length];
		
		for(int i = 0; i < (data.length/8); i++){
			aux = cipherA(in);
			System.arraycopy(data,i*8,m,0,8);
			
			for(int j=0; j<8; j++){
				c[j] = (byte)(m[j] ^ aux[j]);
			}
			System.arraycopy(c,0,out,i*8,8);
			in = c;
		}
		return out;
	}
	
	public static byte[] cipherHandlerCBC(byte[] data){
		byte[] in = iVector();
		byte[] m = new byte[8];
		byte[] c =  new byte[8];
		byte[] aux = new byte[8];
		byte[] out = new byte[data.length];
		
		for(int i = 0; i < (data.length/8); i++){
			System.arraycopy(data,i*8,m,0,8);
			
			for(int j=0; j<8; j++){
				aux[j] = (byte)(m[j] ^ in[j]);
			}
			c = cipherA(aux);
			System.arraycopy(c,0,out,i*8,8);
			in = c;
		}
		return out;
	}
	
	public static byte[] cipherHandlerOFB(byte[] data){
		byte[] in = iVector();
		byte[] m = new byte[8];
		byte[] c =  new byte[8];
		byte[] aux = new byte[8];
		byte[] out = new byte[data.length];
		
		for(int i = 0; i < (data.length/8); i++){
			aux = cipherA(in);
			System.arraycopy(data,i*8,m,0,8);
			
			for(int j=0; j<8; j++){
				c[j] = (byte)(m[j] ^ aux[j]);
			}
			System.arraycopy(c,0,out,i*8,8);
			in = aux;
		}
		return out;
	}
	/****************************************************/
	
	public static byte[] cipherA(byte[] d){ //8 bytes = 64 bits
		byte[] result = new byte[8];
		for(int i = 0; i<4 ; i++){
			result[i] = (byte)(d[i] ^ d[i+4]);
			result[i+4] = d[i];
		}
		return result;
	}
	
	public static byte[] join (byte[] h, byte[] d){
		byte[] data = new byte[h.length + d.length];
		System.arraycopy(h,0,data,0,h.length);
		System.arraycopy(d,0,data,h.length,d.length);
		return data;
	}
	
	public static void save(byte[] d, String f) throws Throwable{
		File of = new File(f);
		FileOutputStream fos = new FileOutputStream(of);
		
		fos.write(d);
		fos.flush();
		fos.close();
	}
	
	public static byte[] iVector(){
		byte[] iv = new byte[8];
		for(int i=0; i<8; i++){
			iv[i] = 0;
		}
		return iv;
	}
}
