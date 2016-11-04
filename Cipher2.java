import java.io.*;

public class Cipher2{
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
		char[] p = new char[64];
		for(int i = 0; i<8 ; i++){
			String s = Integer.toBinaryString(d[i]);
			char[] bitaux = s.toCharArray();
			
			for(int j=0; j<8; j++){
				if(j<(8-bitaux.length))
					p[(8*i)+j] = '0';
				else
					p[(8*i)+j] = bitaux[j-(8-bitaux.length)];
			}
			
		}
		char[] pp = permutation(p);
		char[]r = new char[32];
		char[]l = new char[32];
		char[]rf = new char[32];
		char[]lf = new char[32];
		char[]f = new char[64];
		System.arraycopy(pp,0,l,0,32);
		System.arraycopy(pp,32,lf,0,32);
		
		char[]aux = expansion(r);
		char[]key = key();
		char[]aux2 = new char[48];
		for(int h=0; h<48;h++){
			aux2[h] =(char)(aux[h] ^ key[h]);
		}
		for(int g=0; g<32; g++){
			rf[g] =(char)(aux2[g] ^ l[g]);
		}
		System.arraycopy(lf,0,f,0,32);
		System.arraycopy(rf,0,f,32,32);
		for(int i=0; i<8; i++){
			char[] saux = new char[8];
			System.arraycopy(f,(i*8),saux,0,7);			
			String s = new String(saux);
			System.out.println(s);
			//int si = Integer.valueOf(s);
			//System.out.println(si);
			result[i] = s.getBytes();
			//result[i] = Byte.parseByte(s,2);
		}
		return result;
	}
	
	public static char[] permutation(char[] p){
		char[] pp = {p[57],p[49],p[41],p[33],p[25],p[17],p[9],p[1],
					p[59],p[51],p[43],p[35],p[27],p[19],p[11],p[3],
					p[61],p[53],p[45],p[37],p[29],p[21],p[13],p[5],
					p[63],p[55],p[47],p[39],p[31],p[23],p[15],p[7],
					p[56],p[48],p[40],p[32],p[24],p[16],p[8],p[0],
					p[58],p[50],p[42],p[34],p[26],p[18],p[10],p[2],
					p[60],p[52],p[44],p[36],p[28],p[20],p[12],p[4],
					p[62],p[54],p[46],p[38],p[30],p[22],p[14],p[6]
				};
		return pp;
	}
	
	public static char[] expansion(char[] p){
		char[] pp = {p[31],p[0],p[1],p[2],p[3],p[4],
					p[3],p[4],p[5],p[6],p[7],p[8],
					p[7],p[8],p[9],p[10],p[11],p[12],
					p[11],p[12],p[13],p[14],p[15],p[16],
					p[15],p[16],p[17],p[18],p[19],p[20],
					p[19],p[20],p[21],p[22],p[23],p[24],
					p[23],p[24],p[25],p[26],p[27],p[28],
					p[27],p[28],p[29],p[30],p[31],p[0]
					};
		return pp;
	}
	
	public static char[] key(){
		char[] k = {	'0','1','0','0','1','1','1','0',
					'0','1','1','0','1','0','0','1',
					'0','1','1','0','0','1','0','0',
					'0','1','1','0','1','0','0','1',
					'0','1','1','0','0','0','0','1',
					'0','1','0','0','0','0','1','1'
					};
		return k;
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
