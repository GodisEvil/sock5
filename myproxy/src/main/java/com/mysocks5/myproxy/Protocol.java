package com.mysocks5.myproxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.naming.spi.DirStateFactory.Result;

import org.json.JSONObject;

public class Protocol {
	public static String METHOD_KEEPALIVE = "0x82";
	public static String METHOD_DATA = "0x81";
	
    public static boolean confirmMethod(OutputStream out, InputStream in)	{
    	byte[] ask = {0x05, 0x01, (byte) 0x80};
    	byte[] buf = new byte[10];
    	int len = 0;
		try {
			out.write(ask);
			len = in.read(buf);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		// 应该收到 0580
		if (len != 2 || buf[0] != 0x05 || buf[1] != (byte)0x80)	{
			System.out.println("response is not right: ");
			printHexString(buf);
			return false;
		}
    	
    	return true;
    }
	
    public static boolean auth(OutputStream out, InputStream in)	{
    	Map<String, String> data = new HashMap<String, String>();
		data.put("imsi", getImsi());
		data.put("apn_name", getSysver());
		data.put("ver", "1");
		JSONObject jdata = new JSONObject(data);
		byte[] info;
		try {
			info = jdata.toString().getBytes("utf-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		short infolen = (short) info.length;
		byte[] linfo = shortToByteArray(infolen);
		byte[] ver = {0x05};
		byte[] prefix = addBytes(ver, linfo);
		try {
			out.write(addBytes(prefix, info));
			byte[] buf = new byte[10];
	    	int len = in.read(buf);
	    	if (len != 2 || buf[0] != 0x05 || buf[1] != 0x00)	{
	    		System.out.println("response is not right: ");
				printHexString(buf);
				return false;
	    	}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		
		return true;
    }
    
    /**
     * 提取出 cmd， rsv ，atyp， dst， dport, endpos, dataLen（本次包长度）
     * @param data
     * @return
     * @throws UnsupportedEncodingException 
     */
    public static Map<String, String>	splitHeader(byte[] bdata)	{
    	printHexString(bdata);
    	if (bdata[0] != 0x05)	{
    		System.out.println("The version must be 5");
    		return null;
    	}
    	Map<String, String> result = new HashMap<String, String>(); 
//    	byte[] cmd = {bdata[1]};
//    	byte[] keepalive = {(byte)0x82};
//    	byte[] data = {(byte)0x81};
    	// ver  = 5 表示至少第一个字节是头部，可能后面没有数据了
    	result.put("ver", "5");
    	// 要是只有1个字节，那么立即返回
    	if (bdata.length < 2)	{
    		result.put("packLen", "3");
    		return result;
    	}
    	if (bdata[1] == (byte)0x82)	{
    		result.put("cmd", METHOD_KEEPALIVE);
    		result.put("packLen", "2");
    		System.out.println("received keepalive");
    		return result;
    	} else if (bdata[1] == (byte)0x81)	{
    		result.put("cmd", METHOD_DATA);
    	} else	{
    		System.out.println("unknown cmd ");
    		return result;
    	}
    	// 头部不完整，那么保留
    	if (bdata.length <= 4)	{
    		result.put("packLen", "5");
    		return result;
    	}
    	int rsv = bdata[2];
    	result.put("rsv", "" + rsv);
    	int atyp = bdata[3];
    	int portEnd = 0;
    	if (bdata[3] == 0x1)	{
    		// ipv4
    		result.put("atyp", "ipv4");
    		result.put("dst", bytesToIp(subBytes(bdata, 4, 4)));
    		result.put("dport", "" + getShort(bdata, 8));
    		portEnd = 10;
    		result.put("endpos", "" + (portEnd + 2));
//    		result.put("dlen", "" + (bdata.length - 10));
    	} else if (bdata[3] == 0x03) {
			result.put("atyp", "domain");
			int dlen = bdata[4];
			result.put("dst", new String(bdata, 5, dlen));
			result.put("dport", "" + getShort(bdata, 5+dlen));
			portEnd = 7+dlen;
			result.put("endpos", "" + (portEnd + 2));
//			result.put("dlen", "" + (bdata.length - 7 - dlen));
		} else if (bdata[3] == 0x04) {
			result.put("atyp", "ipv6");
			System.out.println("ipv6 is not supported");
			return null;
		} else {
			System.out.println("unknown atyp: ");
			return null;
		}
    	System.out.println("");
    	short datalen = getShort(bdata, portEnd);
    	System.out.println("datalen is " + datalen + ", portEnd is " + portEnd);
    	// 包总长度是 header + 2 + datalen
    	int dataLen = datalen + portEnd + 2;
    	result.put("packLen", "" + dataLen);
    	
    	return result;
    }
    
    public static byte[] createRejectMsg(byte[] bdata)	{
    	byte[] status = {0x01};
    	return addBytes(subBytes(bdata, 0, 3), status);
    }
    
    public static byte[] createDataHeader(int rsv, short length)	{
    	byte[] prefix = {0x05, (byte)0x81, (byte)rsv, 0x00};
    	return addBytes(prefix, shortToByteArray(length));
    }
    
    public static short getShort(byte[] b, int index) {
        return (short) (((b[index + 1] & 0xff) | b[index + 0] << 8));
    }
    
    public static byte[] subBytes(byte[] src, int begin, int count) {
        byte[] bs = new byte[count];
        for (int i=begin; i<begin+count; i++) bs[i-begin] = src[i];
        return bs;
    }
    
    public static String bytesToIp(byte[] src) {
        return (src[0] & 0xff) + "." + (src[1] & 0xff) + "." + (src[2] & 0xff)
                + "." + (src[3] & 0xff);
    }
    
    public static byte[] shortToByteArray(short s) {
        byte[] targets = new byte[2];
        for (int i = 0; i < 2; i++) {
            int offset = (targets.length - 1 - i) * 8;
            targets[i] = (byte) ((s >>> offset) & 0xff);
        }
        return targets;
    }
    
    public static byte[] addBytes(byte[] d1, byte[] d2)	{
    	byte[] d3 = new byte[d1.length + d2.length];
    	System.arraycopy(d1, 0, d3, 0, d1.length);
    	System.arraycopy(d2, 0, d3, d1.length, d2.length);
//    	printHexString(d3);
    	return d3;
    }
    
    public static void printHexString(byte[] b)	{
    	String result = "";
    	for (int i = 0; i < b.length; i++)	{
    		String hex = Integer.toHexString(b[i] & 0xFF);
    		if (hex.length() == 1)	{
    			hex = '0' + hex;
    		}
    		result += hex;
    	}
    	System.out.println(result);
    }
    
    public static String getImsi()	{
    	return "470061234567";
    }
    
    public static String getSysver()	{
    	return "android 7.0";
    }
}
