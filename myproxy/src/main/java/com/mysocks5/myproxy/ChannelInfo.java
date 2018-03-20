package com.mysocks5.myproxy;

public class ChannelInfo {
	private int rsv;
	
	public int getRsv()	{
		return this.rsv;
	}
	
	public void setRsv(int rsv)	{
		// rsv 只有一个字节
		this.rsv = rsv;
	}
	
	public ChannelInfo(int rsv)	{
		setRsv(rsv);
	}
}
