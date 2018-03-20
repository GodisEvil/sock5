package com.mysocks5.myproxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.channels.UnresolvedAddressException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;


/**
 *	socks5 代理客户端，首先主动连接到服务器，发送 \x05\x1\x80 表示只支持 80 方法
 *	服务器应该返回 \x05\x80 表示选择了 \x80 方法
 *	之后发送 \x05[2byte dlen][json data]；
 *	服务器会返回 \x05\x00
 *	然后不再发送任何消息，接收到
 *	\x05\x81 后不做任何处理
 *	\x05\x80[1 rsv][1 atyp][dst][2 dport][data]
 *	时，首先检查 dst:dport 是否已连接，未连接则创建连接，并轮询读；
 *	否则不处理；
 *	读取到的数据如果来自新建的连接，返回时使用
 *	rsv status data
 *	1	1		-
 *	这样的结构
 *
 */
public class App 
{
    public static void main( String[] args )
    {
    	SocketChannel sc = null;
    	Selector selector = null;
    	Map<Integer, SelectionKey> connMap = new HashMap<Integer, SelectionKey>();
        try {
        	sc = SocketChannel.open();
        	sc.connect(new InetSocketAddress("api.linkcel.com", 9999));
        	Socket socket = sc.socket();
//			Socket socket = new Socket("127.0.0.1", 9999);
			socket.setSoTimeout(30000);
			OutputStream out = socket.getOutputStream();
			InputStream in = socket.getInputStream();
			
			if (!Protocol.confirmMethod(out, in))	{
				return ;
			}
			if (!Protocol.auth(out, in))	{
				return ;
			}
			// 接下来接收消息然后处理，这需要用 select 来异步处理
        	selector = Selector.open();
        	sc.configureBlocking(false);
        	// 注册到指定的 selector 对象，注册事件
        	ChannelInfo sChannelInfo = new ChannelInfo(-1);
        	ChannelInfo sChannelInfo2 = new ChannelInfo(-2);
        	SelectionKey key = sc.register(selector, SelectionKey.OP_READ, sChannelInfo);
        	
        	connMap.put(-1, key);
        	// like /127.0.0.1:55727-->/127.0.0.1:9999
        	System.out.println("sc: " + (connMap.get(-1).toString()));
        	
        	byte[] remain = null;
        	
        	// 循环处理事件
        	// 由于 register ——> cancel ——> register 之间，在  cancel 和 register 之间必须经过一次 select，否则会报异常
        	// 所以在需要注册时先标记，等下一次 select 之后再注册；也就是说，要发送的数据，会在一轮循环之后再发送
        	// 在注册到 select 的时候，先尝试把数据发出去，发出去多少算多少
        	while (selector.select() > 0)	{
        		Set<SelectionKey> selectionKeys = selector.selectedKeys();
        		for (Iterator<SelectionKey> it = selectionKeys.iterator(); it.hasNext();)	{
        			SelectionKey sk = it.next();
        			it.remove();
        			if (!sk.isReadable())	{
        				// 可写的只有 控制器
            			System.out.println("is not readable");
            			System.exit(1);	
        			}
    				// 获取该 channel 绑定的 rsv
    				ChannelInfo tmpChannelInfo = (ChannelInfo)sk.attachment();
    				
    				// 首先读取数据
    				SocketChannel sChannel = (SocketChannel) sk.channel();
    				ByteBuffer buffer = ByteBuffer.allocate(2048);
    				int dataLen = 0;
    				try	{
    					dataLen = sChannel.read(buffer);
    					if (dataLen <= 0)	{
    						System.out.println("rsv = " + tmpChannelInfo.getRsv() + " read return " + dataLen);
    						throw new IOException("error: read " + dataLen + " bytes");
    					}
    					System.out.println("read " + dataLen + " bytes");
    				} catch (IOException e) {
    					e.printStackTrace();
    					// 如果和控制服务器的连接断了就退出
    					if (tmpChannelInfo.getRsv() == -1)	{
    						System.out.println("quit because read error");
    						System.exit(0);
    					} else	{
    						// 某个远程连接断掉了
    						connMap.remove(tmpChannelInfo.getRsv());
							selectionKeys.remove(tmpChannelInfo);
    						sk.cancel();
    						System.out.println("close channle " + tmpChannelInfo.getRsv() + " and continue");
        					continue;
    					}
					}
    				
    				byte[] bdata = new byte[dataLen];
					buffer.flip();
					buffer.get(bdata);

    				
    				if (tmpChannelInfo.getRsv() == -1)	{
    					// 是控制服务器发来的数据，从连接列表中查找该 rsv 是否已经有连接了；
    					// 处理数据，提取出 rsv 和目的地址，端口
    					if (remain != null && remain.length > 0)	{
    						bdata = Protocol.addBytes(remain, bdata);
    					}
    					byte[] tmpData = bdata;
    					while (tmpData != null && tmpData.length > 0)	{
    						System.out.println("split data package");
    						bdata = tmpData;
    						buffer = ByteBuffer.wrap(bdata);
    						Map<String, String> dinfo = Protocol.splitHeader(tmpData);
        					if (dinfo == null || dinfo.size() <= 0)	{
        						// 到控制服务器的链接断了就关闭
        						System.out.println("quit because of split header failed");
        						System.exit(1);
        					}
        					System.out.println(dinfo.toString());
        					int packLen = Integer.valueOf(dinfo.get("packLen"));
        					if (tmpData.length >= packLen)	{
        						tmpData = Protocol.subBytes(bdata, packLen, bdata.length - packLen);
        						remain = null;
        					} else	{
        						// 如果本次的包长度不够，表示有些数据在下一个包中，本次不处理
        						remain = tmpData;
        						tmpData = null;
        						break;
        					}
        					
        					if (dinfo.get("cmd").equals(Protocol.METHOD_KEEPALIVE))	{
        						System.out.println("keepalive, continue");
//            						sChannel.register(selector, SelectionKey.OP_READ, tmpChannelInfo);
        						continue;
        					}
        					// 否则查找该 rsv 是否已有连接，没有则新建；
        					// 有的话比较目的地址是否一致，一致则发送数据；否则关闭连接并新建
        					int tmpRsv = Integer.valueOf(dinfo.get("rsv"));
        					SocketAddress dest = new InetSocketAddress(dinfo.get("dst"), Integer.valueOf(dinfo.get("dport")));
        					if (connMap.containsKey(tmpRsv))	{
        						System.out.println("hit rsv " + tmpRsv);
        						SelectionKey tmpSk = connMap.get(tmpRsv);
        						SocketChannel server = (SocketChannel)tmpSk.channel();
        						SocketAddress serverAddress = null;
        						try {
        							serverAddress = server.getRemoteAddress();
								} catch (Exception e) {
									// 要是获取对端地址失败，表示该套接字已经关闭了；走下面的新建连接
									System.out.println("rsv " + tmpRsv + " server closed");
								}
        						
        						if (serverAddress != null && serverAddress.equals(dest))	{
        							try {
        								int endpos = Integer.valueOf(dinfo.get("endpos"));
            							// 设置消息的位置为去掉头部的起始点，发送之后的数据
            							buffer.position(endpos);
        								
    									if (server.write(buffer) <= 0)	{
    										throw new IOException("server " + tmpRsv + " is closed");
    									};
    								} catch (IOException e) {
    									// 发送出错，那么删除掉并从 select 删除，返回错误
    									System.out.println("rsv " + tmpRsv + " deal failed, return reject and delete server");
    									selectionKeys.remove(tmpSk);
    									connMap.remove(tmpRsv);
    									tmpSk.cancel();
    									sc.write(ByteBuffer.wrap(Protocol.createRejectMsg(bdata)));
    								}
        						} else	{
        							// 关闭已有连接，退出select，新建连接，发送要转发的数据并加入到 select
        							if (server != null)	{
        								System.out.println("old remote address " + server.getRemoteAddress().toString() + 
        										", need " + dest.toString());
        							}
									selectionKeys.remove(connMap.get(tmpRsv));
									connMap.remove(tmpRsv);
									tmpSk.cancel();
        							
        							SocketChannel destServer = null;
            						try	{
            							destServer = SocketChannel.open(dest);
            						} catch (UnresolvedAddressException e1) {
										// TODO: handle exception
            							System.out.println("cannot resolve " + dest.toString() + ", reject it");
            							sc.write(ByteBuffer.wrap(Protocol.createRejectMsg(bdata)));
    									continue;
									} catch (IOException e) {
            							// 连接到服务器失败，当然拒绝掉
            							System.out.println("cannot connect to " + dest.toString() + ", reject it");
            							sc.write(ByteBuffer.wrap(Protocol.createRejectMsg(bdata)));
    									continue;
    								}
        							destServer.configureBlocking(false);
        							SelectionKey key2 = destServer.register(selector, SelectionKey.OP_READ, new ChannelInfo(tmpRsv));
        							connMap.put(tmpRsv, key2);
        							int endpos = Integer.valueOf(dinfo.get("endpos"));
        							// 设置消息的位置为去掉头部的起始点，发送之后的数据
        							buffer.position(endpos);
        							destServer.write(buffer);
        						}
        					} else {
        						// 新建连接，发送要转发的数据并加入到 select
        						SocketChannel destServer = null;
        						try	{
        							destServer = SocketChannel.open(dest);
        						} catch (UnresolvedAddressException e) {
        							System.out.println("cannot connect to " + dest.toString() + ", reject it");
        							sc.write(ByteBuffer.wrap(Protocol.createRejectMsg(bdata)));
									continue;
								} catch (IOException e) {
        							System.out.println("cannot connect to " + dest.toString() + ", reject it");
        							sc.write(ByteBuffer.wrap(Protocol.createRejectMsg(bdata)));
									continue;
								}
        						destServer.configureBlocking(false);
    							SelectionKey key2 = destServer.register(selector, SelectionKey.OP_READ, new ChannelInfo(tmpRsv));
    							connMap.put(tmpRsv, key2);
    							int endpos = Integer.valueOf(dinfo.get("endpos"));
    							// 设置消息的位置为去掉头部的起始点，发送之后的数据
    							buffer.position(endpos);
    							destServer.write(buffer);
    						}
    					}
//        					sChannel.register(selector, SelectionKey.OP_READ, tmpChannelInfo);
    				} else	{
    					// 非控制器，那么只能是远端返回的，读取并写回控制服务器，添加头部 rsv
    					System.out.println("datalen = " + dataLen);
    					byte[] header = Protocol.createDataHeader(tmpChannelInfo.getRsv(), (short)dataLen);
    					byte[] sendData = Protocol.addBytes(header, bdata);
//    					System.out.println("send: \n" + new String(bdata, "UTF-8"));
    					// 一直写直到全部发送
            			while (sendData.length > 0)	{
        					int tmpWrite = sc.write(ByteBuffer.wrap(sendData));
//            				System.out.println("send " + tmpWrite + " bytes, all data is " + sendData.length + " bytes");
        					if (tmpWrite < sendData.length)	{
        						sendData = Protocol.subBytes(sendData, tmpWrite, sendData.length - tmpWrite);	
        					} else	{
        						break;
        					}
            			}
    				}
        		}
        	}
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.exit(1);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.exit(1);
		}
    }
}
