
//这个文件表示的是apdu
//APDU（应用协议数据单元 application protocol data units）命令

package eWallet;

import javacard.framework.JCSystem;

public class Papdu {
	//apdu命令的几大结构模块
	public byte cla, ins, p1, p2;
	public short lc, le;
	public byte[] pdata;
	
	public Papdu(){
		//apdu的数据段部分最大长度为255字节
		pdata = JCSystem.makeTransientByteArray((short)255, JCSystem.CLEAR_ON_DESELECT);
		//代码解释：分配内存空间，因为卡片不会回收对象，如果用new的话，就会不断累积，
		//而这个函数申请的函数，第二个参数确定了内存回收时间。
	}
	
	/*
	 * 功能：判断APDU命令是包含数据
	 * 参数：无
	 * 返回：APDU命令包含数据的判断
	 */
	public boolean APDUContainData(){
		switch(ins){
		case condef.INS_CREATE_FILE:
		case condef.INS_LOAD:
		case condef.INS_NIIT_TRANS:
		case condef.INS_WRITE_KEY:
		case condef.INS_WRITE_BIN:
			//需手动添加消费的不然返回lc长度异常！！！
		case condef.INS_PURCHASE:
		
			return true;
		}
		return false;
	}
}
