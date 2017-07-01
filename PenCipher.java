
//这个文件表示的是DES加解密
package eWallet;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public class PenCipher {
	private Cipher desEngine;
	private Key deskey;
	
	public PenCipher(){
		desEngine = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
		deskey = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
	}
	
	/*
	 * 功能：DES运算
	 * 参数：key 密钥; kOff 密钥的偏移量; data 所要进行加解密的数据; dOff 数据偏移量； dLen 数据的长度; r 加解密后的数据缓冲区； rOff 结果数据偏移量； mode 加密或解密运算模式
	 * 返回：无
	 */
	public final void cdes(byte[] akey, short kOff, byte[] data, short dOff, short dLen, byte[] r, short rOff, byte mode){
		//设置ＤＥＳ密钥
		((DESKey)deskey).setKey(akey, kOff);
		//初始化密钥及加密模式
		desEngine.init(deskey, mode);
		//加密
		desEngine.doFinal(data, dOff, dLen, r, rOff);
	}
	
	/*
	 * 功能：生成过程密钥
	 * 参数：key 密钥； data 所要加密的数据； dOff 所加密的数据偏移量； dLen 所加密的数据长度； r 加密后的数据； rOff 加密后的数据存储偏移量
	 * 返回：无
	 */
	public final void gen_SESPK(byte[] key, byte[]data, short dOff, short dLen, byte[] r, short rOff){
		//todo
		byte[] temp1 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT); //临时数组
		byte[] temp2 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT); //临时数组
		
		//3轮DES
		cdes(key, (short)0, data, (short)0, dLen, temp1, (short)0, Cipher.MODE_ENCRYPT);
		cdes(key, (short)8, temp1, (short)0, dLen, temp2, (short)0, Cipher.MODE_DECRYPT);
		cdes(key,(short)0,temp2,(short)0,dLen,r,rOff,Cipher.MODE_ENCRYPT);
		
	}
	
	/*
	 * 功能：8个字节的异或操作
	 * 参数：d1 进行异或操作的数据1 d2:进行异或操作的数据2 d2_off:数据2的偏移量
	 * 返回：无
	 */
	public final void xorblock8(byte[] d1, byte[] d2, short d2_off){
		//todo: 两个数据块进行异或，异或结果存入数据块d1中
		/*
		short i=0;
		while(i<8)  //d1.length) 这样造成数组越界，因为data32位但这只需异或8位
		{
			d1[i]^=d2[d2_off]; //
			d2_off++;
			i++;
		}
		*/
		
		//两个数据块进行异或，异或结果存入数据块d2中
		short i = 0;
		while(i < 8)  /*d1.length) 这样造成数组越界，因为data32位但这只需异或8位*/				
		{
			d2[d2_off] ^= d1[i];//或者(byte)(d1[i] ^ d2[d2_off])
			d2_off++;
			i++;
		}
		
	}
	
	/*
	 * 功能：字节填充
	 * 参数：data 所要填充的数据； len 数据的长度
	 * 返回：填充后的字节长度
	 */
	public final short pbocpadding(byte[] data, short len){
		//todo: 填充字符串至8的倍数
		data[len] = (byte)0x80; //先补充0x80
		len++;
		
		while(len%8 != 0)  //8的倍数
		{
			data[len] = (byte)0x00;
			len++;
		}
		//测试大招--直接抛出len值看是不是这里有bug
		//ISOException.throwIt(len);
		return len;
	}
	
	/*
	 * 功能：MAC和TAC的生成
	 * 参数：key 密钥; data 所要加密的数据; dl 所要加密的数据长度； mac 所计算得到的MAC和TAC码
	 * 返回：无
	 */
	public final void gmac4(byte[] key, byte[] data, short dl, byte[] mac){//特别注意这里传进来的data会被修改！
		//todo
		//先填充，再进行多轮des
		
		short new_dl = pbocpadding(data, dl);
		byte[] init_num = {0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00};
		short num = (short)(new_dl/8);  //切分成多少块
		
		/*修改异或前版本为:xorblock8(data, ini_num, (short)0);*/
		xorblock8(init_num, data, (short)0);
		
		byte[] cipher = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);//密文暂存
		
		for(short i=1; i <= num; i++)
		{
			cdes(key, (short)0, data, (short)(8*(i-1)), (short)8, cipher, (short)0, Cipher.MODE_ENCRYPT);
			if(i < num)
			{
				xorblock8(cipher, data, (short)(8*i));
			}
		}
		
		//最后一个密文就是mac/tac
		for(short i=0; i<4; i++)//mac是四字节的,计算结果是8位，所以取前四位就好,否则也会越界
		{
			mac[i] = cipher[i];
		}
		
		
	}
}
