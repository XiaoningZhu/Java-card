
//����ļ���ʾ����apdu
//APDU��Ӧ��Э�����ݵ�Ԫ application protocol data units������

package eWallet;

import javacard.framework.JCSystem;

public class Papdu {
	//apdu����ļ���ṹģ��
	public byte cla, ins, p1, p2;
	public short lc, le;
	public byte[] pdata;
	
	public Papdu(){
		//apdu�����ݶβ�����󳤶�Ϊ255�ֽ�
		pdata = JCSystem.makeTransientByteArray((short)255, JCSystem.CLEAR_ON_DESELECT);
		//������ͣ������ڴ�ռ䣬��Ϊ��Ƭ������ն��������new�Ļ����ͻ᲻���ۻ���
		//�������������ĺ������ڶ�������ȷ�����ڴ����ʱ�䡣
	}
	
	/*
	 * ���ܣ��ж�APDU�����ǰ�������
	 * ��������
	 * ���أ�APDU����������ݵ��ж�
	 */
	public boolean APDUContainData(){
		switch(ins){
		case condef.INS_CREATE_FILE:
		case condef.INS_LOAD:
		case condef.INS_NIIT_TRANS:
		case condef.INS_WRITE_KEY:
		case condef.INS_WRITE_BIN:
			//���ֶ�������ѵĲ�Ȼ����lc�����쳣������
		case condef.INS_PURCHASE:
		
			return true;
		}
		return false;
	}
}
