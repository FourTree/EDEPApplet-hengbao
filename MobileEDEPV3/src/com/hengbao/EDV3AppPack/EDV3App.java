/**
 * 文件名：[EDV3App.java]
 * 版权:恒宝股份
 * 描述：电子钱包应用Applet文件，完成电子钱包应用的构造和注册，添加8090扩展共享接口，实现STK菜单调用电子钱包功能。
 * 修改人：郑涛、郝寿朋
 * 修改时间：20140903
 * 修改内容：添加共享接口；性能优化
 */

/**
 * EDV3AppPack,电子钱包依赖包
 * 实现电子钱包应用JAVA壳，调用功能包中的函数实现电子钱包应用
 * Package ID：D156000027455032 Version：13
 * 公司版权信息：恒宝股份
 */
package com.hengbao.EDV3AppPack;

import javacard.framework.*;
import javacard.framework.Applet;
import javacard.framework.MultiSelectable;

import com.hengbao.EDV3FunPack.*;

/**
 * EDV3App类
 * 实现电子钱包应用的构造、注册和共享接口扩展。
 * @author  [郑涛、郝寿朋]
 * @version  [13，2014-09-03]
 */
public class EDV3App extends Applet implements AppletEvent, MultiSelectable,
                EDEPFUNShareableInterface
{
    EDEPPro ep;

    public EDV3App(byte[] bArray, short bOffset, byte bLength)
    {
        ep = new EDEPPro();
        ep.initEDEPPro(bArray, bOffset, bLength);// 调用EDEPFunPack
        register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        new EDV3App(bArray, bOffset, bLength);// GP-compliant JavaCard applet
                                              // registration
    }

    public void uninstall()
    {

    }

    public boolean select()
    {
        ep.setSelectRamVar();
        ep.INS_save[0] = 0; // 存储上一条指令INS清0
        ep.ramShort1[0] = 0;// 将当前DF设置为MF
        ep.ramShort1[4] = 0;// 当前DF的上级DF置为MF自己

        return true;
    }

    public void deselect()
    {

    }

    public boolean select(boolean appInstAlreadyActive)
    {
        return true;
    }

    public void deselect(boolean appInstStillActive)
    {

    }

    public void process(APDU apdu)
    {
        if (selectingApplet())
        {
            if ((byte) 1 == ep.AIDSelect(apdu))
            {
                return;
            }
        }
        ep.process(apdu);
    }

    public short CMD_8090(byte[] buffer)
    {
        short sw = 0;
        short rtLen = 0;
        byte flag = 1;
        APDU apdu = null;
        
        rtLen = (short) (buffer[ISO7816.OFFSET_LC] & 0x00ff);
        Util.arrayCopyNonAtomic(buffer, (short) ISO7816.OFFSET_CDATA, buffer,
                        (short) 0, rtLen);
        Util.arrayFillNonAtomic(buffer, rtLen, rtLen, (byte) 0);
        switch (buffer[ISO7816.OFFSET_INS])
        {
            case (byte) 0x5C:
                ep.CMD_805C(buffer, apdu, (byte) flag);
                sw = Util.getShort(buffer, (short) (buffer[0] + 1));
                break;
            case (byte) 0xa4:
                ep.CMD_00A4(buffer, apdu, (byte) flag);
                // buf中数据:3B6F39841088888888881000300000000100000000A5259F0801029F0C1E0000000000000000000000000000000000000000000000000000000000009000
                sw = Util.getShort(buffer, (short) (buffer[0] + 1));
                break;
            case (byte) 0xb0:
                ep.CMD_00B0(buffer, apdu, (byte) flag);
                sw = Util.getShort(buffer, (short) (buffer[0] + 1));
                break;
            case (byte) 0xf1: // GETKEY
                ep.CMD_00F1(buffer, apdu, (byte) flag);
                sw = Util.getShort(buffer, (short) (buffer[0] + 1));
                break;
            case (byte) 0xb2:
                ep.CMD_00B2(buffer, apdu, (byte) flag);
                sw = Util.getShort(buffer, (short) (buffer[0] + 1));
                break;
        }
        return sw;
    }

    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter)
    {
        return (Shareable) this;
    }

}