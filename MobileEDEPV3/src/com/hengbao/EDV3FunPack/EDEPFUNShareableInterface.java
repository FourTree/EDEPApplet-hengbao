/**
 * 文件名：[EDEPFUNShareableInterface.java]
 * 版权:恒宝股份
 * 描述：电子钱包应用共享接口文件 
 * 修改人：郑涛
 * 修改时间：20140903
 * 修改内容：添加共享接口
 */

/**
 * EDV3FunPack,电子钱包应用功能包
 * 实现电子钱包应用变量初始化、基本功能函数及共享接口。
 * Package ID：D156000027455033 Version：13
 * 公司版权信息：恒宝股份
 */
package com.hengbao.EDV3FunPack;
import javacard.framework.Shareable;

/**
 * EDEPFUNShareableInterface共享接口
 * 增加共享接口，供STK菜单调用和读取电子钱包应用中的指令和数据
 * @author  [郑涛]
 * @version  [13，2014-09-03]
 */
public interface EDEPFUNShareableInterface extends Shareable {

	public short CMD_8090(byte[] buf);
}
