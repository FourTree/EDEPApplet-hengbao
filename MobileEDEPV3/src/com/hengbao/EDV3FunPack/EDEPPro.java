/**
 * 文件名：[EDEPPro.java]
 * 版权:恒宝股份
 * 描述：电子钱包应用功能文件，实现钱包应用中所有的基本功能。
 * 修改人：郑涛、郝寿朋
 * 修改时间：20140903
 * 修改内容：完善基本功能，性能优化
 */

/**
 * EDV3FunPack,电子钱包应用功能包
 * 实现电子钱包应用变量初始化、基本功能函数及共享接口。
 * Package ID：D156000027455033 Version：13
 * 公司版权信息：恒宝股份
 */
package com.hengbao.EDV3FunPack;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * EDEPPro类
 * 实现电子钱包应用变量声明、初始化，基本功能函数
 * @author  [郑涛、郝寿朋]
 * @version  [13，2014-09-03]
 */
public class EDEPPro
{
    /* 常量 START */
    public final byte ramByteLenEDEP = 15;// ramByte分配的空间大小
    public final byte ramShortLenEDEP = 8;// ramShort分配的空间大小
    public final short GET_RESPONSE_FLAG = 0x1; // renponse可执行标识，00：不能
                                                // 01：可以执行response指令
    public final short KeyIndexOff = 0x2; // 密钥索引
    public final short transStatusOff = 0x03; // 交易状态
    public final short randomFlagOff = 0x04; // 随机数生成标识
    public final short appTypeOff = 0x05; // 应用类型
    public final short EP0ED1ET2FLAGOff = 0x06;// ED/EP区分标识，00：EP,01:ED
    
    // CAPP专用
    public final short CAPPSFIOff = 0x07; // ramByte[CAPPSFIOff]临时存储CAPP的SFI
    public final short CAPPTypeIDOff = 0x09;// ramByte[CAPPTypeIDOff]临时存储CAPP的消费类型标识
    public final short MaxBalanceOff = 1;// ramShort[1]：临时存储余额上限文件的偏移地址
    public final short EDEPETFileAddressOff = 2;// 临时存储EDEP相关文件的偏移地址
    public final short CAPPBufLenOff = 5;// ramShort[5]：临时存储CAPP的buf长度
    public final short CAPPRecNOOff = 6;// ramShort[6]：临时存储CAPP的记录数

    // 错误定义
    public final short COMM_WARNING_ERROR = (short)0x9403;
    public final short BALANCE_ZERO_ERROR = (short)0x9401;
    public final short MAC_ERROR = (short)0x9302;
    public final short TRANS_STATUS_NOT_SATISFIED = (short)0x6901;
    public final short MAC_TAC_USELESS = (short)0x9406;
    public final short GREY_LOCK_ERROR = (short)0x9408;
    public final short CAPP_LOCK_ERROR = (short)0x9407;

    // 抛出异常的名称
    public final short TRIES_REMAINING = 0x63C0;// 尝试次数
    public final short VERIFY_INCORRECT = (short)0x6300;// 校验错误
    public final short CLA_NOT_MATCHED = 0x6900;// CLA与线路保护属性不匹配
    public final short FILE_TYPE_NOT_MATCHED = 0x6981;// 文件类型不匹配
    public final short NO_CURRENT_EF = 0x6986;// 没有EF被选择
    public final short FILE_MAC_ERROR = 0x6988;// MAC验证错误
    public final short TLV_FORMAT_NOT_MATCHED = 0x6A85;// 与TLV结构不相符
    public final short KEY_FILE_NOT_FOUND = 0x6A88;// 密钥文件找不到
    public final short FILE_ALREADY_EXIST = 0x6A89;// 文件已经存在（FID重复）
    public final short KEY_FILE_NOT_EXIST = 0x6A8B;// KEY文件没有建立(DF下应先创建KEY文件)
    public final short APPLICATION_LOCED_PERMANENT = (short)0x9303;// 应用永久锁定

    // APDU常量
    public final byte APPEND_RECORD = (byte)0xE2;// 追加记录
    public final byte CARD_ISSUE = (byte)0x0A;// 结束个人化
    public final byte VERIFY_TRANSPORTKEY = (byte)0x2A;// 传输码校验
    public final byte CREAT_FILE = (byte)0xE0;// 建立MF
    public final byte Erase_DF = (byte)0xEE;// 擦除DF
    public final byte WRITE_KEY = (byte)0xD4;// Write Key
    public final byte SELECT = (byte)0xA4; // 自定义选择文件
    public final byte GET_CHALLENGE = (byte)0x84; // 自定义选择文件
    public final byte APP_BLOCK = (byte)0x1E;
    public final byte APP_UNBLOCK = (byte)0x18;
    public final byte CARD_BLOCK = (byte)0x16;
    public final byte GET_RESPONSE = (byte)0xc0;
    public final byte Read_Binary = (byte)0xb0;
    public final byte Read_record = (byte)0xb2;
    public final byte Update_Binary = (byte)0xd6;
    public final byte Update_Record = (byte)0xDC;
    public final byte Verify = (byte)0x20;
    public final byte Ext_Authentication = (byte)0x82;
    public final byte Int_Authentication = (byte)0x88;
    public final byte Change_Reload_PIN = (byte)0x5e;
    public final byte Unblock_PIN = (byte)0x24;
    public final byte CREDIT_FOR_LOAD = (byte)0x52;
    public final byte DEBIT_FOR_PURCHASE_CASH_WITHDRAW_DEBIT_FOR_UNLOAD = (byte)0x54;
    public final byte GET_BALANCE = (byte)0x5C;
    public final byte INITIALIZE_FOR_CASH_WITHDRAW_FORLOAD_FOR_PURCHASE_FOR_UNLOAD_FOR_UPDATE = (byte)0x50;
    public final byte UPDATE_OVERDRAW_LIMIT = (byte)0x58;
    public final byte GET_TRANSACTION_PROVE = (byte)0x5A;
    public final byte GET_TRANSSTATUS = (byte)0x88;
    public final byte GET_LOCK_PROOF = (byte)0xCA;
    public final byte Write_ZJB_Number = (byte)0x02;

    // 密钥类型
    public final byte TEAK_TYPE = 0x39;
    public final byte TIAK_TYPE = 0x30;
    public final byte DAMK_TYPE = 0x36;
    public final byte DPK_TYPE = 0x27;// modify by zhengtao 20131210
    public final byte DLK_TYPE = 0x26; // modify by zhengtao
    public final byte DTK_TYPE = 0x25; // modify by zhengtao
    public final byte DPUK_TYPE = 0x37;
    public final byte DRPK_TYPE = 0x38;
    public final byte DULK_TYPE = 0x28;// modify bu zhengtao 20131210
    public final byte DUK_TYPE = 0x29; // modify bu zhengtao 20131210
    public final byte DUKK_TYPE = 0x24;
    public final byte DPIN_TYPE = 0x3A;
    public final byte APPULK_TYPE = 0x21;
    public final byte APPLK_TYPE = 0x20;
    public final byte KEY_INDEX = 0x0;// modify by zhengtao 20131209

    // 交易类型标识常量
    public final byte EDL = (byte)0x01;// ED圈存
    public final byte EPL = (byte)0x02;// EP圈存
    public final byte EDUL = (byte)0x03;// 圈提（ED)
    public final byte EDWD = (byte)0x04;// ED取款
    public final byte EDP = (byte)0x05;// ED 消费
    public final byte EPP = (byte)0x06;// EP 消费
    public final byte EDU = (byte)0x07;// ED修改限额
    public final byte CREDIT = (byte)0x08;// 信用消费
    public final byte CAPP = (byte)0x09;// 复合消费交易
    public final byte G_LOCK = (byte)0x91;// 灰锁
    public final byte D_UNLOCK = (byte)0x93;// 解扣
    public final byte G_UNLOCK = (byte)0x95;// 联机解扣

    public final byte APP_PBOC = (byte)0x01; // 标准PBOCEDEP应用
    public final byte APP_PETROL = (byte)0x11;// 中石油应用，已删除
    public final byte APP_HLHT = (byte)0x06;// 互联互通应用
    public final byte APP_ZJB = (byte)0x08;// 住建部钱包应用
    public final byte APP_JTB = (byte)0x10;//交通部应用  add by yujing

    // 当前交易
    public final byte FLAG_ED = (byte)0x1; // 存折
    public final byte FLAG_ET = (byte)0x2;// 加油卡

    // added by lrl 建设部交易
    public final byte FLAG_EB = (byte)0x8;// 暂时未用
    public final byte FLAG_ONLINE = (byte)0x1;// 联机、脱机交易FLAG_OFFLINE
    public final byte FLAG_WRITE = (byte)0x1;// 读写标志
    public final short EDFID = (short)0xEF01;// 电子存折文件(EF01)
    public final short EPFID = (short)0xEF02;// 电子钱包文件(EF02)
    public final short PROOFFID = (short)0xEF03;// PBOC的PROOF文件EF03
    public final byte ETSFI = (byte)0x10;// 电子油票ET文件(EF10)
    public final byte SESPKSFI = (byte)0x11;// 电子油票SESPK存储文件(EF11)
    public final short LIMITFID = (short)0xEF05;// 余额上限文件Balance Limit(EF05)
    public final byte STATUSFLAGSFI = (byte)0x04;// 状态标志文件ET_FLAG_FILE(EF04)
    public final byte PETROLSPECIALSFI = (byte)0x14;// 电子油票交易专用明细(EF20)

    // 卡片交易状态
    public final byte G_TranStatus_L = (byte)1; // 圈存状态
    public final byte G_TranStatus_UL = (byte)2; // 圈提状态
    public final byte G_TranStatus_P = (byte)5; // 消费状态
    public final byte G_TranStatus_U = (byte)6; // 改限状态
    public final byte G_TranStatus_PreLock = (byte)7; // 预灰锁
    public final byte G_TranStatus_LockF = (byte)3; // 灰锁空闲
    public final byte G_TranStatus_UNLock = (byte)4; // 联机解扣
    public final byte G_TranStatus_CAPP1 = (byte)8; // 复合交易状态
    public final byte G_TranStatus_CAPP2 = (byte)9; // Updata CAPP状态

    public final byte DFHeadLen = 32;// DF文件头的长度
    public final byte EFHeadLen = 18;// EF文件头的长度
    public final short EEPROMSize = 0x2000;// 整个文件系统的大小(8K)
    public final byte FCISFI = 0x15;// FCI文件的SFI
    public final short FCIFID = (short)0xEF15;// FCI文件的FID
    public final byte DDFType = (byte)0x30;// DDF的文件类型（包括MF）
    public final byte ADFType = (byte)0x38;// ADF的文件类型
    public final short DirEFFID = (short)0x0001;// DirEF文件的FID(DirEF文件由COS自己来维护）

    // key文件头
    public final short MaintainKeyID = 0x3601;// 应用维护密钥的KID
    public final short MasterKeyID = 0x3900;// 主控密钥的KID
    public final byte KeyHeadLength = 0x07;// 密钥头的长度
    public final byte KeyTypeOff = 0x01;// 密钥类型的偏移量
    public final byte KeyIDOff = 0x02;// 密钥标识的偏移量
    public final byte KeyUseCompeOff = 0x03;// 使用权的偏移量
    public final byte KeyUpdateCompeOff = 0x04;// 修改权的偏移量
    public final byte KeyEditionOff = 0x05;// 密钥版本的偏移量
    public final byte KeyArithMarkOff = 0x06;// 密钥标识的偏移量
    public final byte KeyErrorCountOff = 0x05;// 错误计数的偏移量
    public final byte KeyNextStateOff = 0x06;// 后续状态的偏移量（交易密钥中表示3次MAC错是否锁应用的标志）
    public final byte SFIOff = 0x03;// SFI(短文件标识符）在文件头中的偏移量

    // 文件头中各属性的偏移量
    public final byte FileLenOff = 0x03;// 文件长度在文件头中的偏移量
    public final byte ReadCompeOff = 0x05;// 访问权限1（一般为读权限）的偏移量
    public final byte CreatCompeOff = 0x05;// DF:建立文件的权限
    public final byte WriteCompeOff = 0x06;// 访问权限2（一般为写权限）的偏移量
    public final byte EraseCompeOff = 0x06;// DF:擦除文件的权限
    public final byte LockAttrOff = 0x07;// DF:锁定状态
    public final byte SecuAttrOff = 0x08;// 安全属性在文件头中的偏移量
    public final byte FileNumOff = 0x08;// DF:DF中所包含的文件个数
    public final byte RecNumOff = 0x09;// 记录数在文件头中的偏移量
    public final byte CardStatusFlagOff = 0x09;// MF:卡状态标志
                                               // B0：0x00:个人化未结束，0x01:个人化已经结束
                                               // B1：0x00:MF未创建，0x01:MF已经创建
    public final byte FixedRecLenOff = 0x0B;// 定长记录记录长度在文件头中的偏移量
                                            // 性能优化 hsp 20140625
    public final byte AIDLenOff = 0x0A;// DF:表示AID的长度5-16
    public final byte TotalRecNumOff = 0x0C;// 记录文件中允许的最大记录数 //性能优化 hsp 20140625
    public final byte ApplicatonTypeOff = 0x0B;// DF:应用类型
    public final byte NRecAddrOff = 0x0A;// 循环记录中最新记录的位置（数据占1字节）
                                         // 此处的循环记录的位置指相对位置，是指在该记录文件中在第几条记录的位置处（0-N）
                                         // 性能优化 hsp 20140625
    public final byte DirSFIOff = 0x0C;// DF:Dir SFI

    // 临时数组中各变量的偏移量（当前DF，EF）
    public final byte ramShortLen = 0x06;// 临时short数组的长度
    public final byte ramByteLen = 0x03;// 临时byte数组的长度

    // ramShort1中的偏移量
    public final byte NEFAddrOff = 0x01;// 当前EF的头文件的编移地址；
    public final byte NxtAIDAddrOff = 0x02;// 被选中的AID所在文件的下一个文件的地址的偏移地址
    public final byte DFRestFileNumOff = 0x03;// 当前DF下剩余的文件数//select P2=04时使用
    public final byte NDFParentAddrOff = 0x04;// 当前DF的上一级DF地址的偏移地址

    // ramByte1中的偏移量
    public final byte SecuRegOff = 0x01;// 安全状态寄存器的偏移地址
    public final byte PINIndexOff = 0x02;// MyPIN的指针变量
    
    //文件系统链表指针偏移量
    public final byte DF_SonDF_Off = 0x20;// DF文件头中子DF的偏移位置
    public final byte DF_BrotherDF_Off = 0x22;// DF文件头中兄DF的偏移位置
    public final byte DF_FatherDF_Off = 0x24;// DF文件头中父DF的偏移位置
    public final byte DF_EF_Off = 0x26;// DF文件头中子EF的偏移位置
    public final byte EF_EF_Off = 0x10;// EF文件头中子EF的偏移位置

    public final byte[] TransportKey =
    { 0x43, 0x61, 0x72, 0x64, 0x54, 0x72, 0x61, 0x6E };// 传输码
    public final byte[] Version_inf =
    { 0x14, 0x09, 0x17, (byte)0xED, (byte)0x82, 0x16 };// 代码的版本信息，时间+应用缩写+主版本号+子版本号

    public final byte DAMK_KEY_INDEX = 0x00;// 3600
    public final byte EDU1 = (byte)0x11;// 移动修改透支限额交易类型标示
    /* 常量 END */

    /* RAM START */
    public byte[] ramByte;
    public short[] ramShort;// ramShort[0]临时存储密钥记录的偏移地址

    // 交易使用的RAM数组
    public byte[] SESKEY; // 过程密钥
    public byte[] transNO; // 交易序号
    public byte[] transSum; // 交易金额
    public byte[] machineNUM;// 机器编号
    public byte[] tillTransNO;// 终端交易序号
    public byte[] balance;// ED/EP 余额
    public byte[] overDrawLimit;// 透支限额
    public byte[] dateandTime; // 日期和时间

    public byte[] Random;// 随机数
    public byte[] buffer;// 通用缓冲区 286字节
    public byte[] init;// 初始向量缓冲区
    public byte[] MAC_BUF; // 12 BYTES LEN 前八个字节是TAC_MAC，后四个字节是MAC_BUF
    public short[] big1;// 加减法临时缓冲区
    public short[] big2;// 加减法临时缓冲区

    public Signature MACcalculate;// Mac计算对象 8字节
    public Signature MACcalculate16;// Mac计算对象 16字节
    public DESKey deskey;// 密钥对象 8字节
    public DESKey deskey16;// 密钥对象 16字节
    public Cipher cipherECB;// 加密计算对象
    public RandomData randomData;// 生成随机数的对象

    public short[] ramShort1;// 临时short型数据，掉电或取消选择时丢失
    public byte[] ramByte1;// 临时byte型数组
    public AID selectedAID;// 被选中的AID
    public byte[] KeyPurviewEffective; // Key文件创建权限生效标志，在Select命令中赋值
    public byte[] g_tradeFlag;// 只有1个字节长度，去建设部认证码标识
    public byte[] VarCurrentRec;// 记录文件中当前记录的指针
    public short[] ADFadd;// AID方式选择DF时临时存储复合要求的所有ADF的地址
    public byte[] INS_save;// 存储上一条指令INS hsp
    public byte[] MasterKey_flag; // 用于区分是不是主控密钥 hsp
    public short[] keySer;// 临时存储密钥地址，建议修改为RAM变量 hsp
    public byte[] capp_cache_num; // hsp
    public short[] gLength;// 存储记录长度 hsp
    /* RAM END */

    /* FLASH START */
    public byte[] C9_Flag;// C9参数中相应的参数配置信息
                          // C9_Flag[0]:变长记录文件记录数据格式完全按照TLV的规范进行，否则兼容现有的版本
                          // C9_Flag[1]:1.支持无ADF应用；0.不支持无ADF应用
    public short[] Erase_File_AddrStart;// 记录删除文件的起始地址
    public byte[] MF;// 文件系统存储区
    public short sizeOfMF;// 从C9中获取的MF值
    public byte[] ZJB_Number; // 建设部认证码
    public final byte TRANS_KEY_VERIFY = 0x04;// 传输码校验标志位
    public byte OpenCard_flag = 0;// 开卡标识，0：未开卡，1：已开卡
    public short Uifreepointer = 0;// 自由指针
    public boolean cmEP;// 移动(china mobile)EP标志，为TRUE表示移动EP,为FALSE表示标准EDEP
    public static byte cardLock = 0;// 卡状态，0未锁定，1已经锁定
    /* FLASH END */

    /**
     * 变量初始化
     * 
     * @param[bArray] [存放安装指令的buf，结构:L+可执行加载文件AID+L+可执行模块AID+L+C9参数]
     * @param[bOffset] [偏移到可执行加载文件AID的L字段的偏移量]
     * @param[bLength] [buf总长度]
     */
    public void initEDEPPro(byte[] bArray, short bOffset, byte bLength)
    {
        byte Dist_C9_Flag;// 性能优化 hsp 20140625
        byte i;
        
        ramByte = JCSystem.makeTransientByteArray(ramByteLenEDEP, JCSystem.CLEAR_ON_RESET);
        ramShort = JCSystem.makeTransientShortArray(ramShortLenEDEP, JCSystem.CLEAR_ON_RESET);
        SESKEY = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_RESET);
        transNO = JCSystem.makeTransientByteArray((short)2, JCSystem.CLEAR_ON_RESET);
        transSum = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);
        machineNUM = JCSystem.makeTransientByteArray((short)6, JCSystem.CLEAR_ON_RESET);
        tillTransNO = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);
        balance = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);
        overDrawLimit = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_RESET);
        dateandTime = JCSystem.makeTransientByteArray((short)7, JCSystem.CLEAR_ON_RESET);
        buffer = JCSystem.makeTransientByteArray((short)(286), JCSystem.CLEAR_ON_RESET);
        Random = JCSystem.makeTransientByteArray((short)9, JCSystem.CLEAR_ON_RESET);
        init = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_RESET);
        MAC_BUF = JCSystem.makeTransientByteArray((short)12, JCSystem.CLEAR_ON_RESET);
        MasterKey_flag = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_RESET);// 性能优化
                                                                                            // hsp
                                                                                            // 20140625
        INS_save = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_RESET);// 性能优化
                                                                                      // hsp
                                                                                      // 20140625
        keySer = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_RESET);// 性能优化
                                                                                     // hsp
                                                                                     // 20140625
        capp_cache_num = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_RESET);// 性能优化
                                                                                            // hsp
                                                                                            // 20140625
        gLength = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_RESET);// 性能优化
                                                                                      // hsp
                                                                                      // 20140625
        big1 = JCSystem.makeTransientShortArray((short)4, JCSystem.CLEAR_ON_RESET);
        big2 = JCSystem.makeTransientShortArray((short)4, JCSystem.CLEAR_ON_RESET);
        cipherECB = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, true);
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        C9_Flag = new byte[16];
        for (i = 0; i < (byte)16; i++)
        {
            C9_Flag[i] = (byte)0;
        }
        Erase_File_AddrStart = new short[2];// Erase_File_AddrStart[0]:删除文件链表的起始地址，
        for (i = 0; i < 2; i++) // Erase_File_AddrStart[1]：文件创建时，查找到删除文件中有合适的空间，
                                //该变量存储该删除文件的上一级文件的起始地址，用于删除文件链表的维护
        {
            Erase_File_AddrStart[i] = (short)0;
        }
        MACcalculate = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_M2, true);
        MACcalculate16 = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3, true);
        deskey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, 
                                        KeyBuilder.LENGTH_DES, false); // added
                                                                       // 修改读E2RAM为读RAM
        deskey16 = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, 
                                        KeyBuilder.LENGTH_DES3_2KEY, false);
        VarCurrentRec = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_RESET);
        ADFadd = JCSystem.makeTransientShortArray((short)16, JCSystem.CLEAR_ON_RESET);
        Dist_C9_Flag = 0;// 移动/PBOC标示位
        capp_cache_num[0] = 0;

        /*获取INSTALL指令C9数据*/
        short offset = (short)(bOffset + bArray[bOffset]
                        + bArray[(short)(bOffset + 1 + bArray[bOffset])] + 2);// 取C9对应的长度的偏移量
        sizeOfMF = Util.getShort(bArray, (short)(offset + 1));// 根据C9字段配置文件系统空间大小
        Dist_C9_Flag = (byte)bArray[(short)(offset + 3)];// 根据C9字段区分标准EDEP或者是移动EP
        if (((byte)bArray[(short)(offset + 5)] & 0x04) == 0x04)
        {
            C9_Flag[0] = 1;// modify by zhengtao 20140308
                           // C9中的配置参数放在C9_Flag中，减少变量个数
        }
        C9_Flag[1] = (byte)(bArray[(short)(offset + 5)] & 0x01);
        cmEP = false;
        if ((Dist_C9_Flag & 0x01) == 01)
        {
            cmEP = true;// 表示当前应用为移动EP
        }
        if ((short)(sizeOfMF & (short)0x8000) == (short)0x8000)// 如果根据C9字段确定的空间大小为负数，即超过0x7FFF，
                                                               // 空间大小配置为默认状态，0x2000,8K
                                                               
        {
            MF = new byte[EEPROMSize];// 将EEPROM设置为一维数组中可实现的最大容量32767
            sizeOfMF = EEPROMSize;
        }
        else
        {
            MF = new byte[sizeOfMF];
        }
        
        ramShort1 = JCSystem.makeTransientShortArray(ramShortLen, JCSystem.CLEAR_ON_RESET);
        ramByte1 = JCSystem.makeTransientByteArray(ramByteLen, JCSystem.CLEAR_ON_RESET);
        ZJB_Number = new byte[10];
        g_tradeFlag = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_RESET);
        KeyPurviewEffective = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_RESET);
    }

    /**
     * 通过SFI来寻找当前DF目录下的EF文件，并将该文件的地址返回。按照链式方法查找文件，modify by zhengtao 20131216
     * 
     * @param[SFI] [短文件标识符]
     * @param[flag] [flag=0表示如果找到对应的SFI，则改变当前EF的值，flag=1表示如果找到对应的SFI，不改变当前EF的值。]
     * @return[找到的相应的SFI的起始地址,返回-1表示未找到]
     */
    public short searchFileAddrBySFI(byte SFI, byte flag)
    {
        short lAddr;// =0; hsp
        short Ef_Off;// =0; hsp
        byte SFI_Off = 7;
        
        VarCurrentRec[0] = 0;// 通过SFI方式查找EF文件时，当前记录指针复位；
        lAddr = ramShort1[0];// ramShort1[0]存储的是当前DF文件的偏移地址
        Ef_Off = DF_EF_Off;// 首先查找当前DF文件的子EF

        if ((lAddr = Util.getShort(MF, (short)(lAddr + Ef_Off))) == 0)// 获取相应文件的偏移
                                                                      // hsp
        {
            return -1;
        }

        if ((byte)MF[(short)(lAddr + SFI_Off)] != SFI)// 如果和要查找的文件的SFI一致，跳出
        {
            Ef_Off = EF_EF_Off;// 如果不一致，继续查找当前EF文件的兄EF文件

            for (;;)
            {
                lAddr = Util.getShort(MF, (short)(lAddr + Ef_Off)); // 获取相应文件的偏移
                if (lAddr == (short)0)// 如果到最后一级仍未找到，返回-1
                {
                    return -1;
                }
                if ((byte)MF[(short)(lAddr + SFI_Off)] == SFI)// 如果和要查找的文件的SFI一致，跳出
                {
                    break;
                }
            }
        }
        /* 将选中的DF做为当前DF 隐式文件不改变其为当前文件 */
        if ((flag == 0) && ((MF[(short)(lAddr + 2)] & 0x90) == 0x00))// 要求改变当前EF状态，将该EF置为当前EF
        {
            ramShort1[NEFAddrOff] = lAddr;
        }
        return lAddr;// 返回相应的地址
    }

    /**
     * 根据FID寻找当前DF下的文件 1.按照链式结构查找；2.首先查找DF文件，完毕后查找EF文件。modify by zhengtao
     * 20131216
     * 
     * @param[FID] [文件标识符]
     * @param[flag] [flag:00找到相同的FID后要做为当前DF，其它：找到相同的FID后当前DF不改变]
     * @return[找到的相应的FID的起始地址,返回-1表示未找到]
     */
    public short searchFileAddrByFID(short FID, byte flag)
    {
        short lAddr;// =0; hsp
        short NFID;// =(short)0xffff; hsp
        short Off;
        short Sonorbro_off;
        byte find_Ok = 0;
        
        if (FID == 0x3F00)// 如果要查找的是3F00
        {
            if (Util.getShort(MF, (short)0) != 0x3F00)// 查找文件中3f00是否存在
            {
                return -1;// 如果不存在，返回-1
            }
            if (flag == 0)
            {
                ramShort1[0] = 0x00;// 将当前DF设置为MF
                ramShort1[NDFParentAddrOff] = 0x00;// 当前DF的上级DF置为MF自己
            }
            return 0;
        }
        if (flag != 3)
        {
            NFID = Util.getShort(MF, ramShort1[0]);// 如果找的不是3F00，首先检查当前DF文件是否是要找的文件
            if (FID == NFID)
            {
                return ramShort1[0];
            }
        }
        Off = ramShort1[0];// 从当前DF文件的子DF开始找起
        Sonorbro_off = DF_SonDF_Off;
        Off = Util.getShort(MF, (short)(Off + Sonorbro_off));// 找到偏移地址
        if (Off != 0)// 找到最后一级，跳出
        {
            if (FID != Util.getShort(MF, Off))
            {
                Sonorbro_off = DF_BrotherDF_Off;// 否则继续从子DF的兄DF中查找
                for (;;)
                {
                    Off = Util.getShort(MF, (short)(Off + Sonorbro_off));// 找到偏移地址
                    if (Off == 0)// 找到最后一级，跳出
                    {
                        break;
                    }
                    if (FID == Util.getShort(MF, Off))// 如果FID一致，表明找到文件，跳出
                    {
                        find_Ok = 1;
                        break;
                    }
                }
            }
            else// 如果FID一致，表明找到文件，跳出
            {
                find_Ok = 1;
            }
        }

        if ((find_Ok == 0x00) && (flag != 3))// 如果DF文件中没有找到，继续找EF文件
        {
            Off = ramShort1[0];
            Sonorbro_off = DF_EF_Off; // 找子EF文件
            Off = Util.getShort(MF, (short)(Off + Sonorbro_off));// 读取偏移地址
            if (Off != 0)// 找到最后一级，跳出
            {
                if (FID != Util.getShort(MF, Off))
                {
                    Sonorbro_off = EF_EF_Off;// 继续从子EF文件的兄EF文件中查找
                    for (;;)
                    {
                        Off = Util.getShort(MF, (short)(Off + Sonorbro_off));// 读取偏移地址
                        if (Off == 0)// 找到最后一级，跳出
                        {
                            find_Ok = 0; // 表明未找到文件
                            break;
                        }
                        if (FID == Util.getShort(MF, Off))// 如果FID是否一致
                        {
                            VarCurrentRec[0] = 0;
                            find_Ok = 1;// 表明已找到文件
                            break;
                        }
                    }
                }
                else// 如果FID一致，表明找到文件，跳出
                {
                    VarCurrentRec[0] = 0;
                    find_Ok = 1;// 表明已找到文件
                }
            }
        }

        if (find_Ok == 0)// 未找到文件，返回-1
        {
            return -1;
        }
        lAddr = Off;
        if ((flag == 0) || (flag == 3))
        {
            if ((MF[(short)(lAddr + 2)] & 0x30) == 0x30)// 只有选中的为DF，才能将地址置为当前DF
            {
                ramShort1[NDFParentAddrOff] = ramShort1[0];
                ramShort1[0] = lAddr;
            }
            else if ((MF[(short)(ramShort1[0] + LockAttrOff)] & 0x03) != 0x00)// 如果当前应用已被锁定（临时或永久）
            {
                return -1;
            }
            else if ((MF[CardStatusFlagOff] & 0x01) == 0x00)// 选中的为EF且个人化未结束时，则将该EF置为当前EF
            {
                ramShort1[NEFAddrOff] = lAddr;
            }
            else if ((MF[(short)(lAddr + 2)] & 0x08) == 0x0)// 个人化结束且当前文件不为内部文件
            {
                ramShort1[NEFAddrOff] = lAddr;
            }
        }
        return lAddr;
    }

    /**
     * 通过指定的文件起始地址来查找该密钥文件中有没有与指定KID相同的密钥 modify by zhengtao 20131207
     * 
     * @param[keyType] [密钥类型]
     * @param[KID] [密钥标识]
     * @return[如果找到，则返回该记录的起始地址，否则返回-1或-2。-1：未找到文件记录 -2：未找到密钥文件]
     */
    public short getRecordByKID(byte keyType, byte KID)
    {
        short ADF_fileADDR_Offset = 40;
        short typeKID = Util.makeShort(keyType, KID);
        short kfAddr;
        byte i;

        /*性能优化 20140429 zhengtao 如果取DF下的Key文件直接从文件头中读取地址*/
        if ((ramShort1[0] != 0) || (C9_Flag[1] == 1))
        {
            kfAddr = Util.getShort(MF, (short)(ramShort1[0] + ADF_fileADDR_Offset));
        }
        else
        {
            kfAddr = searchFileAddrByFID((short)0x0000, (byte)1);// 密钥文件的地址
        }
        
        short lAddr = (short)(kfAddr + EFHeadLen);// 文件体位置处
        short record_Num = MF[(short)(kfAddr + 9)];// 密钥文件中已有的密钥记录数 modify by
                                                   // zhengtao 20140320
                                                   // 密钥记录数从第一个RFU中读取
        if (kfAddr != -1)
        {
            for (i = 0; i < record_Num; i++)// 当前记录中的文件数
            {
                if ((short)(Util.getShort(MF, (short)(lAddr + 1)) & 0x3fff) 
                                == (short)(typeKID & 0x3fff))// 记录中的密钥的类型和KID和查找的密钥一致
                {
                    return lAddr;
                }
                lAddr = (short)(lAddr + MF[lAddr] + 1);// 每条记录的长度，MF[lAddr]是密钥记录的长度
            }
            return -1;
        }
        else
        {
            return -2;
        }
    }

    /**
     * 校验MAC
     * 
     * @param[buf] [APDU指令缓冲区]
     * @param[typeKID] [所需要的密钥的类型和KID]
     * @param[flag] [为0表示应用锁定，为1表示卡锁定，为2不做任何动作，只返6988，为3代表校验正确时不恢复错误计数器]
     * @return[true:校验成功 false:校验失败]
     */
    public boolean verifyMAC(byte[] buf, short typeKID, byte flag)
    {
        boolean MACStatus = false;
        short tempNDFAddr;// = 0; hsp
        short lc = (short)(buf[ISO7816.OFFSET_LC] & 0x00FF);
        short kAddr = getRecordByKID((byte)((typeKID >> 8) & 0x00FF), 
                        (byte)(typeKID & 0x00FF));// 要找的密钥的起始地址
        
        if (kAddr == -1)// 当前DF下找不到
        {
            if (((short)(typeKID & 0x3F00) == MasterKeyID)
                            && (MasterKey_flag[0] == 1))// 如果要找的是主控密钥，则在MF下再找一次
            {
                tempNDFAddr = ramShort1[0];// 保存当前DF地址
                ramShort1[0] = ramShort1[NDFParentAddrOff];// ADF下主控密钥需要用到MF下的主控密钥去计算MAC，解密,将当前DF置为MF以方便密钥查找
                kAddr = getRecordByKID((byte)((typeKID >> 8) & 0x00FF), 
                                (byte)(typeKID & 0x00FF));// 要找的密钥的起始地址
                ramShort1[0] = tempNDFAddr;// 当前DF恢复为原值
                if (kAddr == -1)// 未找到密钥记录
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(KEY_FILE_NOT_FOUND);
                }
                else if (kAddr == -2)// 未找到密钥文件
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                }
            }
            else// 要找的不是主控密钥，直接返回错误
            {
                JCSystem.commitTransaction();
                if (buf[ISO7816.OFFSET_CLA] == (byte)0x84
                                && buf[ISO7816.OFFSET_INS] == (byte)0x1E)
                {
                    ISOException.throwIt(COMM_WARNING_ERROR);
                }
                else
                {
                    ISOException.throwIt(KEY_FILE_NOT_FOUND);
                }
            }
        }
        else if (kAddr == -2)// 未找到密钥文件
        {
            JCSystem.commitTransaction();
            if (buf[ISO7816.OFFSET_CLA] == (byte)0x84
                            && buf[ISO7816.OFFSET_INS] == (byte)0x1E)
            {
                ISOException.throwIt(COMM_WARNING_ERROR);
            }
            else
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
        }
        if (ramByte[randomFlagOff] == 1)// 随机数已经生成
        {
            if (Random[0] == 4)
            {
                Util.arrayCopyNonAtomic(Random, (short)1, init, (short)0, (short)4);
                Util.arrayFillNonAtomic(init, (short)4, (short)4, (byte)0);
            }
            else
            {
                Util.arrayCopyNonAtomic(Random, (short)1, init, (short)0, (short)8);
            }
        }
        else// 随机数未生成时返回错误代码0x6984
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);// 引用数据无效
        }
        DEA_MAC(init, buf, (short)0, (short)(lc + 1), kAddr, (byte)2);// 生成MAC
        ramByte[randomFlagOff] = 0;// 改变随机数状态标志
        if (Util.arrayCompare(buf, (short)(lc + 1), MAC_BUF, (short)0, (short)4) == 0)// 如果验证成功 
                                                                                      // 性能优化 20140429 zhengtao 两个MAC相关的buf进行调整
        {
            MACStatus = true;
            if (flag == 3)
            {
                return true;
            }
            if (((MF[(short)(kAddr + KeyErrorCountOff)] >> 4) & 0x0F) 
                            != (MF[(short)(kAddr + KeyErrorCountOff)] & 0x0F))// 如果错误次数最大值和剩余错误次数相等，则不用写EEPROM
            {
                MF[(short)(kAddr + KeyErrorCountOff)] = 
                                (byte)((MF[(short)(kAddr + KeyErrorCountOff)] & 0xF0) 
                                                | ((MF[(short)(kAddr + KeyErrorCountOff)] >> 4) & 0x0F));// 错误次数恢复最大值
            }
        }
        else// 如果验证失败
        {
            if (flag == 2)
            {
                return false;
            }
            if ((MF[(short)(kAddr + KeyErrorCountOff)] & 0x0F) > (byte)0)// 如果错误次数不为0
            {
                MF[(short)(kAddr + KeyErrorCountOff)]--;
            }
            if (MF[(short)(ramShort1[0] + 2)] == DDFType)// 如果当前文件在DDF或MF下，则不锁应用或锁卡
            {
                return false;
            }
            if ((MF[(short)(kAddr + KeyErrorCountOff)] & 0x0F) == (byte)0)// 如果错误次数为0
            {
                if ((flag == 0) || (flag == 3))// 应用永久锁定
                {
                    MF[(short)(ramShort1[0] + LockAttrOff)] = (byte)((short)(MF[(short)(ramShort1[0] + LockAttrOff)] & 0xFC) | 0x02);
                    JCSystem.commitTransaction();
                    ISOException.throwIt(APPLICATION_LOCED_PERMANENT);// MAC验证第三次失败返9303
                }
                else if (flag == 1)// 卡片锁定
                {
                    cardLock = 1;
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
            }
        }
        return MACStatus;
    }
    
    /**
     * 查找密钥并对密钥使用权限及密钥限制计数器进行检查 add by yujing
     * 
     * @param[keyType] [密钥类型]
     * @param[KID] [密钥标识]
     * @return[要找的密钥的起始地址]
     */
    public short checkBeforeUseKey(byte keyType, byte KID)
    {
        short kAddr = getRecordByKID(keyType,KID);// 要找的密钥的起始地址
        if (kAddr == -1)// 未找到密钥记录
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(KEY_FILE_NOT_FOUND);
        }
        else if (kAddr == -2)// 未找到密钥文件
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        if (!checkSecurity(MF[(short)(kAddr + KeyUseCompeOff)]))// 校验密钥记录的使用权限 
        {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (((MF[(short)(kAddr + KeyErrorCountOff)] & 0x0F) == 0x00) && (MF[(short)(ramShort1[0] + 2)] != DDFType))// 如果错误次数为0且在应用下 modify by yujing
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(APPLICATION_LOCED_PERMANENT);// MAC验证第三次失败返9303
        }
        return kAddr;
    }
    
    /**
     * 校验MAC，用于PIN解锁指令
     * 
     * @param[buf] [APDU指令缓冲区]
     * @param[keyAddr] [密钥地址]
     * @param[flag] [为0表示应用锁定，为1表示卡锁定，为2不做任何动作，只返6988，为3代表校验正确时不恢复错误计数器]
     * @return[true:校验成功 false:校验失败]
     */
    public boolean verifyMACforPINUnblock(byte[] buf, short keyAddr, byte flag)
    {
        boolean MACStatus = false;
        short lc = (short)(buf[ISO7816.OFFSET_LC] & 0x00FF);
        
        if (ramByte[randomFlagOff] == 1)// 随机数已经生成
        {
            if (Random[0] == 4)
            {
                Util.arrayCopyNonAtomic(Random, (short)1, init, (short)0, (short)4);
                Util.arrayFillNonAtomic(init, (short)4, (short)4, (byte)0);
            }
            else
            {
                Util.arrayCopyNonAtomic(Random, (short)1, init, (short)0, (short)8);
            }
        }
        else// 随机数未生成时返回错误代码0x6984
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);// 引用数据无效
        }
        DEA_MAC(init, buf, (short)0, (short)(lc + 1), keyAddr, (byte)2);// 生成MAC
        ramByte[randomFlagOff] = 0;// 改变随机数状态标志
        if (Util.arrayCompare(buf, (short)(lc + 1), MAC_BUF, (short)0, (short)4) == 0)// 如果验证成功 
                                                                                      // 性能优化 20140429 zhengtao 两个MAC相关的buf进行调整
        {
            MACStatus = true;
            if (flag == 3)
            {
                return true;
            }
            if (((MF[(short)(keyAddr + KeyErrorCountOff)] >> 4) & 0x0F) 
                            != (MF[(short)(keyAddr + KeyErrorCountOff)] & 0x0F))// 如果错误次数最大值和剩余错误次数相等，则不用写EEPROM
            {
                MF[(short)(keyAddr + KeyErrorCountOff)] = 
                                (byte)((MF[(short)(keyAddr + KeyErrorCountOff)] & 0xF0) 
                                                | ((MF[(short)(keyAddr + KeyErrorCountOff)] >> 4) & 0x0F));// 错误次数恢复最大值
            }
        }
        else// 如果验证失败
        {
            if (flag == 2)
            {
                return false;
            }
            if ((MF[(short)(keyAddr + KeyErrorCountOff)] & 0x0F) > (byte)0)// 如果错误次数不为0
            {
                MF[(short)(keyAddr + KeyErrorCountOff)]--;
            }
            if (MF[(short)(ramShort1[0] + 2)] == DDFType)// 如果当前文件在DDF或MF下，则不锁应用或锁卡
            {
                return false;
            }
            if ((MF[(short)(keyAddr + KeyErrorCountOff)] & 0x0F) == (byte)0)// 如果错误次数为0
            {
                if ((flag == 0) || (flag == 3))// 应用永久锁定
                {
                    MF[(short)(ramShort1[0] + LockAttrOff)] = (byte)((short)(MF[(short)(ramShort1[0] + LockAttrOff)] & 0xFC) | 0x02);
                    JCSystem.commitTransaction();
                    ISOException.throwIt(APPLICATION_LOCED_PERMANENT);// MAC验证第三次失败返9303
                }
                else if (flag == 1)// 卡片锁定
                {
                    cardLock = 1;
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
            }
        }
        return MACStatus;
    }


    /**
     * 校验MAC 用于移动钱包密钥的建立和更新
     * 
     * @param[buf] [APDU指令缓冲区]
     * @param[typeKID] [所需要的密钥的类型和KID]
     * @param[flag] [为0表示应用锁定，为1表示卡锁定，其它表示不做任何动作，只返6988]
     * @return[true:校验成功 false:校验失败]
     */
    public boolean verifyMAC_For_WRKEY(byte[] buf, short typeKID, byte flag)
    {
        boolean MACStatus = false;
        short tempNDFAddr;// = 0; hsp
        short kAddr = getRecordByKID((byte)((typeKID >> 8) & 0x00FF), 
                                     (byte)(typeKID & 0x00FF));// 要找的密钥的起始地址
        
        if (kAddr == -1)// 当前DF下找不到
        {
            if ((short)(typeKID & 0x3f00) == MasterKeyID)// 如果要找的是主控密钥，则在MF下再找一次
            {
                tempNDFAddr = ramShort1[0];// 保存当前DF地址
                ramShort1[0] = 0x00;// ADF下主控密钥需要用到MF下的主控密钥去计算MAC，解密,将当前DF置为MF以方便密钥查找
                kAddr = getRecordByKID((byte)((typeKID >> 8) & 0x00FF), 
                                       (byte)(typeKID & 0x00FF));// 要找的密钥的起始地址
                ramShort1[0] = tempNDFAddr;// 当前DF恢复为原值
                if (kAddr == -1)
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(KEY_FILE_NOT_FOUND);
                }
                else if (kAddr == -2)
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                }
            }
            else
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(KEY_FILE_NOT_FOUND);
            }
        }
        else if (kAddr == -2)
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        Util.arrayFillNonAtomic(init, (short)0, (short)8, (byte)0);
        /*生成MAC*/
        ramShort[0] = kAddr;
        SESKEYOdbm();
        DEA_MAC(init, buf, (short)0, 
                (short)((buf[ISO7816.OFFSET_LC] + 5 - 4) & 0x00FF), 
                kAddr, (byte)1);
        /*比较MAC*/
        ramByte[randomFlagOff] = 0;// 改变随机数状态标志
        if (Util.arrayCompare(buf, 
                              (short)((buf[ISO7816.OFFSET_LC] + 1) & 0x00FF), MAC_BUF, 
                              (short)0, (short)4) == 0)// 如果验证成功
        {
            MACStatus = true;
            if (((MF[(short)(kAddr + KeyErrorCountOff)] >> 4) & 0x0F) 
                            != (MF[(short)(kAddr + KeyErrorCountOff)] & 0x0F))// 如果错误次数最大值和剩余错误次数相等，则不用写EEPROM
            {
                MF[(short)(kAddr + KeyErrorCountOff)] = (byte)((MF[(short)(kAddr + KeyErrorCountOff)] & 0xF0) 
                                | ((MF[(short)(kAddr + KeyErrorCountOff)] >> 4) & 0x0F));// 错误次数恢复最大值
            }
        }
        else// 如果验证失败
        {
            if (flag == 2)
            {
                return false;
            }
            if ((MF[(short)(kAddr + KeyErrorCountOff)] & 0x0F) > 0x00)// 如果错误次数不为0
            {
                MF[(short)(kAddr + KeyErrorCountOff)]--;
            }
            if (MF[(short)(ramShort1[0] + 2)] == DDFType)// 如果当前文件在DDF或MF下，则不锁应用或锁卡
            {
                return false;
            }
            if ((MF[(short)(kAddr + KeyErrorCountOff)] & 0x0F) == 0x00)// 如果错误次数为0
            {
                if (flag == 0)// 应用永久锁定
                {
                    MF[(short)(ramShort1[0] + LockAttrOff)] = (byte)((short)(MF[(short)(ramShort1[0] + LockAttrOff)] & 0xFC) | 0x02);
                    JCSystem.commitTransaction();
                    ISOException.throwIt(APPLICATION_LOCED_PERMANENT);// MAC验证第三次失败返9303
                }
                else if (flag == 1)// 卡片锁定
                {
                    cardLock = 1;
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
            }
        }
        return MACStatus;
    }

    /**
     * 验证是否满足操作的权限
     * 
     * @param[SC] [权限值 ]
     */
    public boolean checkSecurity(byte SC)
    {
        byte tempByte;

        if (KeyPurviewEffective[0] == 0)// 如果当前DF下没有EF文件时，权限不生效
        {
            return true;
        }
        tempByte = (byte)(ramByte1[SecuRegOff] & 0x0f); // hsp
        if (((byte)((SC >> 4) & 0x0F) >= tempByte)
                        && (tempByte >= (byte)(SC & 0x0F)))
        {
            return true;
        }
        return false;
    }

    /**
     * 根据RecNo来查找指定EF变长记录文件的记录
     * 注意：在使用此函数前，请判断RecNo的值是否会超出记录文件中现有记录数的范围
     * 检查TLV格式时，现有的Native版本未完全按照规范进行，为了兼容现有版本，而且也可以完全按照规范进行，通过
     * C9字段确定参数C9_Flag[0]，表明是按照规范进行还是兼容现有版本
     * 
     * @param[efAddr] [EF变长记录文件的文件头地址]
     * @param[RecNo] [记录号]
     * @return[记录的地址，如返回值为-1表示未找到该文件]
     */
    public short getRecordByRecNo(short efAddr, short RecNo)
    {
        short totalLength = 0;
        byte recordNum = MF[(short)(efAddr + RecNumOff)];// 获得记录文件中的记录数
        byte i;

        efAddr = (short)(efAddr + EFHeadLen);
        for (i = 0; i < recordNum; i++)// 循环方式逐条查找记录
        {
            if(C9_Flag[0] == 1)//按照标准的TLV格式进行判断
            {
                if((MF[efAddr] & 0x1F) == 0x1F)//如果低五位为1F时，表明有两个TAG
                {
                    if(((short)(MF[(short)(efAddr + 2)] & 0x00FF) > 0x0081) || (MF[(short)(efAddr + 2)] == (byte)0x80))//长度标志不可能大于0x81,否则报错
                    {
                        ISOException.throwIt(TLV_FORMAT_NOT_MATCHED);
                    }
                    if(MF[(short)(efAddr + 2)] == (byte)0x81)//循环记录的前两个字节是TAG,如果第三个字节是81，表明第四个字节表示记录长度
                    {
                        totalLength = (short)((MF[(short)(efAddr + 3)] & 0x00FF) + 4);
                    }
                    else
                    {
                        totalLength = (short)((MF[(short)(efAddr+2)]&0x00FF)+3);
                    }
                }
                else//记录中只有一个TAG
                {
                    if(((short)(MF[(short)(efAddr + 1)] & 0x00FF) > 0x0081) || (MF[(short)(efAddr + 2)] == (byte)0x80))//长度标志不可能大于0x81,否则报错
                    {
                        ISOException.throwIt(TLV_FORMAT_NOT_MATCHED);
                    }
                    if(MF[(short)(efAddr + 1)] == (byte)0x81)
                    {
                        totalLength = (short)((MF[(short)(efAddr + 2)] & 0x00FF) + 3);
                    }
                    else
                    {
                        totalLength = (short)((MF[(short)(efAddr + 1)] & 0x00FF) + 2);
                    }
                }
            }
            else
            {
                totalLength = (short)((MF[(short)(efAddr + 1)] & 0x00FF) + 2);                  
            }
            if ((i + 1) == RecNo)
            {
                break;// 找到指定的记录号
            }
            efAddr += totalLength;
        }
        if ((i + 1) != RecNo)
        {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);// 越界，返错
        }
        gLength[0] = totalLength;
        return efAddr;
    }

    /**
     * 检查数据是否为TLV格式
     * 
     * @param[arr] [数据的存储buf]
     * @param[off] [被检查数据在buf中的偏移]
     * @param[length] [被检查数据的长度]
     * @return[-1：数据格式不符合TLV格式；其他：L的值]
     */
    public short checkTLVFormat(byte[] arr, short off, short length)
    {
        short tlLen;// TVL中Tag和lenth所占的字节数
        short len;// value值的长度
        
        if (C9_Flag[0] == 1)// 按照标准的TLV规范进行检查
        {
            if ((arr[off] & 0x1F) == 0x1F)// 记录的第一个字节低5位为1F，表明是两个TAG
            {
                if (((short)(arr[(short)(off + 2)] & 0x00FF) > (short)0x0081)
                                || (arr[(short)(off + 2)] == (byte)0x80))// 长度标志不可能大于0x81,否则报错
                {
                    return -1;
                }
                if (arr[(short)(off + 2)] == (byte)0x81)// 该字节为81时，表明其后的是长度字节
                {
                    tlLen = 4;// 两个TAG+一个81+一个L
                    len = (short)(arr[(short)(off + 3)] & 0x00FF);
                }
                else
                {
                    tlLen = 3;
                    len = (short)(arr[(short)(off + 2)] & 0x00FF);
                }
            }
            else// 只有一个TAG
            {
                if (((short)(arr[(short)(off + 1)] & 0x00FF) > (short)0x0081)
                                || (arr[off] == (byte)0x80))// 长度标志不可能大于0x81,否则报错
                {
                    return -1;
                }
                if (arr[(short)(off + 1)] == (byte)0x81)// 该字节为81时，表明其后的是长度字节
                {
                    tlLen = 3;
                    len = (short)(arr[(short)(off + 2)] & 0x00FF);
                }
                else
                {
                    tlLen = 2;
                    len = (short)(arr[(short)(off + 1)] & 0x00FF);
                }
            }
        }
        else//兼容现有的Native版本
        {
            if((0 == arr[(short)off]) || (0xff == arr[(short)off]))
            {
                return -1;
            }
            tlLen = 2;
            len = (short)(arr[(short)(off+1)]&0x00FF);
        }
        if ((short)(length - tlLen) != len)
        {
            return -1;
        }
        return len;
    }

    /**
     * 变长记录文件追加记录
     * 
     * @param[efAddr] [变长记录文件地址]
     * @param[buf] [追加记录内容buf]
     * @param[off] [追加记录内容在buf中的偏移]
     * @param[length] [追加记录长度]
     */
    public void appendVarRecord(short efAddr, byte[] buf, short off,
                    short length)
    {
        short addr;
        short efLen;
        
        addr = getRecordByRecNo(efAddr, (byte)(MF[(short)(efAddr + RecNumOff)] + 1));// 找到记录文件中未使用空间的起始地址
        if (addr == -1)// 没有剩余空间
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        efLen = Util.getShort(MF, (short)(efAddr + FileLenOff));// 该记录文件的空间大小

        if (((short)(addr + length) > (short)(efAddr + EFHeadLen + efLen))
                        || ((short)(addr + length) < 0))// 文件剩余空间不够
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        if (checkTLVFormat(buf, off, length) == -1)// 检查记录的TLV格式是否正确
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(TLV_FORMAT_NOT_MATCHED);
        }
        Util.arrayCopy(buf, off, MF, addr, length);// 添加记录
        MF[(short)(efAddr + RecNumOff)]++;// 记录数加1
    }

    /**
     * 循环记录文件追加记录
     * 
     * @param[efAddr] [循环记录文件地址]
     * @param[buf] [追加记录内容buf]
     * @param[off] [追加记录内容在buf中的偏移]
     * @param[length] [追加记录长度]
     */ 
    public void appendCycRecord(short efAddr, byte[] buf, short off,
                    short length)
    {
        byte nonceRec = MF[(short)(efAddr + NRecAddrOff)];// 最新记录是第几条记录
        short recLen = (short)(MF[(short)(efAddr + FixedRecLenOff)] & 0x00FF);// 记录的长度
        byte totalRecNum = 0;
        byte recNum = MF[(short)(efAddr + RecNumOff)];// 性能优化 hsp 20140625
        short sBuf = 0;
        
        if (recLen != 0)
        {
            totalRecNum = (byte)(MF[(short)(efAddr + FixedRecLenOff + 1)]);// 循环记录中共可以容纳的记录数=文件体大小/每条记录长度
        }
        if ((recLen == 0) || (totalRecNum == 0))// 如果记录长度为0或者记录文件中的总记录数为0
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_FILE_FULL);// 文件空间不足
        }
        if (length != recLen)// 追加的记录长度和记录文件的记录长度不一致
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (0 == recNum)// 第一条记录
        {
            MF[(short)(efAddr + RecNumOff)]++;
        }
        else if (recNum >= totalRecNum)// 循环添加，只更新记录指针
        {
            MF[(short)(efAddr + NRecAddrOff)] = (byte)((nonceRec + 1) % totalRecNum);
        }
        else// 记录数未满，记录指针与记录数同时更新
        {
            recNum++;
            sBuf = (short)((((short)recNum & 0x00ff) << 8) | (((short)((nonceRec + 1) % totalRecNum)) & 0x00ff));
            Util.setShort(MF, (short)(efAddr + RecNumOff), sBuf);
        }
        Util.arrayCopy(buf, off, MF, (short)(efAddr + EFHeadLen + MF[(short)(efAddr + NRecAddrOff)]
                        * recLen), recLen);
    }


    /**
     * 追加记录，在记录文件中追加新的记录，前提是有足够的空间 包括变长记录，循环记录
     * 注：定长记录中，在文件建立初始，文件记录就是满的，以后只能修改不追加 modify by zhengtao 20131216
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_00E2(APDU apdu)
    {
        short length;// = 0; hsp
        short off;// = 0; hsp
        short kAddr;// yujing
        byte type;// = 0; hsp
        short lEFAddr;
        byte[] buf = apdu.getBuffer();

        if ((buf[ISO7816.OFFSET_CLA] != (byte)0)
                        && (buf[ISO7816.OFFSET_CLA] != (byte)0x04))// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (buf[ISO7816.OFFSET_P1] != 0x00)// 追加记录时P1必须为0
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if ((buf[ISO7816.OFFSET_P2] & 0x07) != 0x00)// B2B1B0如果不为0
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (buf[ISO7816.OFFSET_LC] == 0x00)// 如果追加的数据长度为0
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
        if ((buf[ISO7816.OFFSET_P2] & 0xF8) != 0x00)// 追加指定的记录文件
        {
            lEFAddr = searchFileAddrBySFI((byte)(((buf[ISO7816.OFFSET_P2] & 0xF8) >> 3) & 0x1F), (byte)0);// 按SFI访问，P2的高五位为SFI
            if (lEFAddr == -1)
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }

            if (((MF[CardStatusFlagOff] & 0x01) == 0x01)
                            && ((MF[(short)(lEFAddr + 2)] & 0x08) == 0x08))// 如果个人化已经结束且选择的是内部文件
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);// 内部文件不能读，找到也算是未找到
            }
        }
        else
        {
            if (ramShort1[NEFAddrOff] == (short)0x0000)
            {
                ISOException.throwIt(NO_CURRENT_EF);
            }
            lEFAddr = ramShort1[NEFAddrOff];
        }
        if (((short)(MF[(short)(lEFAddr + SecuAttrOff)] & 0x30) != 0x00 && buf[ISO7816.OFFSET_CLA] != 04)
                        || (short)(MF[(short)(lEFAddr + SecuAttrOff)] & 0x30) == 0x00
                        && buf[ISO7816.OFFSET_CLA] != 0x00)
        {
            ISOException.throwIt(CLA_NOT_MATCHED);// CLA不匹配
        }
        length = (short)(buf[ISO7816.OFFSET_LC] & 0x00FF);
        off = ISO7816.OFFSET_CDATA;
        JCSystem.beginTransaction();
        if(((short)MF[(short)(lEFAddr + SecuAttrOff)] & 0x30) != 0x00)
        {
            kAddr = checkBeforeUseKey(DAMK_TYPE, (byte)(MF[(short)(lEFAddr + SecuAttrOff)] & 0x0F));//查找密钥并检查密钥使用权限和限制次数  yujing
            if (((short)MF[(short)(lEFAddr + SecuAttrOff)] & 0x20) == 0x20)// 当前文件要求校验MAC
            {
                if (length <= 4)
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                /*typeKID = (short)((DAMK_TYPE << 8) 
                            | (MF[(short)(lEFAddr + SecuAttrOff)] & (short)0x0F));*/
                
                if (!verifyMACforPINUnblock(buf, kAddr, (byte)0))// 校验MAC modify by yujing
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(FILE_MAC_ERROR);
                }
                length -= 4;
            }
            if ((MF[(short)(lEFAddr + SecuAttrOff)] & 0x10) == 0x10)// 当前文件要求解密数据域
            {
                if ((length % 8) != 0)// 如果要解密的数据不是8的倍数则报错
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                /*short kAddr = getRecordByKID(DAMK_TYPE, 
                                         (byte)(MF[(short)(lEFAddr + SecuAttrOff)] & 0x0F));// 要找的密钥的起始地址
            if (kAddr == -1)// 未找到密钥记录
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(KEY_FILE_NOT_FOUND);
            }
            else if (kAddr == -2)// 未找到密钥文件
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }*/
                DEA_Encrypt(buf, ISO7816.OFFSET_CDATA, length, kAddr, (short)1);// 解密
                length = (short)(buf[ISO7816.OFFSET_CDATA] & 0x00FF);// 加密数据长度
                off++;// 数据域在buf中的偏移量(前一位为LD)
            }
        }
        if ((MF[CardStatusFlagOff] & 0x01) == 0x01)// 个人化已经结束
        {
            if (!checkSecurity(MF[(short)(lEFAddr + WriteCompeOff)]))// 校验文件的写权限
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        }
        type = MF[(short)(lEFAddr + 2)];
        if ((type & 0x30) == (byte)0x30 || (type & 0x07) == 0x02
                        || (type & 0x07) == 0x01)// 除透明文件之外的所有文件都为记录文件(定长记录不能追加)
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(FILE_TYPE_NOT_MATCHED);// 文件类型不匹配
        }
        if ((short)(Util.getShort(MF, (short)(lEFAddr + FileLenOff))) == (short)0)// 如果选择是文件体为0的文件
        {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);// 空间不足
        }
        if ((type & 0x07) == 0x04)// 变长记录文件
        {
            appendVarRecord(lEFAddr, buf, off, length);
        }
        else if ((type & 0x07) == 0x06)// 循环记录文件
        {
            appendCycRecord(lEFAddr, buf, off, length);
            VarCurrentRec[0] = 1;
        }
        else
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(FILE_TYPE_NOT_MATCHED);// 文件类型不匹配
        }
        JCSystem.commitTransaction();
    }

    /**
     * 根据AID寻找当前DF下的DF文件(EF文件没有AID)
     * 注：请SELECT APDU函数在调用该函数之前判断P2不能为0,2以外的其它数
     * 
     * @param[AIDArray] [AID字符串buffer]
     * @param[aOffset] [AID字符串中AID的有效偏移]
     * @param[aLength] [AID长度]
     * @param[P2] [apdu指令中P2参数]
     * @param[flag] [00找到相同的AID后要做为当前DF，其它：找到相同的AID后当前DF不改变]
     * @return[找到的相应的AID的起始地址，没找到对应的AID，则返回-1]
     */
    public short searchFileAddrByAID(byte[] AIDArray, short aOffset,
                    byte aLength, byte P2, byte flag)
    {
        short DFFileNum = MF[(short)(ramShort1[0] + FileNumOff)];// 当前DF下所有的文件个数
        short Off;// =0; hsp
        short SonorBroDF_Off;
        short tShort;
        byte find_Ok = 0;
        byte index = 0;
        byte i;

        if (P2 == (byte)2)// 由于ADFadd只在P2=2时起作用，而现在暂不支持P2=2，顾在此处加判断 hsp
        {
            for (i = 0; i < 16; i++)
            {
                ADFadd[i] = (short)0x00;
            }
        }
        Off = (short)(ramShort1[0]);
        SonorBroDF_Off = DF_SonDF_Off;// 从子DF文件找起
        for (;;)
        {
            /*modify by zhengtao 20140306 AID选择方式应该支持部分AID选择，LC可以比AID的长度小*/
            if ((aLength != 0) && (aLength <= MF[(short)(Off + AIDLenOff)]))
            {
                if ((P2 == 0) || (P2 == 4))
                {
                    if (Util.arrayCompare(MF, (short)(Off + 16), AIDArray, (short)aOffset, aLength) == 0)// 比较AID是否一致
                    {
                        ramShort1[NxtAIDAddrOff] = (short)(Off);// 获得下一个文件的位置
                        ramShort1[DFRestFileNumOff] = (short)(DFFileNum - 1);// 剩余文件数
                        find_Ok = 1;// 已找到文件
                        break;
                    }
                }
                else
                {
                    if (Util.arrayCompare(MF, (short)(Off + 16), AIDArray, (short)aOffset, aLength) == 0)// 比较AID是否一致
                    {
                        ADFadd[index] = Off;
                        index++;
                    }
                }
            }

            tShort = Util.getShort(MF, (short)(Off + SonorBroDF_Off)); // hsp
            if (tShort == (short)0)// 文件系统的最后一级
            {
                find_Ok = 0;// 未找到
                break;
            }
            else
            {
                Off = tShort;// 文件的偏移地址
            }

            SonorBroDF_Off = DF_BrotherDF_Off;// 子DF不满足要求时继续查找子DF的兄DF
            DFFileNum--;
        }
        if (P2 == 2)
        {
            for (i = 0; i < 16; i++)
            {
                if (ADFadd[i] == ramShort1[NxtAIDAddrOff]
                                || ADFadd[i] == (short)0)
                {
                    break;
                }
            }
            if (i + 1 == index)
            {
                find_Ok = 0;
            }
            else if (i == index)
            {
                Off = ADFadd[0];
            }
            else
            {
                Off = ADFadd[i + 1];
            }
        }
        if (find_Ok == 0) // 未找到
        {
            return -1;// 未找到相同的AID
        }
        if ((flag == 0) || (flag == 3))// 将找到的DF置为当前DF
        {
            ramShort1[NDFParentAddrOff] = Util
                            .getShort(MF, (short)(Off + DF_FatherDF_Off));
            ramShort1[0] = Off;// 设置找到的DF为当前DF
        }
        return Off;
    }
    
    /**
     * 选择文件，通过FID或AID来对文件进行选择 modify by zhengtao 20131216
     * 1.如果当前当前DF下没有EF文件时，创建Key文件不需要权限。2.成功选择文件后安全状态寄存器都清零
     * 
     * @param[bufferapdu] [STK菜单通过共享接口调用00A4指令时传入的指令数据]
     * @param[apdu] [APDU对象]
     * @param[flag] [00：通过APDU指令执行00A4指令，FCI信息直接返回；其他：共享接口调用00A4指令，
                                    FCI信息存储在buf中，供STK菜单读取，不能直接返回]
     */
    public void CMD_00A4(byte[] bufferapdu, APDU apdu, byte flag)
    {
        byte[] buf;// 接口修改
        
        if (flag == (byte)0x00)
        {
            buf = apdu.getBuffer();
        }
        else
        {
            buf = bufferapdu;
            apdu = null;
        }

        short FID;// = 0; hsp
        short lAddr = 0;
        short p1p2;// =0; hsp
        short length;// = 0;//记录长度 hsp
        short FCIAddr;// =0; hsp
        short temp = 0;
        short ADF_fileADDr_Offset = 40;
        byte p2 = buf[ISO7816.OFFSET_P2];

        p1p2 = Util.getShort(buf, ISO7816.OFFSET_P1);
        ramByte[GET_RESPONSE_FLAG] = 0;

        if (buf[ISO7816.OFFSET_CLA] != (byte)0)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if ((p1p2 != 0x0000) && (p1p2 != 0x0400) && (p1p2 != 0x0402)
                        && (p1p2 != 0x0404))
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        /* add by zhengtao 20140308 无ADF应用只支持AID选择方式*/
        if (buf[ISO7816.OFFSET_P1] == 0x00)// 按FID选择
        {
            if ((cmEP) && ((MF[CardStatusFlagOff] & 0x01) == 0x01))// 移动钱包不支持FID选择
            {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if (buf[ISO7816.OFFSET_LC] != 2)// FID只能为两位
            {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            if (flag == (byte)0x00)//add by yujing
            {
                apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 
            }
            FID = Util.getShort(buf, ISO7816.OFFSET_CDATA);
            if (FID == (short)0x0000)// 如果FID=0000，返0x6a82,0000是密钥文件，不能选择
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            lAddr = searchFileAddrByFID(FID, (byte)0);// 根据FID查找文件地址
            if (lAddr == -1)// 未找到
            {
                temp = ramShort1[0];
                ramShort1[0] = ramShort1[NDFParentAddrOff];// 如果孩子中找不到，再从兄弟中找
                lAddr = searchFileAddrByFID(FID, (byte)3);
            }
        }
        else if (buf[ISO7816.OFFSET_P1] == 0x04)// 按文件名来选择
        {
            if (flag == (byte)0x00)//add by yujing
            {
                apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 
            }
            if (p2 == 2)
            {
                temp = ramShort1[0];
                ramShort1[0] = ramShort1[NDFParentAddrOff];// 如果孩子中找不到，再从兄弟中找
                ramShort1[NxtAIDAddrOff] = temp;
                lAddr = searchFileAddrByAID(buf, ISO7816.OFFSET_CDATA, buf[ISO7816.OFFSET_LC], p2, (byte)0);
            }
            else
            {
                temp = ramShort1[0];
                ramShort1[0] = ramShort1[NDFParentAddrOff];// 如果孩子中找不到，再从兄弟中找
                lAddr = searchFileAddrByAID(buf, ISO7816.OFFSET_CDATA, buf[ISO7816.OFFSET_LC], p2, (byte)0);
                if (lAddr == -1)
                {
                    ramShort1[0] = temp;
                    lAddr = searchFileAddrByAID(buf, ISO7816.OFFSET_CDATA, buf[ISO7816.OFFSET_LC], p2, (byte)0);
                }
            }
        }
        else
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (lAddr == -1)
        {
            ramShort1[0] = temp;
            if ((MF[(short)(ramShort1[0] + LockAttrOff)] & 0x03) == 0x02)// 如果当前应用（ADF）被永久锁定
            {
                ISOException.throwIt(APPLICATION_LOCED_PERMANENT);// 应用被永久锁定
            }
            else if ((MF[(short)(ramShort1[0] + LockAttrOff)] & 0x03) == 0x01)// 如果当前应用（ADF）被临时锁定
            {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        if (((short)MF[(short)(lAddr + 2)] & 0x30) == 0x30)// 如果选中的为DF文件，注：此处0x80为128，是正数
        {
            if (Util.getShort(MF, (short)(ramShort1[0] + DF_EF_Off)) == 0)// 当前DF下没有EF文件时，创建Key文件不需要权限
                                                                          // add by
                                                                          // zhengtao
                                                                          // 20131203
            {
                KeyPurviewEffective[0] = (byte)0;
            }
            else
            {
                KeyPurviewEffective[0] = (byte)1;
            }
            setSelectRamVar();

            /*返回值的组织*/
            buf[0] = 0x6F;
            buf[2] = (byte)0x84;
            buf[3] = MF[(short)(lAddr + AIDLenOff)];// 当前DF的AID的长度

            Util.arrayCopyNonAtomic(MF, (short)(lAddr + 0x10), buf, (short)4, buf[3]);// 被先中的DF的AID
            buf[4 + buf[3]] = (byte)0xA5;
            if (MF[(short)(lAddr + 2)] == DDFType)// 如果为DDF(包括MF-PSE）
            {
                length = (byte)(4 + buf[3]);
                buf[(short)(length + 1)] = 0x03;// A5 03 88 01
                                                // 01固定值,目录基本文件DirEF的SFI为01
                buf[(short)(length + 2)] = (byte)0x88;
                buf[(short)(length + 3)] = 0x01;
                buf[(short)(length + 4)] = (byte)(MF[(short)(lAddr + DirSFIOff)] & 0x1F);// 取DIR
                                                                                         // EF的SFI
                buf[1] = (byte)(2 + buf[3] + 2 + 3);

                if (apdu != null)
                {
                    apdu.setOutgoingAndSend((short)0, (short)((buf[1] + 2) & 0x00FF));
                }
                else
                {
                    Util.arrayCopyNonAtomic(buf, (short)0, buf, (short)1, (short)((buf[1] + 2) & 0x00FF));
                    buf[0] = (byte)((buf[2] + 2) & 0x00FF);
                    buf[(short)(buf[0] + 1)] = (byte)0x90;
                    buf[(short)(buf[0] + 2)] = (byte)0x00;
                }
            }
            else// ADF 建立的DF文件类型只有DDFType和ADFType两种，没有其它可能，所以此处不用再做判断
            {
                ramByte[appTypeOff] = MF[(short)(ramShort1[0] + ApplicatonTypeOff)];
                if ((MF[(short)(lAddr + LockAttrOff)] & 0x03) == 0x02)// 如果当前应用（ADF）被永久锁定
                {
                    ISOException.throwIt(APPLICATION_LOCED_PERMANENT);// 应用被永久锁定
                }
                buf[buf[3] + 5] = 0x04;// 9F08 01 XX 应用版本号
                Util.setShort(buf, (short)(buf[3] + 6), (short)(0x9F08));// 应用版本号
                buf[buf[3] + 8] = 0x01;// 占一个字节
                Util.setShort(buf, (short)(buf[3] + 10), (short)0x9F0C);// 发卡方自定数据FCI的TAG
                if (cmEP)
                {
                    Util.setShort(buf, (short)(buf[3] + 10), (short)0x9F0C);// 发卡方自定数据FCI的TAG
                }
                /* 性能优化 20140429 zhengtao FCI中控制信息文件直接从文件头中读取*/
                FCIAddr = Util.getShort(MF, (short)(lAddr + ADF_fileADDr_Offset + 12));// 通过FCI
                                                                                       // SFI
                                                                                       // 读
                if (FCIAddr == -1)// 没有建立FCI文件
                {
                    buf[(short)(buf[3] + 9)] = 0x02;// 应用版本号默认为02//CHG by
                                                    // liyong 111125
                    buf[(short)(buf[3] + 12)] = 0;// FCI文件不存在，长度为0
                    buf[(short)(buf[3] + 5)] += 3;// 9F0C 00
                }
                else
                {
                    buf[(short)(buf[3] + 9)] = 0x02;// 应用版本号固定为02，CHG by liyong
                                                    // 111125
                    buf[(short)(buf[3] + 12)] = MF[(short)(FCIAddr + FileLenOff + 1)];// FCI文件体的长度
                    Util.arrayCopy(MF, (short)(FCIAddr + EFHeadLen), buf, 
                                   (short)(buf[3] + 13), 
                                   (short)buf[(short)(buf[3] + 12)]);
                    buf[(short)(buf[3] + 5)] += (buf[(short)(buf[3] + 12)] + 3);// 9F0C
                                                                                // len
                                                                                // FCI文件体大小
                }

                buf[1] = (byte)(4 + buf[3] + buf[(short)(buf[3] + 5)]);
                if ((MF[(short)(lAddr + LockAttrOff)] & 0x03) == 0x01)// 如果当前应用（ADF）被临时锁定
                {
                    /*为00C0取响应准备*/
                    if ((APDU.getProtocol() & (byte)0x80) == (byte)0x80)// ctless
                    {
                        if (apdu != null)
                        {
                            apdu.setOutgoingAndSend((short)0, (short)((buf[1] + 2) & 0x00FF));
                        }
                    }
                    else
                    {
                        ramByte[GET_RESPONSE_FLAG] = 1;
                        Util.arrayCopyNonAtomic(buf, (short)0, buffer, (short)0, (short)((buf[1] + 2) & 0x00FF));
                    }
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
                else
                {
                    if (apdu != null)
                    {
                        apdu.setOutgoingAndSend((short)0, (short)((buf[1] + 2) & 0x00FF));
                    }
                    else// 接口返回值,可以只返回9000
                    {
                        Util.arrayCopyNonAtomic(buf, (short)0, buf, (short)1, (short)((buf[1] + 2) & 0x00FF));
                        buf[0] = (byte)((buf[2] + 2) & 0x00FF);
                        buf[(short)(buf[0] + 1)] = (byte)0x90;
                        buf[(short)(buf[0] + 2)] = (byte)0x00;
                    }
                }
            }
        }
        else
        {
            
            if (flag != (byte)0x00)// EF E0 文件直接返回9000
            {
                buf[0] = (byte)0x00;
                buf[(short)(buf[0] + 1)] = (byte)0x90;
                buf[(short)(buf[0] + 2)] = (byte)0x00;
                return;
            }
            if ((MF[(short)(ramShort1[0] + LockAttrOff)] & 0x03) == 0x02)// 如果当前应用（ADF）被永久锁定
            {
                ISOException.throwIt(APPLICATION_LOCED_PERMANENT);// 应用被永久锁定
            }
            else if ((MF[(short)(ramShort1[0] + LockAttrOff)] & 0x03) == 0x01)// 如果当前应用（ADF）被临时锁定
            {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            if ((MF[(short)(lAddr + 2)] & 0x08) == 0x08
                            && (MF[CardStatusFlagOff] & 0x01) == 0x01)// 如果找到的为内部文件且个人化已经结束
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
        }
    }

    /**
     * 产生4或8字节的随机数
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_0084(APDU apdu)// Get Challenge
    {
        byte[] buf = apdu.getBuffer();

        if (buf[ISO7816.OFFSET_CLA] != (byte)0)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if ((buf[ISO7816.OFFSET_P1] != 0) || (buf[ISO7816.OFFSET_P2] != 0))
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if ((buf[ISO7816.OFFSET_LC] != 0x04) && (buf[ISO7816.OFFSET_LC] != 0x08))
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        ProduceRandom(buf[ISO7816.OFFSET_LC]);// 产生4字节的随机数
        ramByte[randomFlagOff] = 1;// 设置随机数标志位为1
        Util.arrayCopyNonAtomic(Random, (short)1, buf, (short)0, Random[0]);
        apdu.setOutgoingAndSend((short)0, Random[0]);
    }

    /**
     * Card Issue结束个人化
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_800A(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();

        if (buf[ISO7816.OFFSET_CLA] != (byte)0x80)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if ((buf[ISO7816.OFFSET_P1] != 0) || (buf[ISO7816.OFFSET_P2] != 0x02))
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);// 参数错误
        }
        if (buf[ISO7816.OFFSET_LC] != 0x00)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);// 长度错误
        }
        if (((byte)((MF[CardStatusFlagOff] >> 2) & 0x01) != 0x01)
                        || ((MF[CardStatusFlagOff] & 0x01) == 0x01))// 如果传输码未校验或个人化已经结束
        {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        JCSystem.beginTransaction();
        ramShort1[0] = 0;// 当前DF置0
        ramShort1[NEFAddrOff] = 0;// 当前EF置0
        JCSystem.commitTransaction();
    }

    /**
     * 更新密钥
     * 
     * @param[keyType] [密钥类型]
     * @param[KID] [密钥标识]
     * @param[buf] [要更新的数据源]
     * @param[Off] [数据源中有效数据偏移]
     */
    public void updateKey(byte keyType, byte KID, byte[] buf, short Off)
    {
        short keyAddr = getRecordByKID(keyType, KID);// 根据类型和KID找对应的KEY
        if (keyAddr == -1)// 未找到记录
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(KEY_FILE_NOT_FOUND);
        }
        else if (keyAddr == -2)// 未找到密钥文件
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        if (!checkSecurity(MF[(short)(keyAddr + KeyUpdateCompeOff)]))// 找到该条密钥下的密钥头中的修改权限，检检安全状态寄存器的值是否满足修改条件
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);// 安全条件不满足
        }
        if ((byte)((keyType & 0x3f)) != (byte)0x3A)// 如果是PIN
        {
            if (buf[(short)(Off - 1)] != (byte)(MF[(short)keyAddr] - 6))// 校验PIN的长度
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
        }
        Util.arrayCopy(buf, Off, MF, (short)(keyAddr + KeyHeadLength), (short)buf[(short)(Off - 1)]);
    }

    /**
     * 检查PIN格式，PIN只能在2--6范围内，数据必须是0--9
     * 
     * @param[dataBuf] [存储PIN值]
     * @param[dataOff] [PIN值在dataBuf中的偏移]
     * @param[dataLen] [PIN长度]
     * @return[false:PIN格式不正确；true：PIN格式正确]
     */ 
    public boolean checkNC(byte dataBuf[], short dataOff, short dataLen)
    {
        if ((dataLen < (short)2) || (dataLen > (short)6))// 如果PIN值长度不在2~6的范围内
        {
            return false;
        }

        for (short i = 0; i < (short)(dataLen - 1); i++)// 校验PIN数据的合法性
        {
            if (((short)(dataBuf[(short)(i + dataOff)] & 0x00f0) > (short)0x0090)
                            || ((short)(dataBuf[(short)(i + dataOff)] & 0x0f) > (short)0x09))
            {
                return false;
            }
        }

        if ((dataBuf[(short)(dataOff + dataLen - 1)] & 0xf0) > 0x90)
        {
            return false;
        }

        if ((dataBuf[(short)(dataOff + dataLen - 1)] & 0x0f) == 0x0f)
        {
            if (dataLen == (short)0x01)
            {
                return false;
            }
            else
            {
                return true;
            }
        }
        else if ((dataBuf[(short)(dataOff + dataLen - 1)] & 0x0f) > 0x09)
        {
            return false;
        }
        else
        {
            return true;
        }
    }

    /**
     * 追加Key(安装密钥）
     * 注：调用该函数前需要判断放入的数据长度是否和对应定长记录文件记录的长度相等。
     * 
     * @param[efAddr] [密钥文件地址]
     * @param[keyType] [密钥类型]
     * @param[KID] [密钥标示]
     * @param[buf] [密钥存储buf]
     * @param[off] [密钥存储buf中的密钥的有效偏移]
     */ 
    public void installKey(short efAddr, byte keyType, byte KID, byte[] buf,
                    short off)
    {
        short recNum = (short)(MF[(short)(efAddr + 9)] & 0x00FF);
        short keyAddr;// =0; hsp
        short i;
        short startAddr, endAddr;
        short ADF_fileADDR_Offset = 40;
        
        startAddr = (short)(efAddr + EFHeadLen);
        endAddr = (short)(startAddr + Util.getShort(MF, (short)(efAddr + 3)));

        /* 按KEY的格式将KEY存放到对应的记录中*/
        if ((!cmEP) || ((MF[CardStatusFlagOff] & 0x01) != 0x01))
        {
            for (i = 0; i < recNum; i++)
            {
                startAddr = (short)(startAddr + MF[startAddr] + 1);
            }
            if ((short)(endAddr - startAddr) < (short)(buf[off] + 2))
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(ISO7816.SW_FILE_FULL);
            }

            /* 判断该文件中有没有同KID的文件*/
            if ((getRecordByKID(keyType, KID) != -1)
                            && (getRecordByKID(keyType, KID) != -2))// 如果找到相同的KID
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(CLA_NOT_MATCHED);// 参数错误
            }
            keyAddr = startAddr;
            MF[keyAddr] = (byte)(buf[off] + 1);// 密钥长度
            MF[(short)(keyAddr + KeyTypeOff)] = keyType;// 密钥类型
            MF[(short)(keyAddr + KeyIDOff)] = KID; // 密钥版本号
            
            if(((ramByte[appTypeOff] & (byte)(0xF6)) == APP_JTB) && ((keyType & 0x3f) == DTK_TYPE) && (KID == 1))//如果是交通部TAC密钥01 add by yujing
            {
                Util.setShort(MF, (short)(ramShort1[0] + ADF_fileADDR_Offset + 14), keyAddr);
            }
            else if (((keyType & 0x3f) == DTK_TYPE) && (KID == 0)) // TAC密钥,直接进行异或后存储 hsp
            {
                Util.setShort(MF, (short)(ramShort1[0] + ADF_fileADDR_Offset + 14), keyAddr);
            }
            Util.arrayCopy(buf, (short)(off + 2), MF, (short)(keyAddr + 3), (short)(buf[off] - 1));
        }
        else
        {
            /* 判断该文件中有没有同KID的文件*/
            keyAddr = getRecordByKID(keyType, KID);
            if ((keyAddr != -1) && (keyAddr != -2))// 如果找到相同的KID
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(CLA_NOT_MATCHED);// 6900,存在相同的KID
            }
            else
            {
                for (i = 0; i < recNum; i++)
                {
                    startAddr = (short)(startAddr + MF[startAddr] + 2);
                }
                if ((short)(endAddr - startAddr) < (short)(buf[off] + 1))
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_FILE_FULL);
                }
                keyAddr = startAddr;
                MF[keyAddr] = (byte)(buf[off] + 1);
                MF[(short)(keyAddr + KeyTypeOff)] = keyType;
                MF[(short)(keyAddr + KeyIDOff)] = KID;
                Util.arrayCopy(buf, (short)(off + 2), MF, 
                               (short)(keyAddr + 3), (short)(buf[off] - 1));
            }
        }
        MF[(short)(efAddr + 9)]++;// 记录数加1
    }

    /**
     * 用于建立和更新PBOC密钥 modify by zhengtao 20131216 1.
     * Key文件刚创建时，安装密钥，文件权限可以忽略，可以明文安装，除了主控密钥也可以按相应权限进行安装。 2.
     * 安装Pin时，指令中的FF不能当成Pin数据。
     * 
     * @param[apdu] [APDU对象]
     * 修改：by zhengtao 校验MAC和解密过程提前，校验KEY文件的写权限过程进行调整
     */
    public void Write_KEYForPBOC(APDU apdu)
    {
        short length;// =0;hsp
        short off;// =0; hsp
        byte[] buf = apdu.getBuffer();
        short KFAddr;// =0; hsp
        short tempNDFAddr;// = 0;临时存放当前DF地址091215 hsp
        short kAddr;// = 0; hsp
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        byte cla = buf[ISO7816.OFFSET_CLA];
        short Pin_len = 0;
        short typeKID;// =0; hsp 密钥类型和密钥标识(唯一标识了一个密钥)
        byte i;

        /* hsp*/
        if ((buf[ISO7816.OFFSET_CLA] != (byte)0x80)
                        && (buf[ISO7816.OFFSET_CLA] != (byte)0x84))
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing

        KFAddr = searchFileAddrByFID((short)0x0000, (byte)1);
        if (KFAddr == -1)
        {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);// 密钥文件找不到
        }
        if ((short)(Util.getShort(MF, (short)(KFAddr + FileLenOff)) - EFHeadLen) == 0)// 密钥文件体大小为0
        {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        length = (short)(buf[ISO7816.OFFSET_LC] & 0x00FF);
        off = ISO7816.OFFSET_CDATA;
        typeKID = Util.makeShort(buf[ISO7816.OFFSET_CDATA], p2);
        JCSystem.beginTransaction();
        if (((MF[(short)(KFAddr + 2)] & 0x97) != 0x01)
                        && ((MF[(short)(KFAddr + 2)] & 0x97) != 0x04))// 只能对密钥文件进行操作
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(FILE_TYPE_NOT_MATCHED);// 文件类型不匹配
        }
        if (p1 == (byte)0x01)// 安装密钥
        {
            MasterKey_flag[0] = 1;  //密钥安装标识
        }
        if(cla == (byte)0x84 && p1 == (byte)0x01)
        {
            if ((MF[(short)(KFAddr + SecuAttrOff)] & 0x20) == 0x20)// 当前文件要求校验MAC
            {
                length -= 4;
                if (!verifyMAC(buf, (short)MasterKeyID, (byte)1))// 如果MAC校验失败
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(FILE_MAC_ERROR);
                }
            }

            if ((MF[(short)(KFAddr + SecuAttrOff)] & 0x10) == 0x10)// 当前文件要求解密数据域
            {
                if ((length % 8) != 0)// 如果要解密的数据不是8的倍数则报错
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }

                kAddr = getRecordByKID(TEAK_TYPE, (byte)0x00);// 要找的密钥的起始地址
                if ((kAddr == -1) || (kAddr == -2))
                {
                    tempNDFAddr = ramShort1[0];// 保存当前DF地址
                    ramShort1[0] = ramShort1[NDFParentAddrOff];// ADF下主控密钥需要用到上层DF的主控密钥去计算MAC，解密,将当前DF置为MF以方便密钥查找
                    kAddr = getRecordByKID(TEAK_TYPE, (byte)0x00);// MF下要找的密钥的起始地址
                    ramShort1[0] = tempNDFAddr;// 当前DF恢复为原值
                    if (kAddr == -1)
                    {
                        JCSystem.commitTransaction();
                        ISOException.throwIt(KEY_FILE_NOT_FOUND);
                    }
                    else if (kAddr == -2)
                    {
                        JCSystem.commitTransaction();
                        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                    }
                }
                DEA_Encrypt(buf, ISO7816.OFFSET_CDATA, length, kAddr, (short)1);// 解密
                length = (short)(buf[ISO7816.OFFSET_CDATA] & 0x00ff);// LD
                off++;
                typeKID = Util.makeShort(buf[off], p2);
            }
        }
        if (p1 == (byte)0x01)// 安装密钥
        {
            MasterKey_flag[0] = 1;
            if (((ramShort1[0] != 0x00)
                            || ((short)(typeKID & 0x3fff) != (short)MasterKeyID))
                            && ((cla & 0x0f) == 0x04))
            {
                if (KeyPurviewEffective[0] == 0)// 判断CLA与文件安全属性的匹配
                {
                    if ((((MF[(short)(KFAddr + SecuAttrOff)] & 0x30) != 0x00) && (cla != (byte)0x84))
                                    || ((MF[(short)(KFAddr + SecuAttrOff)] & 0x30) == 0x00)
                                    && (cla != (byte)0x80))
                    {
                        JCSystem.commitTransaction();
                        ISOException.throwIt(CLA_NOT_MATCHED);// CLA不匹配
                    }
                }       
                
                if ((cla == (byte)0x84)
                                && (MF[(short)(KFAddr + 9)] == 0x00)
                                && ((short)(typeKID & 0x3fff) != MasterKeyID))// 在验证MAC和解密后判断密钥文件中安装的第一个密钥是否为主控密钥
                                                                            // 在需要主控密钥时候，如果密钥文件中密钥个数为0且准备安装的密钥不为主控密钥
                {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);// 报错
                }
            }
            else// 安装主控密钥 主控密钥在安装的时候不能为84
            {
                if (cla == (byte)0x84)
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(FILE_TYPE_NOT_MATCHED);// 文件类型不匹配
                }
                if ((ramShort1[0] == 0x00)
                                && (MF[(short)(KFAddr + EFHeadLen)] == 0x00))// 如果在3F00下，且密钥文件为空,不需要校验权限
                {

                }
                else
                {
                    if (!checkSecurity(MF[(short)(KFAddr + WriteCompeOff)]))// 校验密钥文件的写权限
                    {
                        JCSystem.commitTransaction();
                        ISOException.throwIt((short)(0x6982));
                    }
                }
            }
            /* modify by zhengtao 20140320
                                       兼容Native版本，密钥使用空间保持一致，错误记数(/密钥版本)、算法标识(/后续状态)复用*/
            if ((typeKID & (short)0x3F00) == 0x3A00)// 如果是安装PIN
            {
                /* 判断是否已经存在文件类型为3A的密钥*/
                short lAddr = (short)(KFAddr + EFHeadLen);// 文件体位置处
                if (KFAddr != -1)
                {
                    for (i = 0; i < MF[(short)(KFAddr + 9)]; i++)// 当前记录中的文件数
                    {
                        if ((short)(Util.getShort(MF, (short)(lAddr + 1)) & 0x3fff) == (short)(typeKID & 0x3fff))
                        {
                            JCSystem.commitTransaction();
                            ISOException.throwIt(CLA_NOT_MATCHED);
                        }
                        lAddr = (short)(lAddr + MF[lAddr] + 1);
                    }
                }

                for (i = 0; i < (short)(length - 5); i++)// 计算实际用到的PIN的密钥长度 add
                                                         // by zhengtao 20131216
                {
                    if (buf[(short)(off + 5 + i)] == (byte)0xff)
                    {
                        break;
                    }
                    Pin_len++;
                }
                if ((Pin_len < 2) || (Pin_len > 6))// 如果PIN值长度不在2~6的范围内
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }

                if (!checkNC(buf, (byte)(off + 5), Pin_len))// 检验PIN的格式是否正确
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                Util.arrayCopyNonAtomic(buf, (short)(off), buf, (short)(off + 1), (short)(length));
                /* 剩余位清0(16:密钥值的最大长度，(length-7):实际PIN值的长度)*/
                Util.arrayFillNonAtomic(buf, (short)(off + 5 + Pin_len + 1), (short)(8 - Pin_len), (byte)0xff);// 补ff到8个字节
                buf[(short)(off)] = (byte)13;// 密钥长度
                installKey(KFAddr, buf[(short)(off + 1)], p2, buf, off);// 安装密钥
            }
            else
            {
                /* 密钥存储格式修改为LV格式后不需要判断密钥长度，对此长度没有要求
                   modify by zhengtao 20140220*/
                if (((byte)(length - 5) != (byte)8)
                                && ((byte)(length - 5) != (byte)16))
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }

                if ((buf[(short)off] & 0x3f) == DTK_TYPE) // TAC密钥,直接进行异或后存储 hsp
                {
                    for (i = 0; i < 8; i++)
                    {
                        buf[(short)(off + 5 + i)] = (byte)(buf[(short)(off + 5 + i)] ^ buf[(short)(off + 5 + 8 + i)]);
                    }
                    length -= (byte)8;
                }

                Util.arrayCopyNonAtomic(buf, (short)(off), buf, (short)(off + 1), (short)(length));
                buf[(short)(off)] = (byte)length;

                installKey(KFAddr, buf[(short)(off + 1)], p2, buf, off);
            }
        }
        else// 更新密钥
        {
            kAddr = getRecordByKID((byte)p1, (byte)p2);// 要找的密钥的起始地址

            if ((MF[(short)(kAddr + 1)] & 0x80) == 0x80)// 当前文件要求校验MAC
            {
                length -= 4;
                if (!verifyMAC(buf, (short)MasterKeyID, (byte)1))// 如果MAC校验失败
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(FILE_MAC_ERROR);
                }
            }

            if ((MF[(short)(kAddr + 1)] & 0x40) == 0x40)// 当前文件要求解密数据域
            {
                if ((length % 8) != 0)// 如果要解密的数据不是8的倍数则报错
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }

                kAddr = getRecordByKID(TEAK_TYPE, (byte)0x00);// 要找的密钥的起始地址
                if ((kAddr == -1) || (kAddr == -2))
                {
                    tempNDFAddr = ramShort1[0];// 保存当前DF地址
                    ramShort1[0] = 0x00;// ADF下主控密钥需要用到MF下的主控密钥去计算MAC，解密,将当前DF置为MF以方便密钥查找
                    kAddr = getRecordByKID(TEAK_TYPE, (byte)0x00);// MF下要找的密钥的起始地址
                    ramShort1[0] = tempNDFAddr;// 当前DF恢复为原值
                    if (kAddr == -1)
                    {
                        JCSystem.commitTransaction();
                        ISOException.throwIt(KEY_FILE_NOT_FOUND);
                    }
                    else if (kAddr == -2)
                    {
                        JCSystem.commitTransaction();
                        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                    }
                }
                DEA_Encrypt(buf, ISO7816.OFFSET_CDATA, length, kAddr, (short)1);// 解密
                length = (short)(buf[ISO7816.OFFSET_CDATA] & 0x00ff);// LD
                off++;
                typeKID = Util.makeShort(p1, p2);
            }

            if ((byte)(p1 & 0x3f) == (byte)0x3A)
            {
                for (i = 0; i < (short)(length); i++)// add by zhengtao 20131216
                {
                    if (buf[(short)(off + i)] == (byte)0xff)
                    {
                        break;
                    }
                    Pin_len++;
                }
                if ((Pin_len < 2) || (Pin_len > 6))// 如果PIN值长度不在2~6的范围内
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }

                if (!checkNC(buf, (byte)(off), Pin_len))// 检验PIN的格式是否正确
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                Util.arrayFillNonAtomic(buf, (short)(off + Pin_len), (short)(8 - Pin_len), (byte)0xff);// 补ff到8个字节
                buf[(short)(off - 1)] = (byte)8;
            }
            else if ((byte)(p1 & 0x3f) == DTK_TYPE) // TAC密钥,直接进行异或后存储 hsp
            {
                for (i = 0; i < 8; i++)
                {
                    buf[(short)(off + i)] = (byte)(buf[(short)(off + i)] ^ buf[(short)(off + 8 + i)]);
                }
                length -= (byte)8;
                buf[(short)(off - 1)] = (byte)length;
            }
            else
            {
                buf[(short)(off - 1)] = (byte)length;
            }

            updateKey(p1, p2, buf, off);// add by zhengtao 20131125
        }
    }

    /**
     * 用于建立和更新移动规定密钥
     * 
     * @param[apdu] [APDU对象]
     */
    public void Write_KEYForCM(APDU apdu)
    {
        short length;// =0; hsp
        short off;// =0; hsp
        byte[] buf = apdu.getBuffer();
        short KFAddr;// =0; hsp
        byte cla = buf[ISO7816.OFFSET_CLA];
        short typeKID;// =0; hsp // 密钥类型和密钥标识(唯一标识了一个密钥)

        /* hsp*/
        if ((buf[ISO7816.OFFSET_CLA] != (byte)0x80)
                        && (buf[ISO7816.OFFSET_CLA] != (byte)0x84))
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing

        KFAddr = searchFileAddrByFID((short)0x0000, (byte)1);// 寻找当前DF下的密钥文件
        if (KFAddr == -1)
        {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);// 密钥文件找不到
        }
        if ((short)(Util.getShort(MF, (short)(KFAddr + FileLenOff)) - EFHeadLen) == 0)// 密钥文件体大小为0
        {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        length = (short)(buf[ISO7816.OFFSET_LC] & 0x00FF);
        off = ISO7816.OFFSET_CDATA;

        if ((buf[ISO7816.OFFSET_P1] == 0x01) && (length == 0x00))
        {
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }
        if (length <= 4)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        JCSystem.beginTransaction();
        length -= 4;
        if (!verifyMAC_For_WRKEY(buf, (short)MasterKeyID, (byte)1))// 如果MAC校验失败
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(FILE_MAC_ERROR);
        }

        if ((short)(length % 8) != 0)// 如果要解密的数据不是8的倍数则报错
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        DEA_Encrypt_By_CM(buf, ISO7816.OFFSET_CDATA, length, SESKEY);// 解密
        length = buf[ISO7816.OFFSET_CDATA];// LD
        off++;
        switch (buf[off])
        {
            case (byte)0x01:
                buf[off] = (byte)0x39;
                buf[(short)(off + 1)] = 0x00;
                break;
            case (byte)0x02:
                buf[off] = (byte)0x36;
                break;
            case (byte)0x03:
                buf[off] = (byte)0x07;
                break;
            case (byte)0x04:
                buf[off] = (byte)0x02;
                break;
            case (byte)0x05:
                buf[off] = (byte)0x03;
                break;
            case (byte)0x06:
                buf[off] = (byte)0x038;
                break;
            case (byte)0x07:
                buf[off] = (byte)0x27;
                break;
            case (byte)0x08:
                buf[off] = (byte)0x05;
                break;
            case (byte)0x09:
                buf[off] = (byte)0x37;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                break;
        }
        typeKID = Util.makeShort(buf[off], (byte)buf[(short)(off + 1)]);

        if ((cla == (byte)0x84) && (MF[(short)(KFAddr + RecNumOff)] == 0x00)
                        && (typeKID != MasterKeyID))// 在验证MAC和解密后判断密钥文件中安装的第一个密钥是否为主控密钥
                                                  // 在需要主控密钥时候，如果密钥文件中密钥个数为0且准备安装的密钥不为主控密钥
        {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);// 报错
        }

        if ((MF[(short)(KFAddr + 2)] & 0x93) != 0x11)// 只能对密钥文件进行操作
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(FILE_TYPE_NOT_MATCHED);// 文件类型不匹配
        }
        if (length != 20)
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        installKey(KFAddr, buf[off], (byte)buf[(short)(off + 1)], buf, off);
    }

    /**
     * Write Key 用于建立和更新密钥
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_80D4(APDU apdu)
    {
        if ((!cmEP) || ((MF[CardStatusFlagOff] & 0x01) != 0x01))
        {
            Write_KEYForPBOC(apdu);
            MasterKey_flag[0] = 0;
        }
        else
        {
            Write_KEYForCM(apdu);
        }
        JCSystem.commitTransaction();
    }

    /**
     * 在已删除文件链表中增加一个新的文件 该文件有可能合并到已有文件中，也可能单独增加到该链表中
     * 
     * @param[FileAddr] [待添加文件的起始地址]
     */
    public void AddFileToErasedLink(short FileAddr)
    {
        short LinkAddr;// =0; hsp
        short srtatAddrFile;// =0; hsp
        short FileLen;// =0; hsp
        short nextaddr;// =0 hsp
        short lastaddr;// =0; hsp
        short addrprovisional;// =0; hsp
        byte flag = 0;// 0:正常添加已删除文件，1：已删除文件添加之后查看是否还有空间可以合并
        srtatAddrFile = FileAddr;

        for (;;)
        {
            LinkAddr = Erase_File_AddrStart[0];
            if (LinkAddr == srtatAddrFile)
            {
                return;
            }
            FileLen = Util.getShort(MF, (short)(srtatAddrFile + FileLenOff));
            if ((short)(srtatAddrFile + FileLen) == LinkAddr)// 如果该文件在已删除链表头之前而且和链表头相邻
            {
                Util.setShort(MF, (short)(srtatAddrFile), 
                              Util.getShort(MF, (short)(LinkAddr)));// 把该文件合并到已删除链表头中
                FileLen = (short)(Util.getShort(MF, (short)(LinkAddr + FileLenOff)) + FileLen);
                Util.setShort(MF, (short)(srtatAddrFile + FileLenOff), FileLen);
                Erase_File_AddrStart[0] = srtatAddrFile;
                flag = 1;
            }
            FileLen = Util.getShort(MF, (short)(LinkAddr + FileLenOff));// 读取链表中该文件的大小
            nextaddr = Util.getShort(MF, (short)LinkAddr);
            if ((short)(LinkAddr + FileLen) == srtatAddrFile)// 可以和该文件合并空间
            {
                FileLen = (short)(FileLen + Util.getShort(MF, (short)(srtatAddrFile + FileLenOff)));
                Util.setShort(MF, (short)(LinkAddr + FileLenOff), FileLen);
                if ((short)(LinkAddr + FileLen) == nextaddr)// 合并之后又可以和下一个文件合并空间
                {
                    FileLen = (short)(Util.getShort(MF, (short)(nextaddr + FileLenOff)) + FileLen);
                    Util.setShort(MF, (short)(LinkAddr + FileLenOff), FileLen);
                    Util.setShort(MF, (short)(LinkAddr), Util.getShort(MF, (short)(nextaddr)));// 把该文件合并到已删除链表头中
                }
                srtatAddrFile = LinkAddr;
                flag = 1;
            }
            lastaddr = LinkAddr;// 当前链表文件地址做为lastaddr
            for (;;)
            {
                LinkAddr = Util.getShort(MF, (short)(LinkAddr));// 找下一个已删除链表文件
                if (LinkAddr == 0)// 如果是已删除文件链表的最后
                {
                    if (flag == 0)
                    {
                        Util.setShort(MF, (short)(lastaddr), srtatAddrFile);// 把该文件添加到已删除文件链表的最后
                        return;
                    }
                    else
                    {
                        return;
                    }
                }
                FileLen = Util.getShort(MF, (short)(srtatAddrFile + FileLenOff));// 读取待添加到以上出文件链表中的文件大小
                nextaddr = Util.getShort(MF, (short)(LinkAddr));// 链表中下一个文件地址
                if ((short)(srtatAddrFile + FileLen) == LinkAddr)// 被添加文件可以合并到已删除文件链表中当前文件前面
                {
                    if (flag == 0)
                    {
                        Util.setShort(MF, (short)(srtatAddrFile), nextaddr);// 把该文件合并到已删除链表头中
                        Util.setShort(MF, (short)(lastaddr), srtatAddrFile);// 重新组织已删除文件链表
                    }
                    FileLen = (short)(Util.getShort(MF, (short)(LinkAddr + FileLenOff)) + FileLen);// 合并文件大小
                    Util.setShort(MF, (short)(srtatAddrFile + FileLenOff), FileLen);
                    if (flag == 1)// 如果是已经添加过文件后继续遍历已删除文件链表继续查找
                    {
                        addrprovisional = Erase_File_AddrStart[0];//
                        if (addrprovisional == LinkAddr)// 如果是链表中的第一个文件
                        {
                            Erase_File_AddrStart[0] = srtatAddrFile;
                            Util.setShort(MF, srtatAddrFile, Util.getShort(MF, LinkAddr));
                            break;
                        }
                        for (;;)
                        {
                            lastaddr = addrprovisional;
                            addrprovisional = Util.getShort(MF, addrprovisional);
                            if (addrprovisional == LinkAddr)// 找到该文件的上一个文件
                            {
                                Util.setShort(MF, lastaddr, Util.getShort(MF, LinkAddr));
                                break;
                            }
                        }
                    }
                    flag = 1;
                    break;
                }
                FileLen = Util.getShort(MF, (short)(LinkAddr + FileLenOff));// 读取已删除文件链表中当前文件的文件大小
                if ((short)(LinkAddr + FileLen) == srtatAddrFile)// 待添加文件可以合并到已删除文件链表中当前文件的后面
                {
                    FileLen = (short)(Util.getShort(MF, (short)(srtatAddrFile + FileLenOff)) + FileLen);// 空间合并
                    Util.setShort(MF, (short)(LinkAddr + FileLenOff), FileLen);
                    if ((short)(LinkAddr + FileLen) == nextaddr)// 如果还可以和已删除文件链表中后面一个文件合并
                    {
                        FileLen = (short)(FileLen + Util.getShort(MF, (short)(nextaddr + FileLenOff)));// 继续合并空间
                        Util.setShort(MF, (short)(LinkAddr + FileLenOff), FileLen);
                        Util.setShort(MF, (short)(LinkAddr), Util.getShort(MF, (short)(nextaddr)));
                    }
                    if (flag == 1)// 如果是已经添加过文件后继续遍历已删除文件链表继续查找
                    {
                        addrprovisional = Erase_File_AddrStart[0];//
                        if (addrprovisional == srtatAddrFile)// 如果是链表中的第一个文件
                        {
                            Erase_File_AddrStart[0] = Util.getShort(MF, addrprovisional);
                            srtatAddrFile = LinkAddr;
                            flag = 1;
                            break;
                        }
                        for (;;)
                        {
                            lastaddr = addrprovisional;
                            addrprovisional = Util.getShort(MF, addrprovisional);
                            if (addrprovisional == srtatAddrFile)// 找到该文件的上一个文件
                            {
                                Util.setShort(MF, lastaddr, Util.getShort(MF, addrprovisional));
                                break;
                            }
                        }
                    }
                    srtatAddrFile = LinkAddr;
                    flag = 1;
                    break;
                }
                lastaddr = LinkAddr;
            }
        }
    }

    /**
     * 整理已删除文件为新的单一的链表形式 add by zhengtao 20140403
     * 
     * @param[Addrstart] [被删除DF文件的地址]
     * @return[true：整理成功 ，false：本删除功能只支持单个ADF或单层的DDF，如果DDF下还有DDF，返回false]
     */
    public boolean MakeFileErasedToLink(short Addrstart)
    {
        short startaddr;// =0; hsp
        short lastaddr;// =0; hsp
        short nextaddr;// =0; hsp
        short linkaddr;// =0; hsp
        short DF_addr;// =0; hsp
        short currentlen;// =0; hsp
        byte SonOrBro_Off;// =0; hsp
        startaddr = Addrstart;// 删除DF文件的起始地址
        linkaddr = Erase_File_AddrStart[0];// 已删除链表的起始地址

        Util.setShort(MF, (short)(startaddr + FileLenOff), (short)56);// 被删除DF的文件大小设置为40
        Util.setShort(MF, (short)(startaddr), (short)00);// 原文件头文件标识清零
        AddFileToErasedLink(startaddr);
        SonOrBro_Off = DF_EF_Off;// 首先查找EF文件
        nextaddr = startaddr;
        for (;;)
        {
            if (Util.getShort(MF, (short)(nextaddr + SonOrBro_Off)) != 0)// 如果EF链表不为0
            {
                nextaddr = Util.getShort(MF, (short)(nextaddr + SonOrBro_Off));// 读取EF文件的起始地址
                currentlen = Util.getShort(MF, (short)(nextaddr + FileLenOff));
                Util.setShort(MF, (short)(nextaddr + FileLenOff), (short)(currentlen + EFHeadLen));// 更新文件大小，包括文件头长度
                Util.setShort(MF, (short)(nextaddr), (short)0);// 删除指针字段清零
                AddFileToErasedLink(nextaddr);
                SonOrBro_Off = EF_EF_Off;// 查找EF文件的下一级EF
            }
            else
            {
                break;
            }
        }
        startaddr = Addrstart;// 查找当前DF的子DF层
        SonOrBro_Off = DF_SonDF_Off;
        for (;;)
        {
            if (Util.getShort(MF, (short)(startaddr + SonOrBro_Off)) != 0)// 如果子DF或兄DF不为空
            {
                DF_addr = Util.getShort(MF, (short)(startaddr + SonOrBro_Off));// 读取子DF或兄DF地址
                if (MF[(short)(DF_addr + 2)] == DDFType)// 如果该DF是DDF，不满足条件错误返回
                {
                    return false;
                }
                Util.setShort(MF, (short)(DF_addr + FileLenOff), (short)56); // 该DF文件大小配置为40字节
                Util.setShort(MF, (short)(DF_addr), (short)0);// 删除指针字段清零
                AddFileToErasedLink(DF_addr);
                startaddr = DF_addr;// 开始查找该子DF或兄DF下的EF文件
                SonOrBro_Off = DF_EF_Off;
                nextaddr = startaddr;
                for (;;)
                {
                    if (Util.getShort(MF, (short)(startaddr + SonOrBro_Off)) != 0)// 如果该DF下的EF指针不为空
                    {
                        nextaddr = Util.getShort(MF, (short)(nextaddr + SonOrBro_Off));// 读取该EF的地址
                        if (nextaddr == 0) // 如果该EF不存在则跳出
                        {
                            break;
                        }
                        currentlen = Util.getShort(MF, (short)(nextaddr + FileLenOff));// 读取文件大小
                        Util.setShort(MF, (short)(nextaddr + FileLenOff), (short)(currentlen + EFHeadLen));// 更新文件大小，包括文件头
                        Util.setShort(MF, (short)(nextaddr), (short)0);// 删除指针字段清零
                        AddFileToErasedLink(nextaddr);
                        SonOrBro_Off = EF_EF_Off;
                    }
                    else
                    {
                        break;
                    }
                }
                startaddr = DF_addr;
                SonOrBro_Off = DF_BrotherDF_Off; // 开始查找兄DF文件
            }
            else
            {
                break;
            }
        }

        for (;;)
        {
            linkaddr = Erase_File_AddrStart[0];
            lastaddr = Erase_File_AddrStart[0];
            for (;;)
            {
                currentlen = Util.getShort(MF, (short)(linkaddr + FileLenOff));
                nextaddr = Util.getShort(MF, (short)(linkaddr));
                if ((short)(linkaddr + currentlen) == Uifreepointer)
                {
                    Uifreepointer = linkaddr;// 更新自由指针
                    Util.setShort(MF, (short)(linkaddr), (short)0);
                    if (linkaddr == Erase_File_AddrStart[0])
                    {
                        Erase_File_AddrStart[0] = nextaddr;// 已删除文件链表指针清零
                        if (nextaddr == 0)
                        {
                            return true;
                        }
                    }
                    else
                    {
                        Util.setShort(MF, (short)(lastaddr), (short)nextaddr);
                    }
                    break;
                }
                lastaddr = linkaddr;
                linkaddr = Util.getShort(MF, (short)(linkaddr));
                if (linkaddr == 0)
                {
                    return true;
                }
            }
        }
    }

    /**
     * 擦除DF Erase DF命令删除当前DF下所有的文件内容，包含安全文件、子DF、EF等 删除后可以重建DF下的文件。
     * 删除动作不能改变DF的文件头内容。修改 ：zhengtao 20131204
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_80EE(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();
        short addr = 0;
        short kAddr;// =0; hsp
        short addr_Fa;// =0; hsp
        short addr_Bro;// =0; hsp
        short addr_Son;// =0;//擦除的起始地址 hsp
        short MF_File_len = 40;
        byte p1 = buf[ISO7816.OFFSET_P1];
        short NFID, FIDtem; // hsp
        byte validate_result = 1;

        /* add by zhengtao 20140328 单ADF应用下不支持删除功能 */
        if (C9_Flag[1] == 1)
        {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        /* hsp*/
        if (buf[ISO7816.OFFSET_CLA] != (byte)0x80)
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        if ((buf[ISO7816.OFFSET_P1] > (byte)0x02||buf[ISO7816.OFFSET_P1] < 0)//zhengtao 
                        || buf[ISO7816.OFFSET_P2] != 0x00)// P1只能是0、1、2，P2只能是0
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if ((p1 == (byte)0) || (p1 == (byte)2))// 删除MF下金融文件或0005文件 modify by zhengtao
        {
            if (buf[ISO7816.OFFSET_LC] != 0x08)// LC不能等于8
            {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }           
        }
        else
        {
            if (buf[ISO7816.OFFSET_LC] > 24 || buf[ISO7816.OFFSET_LC] < 13)// LC不在[13,24]范围，[5+8,16+8]
            {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }             
        }
        
        if (buf[ISO7816.OFFSET_LC] == 0x00)// LC不能等于0
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing

        /* add by zhengtao 20140416 删除MF或0005文件必须限制在MF下，删除DF必须限制在被删除DF的父目录下*/
        if ((p1 == (byte)0) || (p1 == (byte)2))// 删除MF下金融文件或0005文件
        {
            if (ramShort1[0] != 0)
            {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }
        else// 删除DF文件
        {
            addr = searchFileAddrByAID(buf, ISO7816.OFFSET_CDATA, (byte)(buf[ISO7816.OFFSET_LC] - 8), (byte)0, (byte)1);// 找到该DF的位置
            if (ramShort1[0] != Util.getShort(MF, (short)(addr + DF_FatherDF_Off)))
            {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }

        /* 外部认证之前需要进行取随机数指令*/
        if (ramByte[randomFlagOff] != 1)// 如果随机数未生成
        {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);// 引用数据无效
        }
        kAddr = getRecordByKID(TEAK_TYPE, buf[ISO7816.OFFSET_P2]);// 外部认证密钥
        if (kAddr == -1)// 密钥记录未找到
        {
            ISOException.throwIt(KEY_FILE_NOT_FOUND);
        }
        else if (kAddr == -2)// 密钥文件未找到
        {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        if ((MF[(short)(kAddr + KeyErrorCountOff)] & 0x0F) == 0x00)// 检查限制次数 add by yujing
        {
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);// 认证方法锁定
        }
        if ((p1 == 0) || (p1 == 2))// p1=0、2时是删除MF，数据域只是加密后的随机数
        {
            DEA_Encrypt(buf, ISO7816.OFFSET_CDATA, buf[ISO7816.OFFSET_LC], kAddr, (short)1);// 解密
        }
        else// p1=1时,删除DF，指令数据域是AID+8字节随机数
        {
            DEA_Encrypt(buf, (short)(ISO7816.OFFSET_CDATA
                            + buf[ISO7816.OFFSET_LC] - 8), (byte)8, kAddr, (short)1);// 解密
        }

        /* 如果验证失败*/
        if ((p1 == (byte)0) || (p1 == (byte)2))// 比较随机数是否一致
        {
            validate_result = Util.arrayCompare(buf, ISO7816.OFFSET_CDATA, Random, (short)1, Random[0]);
        }
        else
        {
            validate_result = Util.arrayCompare(buf, (short)(ISO7816.OFFSET_CDATA
                                            + buf[ISO7816.OFFSET_LC] - 8), Random, (short)1, Random[0]);
        }

        if (validate_result != (byte)0)// 校验失败，返回0x6982
        {
            ISOException.throwIt((short)(0x6982));
        }
        else// 如果验证成功
        {
            MF[(short)(ramShort1[0] + FileNumOff)] = 0;// 将当前DF所包含的文件个数置0
            if (p1 == (byte)1)// 删除DF
            {
                /* 找到DF文件头中文件长度的位置,获得DF文件长度 */
                if (addr == -1)
                {
                    ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                }
                NFID = Util.getShort(MF, addr);// 得到该DF的文件标识;
                /*首先判断该DF是否是它父DF的子DF*/
                addr_Fa = ramShort1[0];
                addr_Son = Util.getShort(MF, (short)(addr_Fa + DF_SonDF_Off));
                FIDtem = Util.getShort(MF, addr_Son);
                JCSystem.beginTransaction();
                if (NFID == FIDtem)// 如果是它父DF的子DF
                {
                    /*判断该DF是否有兄DF*/
                    addr_Bro = Util.getShort(MF, (short)(addr + DF_BrotherDF_Off));
                    if (addr_Bro != 0)// 如果有兄DF，就把该兄DF的位置放入父DF的子DF指针
                    {
                        Util.setShort(MF, (short)(addr_Fa + DF_SonDF_Off), addr_Bro);
                    }
                    else// 如果没有兄DF
                    {
                        Util.setShort(MF, (short)(addr_Fa + DF_SonDF_Off), (short)0x0000);
                    }
                }
                else// 如果不是它父DF的子DF
                {
                    for (;;)
                    {
                        addr_Bro = Util.getShort(MF, (short)(addr_Son + DF_BrotherDF_Off));
                        if (addr_Bro == 0)// 如果没有兄DF，说明该条链中没有需要删除的DF
                        {
                            JCSystem.commitTransaction();
                            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                        }
                        if (addr == addr_Bro)// 找到该DF上个链条的DF的地址，把后个链条的DF的位置放入前一个DF的兄指针
                        {
                            addr_Fa = Util.getShort(MF, (short)(addr + DF_BrotherDF_Off));
                            Util.setShort(MF, (short)(addr_Son + DF_BrotherDF_Off), (short)addr_Fa);
                            break;
                        }
                        addr_Son = addr_Bro;
                    }
                }
                /* modify by zhengtao 20140403
                                                   删除文件后把已删除文件整理为链表格式，不能把该空间清零，自由指针不变*/
                if (Erase_File_AddrStart[0] == (short)0)// 如果删除文件链表的起始地址为0，表明暂时没有删除链表
                {
                    Erase_File_AddrStart[0] = addr;
                    Util.setShort(MF, (short)(addr), (short)0);
                    if ((MF[(short)(addr + 2)] & 0x30) == 0x30)
                    {
                        Util.setShort(MF, (short)(addr + FileLenOff), (short)40);
                    }
                    else
                    {
                        Util.setShort(MF, (short)(addr + FileLenOff), (short)(Util.getShort(MF, (short)(addr + FileLenOff)) + 18));
                    }
                }

                if (MakeFileErasedToLink(addr) == false)
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }

                /* modify by zhengtao 20140305
                                                  删除DF后，当前DF地址指向被删除DF的父DF地址，修改前删除后当前DF指向被删除的DF的地址*/
                ramShort1[NEFAddrOff] = 0;// 当前EF置0

                JCSystem.commitTransaction();
            }
            else if (p1 == (byte)0)// 删除DF 当前DF为MF
            {
                JCSystem.beginTransaction();
                ramShort1[NDFParentAddrOff] = 0x00;
                ramShort1[0] = 0x00;
                ramShort1[NEFAddrOff] = 0x00;
                Util.setShort(MF, (short)DF_SonDF_Off, (short)0x0000);// 子DF指针为0
                Util.setShort(MF, (short)DF_EF_Off, (short)0x0000);// EF指针为0
                Util.arrayFillNonAtomic(MF, (short)(MF_File_len), (short)(Uifreepointer - MF_File_len), (byte)0);
                Uifreepointer = MF_File_len;
                Erase_File_AddrStart[0] = 0;
                Erase_File_AddrStart[1] = 0;
                JCSystem.commitTransaction();
            }
            else// 删除3f00下0005文件
            {
                JCSystem.beginTransaction();
                if (ramShort1[0] != 0)// 只支持删除3F00下0005文件
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                addr = searchFileAddrByFID((short)0x0005, (byte)0);// 根据FID查找文件地址
                if (addr == -1)
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                }
                if (Util.getShort(MF, (short)(ramShort1[0] + DF_EF_Off)) == addr)// 如果是MF的子EF
                {
                    Util.setShort(MF, (short)(ramShort1[0] + DF_EF_Off), Util.getShort(MF, (short)(addr + EF_EF_Off)));// 把MF的EF指针修改为0005文件的下一个文件地址
                }
                else
                {
                    addr_Son = Util.getShort(MF, (short)(ramShort1[0] + DF_EF_Off));
                    for (;;)
                    {
                        if (Util.getShort(MF, (short)(addr_Son + EF_EF_Off)) == addr)
                        {
                            Util.setShort(MF, (short)(addr_Son + EF_EF_Off), Util.getShort(MF, (short)(addr + EF_EF_Off)));
                            break;
                        }
                        addr_Son = Util.getShort(MF, (short)(addr_Son + EF_EF_Off));
                        if (addr_Son == -1)
                        {
                            JCSystem.commitTransaction();
                            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                        }
                    }
                }
                if (Erase_File_AddrStart[0] == (short)0)// 如果删除文件链表的起始地址为0，表明暂时没有删除链表
                {
                    Erase_File_AddrStart[0] = addr;
                    Util.setShort(MF, (short)(addr), (short)0);
                    if ((MF[(short)(addr + 2)] & 0x30) == 0x30)
                    {
                        Util.setShort(MF, (short)(addr + FileLenOff), (short)40);
                    }
                    else
                    {
                        Util.setShort(MF, (short)(addr + FileLenOff), (short)(Util.getShort(MF, (short)(addr + FileLenOff)) + 18));
                    }
                }
                AddFileToErasedLink(addr);
                JCSystem.commitTransaction();
            }
        }
    }

    /**
     * 创建MF
     * 
     * @param[buf] [APDU的数据缓冲区]
     */
    public void creatMF(byte[] buf)
    {
        short MF_File_len = 40;
        
        /* modify by zhengtao 20140115传输码校验要求删除,为了兼容Native版本
           add by zhengtao 20140308 在无ADF应用中不支持MF的创建*/
        if (C9_Flag[1] == 1)
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (searchFileAddrByFID((short)0x3F00, (byte)1) != -1)// 如果MF已经存在
        {
            ISOException.throwIt(FILE_ALREADY_EXIST);
        }
        if (Util.getShort(buf, (short)(ISO7816.OFFSET_CDATA + 1)) == (short)0xFFFF)// 文件标识不能为0xffff
        {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        if (((short)(buf[ISO7816.OFFSET_CDATA + 8] & 0x00FF) > 16)
                        || (((short)(buf[ISO7816.OFFSET_CDATA + 8] & 0x00FF) < 5) && ((short)(buf[ISO7816.OFFSET_CDATA + 8] & 0x00FF) != 0)))// AID的长度不能大于16字节
                                                                                                                                         // modify
                                                                                                                                         // by
                                                                                                                                         // zhengtao
                                                                                                                                         // 20140220
                                                                                                                                         // MF可以没有AID，但是如果有AID，长度必须在5--16字节范围内
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (sizeOfMF < MF_File_len) // MF空间如果小于MF文件头的长度，空间不够
        {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        Util.arrayCopy(buf, (short)(ISO7816.OFFSET_CDATA + 9), MF, (short)16, (short)(buf[ISO7816.OFFSET_CDATA + 8] & 0x00FF));// AID
        Util.arrayCopy(buf, (short)(ISO7816.OFFSET_CDATA + 5), MF, (short)5, (short)2);// 创建权限和删除权限
        Util.setShort(MF, (short)0, (short)0x3F00);// FID:3F00
        MF[2] = DDFType;// MF的文件类型为80
        Util.setShort(MF, FileLenOff, (short)0x0000);// length:0x0000
        MF[FileNumOff] = (byte)0x00;// 文件个数置0x00
        MF[LockAttrOff] = 0;// MF的锁定状态置0
        MF[0x0b] = 0;// 应用类型0
        MF[0x0d] = buf[ISO7816.OFFSET_CDATA + 4]; // 属性字节2生命周期保留在预留字段0处
        Util.setShort(MF, (short)0x0e, (short)0x0000);// 预留字段赋值为0x00
        Util.setShort(MF, (short)0x22, (short)0x0000);// 预留字段赋值为0x00
        Util.setShort(MF, (short)0x24, (short)0x0000);// 预留字段赋值为0x00

        MF[CardStatusFlagOff] = (byte)(0x03);// 设置卡状态标志,b0=0表示个人化未结束,b1=1表示MF已经建立,高四位表示对应PIN在MyPIN中的位置
                                             // modify by zhengtao 20140220,
        /* modify by zhengtao 20140226 兼容Native版本，此处对SFI文件字节的高3bit限制放开
                            目录文件的SFI就在01-1E之间*/
        MF[AIDLenOff] = (byte)(buf[ISO7816.OFFSET_LC] - 9);// AID长度
        MF[DirSFIOff] = buf[ISO7816.OFFSET_CDATA + 3];// SFI
        ramShort1[NDFParentAddrOff] = 0x00;// 父DF地址
        ramShort1[0] = 0x00;// 当前DF地址
        ramShort1[NEFAddrOff] = 0x00;// 当前EF地址
        MF[DF_SonDF_Off] = 0x00; // 子DF指针为0
        MF[DF_EF_Off] = 0x00; // EF指针为0
        Uifreepointer = MF_File_len;// 更新自由指针
    }

    /**
     * 查找最合适的文件空间 add by zhengtao 20140403
     * 
     * @param[startAddr] [已删除文件链表的起始地址]
     * @param[Needlen] [需要的文件长度]
     * @return[找到的最合适的文件的地址]
     */
    public short FindMostFeatFile(short startAddr, short Needlen)
    {
        short AddrStart;// =0; hsp
        short filelen;// =0; hsp
        short difference = (short)(0x7fff);// 差值
        short FeatFileAddr;// =0; hsp
        short CurrentAddr;// =0; hsp
        
        AddrStart = startAddr;
        filelen = (short)(Util.getShort(MF, (short)(AddrStart + FileLenOff)));// 读取第一个文件的长度
        if (filelen == Needlen)// 如果和需要的空间相等
        {
            Erase_File_AddrStart[1] = AddrStart;// Erase_File_AddrStart[1]中记录上一个文件的地址，在找到一个文件后，把它的下一个文件连接到它上一个文件上
            return AddrStart;// 直接返回第一个文件的地址
        }
        else if (filelen > Needlen)// 如果文件大小大于需要的空间大小
        {
            difference = (short)(filelen - Needlen);// 记录两者的差值
        }
        FeatFileAddr = AddrStart;
        for (;;)
        {
            CurrentAddr = AddrStart;
            AddrStart = Util.getShort(MF, (short)(AddrStart));// 找到下一个文件
            if (AddrStart != 0)// 地址不为0
            {
                filelen = (short)(Util.getShort(MF, (short)(AddrStart + FileLenOff)));// 读取文件的大小
                if (filelen == Needlen)// 空间刚好合适
                {
                    Erase_File_AddrStart[1] = CurrentAddr;// 存储上一个文件地址
                    return AddrStart;// 返回当前文件地址
                }
                else if (filelen > Needlen)// 文件长度大于需要的空间
                {
                    if (difference > (short)(filelen - Needlen))// 如果上一个文件的差值比这个文件的差值大
                    {
                        difference = (short)(filelen - Needlen);// 更新差值变量
                        Erase_File_AddrStart[1] = CurrentAddr;// 存储上一个文件地址
                        FeatFileAddr = AddrStart;// 暂停当前文件是最合适的文件
                    }
                }
            }
            else
            {
                break;
            }
        }
        if (FeatFileAddr == startAddr)// 如果找到的是第一个
        {
            if (difference != 0x7fff)
            {
                Erase_File_AddrStart[1] = startAddr;// 存储第一个文件地址
            }
            else
            {
                return -1;
            }
        }
        return FeatFileAddr;// 返回找到的最合适的文件的地址
    }

    /**
     * 找到的最合适的文件空间并修改链表
     * 
     * @param[filepoint] [已删除文件链表的存储指针]
     * @param[needlen] [创建文件需要的长度]
     * @return[返回找到的最合适的文件的地址]
     */
    public short modifyLinkafterFindFile(short[] filepoint, short needlen)
    {
        short startAddr;// =0; hsp
        short currentAddr;// =0; hsp
        short justtheaddr;// =0; hsp
        short nextaddr;// =0; hsp
        
        if (filepoint[0] == 0) // 如果已删除文件链表起始地址为0，异常返回
        {
            return -1;
        }
        startAddr = filepoint[0];// 从该地址开始查找
        justtheaddr = FindMostFeatFile(startAddr, needlen);// 查找最合适的空间去创建文件
        if (justtheaddr != -1)// 找到合适的空间
        {
            if (justtheaddr == startAddr)// 如果找到的是已删除文件链表中的第一个文件
            {
                nextaddr = Util.getShort(MF, (short)(startAddr));// 找到该文件的下一个已删除文件
                if (Util.getShort(MF, (short)(justtheaddr + FileLenOff)) > (short)(needlen + 4))// 如果剩余空间大于EF文件头长度
                {
                    currentAddr = (short)(justtheaddr + needlen);// 重新组织一个新的删除文件头
                    Util.setShort(MF, (short)(currentAddr + FileLenOff), 
                                  (short)(Util.getShort(MF, (short)(justtheaddr + FileLenOff)) - needlen));

                    MF[(short)(currentAddr + 2)] = 0x01;
                    Util.setShort(MF, (short)(currentAddr), nextaddr);// 已删除文件链表中下一个文件链接到该文件上
                }
                else
                {
                    currentAddr = nextaddr;// 已删除文件链表的起始地址指向下一个文件
                }

                filepoint[0] = currentAddr;
            }
            else// 不是已删除文件链表的第一个
            {
                nextaddr = Util.getShort(MF, (short)(justtheaddr));// 读取下一个文件的地址

                if (Util.getShort(MF, (short)(justtheaddr + FileLenOff)) > (short)(needlen + 4))// 如果剩余空间大于一个EF文件头的大小
                {
                    currentAddr = (short)(justtheaddr + needlen);// 计算该文件新的起始地址
                    Util.setShort(MF, (short)(currentAddr + FileLenOff), 
                                  (short)(Util.getShort(MF, (short)(justtheaddr + FileLenOff)) - needlen)); // 更新新的文件大小
                    MF[(short)(currentAddr + 2)] = 0x01;
                    Util.setShort(MF, (short)(currentAddr), nextaddr);// 下一个文件链接到该文件上
                    Util.setShort(MF, (short)(Erase_File_AddrStart[1]), currentAddr);// 把剩下的空间链接到上一个文件上
                }
                else
                {
                    Util.setShort(MF, (short)(Erase_File_AddrStart[1]), nextaddr);// 把下一个文件链接到上一个文件上
                }
            }
        }
        else
        {
            return -1;
        }

        if ((MF[(short)(justtheaddr + 2)] & 0x30) == 0x30)// 如果找到的是DF文件，清空相应的文件链表指针
        {
            Util.setShort(MF, (short)(justtheaddr + DF_SonDF_Off), (short)0x0000);
            Util.setShort(MF, (short)(justtheaddr + DF_BrotherDF_Off), (short)0x0000);
            Util.setShort(MF, (short)(justtheaddr + DF_FatherDF_Off), (short)0x0000);
            Util.setShort(MF, (short)(justtheaddr + DF_EF_Off), (short)0x0000);
        }
        else// 否则只需要清空EF指针
        {
            Util.setShort(MF, (short)(justtheaddr + EF_EF_Off), (short)0x0000);
        }
        return justtheaddr;// 返回找到的最合适的文件的地址

    }

    /**
     * 创建DF modify by zhengtao 20131216 1.按照链表形式进行创建。 2.该函数可以进行伪MF的创建。
     * 注：数据域的长度LC和实际长度由调用该函数者进行判断
     * 
     * @param[buf] [DF文件头信息]
     */
    public void creatDF(byte[] buf)
    {
        short FID;// =0; hsp
        short DF_File_len = 56;
        short Off;// =0; hsp
        short addrPoint;// =0; hsp
        byte SonOrBro_Off;// =0; hsp
        
        if (buf[ISO7816.OFFSET_LC] < (byte)0x09)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if ((buf[ISO7816.OFFSET_P2] < 0) || (buf[ISO7816.OFFSET_P2] > 4))
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);//P1P2错误返回6A86而不是6B00，modify by yujing
        }
        /* add by zhengtao 20140308 无ADF应用不支持创建DDF*/
        if ((C9_Flag[1] == 1) && (buf[ISO7816.OFFSET_P2] == 1))
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);//P1P2错误返回6A86而不是6B00，modify by yujing
        }
        /*  modify by zhengtao 20140308 支持无ADF应用时不需要判断MF是否建立*/
        if (((searchFileAddrByFID((short)0x3F00, (byte)1) == -1) || ((MF[CardStatusFlagOff] & 0x02) == 0x00))
                        && (C9_Flag[1] == 0))// 如果MF未建立
        {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        FID = Util.getShort(buf, (short)(ISO7816.OFFSET_CDATA + 1));
        /*  modify by zhengtao 20140327 单ADF应用下，ADF的FID可以是0x3F00*/
        if (((FID == (short)0x3F00) && (C9_Flag[1] == 0))
                        || (searchFileAddrByFID(FID, (byte)1) != -1))
        {
            ISOException.throwIt(FILE_ALREADY_EXIST);
        }
        if (FID == (short)0xFFFF)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        /* modify by zhengtao 20140308 如果支持无ADF应用，钱包中只有一个应用，不需要该判断*/
        if ((MF[(short)(ramShort1[0] + 2)] == ADFType) && (C9_Flag[1] == 0))// 如果当前的DF为ADF，则报错。ADF下不能建立DF
        {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        /* modify by zhengtao 20140115 MF可以没有AID，但是文件头中AID预留空间只有16字节，所以在此做出限制*/
        if (((short)(buf[ISO7816.OFFSET_CDATA + 8] & 0x00FF) > 16)
                        || ((short)(buf[ISO7816.OFFSET_CDATA + 8] & 0x00FF) < 5 && (short)(buf[ISO7816.OFFSET_CDATA + 8] & 0x00FF) != 0))// modify
                                                                                                                                         // by
                                                                                                                                         // zhengtao
                                                                                                                                         // 20140220
                                                                                                                                         // MF可以没有AID，但是如果有AID，长度必须在5--16字节范围内
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        /* 判断AID是否有冲突(如果找到与数据域中完全相等的AID)*/
        if (buf[(short)(ISO7816.OFFSET_CDATA + 8)] != 0)
        {
            if (searchFileAddrByAID(buf, (short)(ISO7816.OFFSET_CDATA + 9), (byte)(buf[ISO7816.OFFSET_CDATA + 8]), (byte)0, (byte)1) != -1)
            {
                ISOException.throwIt(FILE_ALREADY_EXIST);// AID冲突(注：新建的DF也不能与父辈DF的AID冲突)
            }
        }
        if (C9_Flag[1] == 1)
        {
            selectedAID = JCSystem.getAID();// 获得当前Applet的AID
            if (selectedAID.partialEquals(buf, (short)(ISO7816.OFFSET_CDATA + 9), buf[(short)(ISO7816.OFFSET_CDATA + 8)]) == false)
            {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }
        /* modify by zhengtao 20140308 当支持无ADF应用时不需要检验该权限*/
        if (C9_Flag[1] == 0)
        {
            if (searchFileAddrByFID((short)0x0000, (byte)1) == -1)// 查找当前DF下的KEY文件,如果KEY文件不存在
            {
                ISOException.throwIt(KEY_FILE_NOT_EXIST);
            }
            else// 如果KEY文件存在，判断安全状态机是否满足当前DF的建立权限
            {
                if (!checkSecurity(MF[(short)(ramShort1[0] + CreatCompeOff)]))// 检查是否符合当前DF的建立文件权限
                {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
            }
        }
        /* 目录文件的SFI就在01-1E之间
           modify by zhengtao 20140327 目录文件的SFI全部放开，不判断，兼容Native版本*/
        if ((short)(sizeOfMF - Uifreepointer) < DF_File_len)
        {
            addrPoint = modifyLinkafterFindFile(Erase_File_AddrStart, (short)DF_File_len);
            if (addrPoint == -1)
            {
                ISOException.throwIt(ISO7816.SW_FILE_FULL);
            }
        }
        else
        {
            addrPoint = Uifreepointer;
        }
        SonOrBro_Off = DF_SonDF_Off;
        Off = (short)(ramShort1[0]);
        for (;;)
        {
            if (Util.getShort(MF, (short)(Off + SonOrBro_Off)) == 0)
            {
                MF[(short)(addrPoint)] = buf[ISO7816.OFFSET_CDATA + 1];// 文件标识
                MF[(short)(addrPoint + 1)] = buf[ISO7816.OFFSET_CDATA + 2];
                MF[(short)(addrPoint + 2)] = buf[ISO7816.OFFSET_CDATA];
                MF[(short)(addrPoint + ApplicatonTypeOff)] = buf[ISO7816.OFFSET_CDATA + 4];
                if (buf[ISO7816.OFFSET_P2] == (byte)0x01)
                {
                    MF[(short)(addrPoint + 2)] = DDFType;
                }
                else if (buf[ISO7816.OFFSET_P2] == (byte)0x02)
                {
                    MF[(short)(addrPoint + 2)] = ADFType;
                    MF[(short)(addrPoint + ApplicatonTypeOff)] = 0x01;
                }
                else if (buf[ISO7816.OFFSET_P2] == (byte)0x03)
                {
                    MF[(short)(addrPoint + 2)] = ADFType;
                    MF[(short)(addrPoint + ApplicatonTypeOff)] = 0x08;
                }
                else
                {
                    MF[(short)(addrPoint + 2)] = ADFType;
                }
                Util.setShort(MF, (short)(addrPoint + FileLenOff), (short)0x00);// 文件长度设置为0
                MF[(short)(addrPoint + CreatCompeOff)] = buf[ISO7816.OFFSET_CDATA
                                + CreatCompeOff];// 建立权限
                MF[(short)(addrPoint + EraseCompeOff)] = buf[ISO7816.OFFSET_CDATA
                                + EraseCompeOff];// 擦除权限
                MF[(short)(addrPoint + LockAttrOff)] = 0;// DF的锁定状态置0
                MF[(short)(addrPoint + FileNumOff)] = 0;// 文件个数置0
                if (C9_Flag[1] == 1)// 如果是无ADF应用
                {
                    MF[(short)(addrPoint + CardStatusFlagOff)] = (byte)0x03;
                }
                MF[(short)(addrPoint + AIDLenOff)] = buf[ISO7816.OFFSET_CDATA + 8];// AID长度
                MF[(short)(addrPoint + DirSFIOff)] = buf[ISO7816.OFFSET_CDATA + 3];
                MF[(short)(addrPoint + DirSFIOff + 1)] = (byte)0x00;// 保留字段填充0x00
                MF[(short)(addrPoint + DirSFIOff + 2)] = (byte)0x00;
                MF[(short)(addrPoint + DirSFIOff + 3)] = (byte)0x00;

                Util.arrayCopy(buf, (short)(ISO7816.OFFSET_CDATA + 9), MF, (short)(addrPoint + 0x10), (short)(buf[ISO7816.OFFSET_CDATA + 8] & 0x00FF));// AID
                MF[(short)(addrPoint + DF_FatherDF_Off)] = (byte)((ramShort1[0] >> 8) & 0xff);
                MF[(short)(addrPoint + DF_FatherDF_Off + 1)] = (byte)(ramShort1[0] & 0xff);
                MF[(short)(addrPoint + DF_SonDF_Off)] = 0x00;
                MF[(short)(addrPoint + DF_SonDF_Off + 1)] = 0x00;
                MF[(short)(addrPoint + DF_BrotherDF_Off)] = 0x00;
                MF[(short)(addrPoint + DF_BrotherDF_Off + 1)] = 0x00;
                MF[(short)(addrPoint + DF_EF_Off)] = 0x00;
                MF[(short)(addrPoint + DF_EF_Off + 1)] = 0x00;

                Util.arrayFillNonAtomic(MF, (short)(addrPoint + DF_EF_Off + 2), (short)16, (byte)0xFF);// 性能优化
                                                                                                       // 20140429
                                                                                                       // zhengtao
                                                                                                       // DF文件头扩展16个字节，用于存储关键文件的地址

                MF[(short)(ramShort1[0] + FileNumOff)]++;// 当前DF下的文件数加1
                Util.setShort(MF, (short)(Off + SonOrBro_Off), (short)addrPoint);// 设置链表指针
                if ((short)(sizeOfMF - Uifreepointer) >= DF_File_len)
                {
                    Uifreepointer += DF_File_len;
                }
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
            }
            else
            {
                Off = Util.getShort(MF, (short)(Off + SonOrBro_Off));
                if (Util.getShort(MF, Off) == (short)((buf[ISO7816.OFFSET_CDATA + 1] << 8) | (buf[ISO7816.OFFSET_CDATA + 2])))
                {
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                }
                if (MF[(short)(Off + 0x0a)] == buf[ISO7816.OFFSET_CDATA + 8])
                {
                    if (Util.arrayCompare(MF, (short)(Off + 0x0B), buf, (short)(ISO7816.OFFSET_CDATA + 9), (short)(MF[(short)(Off + 0x0a)])) == 0)
                    {
                        ISOException.throwIt(ISO7816.SW_UNKNOWN);
                    }
                }
                SonOrBro_Off = DF_BrotherDF_Off;
            }
        }
    }

    /**
     * 创建EF
     * 数据域的长度LC和实际长度由调用该函数者进行判断
     * 
     * @param[buf] [EF文件头信息]
     */
    public void creatEF(byte[] buf)
    {
        short FID;// =0; hsp
        short len;
        short Off;
        short EF_File_len = 18;
        short addrPoint;// =0; hsp
        short ADF_fileADDR_Offset = 40;
        byte Bro_Off;
        
        if (((searchFileAddrByFID((short)0x3F00, (byte)1) == -1) || ((MF[CardStatusFlagOff] & 0x02) == 0x00))
                        && (C9_Flag[1] == 0))// 如果MF未建立
        {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        FID = Util.getShort(buf, (short)(ISO7816.OFFSET_CDATA + 4));// 取buf中的FID信息

        /* 除MF之外的DF不可以以3F00和FFFF为FID,也不可以与已经存在的文件同名 */
        if (FID == (short)0x3F00)
        {
            ISOException.throwIt(FILE_ALREADY_EXIST);
        }
        if (FID == (short)0xFFFF)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (searchFileAddrByFID(FID, (byte)1) != -1)// 已经有相同的FID存在
        {
            if (FID == (short)0x0000)// modify by zhengtao 20131226//
                                     // 如果新建EF的FID为0000且文件类型不为内部定长记录
            {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            else
            {
                ISOException.throwIt(FILE_ALREADY_EXIST);
            }
        }
        if ((buf[ISO7816.OFFSET_CDATA + SFIOff]) > 0x1E
                        || (buf[ISO7816.OFFSET_CDATA + SFIOff]) < 0)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if ((short)buf[(short)(ISO7816.OFFSET_CDATA + 3)] != (short)0x00)
        {
            if (searchFileAddrBySFI(buf[(short)(ISO7816.OFFSET_CDATA + 3)], (byte)1) != -1)// 已经有相同的SFI存在
            {
                ISOException.throwIt(FILE_ALREADY_EXIST);
            }
        }

        if ((buf[ISO7816.OFFSET_CDATA] & 0x30) == 0x30)// 如果文件类型最高位为1，则表示不是EF文件
        {
            ISOException.throwIt(FILE_TYPE_NOT_MATCHED);
        }

        /* 如果新建EF的FID不是当前DDF下的DIREF文件，也不是KEY文件，则需要进行下列判断 */
        if ((FID != (short)0x0000)
                        && ((short)(MF[(short)(ramShort1[0] + 2)] & 0x30) == (short)0x30 || FID != (short)(DirEFFID | (MF[(short)(ramShort1[0] + DirSFIOff)] & 0x1F))))
        {
            if (searchFileAddrByFID((short)0x0000, (byte)1) == -1)// 如果新建的不是KEY文件而且KEY不存在
            {
                ISOException.throwIt(KEY_FILE_NOT_EXIST);
            }
            else
            {
                if (!checkSecurity(MF[(short)(ramShort1[0] + CreatCompeOff)]))// 检查是否符合当前DF的建立文件权限
                {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
            }
        }

        /* modify by zhengtao 20131212 创建Key文件时，不需要判断文件类型
         * 文件体+16（EFHeadLen)=整个文件在大小*/
        len = Util.getShort(buf, (short)(ISO7816.OFFSET_CDATA + 1));// 文件体的大小
        if (((buf[ISO7816.OFFSET_CDATA] & 0x07) == 0x02)
                        || ((buf[ISO7816.OFFSET_CDATA] & 0x07) == 0x06))// 如果为定长记录文件（线性或循环）
        {
            len = (short)(((len >> 8) & 0x00FF) * (len & 0x00FF));
        }
        if (len < 0)
        {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        if ((short)(sizeOfMF - Uifreepointer) < (short)(EF_File_len + len))
        {
            addrPoint = modifyLinkafterFindFile(Erase_File_AddrStart, (short)(len + EFHeadLen));
            if (addrPoint == -1)
            {
                ISOException.throwIt(ISO7816.SW_FILE_FULL);
            }
        }
        else
        {
            addrPoint = Uifreepointer;
        }
        Bro_Off = DF_EF_Off;
        Off = (short)(ramShort1[0]);
        for (;;)
        {
            if (Util.getShort(MF, (short)(Off + Bro_Off)) == 0)
            {
                Util.arrayCopy(buf, (short)(ISO7816.OFFSET_CDATA + 4), MF, (short)addrPoint, (short)2);// FID
                Util.arrayCopy(buf, (short)(ISO7816.OFFSET_CDATA), MF, (short)(addrPoint + 2), (short)1);// 类型
                Util.arrayCopy(buf, (short)(ISO7816.OFFSET_CDATA + 7), MF, (short)(addrPoint + 5), (short)2);// 读写权限
                Util.arrayCopy(buf, (short)(ISO7816.OFFSET_CDATA + 3), MF, (short)(addrPoint + 7), (short)1);// SFI
                Util.arrayCopy(buf, (short)(ISO7816.OFFSET_CDATA + 9), MF, (short)(addrPoint + 8), (short)1);// 安全属性
                Util.arrayFillNonAtomic(MF, (short)(addrPoint + 9), (short)9, (byte)0x00);// 性能优化
                                                                                          // 20140429
                                                                                          // zhengtao
                                                                                          // 连续地址的写操作修改为整体填充

                if ((MF[(short)(addrPoint + 2)] & 0x07) == 0x01)
                {
                    if((short)0xEF02 == FID)//加大EF02文件大小,(EF02+EF03)
                    {
                        if( MF[(short)(ramShort1[0] + 2)] == ADFType )  //在ADF下执行
                        {
                            if( ((ramByte[appTypeOff]&APP_HLHT) ==APP_HLHT)
                                            || ((ramByte[appTypeOff]&APP_PBOC) ==APP_PBOC)
                                            || ((ramByte[appTypeOff]&APP_ZJB) ==APP_ZJB)
                                            || (ramByte[appTypeOff] & (byte)(0xF6)) == APP_JTB)//modify by yujing
                            {
								len += (short)12;
                                Util.setShort(MF, (short)(addrPoint+3), len);
                            }
                            else
                            {
                                Util.arrayCopy(buf,(short)(ISO7816.OFFSET_CDATA+1),MF,(short)(addrPoint+3),(short)2);//空间
                            }
                        }
                        else
                        {
                            Util.arrayCopy(buf,(short)(ISO7816.OFFSET_CDATA+1),MF,(short)(addrPoint+3),(short)2);//空间
                        }
                    }
                    else
                    {
                        Util.arrayCopy(buf,(short)(ISO7816.OFFSET_CDATA+1),MF,(short)(addrPoint+3),(short)2);//空间
                    }
                }
                else if (((MF[(short)(addrPoint + 2)] & 0x07) == 0x02)
                                || ((MF[(short)(addrPoint + 2)] & 0x07) == 0x06))// 如果为定长记录文件或循环记录文件
                {
                    MF[(short)(addrPoint + 3)] = (byte)((len >> 8) & 0xff);
                    MF[(short)(addrPoint + 4)] = (byte)(len & 0xff);
                    MF[(short)(addrPoint + RecNumOff)] = 0;// 当前记录数置为0
                    MF[(short)(addrPoint + FixedRecLenOff)] = buf[ISO7816.OFFSET_CDATA + 2];// 记录长度
                    MF[(short)(addrPoint + TotalRecNumOff)] = buf[ISO7816.OFFSET_CDATA + 1];// 记录总数
                    MF[(short)(addrPoint + NRecAddrOff)] = 0;// 最新记录位置
                }
                else if ((MF[(short)(addrPoint + 2)] & 0x07) == 0x04)
                {
                    MF[(short)(addrPoint + 3)] = (byte)((len >> 8) & 0xff);
                    MF[(short)(addrPoint + 4)] = (byte)(len & 0xff);
                    MF[(short)(addrPoint + 9)] = 0;// 记录个数
                }
                else
                {
                    ISOException.throwIt(FILE_TYPE_NOT_MATCHED);// 则表示不是EF，报错。
                }
                MF[(short)(ramShort1[0] + FileNumOff)]++;// 当前DF下的文件数加1

                if ((buf[2] & 0x80) == 0)
                {
                    Util.arrayFillNonAtomic(MF, (short)(addrPoint + EF_File_len), (short)len, (byte)0xff);
                }
                else
                {
                    Util.arrayFillNonAtomic(MF, (short)(addrPoint + EF_File_len), (short)len, (byte)0x00);
                }

                if (Util.getShort(MF, addrPoint) == 0)
                {
                    Util.arrayFillNonAtomic(MF, (short)(addrPoint + EF_File_len), (short)len, (byte)0x00);
                }
                if (FID != (byte)0x00)// 如果新建的不是KEY文件，则将新建文件选为当前文件
                {
                    ramShort1[NEFAddrOff] = (short)addrPoint;
                }
                Util.setShort(MF, (short)(Off + Bro_Off), (short)addrPoint);// 设置链表指针
                /* 性能优化 20140429 zhengtao 把交易过程中需要的必要文件地址扩展到ADF文件头中*/
                if ((ramShort1[0] != 0) || (C9_Flag[1] == 1))
                {
                    if (FID == (short)0x0000)
                    {
                        Util.setShort(MF, (short)(ramShort1[0] + ADF_fileADDR_Offset), (short)addrPoint);// Key文件
                    }
                    else if (FID == (short)0xEF01)
                    {
                        Util.setShort(MF, (short)(ramShort1[0]
                                        + ADF_fileADDR_Offset + 2), (short)addrPoint);// EF01文件
                    }
                    else if (FID == (short)0xEF02)
                    {
                        Util.setShort(MF, (short)(ramShort1[0]
                                        + ADF_fileADDR_Offset + 4), (short)addrPoint);// EF02文件
                    }
                    else if (FID == (short)0xEF03)
                    {
                        Util.setShort(MF, (short)(ramShort1[0]
                                        + ADF_fileADDR_Offset + 6), (short)addrPoint);// EF03文件
                    }
                    else if (FID == (short)0xEF05)
                    {
                        Util.setShort(MF, (short)(ramShort1[0]
                                        + ADF_fileADDR_Offset + 8), (short)addrPoint);// EF05文件
                    }
                    else if (FID == (short)0xEF18 || FID == (short)0x0018)
                    {
                        Util.setShort(MF, (short)(ramShort1[0]
                                        + ADF_fileADDR_Offset + 10), (short)addrPoint);// EF18或0018
                    }
                    else if (buf[ISO7816.OFFSET_CDATA + SFIOff] == MF[(short)(ramShort1[0] + DirSFIOff)])
                    {
                        Util.setShort(MF, (short)(ramShort1[0]
                                        + ADF_fileADDR_Offset + 12), (short)addrPoint);// FCI控制信息中SFI对应的文件
                    }
                }

                if ((short)(sizeOfMF - Uifreepointer) >= (short)(EF_File_len + len))
                {
                    Uifreepointer += (EF_File_len + len);
                }
                g_tradeFlag[0] = (byte)0x5a;
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
            }
            else
            {
                Off = Util.getShort(MF, (short)(Off + Bro_Off));

                if (Util.getShort(MF, Off) == (short)((buf[ISO7816.OFFSET_CDATA + 4] << 8) | (buf[ISO7816.OFFSET_CDATA + 5])))
                {
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                }
                Bro_Off = EF_EF_Off;
            }
        }
    }

    /**
     * APDU指令，用来建立文件，包括MF，DF，EF文件
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_80E0(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();

        /* hsp*/
        if (buf[ISO7816.OFFSET_CLA] != (byte)0x80)
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if ((buf[ISO7816.OFFSET_P1] & 0x3f) > 2
                        || (buf[ISO7816.OFFSET_P1] & 0x3f) < 0)
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (buf[ISO7816.OFFSET_LC] == 0x00)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if ((buf[ISO7816.OFFSET_P1] & 0x3f) == 0x02
                        && buf[ISO7816.OFFSET_LC] != 0x0a)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
        switch ((buf[ISO7816.OFFSET_P1] & 0x3f))
        {
            case (byte)0x00:
                creatMF(buf);
                break;
            case (byte)0x01:
                creatDF(buf);
                break;
            case (byte)0x02:
                creatEF(buf);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                break;
        }
    }

    /**
     * 恢复错误计数器
     * 
     * @param[keyAddress] [错误计数器文件头地址]
     * @param[flag] [flag =0: 恢复错误密钥错误计数器;flag =1: 恢复中石油专用错误计数器]
     */
    public void RestoreCounter(short keyAddress, byte flag)
    {
        short counterAdd;
        
        if (flag == 0)
        {
            counterAdd = (short)(keyAddress + KeyErrorCountOff);
        }
        else
        {
            counterAdd = (short)(keyAddress + EFHeadLen);
        }
        if (((MF[counterAdd] >> 4) & 0x0f) != (MF[counterAdd] & 0x0f))
        {
            MF[counterAdd] = (byte)((MF[counterAdd] & 0x0f0) | ((MF[counterAdd] >> 4) & 0x0f));
        }
    }

    /**
     * 外部认证 modify by zhengtao 20131219 当验证错误次数达到设定值后锁定密钥，返回0x6983（验证方法锁定）
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_0082(APDU apdu)
    {
        short kAddr;// =0; hsp
        byte[] buf = apdu.getBuffer();

        if (buf[ISO7816.OFFSET_CLA] != (byte)0)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (buf[ISO7816.OFFSET_P1] != 0)
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (buf[ISO7816.OFFSET_LC] != 8)// 密文定为8字节
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
        /* 外部认证之前需要进行取随机数指令*/
        if (ramByte[randomFlagOff] != 1)// 如果随机数未生成
        {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);// 引用数据无效
        }
        kAddr = getRecordByKID(TEAK_TYPE, buf[ISO7816.OFFSET_P2]);// 外部认证密钥
         /*modify by zhengtao 20140220 密钥文件和密钥记录未找到都返回0x6a88*/
        if ((kAddr == -1) || (kAddr == -2))
        {
            ISOException.throwIt(KEY_FILE_NOT_FOUND);
        }
        if (!checkSecurity(MF[(short)(kAddr + KeyUseCompeOff)]))// 校验密钥记录的使用权限 add by yujing
        {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if ((MF[(short)(kAddr + KeyErrorCountOff)] & 0x0F) == 0x00)
        {
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);// 认证方法锁定
        }
        DEA_Encrypt(buf, ISO7816.OFFSET_CDATA, buf[ISO7816.OFFSET_LC], kAddr, (short)1);// 解密
        JCSystem.beginTransaction();
        if (Util.arrayCompare(buf, ISO7816.OFFSET_CDATA, Random, (short)1, Random[0]) == 0)// 如果错误次数最大值和剩余错误次数相等，则不用写EEPROM
        { 
            RestoreCounter(kAddr, (byte)0);
            ramByte1[SecuRegOff] = MF[(short)(kAddr + KeyNextStateOff)];// 后续状态赋给安全状态寄存器
        }
        else// 如果验证失败
        {
            ramByte1[SecuRegOff] = 0;// 安全状态计存器清0 add by zhengtao
            MF[(short)(kAddr + KeyErrorCountOff)]--;
            JCSystem.commitTransaction();
            ISOException.throwIt((short)(TRIES_REMAINING + (MF[(short)(kAddr + KeyErrorCountOff)] & 0x0F)));
        }
        JCSystem.commitTransaction();
    }

    /**
     * 校验PIN值，输入PIN值是否正确
     * 校验正确后PIN的错误计数器恢复为初始值，失败后异常退出
     * 
     * @param[keyAddr] [PIN记录的地址]
     * @param[buf] [存储输入的PIN值]
     * @param[offset] [PIN值在buf中的偏移]
     * @param[len] [PIN长度]
     */
    public void cheakPIN(short keyAddr, byte[] buf, byte offset, byte len)
    {
        byte result;
        byte ErrorCount = 0;
        byte Errorlimit = 0;
        
        Errorlimit = (byte)((MF[(short)(keyAddr + KeyErrorCountOff)] & 0xF0) >> 4);
        ErrorCount = (byte)(MF[(short)(keyAddr + KeyErrorCountOff)] & 0x0f);
        result = Util.arrayCompare(buf, (short)offset, MF, (short)(keyAddr + 7), (short)len);

        if ((result == 0) && (MF[(short)(keyAddr + 7 + len)] == -1))
        {
            /* 性能优化 hsp 20140625*/
            if (Errorlimit != ErrorCount)
            {
                JCSystem.beginTransaction();
                MF[(short)(keyAddr + KeyErrorCountOff)] = (byte)((MF[(short)(keyAddr + KeyErrorCountOff)] & 0xF0) | Errorlimit);
                JCSystem.commitTransaction();
            }
        }
        else
        {
            ramByte1[SecuRegOff] = 0;// 安全状态计存器清0
            if (MF[(short)(keyAddr + KeyErrorCountOff)] != 0)
            {
                if (ErrorCount != 0)
                {
                    ErrorCount--;
                    JCSystem.beginTransaction();
                    MF[(short)(keyAddr + KeyErrorCountOff)] = (byte)((MF[(short)(keyAddr + KeyErrorCountOff)] & 0xF0) | ErrorCount);
                    JCSystem.commitTransaction();
                    ISOException.throwIt((short)(TRIES_REMAINING | ErrorCount));
                }
            }
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);
        }
    }

    /**
     * 校验PIN 异常不抛出，只返回，由调用方抛出091221(恢复)
     * 
     * @param[buf] [APDU 缓冲区字节数组]
     */
    public void verifyPIN(byte[] buf)
    {
        short kAddr;// =0; hsp
        byte i;
        byte Pinlen = 0;

        if (buf[ISO7816.OFFSET_P1] != 0)// modify by zhengtao 20131218
                                        // 校验Pin时，P2可以不为0
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if ((buf[ISO7816.OFFSET_LC] < 2) || (buf[ISO7816.OFFSET_LC] > 8))// 检验LC
                                                                     // 如果PIN长度小于2或者大于8则报错
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        for (i = 0; i < (short)(buf[ISO7816.OFFSET_LC]); i++)// 计算实际用到的PIN的密钥长度
                                                             // add by zhengtao
                                                             // 20140220
        {
            if (buf[5 + i] == (byte)0xff)
            {
                break;
            }
            Pinlen++;
        }
        if ((Pinlen < 2) || (Pinlen > 6))// 如果PIN长度小于2或者大于6则报错
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        kAddr = getRecordByKID(DPIN_TYPE, buf[ISO7816.OFFSET_P2]);// 寻找当前DF下的PIN
        if ((kAddr == -1) || (kAddr == -2))// modify by zhengtao 20140220
                                       // PIN未找到返回0x6a88
        {
            ISOException.throwIt(KEY_FILE_NOT_FOUND);
        }
        if (!checkSecurity(MF[(short)(kAddr + KeyUseCompeOff)]))// 校验密钥记录的使用权限
        {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (((MF[(short)(kAddr + KeyErrorCountOff)] & 0xF0) != 0)
                        && ((MF[(short)(kAddr + KeyErrorCountOff)] & 0x0f) == 0))
        {
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);
        }
        cheakPIN(kAddr, buf, ISO7816.OFFSET_CDATA, Pinlen);// 比较pin与当前DF下的PIN
        ramByte1[SecuRegOff] = MF[(short)(kAddr + KeyNextStateOff)];
    }

    /**
     * PIN校验
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_0020(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();

        if (buf[ISO7816.OFFSET_CLA] != (byte)0)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing

        verifyPIN(buf);
    }

    /**
     * 应用锁定
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_841E(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();
        byte keyID = DAMK_KEY_INDEX;// 密钥索引

        if (buf[ISO7816.OFFSET_CLA] != (byte)0x84)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if ((buf[ISO7816.OFFSET_P1] != 0x00)
                        || ((buf[ISO7816.OFFSET_P2] != 0x00 && buf[ISO7816.OFFSET_P2] != 0x01)))
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (buf[ISO7816.OFFSET_LC] != 0x04)// 数据域为4字节MAC
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
        if (MF[(short)(ramShort1[0] + 2)] != (byte)ADFType)// 判断当前的DF是否为ADF
        {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if ((MF[(short)(ramShort1[0] + LockAttrOff)] & 0x03) == 0x02)// 如果应用状态为“永久锁定”
        {
            ISOException.throwIt(APPLICATION_LOCED_PERMANENT);// 应用永久锁定
        }
        if (ramByte[randomFlagOff] != 1)// 如果随机数未生成
        {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);// 引用数据无效
        }
        JCSystem.beginTransaction();

        if (cmEP)
        {
            keyID = 0x01;// for CM EDEP
        }
        short kAddr = getRecordByKID((byte)(APPLK_TYPE & 0x00FF), (byte)(keyID & 0x00FF));// 要找的密钥的起始地址
        if ((kAddr == -1) || (kAddr == -2))
        {
            if((ramByte[appTypeOff] & (byte)(0xF6)) == APP_JTB)//如果是交通部应用应查找维护密钥01 add by yujing
            {
                keyID = 0x01;
            }
            if (!verifyMAC(buf, (short)((DAMK_TYPE << 8) | keyID), (byte)2))// 如果MAC校验失败
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(FILE_MAC_ERROR);// 返回0x6988
            }
        }
        else
        {
            if (!verifyMAC(buf, (short)((APPLK_TYPE << 8) | keyID), (byte)2))// 如果MAC校验失败
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(FILE_MAC_ERROR);// 返回0x6988
            }
        }
        if (buf[ISO7816.OFFSET_P2] == 0x00)// 如果要执行临时锁定
        {
            MF[(short)(ramShort1[0] + LockAttrOff)] = (byte)((MF[(short)(ramShort1[0] + LockAttrOff)] & 0xFC) | 0x01);// 应用临时锁定
        }
        else if (buf[ISO7816.OFFSET_P2] == 0x01)// 如果要执行永久锁定
        {
            MF[(short)(ramShort1[0] + LockAttrOff)] = (byte)((MF[(short)(ramShort1[0] + LockAttrOff)] & 0xFC) | 0x02);// 如果应用已经永久锁定,程序走不到这儿.故不用判断
        }
        JCSystem.commitTransaction();
    }

    /**
     * 应用解锁
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_8418(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();
        byte keyID = DAMK_KEY_INDEX;// 密钥索引

        if (buf[ISO7816.OFFSET_CLA] != (byte)0x84)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if ((buf[ISO7816.OFFSET_P1] != 0) || (buf[ISO7816.OFFSET_P2] != 0))
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (buf[ISO7816.OFFSET_LC] != 0x04)// 数据域为4字节MAC
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
        if (MF[(short)(ramShort1[0] + 2)] != (byte)ADFType)// 判断当前的DF是否为ADF
        {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if ((MF[(short)(ramShort1[0] + LockAttrOff)] & 0x02) == 0x02)// 如果应用状态为“永久锁定”
        {
            ISOException.throwIt(APPLICATION_LOCED_PERMANENT);// 应用永久锁定
        }
        if ((MF[(short)(ramShort1[0] + LockAttrOff)] & 0x01) != 0x01)// 如果应用没有临时锁定”
        {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (ramByte[randomFlagOff] != 1)// 如果随机数未生成
        {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);// 引用数据无效
        }
        if (cmEP)
        {
            keyID = 0x01;// for CM EDEP
        }

        JCSystem.beginTransaction();
        short kAddr = getRecordByKID((byte)(APPULK_TYPE & 0x00FF), (byte)(keyID & 0x00FF));// 要找的密钥的起始地址
        if ((kAddr == -1) || (kAddr == -2))
        {
            if((ramByte[appTypeOff] & (byte)(0xF6)) == APP_JTB)//如果是交通部应用应查找维护密钥01 add by yujing
            {
                keyID = 0x01;
            }
            if (!verifyMAC(buf, (short)((DAMK_TYPE << 8) | keyID), (byte)0))// 如果MAC校验失败
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(FILE_MAC_ERROR);// 返回0x6988
            }
        }
        else
        {
            if (!verifyMAC(buf, (short)((APPULK_TYPE << 8) | keyID), (byte)0))// 如果MAC校验失败
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(FILE_MAC_ERROR);// 返回0x6988
            }
        }
        if ((MF[(short)(ramShort1[0] + LockAttrOff)] & 0x03) == 0x01)// 如果应用被临时锁定
        {
            MF[(short)(ramShort1[0] + LockAttrOff)] = (byte)((MF[(short)(ramShort1[0] + LockAttrOff)] & 0xFC) | 0x00);// 解锁
            if (keySer[0] != 0)
            {
                RestoreCounter(keySer[0], (byte)0);// 恢复密钥错误计数器
            }
        }
        else// 应用未被锁定
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);// 使用条件不满足
        }
        JCSystem.commitTransaction();
    }

    /**
     * 卡片锁定
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_8416(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();
        byte keyID = DAMK_KEY_INDEX;// 密钥索引

        if (buf[ISO7816.OFFSET_CLA] != (byte)0x84)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        if ((buf[ISO7816.OFFSET_P1] != 0) || (buf[ISO7816.OFFSET_P2] != 0x00))
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (buf[ISO7816.OFFSET_LC] != 0x04)// 数据域为4字节MAC
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
        if (MF[(short)(ramShort1[0] + 2)] != (byte)ADFType)// 判断当前的DF是否为ADF
        {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (ramByte[randomFlagOff] != 1)// 如果随机数未生成
        {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);// 引用数据无效
        }

        if (cmEP)
        {
            keyID = 0x01;// for CM EDEP
        }

        JCSystem.beginTransaction();
        if((ramByte[appTypeOff] & (byte)(0xF6)) == APP_JTB)//如果是交通部应用应查找维护密钥01 add by yujing
        {
            keyID = 0x01;
        }
        if (!verifyMAC(buf, (short)((DAMK_TYPE << 8) | keyID), (byte)2))// 如果MAC校验失败,无论几次，都返6988
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(FILE_MAC_ERROR);// 返回0x6988
        }
        EDEPPro.cardLock = 1;
        JCSystem.commitTransaction();
    }

    /**
     * PIN解锁
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_8424(APDU apdu)
    {
        short addrPin;// =0; hsp
        short addrDPUK;// =0; hsp
        byte[] buf = apdu.getBuffer();
        byte i;// = 0; hsp

        if (buf[ISO7816.OFFSET_CLA] != (byte)0x84)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        /*  P2:PIN解锁且修改PIN值*/
        if ((buf[ISO7816.OFFSET_P1] != 0x00) || (buf[ISO7816.OFFSET_P2] != 0x00))
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (buf[ISO7816.OFFSET_LC] != 12)// 密文8+MAC4
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
        addrPin = getRecordByKID(DPIN_TYPE, KEY_INDEX);
        if (addrPin == -1 || addrPin == -2)
        {
            ISOException.throwIt(COMM_WARNING_ERROR);
        }
        if ((MF[(short)(addrPin + KeyErrorCountOff)] & 0x0f) != 0)
        {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (ramByte[randomFlagOff] != 1)// 如果随机数未生成
        {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);// 引用数据无效
        }

        JCSystem.beginTransaction();
        if((ramByte[appTypeOff] & (byte)(0xF6)) == APP_JTB)//如果是交通部应用首先查找PIN解锁密钥02 add by yujing
        {
            addrDPUK = getRecordByKID(DPUK_TYPE, (byte)2);
        }
        else
        {
            addrDPUK = getRecordByKID(DPUK_TYPE, KEY_INDEX); // 解密数据域数据
        }
        if (addrDPUK == -1)
        {
            addrDPUK = getRecordByKID(DPUK_TYPE, (byte)1);
            if (addrDPUK == -1)
            {
                ISOException.throwIt(COMM_WARNING_ERROR);
            }
        }
        else if (addrDPUK == -2)
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        if (!verifyMACforPINUnblock(buf, addrDPUK, (byte)3))
        {
              JCSystem.commitTransaction();
              ISOException.throwIt(FILE_MAC_ERROR);// 返回0x6988
        }
        DEA_Encrypt(buf, ISO7816.OFFSET_CDATA, (short)(buf[ISO7816.OFFSET_LC] - 4), addrDPUK, (short)1);// 解密

        if ((buf[ISO7816.OFFSET_CDATA] < 2) || (buf[ISO7816.OFFSET_CDATA] > 6))// PIN长度只能在2-6之间
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (!checkNC(buf, (byte)(ISO7816.OFFSET_CDATA + 1), buf[ISO7816.OFFSET_CDATA]))// 检验PIN的格式是否正确
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        /*  modify by zhengtao 20140410 对PIN的操作丢弃原有的接口，改为对Key文件的操作*/
        for (i = buf[ISO7816.OFFSET_CDATA]; i < 8; i++)
        {
            buf[ISO7816.OFFSET_CDATA + 1 + i] = (byte)0xff;
        }
        if (Util.arrayCompare(MF, (short)(addrPin + 7), buf, (short)(ISO7816.OFFSET_CDATA + 1), (short)8) == 0)
        {
            if (((MF[(short)(addrPin + KeyErrorCountOff)] >> 4) & 0x0F) != (MF[(short)(addrPin + KeyErrorCountOff)] & 0x0F))
            {
                MF[(short)(addrPin + KeyErrorCountOff)] = (byte)((MF[(short)(addrPin + KeyErrorCountOff)] & 0xF0) | ((MF[(short)(addrPin + KeyErrorCountOff)] >> 4) & 0x0F));// 错误次数恢复最大值
            }
            if (((MF[(short)(addrDPUK + KeyErrorCountOff)] >> 4) & 0x0F) != (MF[(short)(addrDPUK + KeyErrorCountOff)] & 0x0F))
            {
                MF[(short)(addrDPUK + KeyErrorCountOff)] = (byte)((MF[(short)(addrDPUK + KeyErrorCountOff)] & 0xF0) | ((MF[(short)(addrDPUK + KeyErrorCountOff)] >> 4) & 0x0F));// 错误次数恢复最大值
            }
        }
        else
        {
            MF[(short)(addrPin + KeyErrorCountOff)] = (byte)(MF[(short)(addrPin + KeyErrorCountOff)] & 0xF0);
            if ((MF[(short)(addrDPUK + KeyErrorCountOff)] & 0x0F) > 0x00)// 如果错误次数不为0
            {
                MF[(short)(addrDPUK + KeyErrorCountOff)]--;// PIN UNBLOCK key
                                                           // CNT--
            }
            if ((MF[(short)(addrDPUK + KeyErrorCountOff)] & 0x0F) == 0x00)// 如果错误次数为0
            {
                /* 应用永久锁定*/
                MF[(short)(ramShort1[0] + LockAttrOff)] = (byte)((short)(MF[(short)(ramShort1[0] + LockAttrOff)] & 0xFC) | 0x02);
                JCSystem.commitTransaction();
                ISOException.throwIt(APPLICATION_LOCED_PERMANENT);// MAC验证第三次失败返9303
            }
            else
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(FILE_MAC_ERROR);// 0x6988
            }
        }
        JCSystem.commitTransaction();
    }

    /**
     * 生成过程密钥，密钥（前8字节^后8字节）
     * 
     * @param[KeyAdd] [密钥起始地址（密钥头）]
     */
    public void CalculateSESKEY(short KeyAdd)
    {
        short i;
        short keyValueAdd = (short)(KeyAdd + KeyHeadLength);

        for (i = 0; i < 8; i++)
        {
            SESKEY[i] = (byte)(MF[(short)(keyValueAdd + i)] ^ MF[(short)(keyValueAdd + 8 + i)]);
        }
    }

    /**
     * 修改PIN/重装PIN
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_805E(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();
        short length;// = 0; hsp
        short kAddr;// = 0; hsp

        if (buf[ISO7816.OFFSET_CLA] != (byte)0x80)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (((buf[ISO7816.OFFSET_P1] != 0) && (buf[ISO7816.OFFSET_P1] != 1))
                        || buf[ISO7816.OFFSET_P2] != 0)// 判断命令头长度
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        length = (short)(buf[ISO7816.OFFSET_LC] & 0x00FF);
        /* 当前DF的PIN在MyPIN数组中的位置
           modify by zhengtao 20140410 PIN操作修改为基于Key文件的操作*/
        if (buf[ISO7816.OFFSET_P1] == 0x00)// Reload PIN
        {
            if (length < 6 || length > 10)
            {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
            if((ramByte[appTypeOff] & (byte)(0xF6)) == APP_JTB)//如果是交通部应用首先查找重装PIN密钥03 add by yujing
            {
                kAddr = getRecordByKID(DRPK_TYPE, (byte)3);// 要找的密钥的起始地址
            }
            else
            {
                kAddr = getRecordByKID(DRPK_TYPE, KEY_INDEX);// 要找的密钥的起始地址
            }
            if ((kAddr == -1) || (kAddr == -2))
            {
                kAddr = getRecordByKID(DRPK_TYPE, (byte)1);// 要找的密钥的起始地址
            }
            if (kAddr == -1)
            {
                ISOException.throwIt(KEY_FILE_NOT_FOUND);
            }
            else if (kAddr == -2)
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            CalculateSESKEY(kAddr); // 指定密钥的前后八字节异或 hsp

            Util.arrayFillNonAtomic(init, (short)0, (short)8, (byte)0);// 初使值全0

            /* 校验MAC,三次失败则应用永久锁定*/
            DEA_MAC(init, buf, (short)ISO7816.OFFSET_CDATA, (short)(length - 4), kAddr, (byte)1);
            JCSystem.beginTransaction();
            /* 性能优化 20140429 zhengtao*/
            if (Util.arrayCompare(buf, (short)(buf[ISO7816.OFFSET_LC] + 5 - 4), MAC_BUF, (short)0, (short)4) == 0)// 如果验证成功
            {
                /* 如果错误次数最大值和剩余错误次数相等，则不用写EEPROM */
                if (((MF[(short)(kAddr + KeyErrorCountOff)] >> 4) & 0x0F) != (MF[(short)(kAddr + KeyErrorCountOff)] & 0x0F))
                {
                    MF[(short)(kAddr + KeyErrorCountOff)] = (byte)((MF[(short)(kAddr + KeyErrorCountOff)] & 0xF0) | ((MF[(short)(kAddr + KeyErrorCountOff)] >> 4) & 0x0F));// 错误次数恢复最大值
                }
            }
            else// 如果验证失败
            {
                if ((MF[(short)(kAddr + KeyErrorCountOff)] & 0x0F) > 0x00)// 如果错误次数大于0
                {
                    MF[(short)(kAddr + KeyErrorCountOff)]--;
                }
                if (MF[(short)(ramShort1[0] + 2)] == DDFType)// 如果当前文件在DDF或MF下，则不锁应用或锁卡
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(FILE_MAC_ERROR);// 返回0x6988
                }
                if ((MF[(short)(kAddr + KeyErrorCountOff)] & 0x0F) == 0x00)// 如果错误次数为0，则应用永久锁定
                {
                    MF[(short)(ramShort1[0] + LockAttrOff)] = (byte)((MF[(short)(ramShort1[0] + LockAttrOff)] & 0xFC) | 0x02);
                    JCSystem.commitTransaction();
                    ISOException.throwIt(APPLICATION_LOCED_PERMANENT);// MAC验证第三次失败返9303
                }
                JCSystem.commitTransaction();
                ISOException.throwIt(FILE_MAC_ERROR);// 返回0x6988
            }

            length -= 4;
            if ((length < 2) || (length > 6))// 检查PIN的数据格式: PIN长度只能在2-6之间
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            if (!checkNC(buf, ISO7816.OFFSET_CDATA, (byte)length))
            {
                JCSystem.commitTransaction();

                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            kAddr = getRecordByKID(DPIN_TYPE, KEY_INDEX);// 要找的密钥的起始地址
                                                         // modify by zhengtao
                                                         // 20140410
                                                         // 对PIN的操作不再基于接口，直接对Key文件操作
            if (kAddr == -1)
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(COMM_WARNING_ERROR);
            }
            for (byte i = (byte)length; i < 8; i++)
            {
                buf[ISO7816.OFFSET_CDATA + i] = (byte)0xFF;
            }
            Util.arrayCopy(buf, (short)ISO7816.OFFSET_CDATA, MF, (short)(kAddr + 7), (short)8);
            MF[(short)(kAddr + KeyErrorCountOff)] = (byte)((MF[(short)(kAddr + KeyErrorCountOff)] & 0xF0) | ((MF[(short)(kAddr + KeyErrorCountOff)] & 0xF0) >> 4));
            JCSystem.commitTransaction();
        }
        else// Change PIN
        {
            if ((buf[ISO7816.OFFSET_LC] < 5) || (buf[ISO7816.OFFSET_LC] > 13))
            {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
            kAddr = getRecordByKID(DPIN_TYPE, buf[ISO7816.OFFSET_P2]);// 寻找当前DF下的PIN
            if (kAddr == -1)
            {
                ISOException.throwIt(KEY_FILE_NOT_FOUND);
            }
            else if (kAddr == -2)
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            if ((MF[(short)(kAddr + KeyErrorCountOff)] & 0x0f) == 0)
            {
                ISOException.throwIt(ISO7816.SW_FILE_INVALID);
            }

            byte i = 0;
            for (; i < length; i++)// 找FF分融符
            {
                if ((byte)buf[ISO7816.OFFSET_CDATA + i] == (byte)0xFF)
                {
                    break;
                }
            }

            if ((i >= (short)(length - 1)) || (i < 2))// 如果旧PIN小于2或者没有新PIN，或者没有FF
            {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            if ((i < 2) || (i > 6))// // 如果旧PIN的格式不对 PIN长度只能在2-6之间
            {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            if (!checkNC(buf, ISO7816.OFFSET_CDATA, i))
            {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            if (((byte)(length - i - 1) < 2) || ((byte)(length - i - 1) > 6))// PIN长度只能在2-6之间
            {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            if (!checkNC(buf, (byte)(ISO7816.OFFSET_CDATA + i + 1), (byte)(length
                            - i - 1)))// 如果新PIN格式不对
            {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            /* modify by zhengtao 20140410 对PIN的操作丢弃现有接口，改用对Key文件的操作；*/
            cheakPIN(kAddr, buf, ISO7816.OFFSET_CDATA, i);
            JCSystem.beginTransaction();
            byte j = (byte)(length - i - 1);
            for (; j < 8; j++)
            {
                buf[(short)(ISO7816.OFFSET_CDATA + i + 1 + j)] = (byte)0xFF;
            }
            Util.arrayCopy(buf, (short)(ISO7816.OFFSET_CDATA + i + 1), MF, (short)(kAddr + 7), (short)(8));
            MF[(short)(kAddr + KeyErrorCountOff)] = (byte)((MF[(short)(kAddr + KeyErrorCountOff)] & 0xF0) | ((MF[(short)(kAddr + KeyErrorCountOff)] & 0xF0) >> 4));
            JCSystem.commitTransaction();
        }
    }

    /**
     * 内部认证
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_0088(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();

        /* hsp*/
        if (buf[ISO7816.OFFSET_CLA] != (byte)0)
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (buf[ISO7816.OFFSET_P1] != (byte)0)
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (buf[ISO7816.OFFSET_LC] == (byte)0)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if ((byte)(buf[ISO7816.OFFSET_LC] & 0x80) == (byte)0x80)
        {
            if ((buf[ISO7816.OFFSET_LC] & 0x7f) > 0x70)
            {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
        short temp = (short)((buf[ISO7816.OFFSET_LC] & 0x00FF) % 8);
        if (temp != 0)//数据域长度不是8的倍数先补80，如果补80后仍不是8的倍数在其后接着补00直到长度为8的倍数 
                      //add by yujing
        {
            Util.arrayFillNonAtomic(buf, (short)(ISO7816.OFFSET_CDATA + ((short)buf[(short)(ISO7816.OFFSET_LC)] & 0x00ff)), (short)1, (byte)0x080);//补80
            if(temp < 7)
            {
                Util.arrayFillNonAtomic(buf, (short)(ISO7816.OFFSET_CDATA +((short)buf[(short)(ISO7816.OFFSET_LC)] & 0x00ff) + 1), (short)(7 - temp), (byte)00);//补80
            }
            temp = (short)(((short)buf[ISO7816.OFFSET_LC] + 8 - temp) & 0x00ff);
        }
        else
        {
            temp = (short)(((short)buf[ISO7816.OFFSET_LC] & 0x00ff));
        }
        short kAddr = getRecordByKID(TIAK_TYPE, buf[ISO7816.OFFSET_P2]);// 要找的密钥的起始地址
        if ((kAddr == -1) || (kAddr == -2))
        {
            ISOException.throwIt(KEY_FILE_NOT_FOUND);
        }
        if (!checkSecurity(MF[(short)(kAddr + KeyUseCompeOff)]))// 检查使用权限 modify by yujing
        {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        DEA_Encrypt(buf, ISO7816.OFFSET_CDATA, temp, kAddr, (short)0);
        apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, temp);
    }

    /**
     * 读线性定长记录
     * 
     * @param[efAddr] [文件头地址]
     * @param[RecNo] [要读取的记录]
     * @param[arr] [存放返回数据的buf]
     * @param[offset] [实际存储位置在arr中的偏移量]
     * @param[flag] [STK接口标识]
     * @return[返回记录长度]
     */
    public short readFixedRecord(short efAddr, short RecNo, byte[] arr,
                    short offset, byte flag)
    {
        byte recordNum = MF[(short)(efAddr + TotalRecNumOff)];// 得到定长记录的当前记录数
        short recordLength = (short)(MF[(short)(efAddr + FixedRecLenOff)] & 0x00FF);

        if ((RecNo > recordNum) || (RecNo <= 0))
        {
            if (flag == 0)
            {
                ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
            }
            else
            {
                /* 接口返回的数据,现已存在于buf中偏移1.*/
                arr[0] = (byte)0x00;
                arr[1] = (byte)0x90;
                arr[2] = (byte)0x00;
                return 0;
            }
        }

        Util.arrayCopyNonAtomic(MF, (short)(efAddr + EFHeadLen + recordLength
                        * (RecNo - 1)), arr, (short)offset, recordLength);
        return recordLength;
    }
    /**
     * 读线性变长记录
     * 
     * @param[efAddr] [文件头地址]
     * @param[RecNo] [要读取的记录]
     * @param[arr] [存放返回数据的buf]
     * @param[offset] [实际存储位置在arr中的偏移量]
     * @param[flag] [STK接口标识]
     * @return[返回记录长度]
     */
    public short readVarRecord(short efAddr, short RecNo, byte[] arr,
                    short offset, byte flag)
    {
        short addr;// =0; hsp
        byte recordNum = MF[(short)(efAddr + RecNumOff)];// 记录数
        
        if ((RecNo > recordNum) || (RecNo <= 0))// 查询记录不在记录数范围内
        {
            if (flag == 0)
            {
                ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
            }
            else
            {
                /* 接口返回的数据,现已存在于buf中偏移1.*/
                arr[0] = (byte)0x00;
                arr[1] = (byte)0x90;
                arr[2] = (byte)0x00;

                return 0;
            }
        }
        addr = getRecordByRecNo(efAddr, RecNo);// 相应记录的地址
        if (addr == -1)
        {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }
        Util.arrayCopyNonAtomic(MF, addr, arr, offset, gLength[0]);
        return gLength[0];
    }

    /**
     * 读循环文件中的记录 
     * 
     * @param[efAddr] [文件头地址]
     * @param[RecNo] [要读取的记录号]
     * @param[arr] [存放返回数据的buf]
     * @param[offset] [实际存储位置在arr中的偏移量]
     * @param[flag] [STK接口标识]
     * @return[返回记录长度]
     */
    public short readCycRecord(short efAddr, short RecNo, byte[] arr,
                    short offset, byte flag)
    {
        short lAddr;// =0; hsp
        short length = (short)(MF[(short)(efAddr + FixedRecLenOff)] & 0x00FF);// 一条记录的长度
        byte NonceRec = 0;
        short efLen = Util.getShort(MF, (short)(efAddr + FileLenOff));
        byte cycRecNum = (byte)((short)(efLen) / length);// 循环记录的个数=（记录文件大小-文件头的长度）/每条记录长度
        
        if (cmEP)// CM EDEP
        {
            if ((RecNo > cycRecNum) || (RecNo <= 0))
            {
                ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
            }
        }
        else// PBOC EDEP
        {
            if ((RecNo > (short)MF[(short)(efAddr + RecNumOff)]) || (RecNo <= 0))
            {
                if (flag == 0)
                {
                    ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
                }
                else
                {
                    /* 接口返回的数据,现已存在于buf中偏移1.*/
                    arr[0] = (byte)0x00;
                    arr[1] = (byte)0x90;
                    arr[2] = (byte)0x00;
                    return 0;
                }
            }
        }
        NonceRec = MF[(short)(efAddr + NRecAddrOff)];// 获取当前循环记录的位置,占一个字节
        lAddr = (short)(efAddr + EFHeadLen);// 记录文件文件体的位置
        Util.arrayCopy(MF, (short)((short)((short)(NonceRec + cycRecNum - RecNo + 1) % cycRecNum)
                        * length + lAddr), arr, (short)offset, length);
        return length;
    }


    /**
     * 读记录，包括读定长记录，变长记录，循环记录 modify by zhengtao 20131216
     * 由主函数来判断MF是否为NULL
     * 
     * @param[bufferapdu] [STK菜单通过共享接口调用00B2指令时传入的指令数据]
     * @param[apdu] [APDU对象]
     * @param[flag] [00：通过APDU指令执行00B2指令，FCI信息直接返回；其他：共享接口调用00B2指令，
                                    FCI信息存储在buf中，供STK菜单读取，不能直接返回]
     */
    public void CMD_00B2(byte[] bufferapdu, APDU apdu, byte flag)
    {
        byte[] buf;

        if (flag == (byte)0x00)
        {
            buf = apdu.getBuffer();
        }
        else
        {
            buf = bufferapdu;
            apdu = null;
        }

        byte type;// =0; hsp
        byte mode;// =0; hsp
        byte recNo;// =0; hsp
        byte lc = buf[ISO7816.OFFSET_LC];
        short length;// =0; hsp
        short lEFAddr;// = 0; hsp
        byte tByte; // 临时byte变量

        if (buf[ISO7816.OFFSET_CLA] != (byte)0)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if ((buf[ISO7816.OFFSET_P2] & 0x07) > 0x04)// modify by zhengtao
                                                   // 变长记录文件可以通过TAG来查找
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if ((buf[ISO7816.OFFSET_P2] & 0xF8) != 0x00)// 读指定的记录
        {
            /* 按SFI访问，P2的高五位为SFI
               add by zhengtao 20140305 如果SFI=0时，返回0x6a82,保护密钥文件*/
            tByte = (byte)(((buf[ISO7816.OFFSET_P2] & 0xF8) >> 3) & 0x1F);
            if (tByte == (byte)0)
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            lEFAddr = searchFileAddrBySFI(tByte, (byte)0);
	    	if(lEFAddr == -1)
	    	    ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            if (((MF[CardStatusFlagOff] & 0x01) == 0x01)
                            && ((MF[(short)(lEFAddr + 2)] & 0x08) == 0x08))// 如果个人化已经结束且所选择的文件为内部文件
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);// 内部文件不能读，找到也算是未找到
            }
        }
        else
        {
            if (ramShort1[NEFAddrOff] == (short)0x0000)
            {
                ISOException.throwIt(NO_CURRENT_EF);// 当前DF下没有EF被选择(当前DF不在当前EF的范围内)
            }
            lEFAddr = ramShort1[NEFAddrOff];
        }
        if (flag == (byte)0x00)
        {
            if ((MF[CardStatusFlagOff] & 0x01) == 0x01)// 个人化已经结束
            {
                if (!checkSecurity(MF[(short)(lEFAddr + ReadCompeOff)]))
                {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
            }
        }
        type = MF[(short)(lEFAddr + 2)];
        if (((type & 0x30) == (byte)0x30) || ((type & 0x07) == 0x00)) // 非记录文件不能读(个人化结束之前，内部记录文件也可读)
        {
            ISOException.throwIt(FILE_TYPE_NOT_MATCHED);// 文件类型不匹配
        }
        if ((short)(Util.getShort(MF, (short)(lEFAddr + FileLenOff))) == (short)0x0000)// 如果选择是文件体为0的文件
        {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);// 记录找不到
        }

        length = 0;
        if ((byte)(type & 0x07) == (byte)0x06)// 循环记录
        {
            if((buf[ISO7816.OFFSET_P2] & 0x07) != 0x04)// 循环记录文件只能通过记录号来读记录  add by yujing
            {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            length = readCycRecord(lEFAddr, buf[ISO7816.OFFSET_P1], buf, (byte)1, flag);
        }
        else if ((byte)(type & 0x07) == (byte)0x02)// 定长记录
        {
            if((buf[ISO7816.OFFSET_P2] & 0x07) != 0x04)// 定长记录文件只能通过记录号来读记录  add by yujing
            {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            length = readFixedRecord(lEFAddr, buf[ISO7816.OFFSET_P1], buf, (byte)1, flag);
        }
        else if ((byte)(type & 0x07) == (byte)0x04)// 变长记录
        {
            /* modify by zhengtao 20140319
                                       读循环记录文件可以通过TAG方式查找，并且可以查找第一条、下一条、上一条、最后一条等*/
            mode = (byte)(buf[ISO7816.OFFSET_P2] & 0x07);
            if (mode == 0x04)
            {
                recNo = buf[ISO7816.OFFSET_P1];
                if (buf[ISO7816.OFFSET_P1] == 0)
                {
                    recNo = VarCurrentRec[0];
                }
            }
            else
            {
                if (buf[ISO7816.OFFSET_P1] == 0)
                {
                    recNo = VarCurrentRec[0];
                }
                else
                {
                    recNo = FindVarRecByTag(lEFAddr, mode, buf[ISO7816.OFFSET_P1]);
                }
            }

            length = readVarRecord(lEFAddr, (short)recNo, buf, (short)1, flag);
            if ((mode & 0x04) != 4)
            {
                VarCurrentRec[0] = recNo;
            }
        }
        else
        {
            ISOException.throwIt(FILE_TYPE_NOT_MATCHED);// 文件类型不匹配
        }

        if ((lc != (byte)length) && (lc != 0))
        {
            if ((APDU.getProtocol() & (byte)0x80) == (byte)0x80)
            {
                if (flag == (byte)0x00)
                {
                    apdu.setOutgoingAndSend((short)1, (short)(length & 0x00ff));
                }
                else
                {
                    /* 接口返回的数据,现已存在于buf中偏移1.*/
                    buf[0] = (byte)length;
                    buf[(short)(buf[0] + 1)] = (byte)0x90;
                    buf[(short)(buf[0] + 2)] = (byte)0x00;
                }
            }
            else
            {
                if (flag == (byte)0x00)
                {
                    ISOException.throwIt((short)(ISO7816.SW_CORRECT_LENGTH_00 | length));
                }
                else
                {
                    /* 接口返回的数据,现已存在于buf中偏移1.*/
                    buf[0] = (byte)length;
                    buf[(short)(buf[0] + 1)] = (byte)0x90;
                    buf[(short)(buf[0] + 2)] = (byte)0x00;
                }
            }
        }
        else// LC和记录长度一致或者LC为0
        {
            if (flag == (byte)0x00)
            {
                apdu.setOutgoingAndSend((short)1, (short)(length & 0x00ff));
            }
            else
            {
                /* 接口返回的数据,现已存在于buf中偏移1.*/
                buf[0] = (byte)length;
                buf[(short)(buf[0] + 1)] = (byte)0x90;
                buf[(short)(buf[0] + 2)] = (byte)0x00;
            }
        }
    }

    /**
     * 读二进制文件，只有二进制文件适用
     * 
     * @param[bufferapdu] [STK菜单通过共享接口调用00B0指令时传入的指令数据]
     * @param[apdu] [APDU对象]
     * @param[flag] [00：通过APDU指令执行00B0指令，FCI信息直接返回；其他：共享接口调用00B0指令，
                                    FCI信息存储在buf中，供STK菜单读取，不能直接返回]
     */
    public void CMD_00B0(byte[] bufferapdu, APDU apdu, byte flag)
    {
        byte[] buf;// 接口修改
        
        if (flag == (byte)0x00)
        {
            buf = apdu.getBuffer();
        }
        else
        {
            buf = bufferapdu;
            apdu = null;
        }

        short binOff = (short)(buf[ISO7816.OFFSET_P2] & 0x00FF);
        short len = (short)(buf[ISO7816.OFFSET_LC] & 0x00FF);
        short length;// =0; hsp
        short lEFAddr;// = 0; hsp
        byte p1 = buf[ISO7816.OFFSET_P1];
        short tShort; // 临时short型变量

        if (buf[ISO7816.OFFSET_CLA] != (byte)0)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if ((byte)(p1 & (byte)0x80) == (byte)0x80)// B7为1 按SFI访问，P1的低五位为SFI
        {
            if ((p1 & 0x60) != 0x00)// B5B6如果不为0
            {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if ((cmEP) && ((MF[CardStatusFlagOff] & 0x01) == 0x01))
            {
                if (((p1 & 0x1F) < 0x15) || ((p1 & 0x1F) > 0x1E))
                {
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
            }
            if ((byte)(p1 & 0x1F) == 0)// add by zhengtao 20140305
                                       // 如果SFI=0时，返回0x6a82,保护密钥文件
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }

            lEFAddr = searchFileAddrBySFI((byte)(p1 & 0x1F), (byte)0);
            if (lEFAddr == -1)
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            if (((MF[CardStatusFlagOff] & 0x01) == 0x01)
                            && ((MF[(short)(lEFAddr + 2)] & 0x08) == 0x08))// 如果找到的是内部文件且个人化文件结束
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);// 内部文件不能读，找到也算是未找到
            }
        }
        else
        {
            if ((cmEP) && ((MF[CardStatusFlagOff] & 0x01) == 0x01))
            {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if (ramShort1[NEFAddrOff] == (short)0x0000)
            {
                ISOException.throwIt(NO_CURRENT_EF);
            }
            lEFAddr = ramShort1[NEFAddrOff];
            binOff |= (short)(p1 << 8);
        }
        if (((MF[(short)(lEFAddr + 2)] & 0x30) == 0x30)
                        || ((MF[(short)(lEFAddr + 2)] & 0x07) != 0x01))// 如果不是EF文件或者不是二进制文件，则报错
        {
            ISOException.throwIt(FILE_TYPE_NOT_MATCHED);
        }
        if ((MF[CardStatusFlagOff] & 0x01) == 0x01)// 个人化已经结束
        {
            if (!checkSecurity(MF[(short)(lEFAddr + ReadCompeOff)]))
            {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        }

        tShort = (short)(Util.getShort(MF, (short)(lEFAddr + FileLenOff))); // hsp
        if (tShort == (short)0)// 如果选择是文件体为0的文件
        {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);// 偏移量错误
        }

        if (len == 0)
        {
            length = tShort;// 文件体的大小
            len = (short)(length - binOff);
            if (len > (short)0x00FF)
            {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
        }

        if (binOff >= tShort)// 偏移超出文件长度
        {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        if (((short)(tShort) < (short)(binOff + len))
                        || (buf.length < (short)(len + 1))
                        || ((short)(binOff + len) < 0))
        {
            ISOException.throwIt((short)(ISO7816.SW_CORRECT_LENGTH_00 + tShort - binOff));
        }
        Util.arrayCopyNonAtomic(MF, (short)(lEFAddr + 18 + binOff), buf, (short)1, len);

        if (apdu != null)
        {
            apdu.setOutgoingAndSend((short)1, len);// 为配合接口将此处改为1
        }
        else
        {
            /* 接口返回的数据,现已存在于buf中偏移1.*/
            buf[0] = (byte)len;
            buf[(short)(buf[0] + 1)] = (byte)0x90;
            buf[(short)(buf[0] + 2)] = (byte)0x00;
        }
    }

    /**
     * 更新二进制文件
     * 
     * @param[efAddr] [待更新文件地址]
     * @param[offset] [实际更新位置在文件中的偏移量]
     * @param[length] [要更新数据长度]
     * @param[srcBuf] [要更新的数据源]
     * @param[srcOff] [数据源中有效数据偏移]
     */
    public void updateBinary(short efAddr, short offset, short length,
                    byte[] srcBuf, short srcOff)
    {
        short fileLen;// =0; hsp
        short EF_File_len = 18;
        
        fileLen = Util.getShort(MF, (short)(efAddr + FileLenOff));
        if (offset >= (short)fileLen)// 偏移量超出文件长度
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        if ((srcBuf.length < (short)(srcOff + length))
                        || ((short)(fileLen) < (short)(offset + length))
                        || ((short)(offset + length) < 0))// 源buf的长度小于偏移量+更新长度\\文件长度小于偏移量+更新长度
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopy(srcBuf, (short)srcOff, MF, (short)(efAddr + EF_File_len + offset), length);
    }

    /**
     * 更新二进制文件
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_00D6(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();
        short binOff;// = 0; hsp
        short kAddr;// yujing
        //short typeKID;// = 0; hsp
        short srcBufOff;// = 0; hsp
        short length;// = 0; hsp
        byte p1 = buf[ISO7816.OFFSET_P1];
        short lEFAddr;// = 0; hsp
        binOff = (short)(buf[ISO7816.OFFSET_P2] & 0x00FF);

        if ((buf[ISO7816.OFFSET_CLA] != (byte)0)
                        && (buf[ISO7816.OFFSET_CLA] != (byte)0x04))// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if ((byte)(buf[ISO7816.OFFSET_P1] & (byte)0x80) == (byte)0x80)// B7为1
        {
            if ((p1 & 0x60) != 0x00)// B5B6如果不为0
            {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if ((cmEP) && ((MF[CardStatusFlagOff] & 0x01) == 0x01))// special
                                                                   // for CM EP
            {
                if (((p1 & 0x1F) < 0x15) || ((p1 & 0x1F) > 0x1E))// SFI:[0x15,0x1E]
                {
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
                if (((p1 & 0x1F) == 0x15)
                                && ((buf[ISO7816.OFFSET_CLA] & 0x0F) != 0x04))
                {
                    ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);// 15文件必须带线路保护写
                }
            }
            if ((byte)(p1 & 0x1F) == 0)// add by zhengtao 20140305
                                       // SFI=0时返回0x6a82 ,为了保护密钥文件
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }

            lEFAddr = searchFileAddrBySFI((byte)(p1 & 0x1F), (byte)0);// 根据SFI查找文件地址

            if (lEFAddr == -1)// 文件未找到
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            if ((MF[CardStatusFlagOff] & 0x01) == 0x01
                            && (MF[(short)(lEFAddr + 2)] & 0x08) == 0x08)// 如果找到的为内部文件且个人化已经结束
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);// 内部文件不能读，找到也算是未找到
            }
            if (lEFAddr != ramShort1[NEFAddrOff])// 找到的EF地址和当前EF文件地址不一致
            {
                ISOException.throwIt(NO_CURRENT_EF);// 当前DF下没有EF被选择(当前DF不在当前EF的范围内)
            }
        }
        else
        {
            if ((cmEP) && ((MF[CardStatusFlagOff] & 0x01) == 0x01))
            {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if (ramShort1[NEFAddrOff] == (short)0x0000)
            {
                ISOException.throwIt(NO_CURRENT_EF);
            }
            lEFAddr = ramShort1[NEFAddrOff];
            binOff |= (short)(p1 << 8);
        }

        if (buf[ISO7816.OFFSET_LC] == 0x00)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (((MF[(short)(lEFAddr + 2)] & 0x30) == 0x30)
                        || ((MF[(short)(lEFAddr + 2)] & 0x07) != 01))// 如果不是EF文件或者不是二进制文件，则报错
        {
            ISOException.throwIt(FILE_TYPE_NOT_MATCHED);
        }
        if ((((MF[(short)(lEFAddr + SecuAttrOff)] & 0x30) != 0x00) && (buf[ISO7816.OFFSET_CLA] != 04))
                        || ((MF[(short)(lEFAddr + SecuAttrOff)] & 0x30) == 0x00)
                        && (buf[ISO7816.OFFSET_CLA] != 0x00))
        {
            ISOException.throwIt(CLA_NOT_MATCHED);// CLA不匹配
        }

        if (binOff >= (short)(Util.getShort(MF, (short)(lEFAddr + FileLenOff))))// 如果偏移量超出了文件的大小
        {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
        length = (short)(buf[ISO7816.OFFSET_LC] & 0x00FF);
        srcBufOff = ISO7816.OFFSET_CDATA;
        JCSystem.beginTransaction();

        if (Util.getShort(MF, (short)(lEFAddr + FileLenOff)) == (short)0)
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        if(((short)MF[(short)(lEFAddr + SecuAttrOff)] & 0x30) != 0x00)
        {
            kAddr = checkBeforeUseKey(DAMK_TYPE, (byte)(MF[(short)(lEFAddr + SecuAttrOff)] & 0x0F));//查找密钥并检查密钥使用权限和限制次数  yujing
            if ((MF[(short)(lEFAddr + SecuAttrOff)] & 0x20) == 0x20)// 当前文件要求校验MAC
            {
                if (length <= 4)
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                
                //typeKID = (short)((DAMK_TYPE << 8) | (MF[(short)(lEFAddr + SecuAttrOff)] & (short)0x0F));
                length -= 4;
                if (!verifyMACforPINUnblock(buf, kAddr, (byte)0))// 校验MAC modify by yujing
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(FILE_MAC_ERROR);
                }
            }
            if ((MF[(short)(lEFAddr + SecuAttrOff)] & 0x10) == 0x10)// 当前文件要求解密数据域
            {
                if ((length % 8) != 0)// 如果要解密的数据不是8的倍数则报错
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
               /* short kAddr = getRecordByKID(DAMK_TYPE, (byte)(MF[(short)(lEFAddr + SecuAttrOff)] & 0x0F));// 要找的密钥的起始地址
                if (kAddr == -1)// 未找到记录
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(KEY_FILE_NOT_FOUND);
                }
                else if (kAddr == -2)// 未找到文件
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                }*/
                DEA_Encrypt(buf, ISO7816.OFFSET_CDATA, length, kAddr, (short)1);// 解密
                length = (short)(buf[ISO7816.OFFSET_CDATA] & 0x00FF);// LD
                srcBufOff++;// LD之后的数据
            }
        }
        if ((MF[CardStatusFlagOff] & 0x01) == 0x01)// 个人化已经结束
        {
            if (!checkSecurity(MF[(short)(lEFAddr + WriteCompeOff)]))// 校验写权限
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        }

        updateBinary(lEFAddr, binOff, length, buf, srcBufOff);
        JCSystem.commitTransaction();
    }

    /**
     * 更新定长记录文件记录
     * 
     * @param[efAddr] [待更新文件地址]
     * @param[RecNo] [待更新的文件记录号]
     * @param[buf] [要更新的数据源]
     * @param[off] [数据源中有效数据偏移]
     */
    public void updateFixedRecord(short efAddr, short RecNo, byte[] buf,
                    short off)
    {
        byte recordNum = MF[(short)(efAddr + TotalRecNumOff)];// 得到定长记录的当前记录数
        short recordLength = (short)(MF[(short)(efAddr + FixedRecLenOff)] & 0x00FF);
        
        if ((RecNo > recordNum) || (RecNo <= 0))
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }
        if (recordLength != 0)
        {
            Util.arrayCopy(buf, off, MF, (short)(efAddr + EFHeadLen + recordLength
                            * (RecNo - 1)), recordLength);
        }
    }

    /**
     * 更新变长记录文件记录
     * 
     * @param[efAddr] [待更新文件地址]
     * @param[RecNo] [待更新的文件记录号]
     * @param[buf] [要更新的数据源]
     * @param[off] [数据源中有效数据偏移]
     * @param[len] [要更新数据长度]
     */
    public void updateVarRecord(short efAddr, short RecNo, byte[] buf,
                    short off, short len)
    {
        short addr;
        short vLen;// TLV中value的长度
        short tagLen;
        byte recordNum = MF[(short)(efAddr + RecNumOff)];

        if ((RecNo > recordNum) || (RecNo <= 0))
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }

        vLen = checkTLVFormat(buf, off, len);// 得到value值的长度
        if (vLen == -1)
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(TLV_FORMAT_NOT_MATCHED);// 数据域中的数据不符合TLV格式
        }

        addr = getRecordByRecNo(efAddr, RecNo);
        /* modify by zhengtao 20140416 更新变长记录文件时只要求L一致，Tag可以改变
           090116LY//modify by zhengtao 20131231
                            此处代码原本是屏蔽掉的，但是更新变长记录文件时应该比较数据长度，所以再次打开*/
        if ((buf[off] & 0x1F) == 0x1F)
        {
            tagLen = 2;
        }
        else
        {
            tagLen = 1;
        }
        if (Util.arrayCompare(buf, (short)(off + tagLen), MF, (short)(addr + tagLen), (short)(len
                        - vLen - tagLen)) != 0)// 比较两个TLV的TL是否相等
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(TLV_FORMAT_NOT_MATCHED);
        }

        if (addr == -1)
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }

        Util.arrayCopy(buf, off, MF, addr, gLength[0]);
    }

    /**
     * 按照记录标识符查找变长记录
     * 
     * @param[efaddr] [变长记录文件地址]
     * @param[mode] [查找方式：00：读第一条;01：读最后一条；02：读下一条；03：读上一条]
     * @param[Tag] [记录标识符]
     * @return[符合要求的记录的记录号]
     */
    public byte FindVarRecByTag(short efaddr, byte mode, byte Tag)
    {
        short beginaddr;// =0; hsp
        byte recNo;// =0; hsp
        byte recTotal;// =0; hsp
        
        recTotal = MF[(short)(efaddr + RecNumOff)];
        beginaddr = (short)(efaddr + EFHeadLen);
        if ((byte)(mode & 0x01) == (byte)0x00)
        {
            for (recNo = 1; recNo <= recTotal; recNo++)
            {
                if (MF[beginaddr] == Tag)
                {
                    if ((byte)(mode & 0x02) == (byte)0x02)
                    {
                        if (recNo > VarCurrentRec[0])
                        {
                            return recNo;
                        }
                    }
                    else
                    {
                        return recNo;
                    }
                }
                beginaddr = (short)(beginaddr + MF[(short)(beginaddr + 1)] + 2);
            }
            return 0;
        }
        else
        {
            recNo = recTotal;
            if ((byte)(mode & 0x02) == (byte)0x02)
            {
                if (VarCurrentRec[0] != 0)
                {
                    recNo = (byte)(VarCurrentRec[0] - 1);
                }
            }
            if (recNo == 0)
            {
                return 0;
            }
            while (recNo > 0)
            {
                beginaddr = getRecordByRecNo(efaddr, recNo);
                if ((MF[beginaddr] == 0xFF) || (MF[beginaddr] == 0x00))
                {
                    return 0;
                }
                if (MF[beginaddr] == Tag)
                {
                    return recNo;
                }
                recNo--;
            }
            return 0;
        }
    }

    /**
     * 修改（更新）记录，包括定长记录，变长记录 注：循环记录不能更新
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_00DC(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();
        byte type;// =0; hsp
        byte recNo, mode;// =0; hsp
        byte CycUpdataRec;// = 0; hsp
        short kAddr;// yujing
        //short typeKID;// =0; hsp
        short length;// =0; hsp
        short off;// =0; hsp
        short lEFAddr;// = 0;//EF文件地址局部变量 hsp
        short RecAddr;// =0;//循环记录文件更新记录的地址 hsp

        /* hsp*/
        if ((buf[ISO7816.OFFSET_CLA] != (byte)0x00)
                        && (buf[ISO7816.OFFSET_CLA] != (byte)0x04)
                        && (buf[ISO7816.OFFSET_CLA] != (byte)0x80))
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        
        if ((buf[ISO7816.OFFSET_P2] & 0x07) > 0x04)// 只能通过记录号来读记录
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
        if ((buf[ISO7816.OFFSET_P2] & 0xF8) != 0x00)// 读指定的记录 按SFI访问，P2的高五位为SFI
        {
            if ((byte)(((buf[ISO7816.OFFSET_P2] & 0xF8) >> 3) & 0x1F) == 0)// add
                                                                           // by
                                                                           // zhengtao
                                                                           // 20140305
                                                                           // 如果SFI=0时，返回0x6a82,保护密钥文件
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            lEFAddr = searchFileAddrBySFI((byte)(((buf[ISO7816.OFFSET_P2] & 0xF8) >> 3) & 0x1F), (byte)0);
            if (lEFAddr == -1)
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            if ((MF[CardStatusFlagOff] & 0x01) == 0x01
                            && (MF[(short)(lEFAddr + 2)] & 0x08) == 0x08)// 如果个人化已经结束且选择的是内部文件
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);// 内部文件不能读，找到也算是未找到
            }
        }
        else
        {
            if (ramShort1[NEFAddrOff] == (short)0x0000)
            {
                ISOException.throwIt(NO_CURRENT_EF);// 当前DF下没有EF被选择(当前DF不在当前EF的范围内)
            }
            lEFAddr = ramShort1[NEFAddrOff];// EF文件地址局部变量
        }
        if ((((MF[(short)(lEFAddr + SecuAttrOff)] & 0x30) != 0x00) 
                        && (buf[ISO7816.OFFSET_CLA] != 0x04))
                        || ((MF[(short)(lEFAddr + SecuAttrOff)] & 0x30) == 0x00)
                        && (buf[ISO7816.OFFSET_CLA] != 0x00))
        {
            ISOException.throwIt(CLA_NOT_MATCHED);// CLA不匹配
        }

        length = (short)(buf[ISO7816.OFFSET_LC] & 0x00FF);
        off = ISO7816.OFFSET_CDATA;
        JCSystem.beginTransaction();
        if(((short)MF[(short)(lEFAddr + SecuAttrOff)] & 0x30) != 0x00)
        {
            kAddr = checkBeforeUseKey(DAMK_TYPE, (byte)(MF[(short)(lEFAddr + SecuAttrOff)] & 0x0F));//查找密钥并检查密钥使用权限和限制次数  yujing
            if ((MF[(short)(lEFAddr + SecuAttrOff)] & 0x20) == 0x20)// 当前文件要求校验MAC
            {
                if (length <= 4)
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                
                //typeKID = (short)((DAMK_TYPE << 8) | (MF[(short)(lEFAddr + SecuAttrOff)] & (short)0x0F));
                if (!verifyMACforPINUnblock(buf, kAddr, (byte)0))//校验MAC modify by yujing
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(FILE_MAC_ERROR);
                }
                length -= 4;
            }
            if ((MF[(short)(lEFAddr + SecuAttrOff)] & 0x10) == 0x10)// 当前文件要求解密数据域
            {
                if ((length % 8) != 0)// 如果要解密的数据不是8的倍数则报错
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                /*short kAddr = getRecordByKID(DAMK_TYPE, (byte)(MF[(short)(lEFAddr + SecuAttrOff)] & 0x0F));// 要找的密钥的起始地址
                if (kAddr == -1)
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(KEY_FILE_NOT_FOUND);
                }
                else if (kAddr == -2)
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                }*/
                DEA_Encrypt(buf, ISO7816.OFFSET_CDATA, length, kAddr, (short)1);// 解密
                length = (short)(buf[ISO7816.OFFSET_CDATA] & 0x00FF);// LD
                off++;// 数据域在buf中的偏移量(前一位为LD)
            }
        }
        if ((MF[CardStatusFlagOff] & 0x01) == 0x01)// 个人化已经结束
        {
            if (!checkSecurity(MF[(short)(lEFAddr + WriteCompeOff)]))
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        }

        type = MF[(short)(lEFAddr + 2)];
        if (((type & 0x30) == (byte)0x30) || ((type & 0x07) == 0x00))// 除透明文件之外的所有文件都为记录文件(循环记录不能更新)
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(FILE_TYPE_NOT_MATCHED);// 文件类型不匹配
        }

        if ((short)(Util.getShort(MF, (short)(lEFAddr + FileLenOff))) == (short)0x0000)
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }
        if ((type & 0x07) == 0x02)// 定长记录
        {
            if((buf[ISO7816.OFFSET_P2] & 0x07) != 0x04)// 定长记录文件只能通过记录号来读记录  modify by yujing
            {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if ((short)(MF[(short)(lEFAddr + FixedRecLenOff)] & 0x00FF) != length)// 数据域的长度是否等于记录的长度
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            updateFixedRecord(lEFAddr, buf[ISO7816.OFFSET_P1], buf, off);
        }
        else if ((type & 0x07) == 0x04)// 变长记录
        {
            mode = (byte)(buf[ISO7816.OFFSET_P2] & 0x07);
            if (mode == 0x04)
            {
                recNo = buf[ISO7816.OFFSET_P1];
                if (buf[ISO7816.OFFSET_P1] == 0)
                {
                    recNo = VarCurrentRec[0];
                }
            }
            else
            {
                if (buf[ISO7816.OFFSET_P1] == 0)
                {
                    recNo = VarCurrentRec[0];
                }
                else
                {
                    recNo = FindVarRecByTag(lEFAddr, mode, buf[ISO7816.OFFSET_P1]);
                }
            }
            updateVarRecord(lEFAddr, recNo, buf, off, length);
            if ((mode & 0x04) != 0x04)
            {
                VarCurrentRec[0] = recNo;
            }
        }
        else if ((type & 0x07) == 0x06) // 循环记录文件
        {
            mode = (byte)(buf[ISO7816.OFFSET_P2] & 0x07);
            if ((buf[ISO7816.OFFSET_P1] != 0) && (mode == 3))// add by zhengtao
                                                             // 20140319
                                                             // mode=3时00dc可以追加循环记录文件
            {
                appendCycRecord(lEFAddr, buf, off, length);
                VarCurrentRec[0] = 1;
            }
            else if ((buf[ISO7816.OFFSET_P1] != 0) && (mode == 4))// add by zhengtao
                                                                  // 20140319
                                                                  // mode=4时00dc可以更新循环记录文件
            {
                if ((byte)length != MF[(short)(lEFAddr + FixedRecLenOff)])// 更新长度和循环记录文件的记录长度不一致返回6700
                {
                    JCSystem.commitTransaction();
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                if (MF[(short)(lEFAddr + TotalRecNumOff)] == MF[(short)(lEFAddr + RecNumOff)])// 如果记录数等于最大记录数，说明所有记录都已追加
                {
                    if (buf[ISO7816.OFFSET_P1] > MF[(short)(lEFAddr + TotalRecNumOff)])// 如果要更新的记录超过总记录数，返回6a83
                    {
                        JCSystem.commitTransaction();
                        ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
                    }
                }
                else
                {
                    if (buf[ISO7816.OFFSET_P1] > MF[(short)(lEFAddr + RecNumOff)])// 如果要更新的记录超过记录数，返回6a83
                    {
                        JCSystem.commitTransaction();
                        ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
                    }
                }
                /*记录数所指向的记录当成第一条记录，从该记录向前循环计算*/
                if (MF[(short)(lEFAddr + RecNumOff)] >= buf[ISO7816.OFFSET_P1])// 如果记录数不小于要更新的记录
                {
                    CycUpdataRec = (byte)(MF[(short)(lEFAddr + RecNumOff)] - buf[ISO7816.OFFSET_P1]);
                }
                else// 如果记录数小于要更新的记录
                {
                    CycUpdataRec = (byte)(MF[(short)(lEFAddr + TotalRecNumOff)] - (buf[ISO7816.OFFSET_P1] - MF[(short)(lEFAddr + RecNumOff)]));
                }
                RecAddr = (short)(lEFAddr + EFHeadLen + CycUpdataRec
                                * MF[(short)(lEFAddr + FixedRecLenOff)]);
                Util.arrayCopy(buf, off, MF, RecAddr, length);
            }
            else
            {
                JCSystem.commitTransaction();
                ISOException.throwIt(FILE_TYPE_NOT_MATCHED);// 文件类型不匹配
            }
        }
        else
        {
            JCSystem.commitTransaction();
            ISOException.throwIt(FILE_TYPE_NOT_MATCHED);// 文件类型不匹配
        }
        JCSystem.commitTransaction();
    }

    /**
     * Verify Transport Key传输码校验
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_802A(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();

        if (buf[ISO7816.OFFSET_CLA] != (byte)0x80)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0x00)
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);// 参数错误
        }
        if (buf[ISO7816.OFFSET_LC] != 0x08)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);// 长度错误
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
        if (Util.arrayCompare(TransportKey, (short)0, buf, ISO7816.OFFSET_CDATA, (short)8) != 0)
        {
            ISOException.throwIt(VERIFY_INCORRECT);// 校验错误
        }
        MF[CardStatusFlagOff] |= TRANS_KEY_VERIFY;// 校验成功，状态位置1
        JCSystem.beginTransaction();
        JCSystem.commitTransaction();
    }

    /**
     * 指令分发主流程，详见流程图
     * 
     * @param[apdu] [APDU对象]
     */
    public void process(APDU apdu)
    {

        byte[] buf = apdu.getBuffer();
        byte INS = buf[ISO7816.OFFSET_INS];
        byte CLA = buf[ISO7816.OFFSET_CLA];

        if (OpenCard_flag == 0)
        {
            if ((INS == (byte)0xDF) && (CLA == (byte)0x80))
            {
                CMD_80DF(apdu);
                return;
            }
            else
            {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
        }
        if ((INS == (byte)0xDF) && (CLA == (byte)0x80))
        {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        if (cardLock == 1)// 卡片锁定
        {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        if (INS_save[0] != (byte)0x84)
        {
            ramByte[randomFlagOff] = 0;
        }
        INS_save[0] = INS;

        CLA = (byte)(CLA & 0xFC);// 检查CLA放到单个指令中 hsp
        buf[ISO7816.OFFSET_CLA] = CLA; // 安全通道修改 hsp

        if (MF[(short)(ramShort1[0] + 2)] == ADFType) // 在ADF下执行
        {
            /* 检查应用状态 */
            if ((byte)(MF[(short)(ramShort1[0] + LockAttrOff)] & 0x03) == (byte)1) // 应用临时锁定
            {
                if ((INS != SELECT) && (INS != GET_CHALLENGE)
                                && (INS != APP_BLOCK) && (INS != APP_UNBLOCK)
                                && (INS != CARD_BLOCK) && (INS != GET_RESPONSE))
                {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
            }
            if ((byte)(MF[(short)(ramShort1[0] + LockAttrOff)] & 0x03) == (byte)2) // 应用永久锁定
            {
                if ((INS != SELECT) && (INS != GET_CHALLENGE)
                                && (INS != CARD_BLOCK) && (INS != GET_RESPONSE))
                {
                    ISOException.throwIt(APPLICATION_LOCED_PERMANENT);
                }
            }

            /* 交易指令分发 */
            if ((INS != (byte)0xC0) || (CLA != (byte)0x00))// 除去00A4指令，不可执行gerresponse指令
            {
                ramByte[GET_RESPONSE_FLAG] = 0;// 不可执行gerresponse指令
            }
            try
            {
                if (((ramByte[appTypeOff] & APP_HLHT) == APP_HLHT)
                                || ((ramByte[appTypeOff] & APP_PBOC) == APP_PBOC)
                                || ((ramByte[appTypeOff] & APP_ZJB) == APP_ZJB) 
                                || (ramByte[appTypeOff] & (byte)(0xF6)) == APP_JTB) // 判断应用类型 添加交通部应用modify by yujing
                {
                    switch (INS)
                    {
                        case CREDIT_FOR_LOAD:
                            CMD_8052(apdu);
                            return;
                        case DEBIT_FOR_PURCHASE_CASH_WITHDRAW_DEBIT_FOR_UNLOAD:
                            CMD_8054(apdu);
                            return;
                        case GET_BALANCE:
                            CMD_805C(buf, apdu, (byte)0x00);
                            return;
                        case GET_TRANSACTION_PROVE:
                            CMD_805A(apdu);
                            return;
                        case INITIALIZE_FOR_CASH_WITHDRAW_FORLOAD_FOR_PURCHASE_FOR_UNLOAD_FOR_UPDATE:
                            CMD_8050(apdu);
                            return;
                        case UPDATE_OVERDRAW_LIMIT:
                            CMD_8058(apdu);
                            return;
                        case GET_TRANSSTATUS:
                            if (CLA == (byte)0x80)
                            {
                                CMD_8088(apdu);
                                return;
                            }
                    }
                }
            }
            catch (ISOException ie)
            {
                short sw = ie.getReason();

                if (sw != ISO7816.SW_NO_ERROR)
                {
                    ramByte[transStatusOff] = 0x00;// 空闲状态
                    ISOException.throwIt(ie.getReason());
                }
            }
        }

        /* 基本指令 */
        try
        {
            switch (INS)
            {
                case SELECT:
                    CMD_00A4(buf, apdu, (byte)0x00);
                    return;
                case Read_record:
                    CMD_00B2(buf, apdu, (byte)0x00);
                    return;
                case Read_Binary:
                    CMD_00B0(buf, apdu, (byte)0x00);
                    return;
                case Verify:
                    CMD_0020(apdu);
                    return;
                case Update_Binary:
                    CMD_00D6(apdu);
                    return;
                case Update_Record:
                    if (CLA == (byte)0x80)
                    {
                        CMD_80DC(apdu);
                        return;
                    }
                    else
                    {
                        CMD_00DC(apdu);
                        return;
                    }
                case APPEND_RECORD:
                    CMD_00E2(apdu);
                    return;
                case Write_ZJB_Number:
                    CMD_8002(apdu);
                    return;
              //case 0x04: //用于调试
                  //CMD_8004(apdu);
                  //return;
                case GET_CHALLENGE:
                    CMD_0084(apdu);
                    return;
                case CARD_ISSUE:
                    CMD_800A(apdu);
                    return;
                case WRITE_KEY:
                    CMD_80D4(apdu);
                    return;
                case Erase_DF:
                    CMD_80EE(apdu);
                    return;
                case CREAT_FILE:
                    CMD_80E0(apdu);
                    return;
                case Int_Authentication:
                    if (CLA == (byte)0)
                    {
                        CMD_0088(apdu);
                        return;
                    }
                case Ext_Authentication:
                    CMD_0082(apdu);
                    return;
                case VERIFY_TRANSPORTKEY:
                    CMD_802A(apdu);
                    return;
                case Change_Reload_PIN:
                    CMD_805E(apdu);
                    return;
                case Unblock_PIN:
                    CMD_8424(apdu);
                    return;
                case GET_RESPONSE:
                    CMD_00C0(apdu);
                    return;
                case GET_LOCK_PROOF:
                    /* hsp*/
                    if (CLA == (byte)0xE0)
                    {
                        ramByte[transStatusOff] = (byte)0x00; // 空闲状态
                    }
                    if ((CLA != (byte)0x80) && (CLA != (byte)0xE0))
                    {
                        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                    }

                    if (CLA == (byte)0x80)
                    {
                        CMD_80CA(apdu);
                        return;
                    }
            }

            if (MF[(short)(ramShort1[0] + 2)] == ADFType)
            {
                if (((ramByte[appTypeOff] & APP_HLHT) == APP_HLHT)
                                || ((ramByte[appTypeOff] & APP_PBOC) == APP_PBOC)
                                || ((ramByte[appTypeOff] & APP_ZJB) == APP_ZJB)
                                || (ramByte[appTypeOff] & (byte)(0xF6)) == APP_JTB)//添加交通部应用modify by yujing
                {
                    switch (INS)
                    {
                        case APP_BLOCK:
                            CMD_841E(apdu);
                            return;
                        case APP_UNBLOCK:
                            CMD_8418(apdu);
                            return;
                        case CARD_BLOCK:
                            CMD_8416(apdu);
                            return;
                    }
                }
            }
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        catch (ISOException ie)
        {
            short sw = ie.getReason();
            if ((sw != ISO7816.SW_NO_ERROR)
                            && ((short)(sw & 0x7f00) != ISO7816.SW_BYTES_REMAINING_00)
                            && ((short)(sw & 0x7f00) != ISO7816.SW_CORRECT_LENGTH_00)
                            && (sw != ISO7816.SW_UNKNOWN))
            {
                ramByte[transStatusOff] = 0x00;// 空闲状态
            }
            ISOException.throwIt(ie.getReason());
        }
        finally
        {
            if ((INS != (byte)0xA4) || (CLA != (byte)0x00))// 除去00A4指令，不可执行gerresponse指令
            {
                ramByte[GET_RESPONSE_FLAG] = 0;
            }
            if (!(((INS == (byte)0xdc) && (CLA == (byte)0x80))
                            || ((INS == (byte)0xca) && (CLA == (byte)0x80)) || (INS == (byte)0x88)))
            {
                ramByte[transStatusOff] = 0x00; // 交易状态清0
            }
        }
    }

    /**
     * 生成MAC，存放在TAC_MAC
     * 
     * @param[init] [生成MAC的初始向量]
     * @param[msg] [生成MAC的明文]
     * @param[msgoff] [报文在msg中的偏移量]
     * @param[len] [报文长度]
     * @param[keyoffset] [密钥在MF中的偏移量，对单字节密钥来说，此字节无效]
     * @param[flag] [flag=1:单倍长密钥计算MAC flag=2: 双倍长密钥计算MAC]
     */
    public void DEA_MAC(byte[] init, byte[] msg, short msgoff, short len,
                    short keyoffset, byte flag)
    {
        if (flag == 1)
        {
            deskey.setKey(SESKEY, (short)0);
            MACcalculate.init(deskey, Signature.MODE_SIGN, init, (short)0, (short)8);
            MACcalculate.sign(msg, msgoff, len, MAC_BUF, (short)0);// 性能优化
        }
        else
        {
            deskey16.setKey(MF, (short)(keyoffset + KeyHeadLength));
            MACcalculate16.init(deskey16, Signature.MODE_SIGN, init, (short)0, (short)8);
            MACcalculate16.sign(msg, msgoff, len, MAC_BUF, (short)0);
        }
    }

    /**
     * 生成移动要求会话密钥
     * 预 处 理：随机数、80000000
     */
    public void SESKEYOdbm()
    {
        Util.arrayCopyNonAtomic(Random, (short)1, buffer, (short)0, (short)4);
        buffer[4] = (byte)0x80;
        buffer[5] = (byte)0x00;
        buffer[6] = (byte)0x00;
        buffer[7] = (byte)0x00;
        Util.arrayCopyNonAtomic(DEA_Encrypt(buffer, (short)0, (byte)8, ramShort[0], (short)0), (short)0, SESKEY, (short)0, (short)0x8);
    }

    /**
     * Single DES加密/解密
     * 
     * @param[input] [要加密或解密的数据]
     * @param[inputoff] [数据在input中的偏移]
     * @param[inputlength] [报文长度]
     * @param[key] [密钥在MF中的偏移量]
     * @param[flag] [flag =0: 加密 flag =1: 解密]
     * @return[明文或密文的数组的起始地址]
     */
    public byte[] SingleDes(byte[] input, short inputoff, short inputlength,
                    byte[] key, short flag)
    {
        deskey.setKey(key, (short)0);
        if (flag == 0)
        {
            cipherECB.init(deskey, Cipher.MODE_ENCRYPT);
        }
        else
        {
            cipherECB.init(deskey, Cipher.MODE_DECRYPT);
        }
        cipherECB.doFinal(input, inputoff, inputlength, input, (short)0);
        return input;
    }

    /**
     * 3DES加密/解密 modify by zhengtao 20140110 加解密方式按照密钥长度分别支持3DES和单DES两种算法
     * 
     * @param[input] [要加密或解密的数据]
     * @param[inputoff] [数据在input中的偏移]
     * @param[inputlength] [报文长度]
     * @param[keyoffset] [密钥在MF中的偏移量]
     * @param[flag] [flag =0: 加密 flag =1: 解密]
     * @return[明文或密文的数组的起始地址]
     */
    public byte[] DEA_Encrypt(byte[] input, short inputoff, short inputlength,
                    short keyoffset, short flag)
    {
        if((MF[keyoffset]-6) > (byte)0x08)
        {
            deskey16.setKey(MF, (short)(keyoffset + KeyHeadLength));
            if (flag == 0)
            {
                cipherECB.init(deskey16, Cipher.MODE_ENCRYPT);
            }
            else
            {
                cipherECB.init(deskey16, Cipher.MODE_DECRYPT);
            }
            cipherECB.doFinal(input, inputoff, inputlength, input, inputoff);
        }
        else
        {
            deskey.setKey(MF, (short)(keyoffset + KeyHeadLength));
            if (flag == 0)
            {
                cipherECB.init(deskey, Cipher.MODE_ENCRYPT);
            }
            else
            {
                cipherECB.init(deskey, Cipher.MODE_DECRYPT);
            }
            cipherECB.doFinal(input, inputoff, inputlength, input, inputoff);
        }

        return input;
    }

    /**
     * 移动指令中3DES解密
     * 
     * @param[input] [要解密的数据]
     * @param[inputoff] [数据在input中的偏移]
     * @param[inputlength] [报文长度]
     * @param[key] [解密时使用的密钥数据]
     * @return[明文或密文的数组的起始地址]
     */
    public byte[] DEA_Encrypt_By_CM(byte[] input, short inputoff,
                    short inputlength, byte[] key)
    {
        deskey.setKey(key, (short)0);
        cipherECB.init(deskey, Cipher.MODE_DECRYPT);
        cipherECB.doFinal(input, inputoff, inputlength, input, inputoff);
        return input;
    }

    /**
     * 生成TAC过程密钥，TAC密钥（前8字节^后8字节）
     * 
     * @param[tacKeyAdd] [TAC密钥起始地址（密钥头） ]
     */
    public void CalculateTACSESKEY(short tacKeyAdd)
    {
        short keyValueAdd = (short)(tacKeyAdd + KeyHeadLength);
        Util.arrayCopyNonAtomic(MF, keyValueAdd, SESKEY, (short)0, (short)8);
    }

    /**
     * 生成联机过程密钥
     * 预 处 理：随机数、联机交易序号、应用密钥起始地址
     */
    public void SESKEYOnline()
    {
        Util.arrayCopyNonAtomic(Random, (short)1, buffer, (short)0, (short)4);
        Util.arrayCopyNonAtomic(transNO, (short)0, buffer, (short)4, (short)2);
        buffer[6] = (byte)0x80;
        buffer[7] = (byte)0x00;
        Util.arrayCopyNonAtomic(DEA_Encrypt(buffer, (short)0, (byte)8, ramShort[0], (short)0), (short)0, SESKEY, (short)0, (short)0x8);
    }

    /**
     * 生成脱机过程密钥
     * 预 处理：随机数、脱机交易序号、终端交易序号、应用密钥起始地址
     */
    public void SESKEYOffline()
    {
        Util.arrayCopyNonAtomic(Random, (short)1, buffer, (short)0, (short)4);
        Util.arrayCopyNonAtomic(transNO, (short)0, buffer, (short)4, (short)2);
        Util.arrayCopyNonAtomic(tillTransNO, (short)2, buffer, (short)6, (short)2);
        Util.arrayCopyNonAtomic(DEA_Encrypt(buffer, (short)0, (byte)8, (short)ramShort[0], (short)0), (short)0, SESKEY, (short)0, (short)0x8);
    }

    /**
     * 生成联机MAC1
     * 预 处理：ED/EP交易序号（交易前）、交易金额、交易类型标识、终端机编号、SESKEY
     */
    public void MAC1Online()
    {
        Util.arrayCopyNonAtomic(balance, (short)0, buffer, (short)0, (short)4);
        Util.arrayCopyNonAtomic(transSum, (short)0, buffer, (short)4, (short)4);
        buffer[8] = ramByte[0];
        Util.arrayCopyNonAtomic(machineNUM, (short)0, buffer, (short)9, (short)6);
        DEA_MAC(init, buffer, (short)0, (short)15, (short)0, (byte)1);// DES_MAC为MAC1
    }

    /**
     * 生成脱机MAC1
     * 预 处理：交易金额、交易类型标识、终端机编号、交易日期＋交易时间、SESKEY
     */
    public void MAC1Offline()
    {
        Util.arrayCopyNonAtomic(transSum, (short)0, buffer, (short)0, (short)4);
        buffer[4] = ramByte[0];
        Util.arrayCopyNonAtomic(machineNUM, (short)0, buffer, (short)5, (short)6);
        Util.arrayCopyNonAtomic(dateandTime, (short)0, buffer, (short)11, (short)7);// 交易日期
                                                                                    // ＋
                                                                                    // 交易时间
        DEA_MAC(init, buffer, (short)0, (short)18, (short)0, (byte)1);// DES_MAC为MAC1
    }

    /**
     * 生成联机MAC2
     * 预 处理：交易金额、交易类型标识、终端机编号、交易日期＋交易时间、过程密钥SESKEY
     */
    public void MAC2Online()
    {
        Util.arrayCopyNonAtomic(transSum, (short)0, buffer, (short)0, (short)4);
        buffer[4] = ramByte[0];
        Util.arrayCopyNonAtomic(machineNUM, (short)0, buffer, (short)5, (short)6);
        Util.arrayCopyNonAtomic(dateandTime, (short)0, buffer, (short)11, (short)7);// 交易日期
                                                                                    // ＋
                                                                                    // 交易时间
        DEA_MAC(init, buffer, (short)0, (short)18, (short)0, (byte)1);// DES_MAC为MAC2
    }

    /**
     * 生成脱机MAC2
     * 预 处 理：交易金额、过程密钥SESKEY
     */
    public void MAC2Offline()
    {
        Util.arrayCopyNonAtomic(transSum, (short)0, buffer, (short)0, (short)4);
        /* DES_MAC为MAC2
                            不到8字节的报文算MAC和加密结果是一样的*/
        Util.arrayFillNonAtomic(init, (short)0, (short)8, (byte)0);// 清零
        DEA_MAC(init, buffer, (short)0, (short)4, (short)0, (byte)1);
    }

    /**
     * 生成联机MAC3
     * 预 处 理：交易金额、过程密钥SESKEY
     */
    public void MAC3Online()
    {
        Util.arrayCopyNonAtomic(balance, (short)0, buffer, (short)0, (short)4);
        Util.arrayCopyNonAtomic(transNO, (short)0, buffer, (short)4, (short)2);
        Util.arrayCopyNonAtomic(transSum, (short)0, buffer, (short)6, (short)4);
        buffer[10] = ramByte[0];
        Util.arrayCopyNonAtomic(machineNUM, (short)0, buffer, (short)11, (short)6);
        Util.arrayCopyNonAtomic(dateandTime, (short)0, buffer, (short)17, (short)7);// 交易日期
                                                                                    // ＋
                                                                                    // 交易时间
        DEA_MAC(init, buffer, (short)0, (short)24, (short)0, (byte)1);// DES_MAC为MAC3
    }

    /**
     * 生成联机TAC
     * INPUT:ED/EP余额（交易后）、ED/EP联机交易序号（交易前）、交易金额、交易类型标识、终端机编号、交易日期＋交易时间、DTK(SESKEY)
     * OUPUT: TAC
     */
    public void TACOnline()
    {
        Util.arrayCopyNonAtomic(balance, (short)0, buffer, (short)0, (short)4);
        Util.arrayCopyNonAtomic(transNO, (short)0, buffer, (short)4, (short)2);
        Util.arrayCopyNonAtomic(transSum, (short)0, buffer, (short)6, (short)4);
        buffer[10] = ramByte[0];
        Util.arrayCopyNonAtomic(machineNUM, (short)0, buffer, (short)11, (short)6);
        Util.arrayCopyNonAtomic(dateandTime, (short)0, buffer, (short)17, (short)7);// 交易日期
                                                                                    // ＋
                                                                                    // 交易时间
        DEA_MAC(init, buffer, (short)0, (short)24, (short)0, (byte)1);// DES_MAC为MAC3
    }

    /**
     * 生成脱机TAC
     * INPUT:交易金额、、交易类型标识、、终端机编号、终端交易序号、交易日期＋交易时间、DTK
     * OUTPUT: TAC
     */
    public void TACOffline()
    {
        Util.arrayCopyNonAtomic(transSum, (short)0, buffer, (short)0, (short)4);
        buffer[4] = ramByte[0];
        Util.arrayCopyNonAtomic(machineNUM, (short)0, buffer, (short)5, (short)6);
        Util.arrayCopyNonAtomic(tillTransNO, (short)0, buffer, (short)11, (short)4);
        Util.arrayCopyNonAtomic(dateandTime, (short)0, buffer, (short)15, (short)7);// 交易日期
                                                                                    // ＋
                                                                                    // 交易时间
        DEA_MAC(init, buffer, (short)0, (short)22, (short)0, (byte)1);// DES_MAC为MAC3
    }

    /**
     * 生成交易记录
     */
    public void ProduceTransDaily()
    {
        short fileAdd;
        short ADF_fileADDR_Offset = 40;

        if ((fileAdd = Util.getShort(MF, (short)(ramShort1[0]
                        + ADF_fileADDR_Offset + 10))) == -1)// 性能优化 20140429
                                                            // zhengtao
                                                            // 交易记录文件地址直接从ADF文件头中读取
        {
            ramByte[transStatusOff] = 0x00; // 空闲状态
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        Util.arrayCopyNonAtomic(transNO, (short)0, buffer, (short)0, (short)2);
        Util.arrayCopyNonAtomic(overDrawLimit, (short)1, buffer, (short)2, (short)3);
        Util.arrayCopyNonAtomic(transSum, (short)0, buffer, (short)5, (short)4);
        buffer[9] = ramByte[0];
        Util.arrayCopyNonAtomic(machineNUM, (short)0, buffer, (short)10, (short)6);
        Util.arrayCopyNonAtomic(dateandTime, (short)0, buffer, (short)16, (short)7);// 交易日期
                                                                                    // ＋
                                                                                    // 交易时间
		appendCycRecord(fileAdd,buffer,(short)0x0,(short)0x17);
    }

    /**
     * 生成交易证明
     * 
     * @param[mac] [存放mac的buf]
     * @param[macOffset] [mac在buf中的偏移量]
     * @param[tac] [存放tac的buf]
     * @param[tacOffset] [tac在buf中的偏移量]
     */
    public void ProduceTransProof(byte[] mac, short macOffset, byte[] tac,
                    short tacOffset)
    {
        buffer[8] = ramByte[0];// 性能优化 全局buffer从第9个字节开始用 hsp
        Util.arrayCopyNonAtomic(transNO, (short)0, buffer, (short)(9), (short)2);
        buffer[(short)(11)] = 0x01;
        Util.arrayCopyNonAtomic(mac, (short)macOffset, buffer, (short)(12), (short)4);
        Util.arrayCopyNonAtomic(tac, (short)tacOffset, buffer, (short)(16), (short)4);
    }

    /**
     * 攒待发送的数据
     * 
     * @param[transStatus] [卡片交易状态]
     */
    public void PrepareSendData(byte transStatus)
    {
        Util.arrayCopyNonAtomic(balance, (short)0, buffer, (short)0x40, (short)4);
        Util.arrayCopyNonAtomic(transNO, (short)0, buffer, (short)0x44, (short)2);

        if ((transStatus == G_TranStatus_L) || (transStatus == G_TranStatus_UL))
        {
            Util.arrayCopyNonAtomic(MF, (short)(ramShort[0] + KeyEditionOff), buffer, (short)0x46, (short)2);
            Util.arrayCopyNonAtomic(Random, (short)1, buffer, (short)0x48, (short)4);
            Util.arrayCopyNonAtomic(MAC_BUF, (short)0, buffer, (short)0x4c, (short)4);
        }
        else// length == 0x0f
        {
            Util.arrayCopyNonAtomic(overDrawLimit, (short)1, buffer, (short)0x46, (short)3);
            Util.arrayCopyNonAtomic(MF, (short)(ramShort[0] + KeyEditionOff), buffer, (short)0x49, (short)2);
            Util.arrayCopyNonAtomic(Random, (short)1, buffer, (short)0x4b, (short)4);
            if (transStatus == G_TranStatus_U)// length == 0x13
            {
                Util.arrayCopyNonAtomic(MAC_BUF, (short)0, buffer, (short)0x4f, (short)4);
            }
        }
    }

    /**
     * 生成随机数 随机数存放在 Random[] 第一字节为长度
     * 
     * @param[len] [长度]
     */
    public void ProduceRandom(short len)
    {
        randomData.generateData(Random, (short)1, len);
        Random[0] = (byte)len;
    }

    /**
     * 四字节加法运算
     * 
     * @param[data1] [加数]
     * @param[data2] [被加数]
     * @param[big12] [存储累加和]
     * @param[off] [累加和在big12的偏移]
     * @return[false:数据溢出；true：数据正常]
     */
    public boolean FourBytesAdd(byte[] data1, byte[] data2, byte[] big12,
                    short off)
    {
        short c = 0;
        short num;// =0;
        byte i;

        for (i = 3; i >= 0; i--)
        {
            big1[i] = (short)(data1[i] & 0x00ff);
            big2[i] = (short)(data2[i] & 0x00ff);
            num = (short)(big1[i] + big2[i] + c);
            big12[(short)(off + i)] = (byte)(num & 0x00FF);
            c = (short)((num >> 8) & 0x00FF);
        }
        if (c != 0x00)
        {
            return false;
        }
        else
        {
            return true;
        }
    }

    /**
     * 四字节减法运算
     * 
     * @param[data1] [减数]
     * @param[data2] [被减数]
     * @param[big12] [存储累加和]
     * @param[off] [累加和在big12的偏移]
     * @return[false:数据溢出；true：数据正常]
     */
    public boolean FourBytesSub(byte[] data1, byte[] data2, byte[] big12)
    {

        byte i;

        if (arrayCompare(data1, (short)0, data2, (short)0, (short)4) < 0)// if
                                                                         // data1
                                                                         // <
                                                                         // data2,
                                                                         // 错误
        {
            return false;
        }

        for (i = 0; i < 4; i++)// convert byte to short
        {
            /* hsp*/
            big1[i] = Util.makeShort((byte)0x00, data1[i]);
            big2[i] = Util.makeShort((byte)0x00, data2[i]);
        }

        if (big1[3] < big2[3])
        {
            big1[3] = (short)(big1[3] + (short)0x0100 - big2[3]);
            big1[2] = (short)(big1[2] - 1);
        }
        else
        {
            big1[3] = (short)(big1[3] - big2[3]);
        }
        if (big1[2] < big2[2])
        {
            big1[2] = (short)(big1[2] + (short)0x0100 - big2[2]);
            big1[1] = (short)(big1[1] - 1);
        }
        else
        {
            big1[2] = (short)(big1[2] - big2[2]);
        }
        if (big1[1] < big2[1])
        {
            big1[1] = (short)(big1[1] + (short)0x0100 - big2[1]);
            big1[0] = (short)(big1[0] - 1);
        }
        else
        {
            big1[1] = (short)(big1[1] - big2[1]);
        }
        big1[0] = (short)(big1[0] - big2[0] + (big1[1] >> 8));

        for (i = 0; i < 4; i++)
        {
            big12[i] = (byte)(big1[i] & 0x00ff);
        }
        return true;
    }

    /**
     * 两组数组比较数据
     * 
     * @param[src] [源数据数组]
     * @param[srcOff] [源数据在src中的偏移]
     * @param[dest] [目的数据数组]
     * @param[destOff] [目的数据在dest中的偏移]
     * @param[length] [比较长度]
     * @return[1:源数据大于目的数据；-1：源数据小于目的数据；0：两组数据相等]
     */
    public byte arrayCompare(byte[] src, short srcOff, byte[] dest,
                    short destOff, short length)
    {
        short i = 0;
        
        for (; i < length; i++)
        {
            if ((short)(src[(short)(srcOff + i)] & 0x00FF) > (short)(dest[(short)(destOff + i)] & 0x00FF))
            {
                return 1;
            }
            if ((short)(src[(short)(srcOff + i)] & 0x00FF) < (short)(dest[(short)(destOff + i)] & 0x00FF))
            {
                return -1;
            }
        }
        return 0;
    }

    /**
     * 错误计数器减1,当计数器为0时，记住锁定的偏移
     * 
     * @param[Address] [指向文件头的起始地址]
     * @param[flag] [flag =0 ,对于key的计数器;flag =1 ,对于解扣计数器，不需要]
     * @return[-1：异常；counter：剩余尝试次数]
     */
    public byte DeduceCounter(short Address, byte flag)
    {
        byte counter;
        short counterAdd;
        
        if (flag == 0)
        {
            counterAdd = (short)(Address + KeyErrorCountOff);
            counter = (byte)(MF[counterAdd] & 0x0f);
        }
        else
        {
            counterAdd = (short)(Address + EFHeadLen);
            counter = (byte)(MF[counterAdd] & 0x0f);
        }

        if (counter > 0)
        {
            counter--;
            if (counter == 0)
            {
                keySer[0] = Address;
            }
            MF[counterAdd] = (byte)((MF[counterAdd] & 0x0f0) | counter);
            return counter;
        }
        return -1;
    }

    /**
     * 读余额文件
     * 
     * @param[EP0ED1ET2Flg] [0：电子钱包余额；其他：电子存折余额]
     * @param[R0W1] [0：读；其他：写]
     * @param[OFF0ON1] [0：OFFLINE；1：ONLINE]
     */
    public void GetEDEPETBalance(byte EP0ED1ET2Flg, byte R0W1, byte OFF0ON1)
    {
        short fileLen;// = 0; hsp
        short fileAddr;// = 0;//文件体起始地址 hsp
        short i;
        short ADF_fileADDR_Offset = 40;
        byte sum;// =0; hsp

        if (EP0ED1ET2Flg == 0x00)
        {
            /* 性能优化 20140429 zhengtao 应用下的余额文件直接从DF文件头中读取 */
            if ((ramShort1[0] != 0) || (C9_Flag[1] == 1))
            {
                ramShort[EDEPETFileAddressOff] = Util
                                .getShort(MF, (short)(ramShort1[0]
                                                + ADF_fileADDR_Offset + 4));
            }
            else
            {
                ramShort[EDEPETFileAddressOff] = searchFileAddrByFID(EPFID, (byte)1);
            }
            if (!cmEP)
            {
                fileLen = 0x08;
            }
            else
            {
                fileLen = 0x0b;
            }
        }
        else
        {
            /* modify by zhengtao 20140303 防止部分金融文件结构的FID和FID不一致
                                        性能优化 20140429 zhengtao 应用下的余额文件直接从DF文件头中读取*/
            if ((ramShort1[0] != 0) || (C9_Flag[1] == 1))
            {
                ramShort[EDEPETFileAddressOff] = Util.getShort(MF, (short)(ramShort1[0]
                                                + ADF_fileADDR_Offset + 2));
            }
            else
            {
                ramShort[EDEPETFileAddressOff] = searchFileAddrByFID(EDFID, (byte)1);
            }
            fileLen = 0x0b;
        }

        if (ramShort[EDEPETFileAddressOff] == -1)
        {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        ramShort[EDEPETFileAddressOff] += EFHeadLen;// modify by zhengtao
                                                    // 20131210
        fileAddr = ramShort[EDEPETFileAddressOff];
        if (R0W1 == 0)// 判断读还是写
        {
            /* hsp*/
            if (MF[(short)(fileAddr - 14)] == (short)0x0c)
            {
                sum = 0;
                for (i = 0; i < (short)0x0b; i++)
                    sum += MF[(short)(fileAddr + i)];
                if (sum != MF[(short)(fileAddr + 0x0b)])
                {
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                }
            }
            if (OFF0ON1 == (byte)0x00)
            {
                Util.arrayCopyNonAtomic(MF, fileAddr, transNO, (short)0, (short)0x2);
            }
            else
            {
                Util.arrayCopyNonAtomic(MF, (short)(fileAddr + 0x2), transNO, (short)0, (short)0x2);
            }
            Util.arrayCopyNonAtomic(MF, (short)(fileAddr + 0x4), balance, (short)0, (short)0x4);

            if ((EP0ED1ET2Flg == 0x00) && (!cmEP))// 如果是PBOC的EP，则透限为0
            {
                Util.arrayFillNonAtomic(overDrawLimit, (short)0, (short)4, (byte)0);
            }
            else
            {
                overDrawLimit[0] = 0;
                Util.arrayCopyNonAtomic(MF, (short)(fileAddr + 0x8), overDrawLimit, (short)1, (short)0x3);
            }
        }
        else
        {
            Util.arrayCopyNonAtomic(MF, fileAddr, buffer, (short)0x00, (short)12);
            if (OFF0ON1 == (byte)0x00)
            {
                Util.arrayCopyNonAtomic(transNO, (short)0, buffer, (short)0x00, (short)0x2);
            }
            else
            {
                Util.arrayCopyNonAtomic(transNO, (short)0, buffer, (short)0x2, (short)0x2);
            }
            Util.arrayCopyNonAtomic(balance, (short)0, buffer, (short)0x4, (short)0x4);
            Util.arrayCopyNonAtomic(overDrawLimit, (short)1, buffer, (short)0x8, (short)0x3);

            /* 性能优化 hsp */
            if (MF[(short)(fileAddr - 14)] == (short)0x0c)
            {
                sum = 0;
                for (i = 0; i < (short)0x0b; i++)
                {
                    sum += buffer[i];
                }
                buffer[(short)0x0b] = (byte)sum;
            }

            if (EP0ED1ET2Flg != 0)// ed
            {
                /* 性能优化 hsp */
                if (MF[(short)(fileAddr - 14)] != (short)0x0c)
                {
                    Util.arrayCopy(buffer, (short)0x0, MF, fileAddr, fileLen);
                }
                else
                {
                    Util.arrayCopy(buffer, (short)0x0, MF, fileAddr, (short)(fileLen + 1));
                }
            }
        }
    }

    /**
     * 初始化圈存
     * 
     * @param[buf] [APDU 缓冲区字节数组]
     */
    public void IntializeLoad(byte[] buf)
    {
        /* 移动到参数检查后面，by liyong100830*/
        switch (buf[ISO7816.OFFSET_P2])
        {
            case (byte)1:
                ramByte[EP0ED1ET2FLAGOff] = FLAG_ED;
                ramByte[0] = EDL;
                break;
            case (byte)2:
                ramByte[EP0ED1ET2FLAGOff] = 0x00;
                ramByte[0] = EPL;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                break;
        }
        if (buf[ISO7816.OFFSET_LC] != (byte)0x0b)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        /* 性能优化 20140507*/
        ramShort[0] = getRecordByKID(DLK_TYPE, ramByte[KeyIndexOff]);
        if ((ramShort[0] == -1) || (ramShort[0] == -2))
        {
            ISOException.throwIt(COMM_WARNING_ERROR);
        }

        if ((ramByte[transStatusOff] == G_TranStatus_CAPP1)
                        || (ramByte[transStatusOff] == G_TranStatus_CAPP2))
        {
            ISOException.throwIt(TRANS_STATUS_NOT_SATISFIED);
        }
        if (!checkSecurity(MF[(short)(ramShort[0] + 3)]))// 校验密钥文件的使用权限 modify
                                                         // by zhengtao 20140220
        {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        ramByte[transStatusOff] = 0x00;

        GetEDEPETBalance(ramByte[EP0ED1ET2FLAGOff], (byte)0x00, FLAG_ONLINE);

        /* 余额已经更新balance == balance + 圈存金额 hsp*/
        if (!FourBytesAdd(balance, transSum, buffer, (short)0x60))
        {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (arrayCompare(buffer, (short)0x60, MF, (short)ramShort[MaxBalanceOff], (short)4) == 1)
        {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        ramByte[transStatusOff] = G_TranStatus_L; // 初使化圈存后状态变为圈存状态
        ProduceRandom((byte)4);
        SESKEYOnline();
        MAC1Online();
        PrepareSendData(ramByte[transStatusOff]);
        Util.arrayCopyNonAtomic(buffer, (short)(0x40), buf, (short)0, (short)0x10);
        Util.arrayCopyNonAtomic(buffer, (short)0x60, balance, (short)0, (short)4);
    }

    /**
     * 初始化消费
     * 
     * @param[buf] [APDU 缓冲区字节数组]
     */
    public void IntializePurchase(byte[] buf)
    {
        /* 移到参数检查后面，by liyong 100830*/
        switch (buf[ISO7816.OFFSET_P2])
        {
            case (byte)1:
                ramByte[EP0ED1ET2FLAGOff] = FLAG_ED;
                ramByte[0] = EDP;
                break;
            case (byte)2:
                ramByte[EP0ED1ET2FLAGOff] = 0x00;
                ramByte[0] = EPP;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                break;
        }
        if (buf[ISO7816.OFFSET_LC] != (byte)0x0b)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if ((ramShort[0] = getRecordByKID(DPK_TYPE, ramByte[KeyIndexOff])) == -1)
        {
            ISOException.throwIt(COMM_WARNING_ERROR);
        }
        if (buf[ISO7816.OFFSET_P2] == (byte)0x01) // modified by lrl 20100903
                                                  // 只有存折消费支持PIN校验
        {
            if (!checkSecurity(MF[(short)(ramShort[0] + 3)]))// 校验密钥文件的使用权限
                                                             // modify by
                                                             // zhengtao
                                                             // 20140220
            {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        }
        if ((ramByte[transStatusOff] == G_TranStatus_CAPP1)
                        || (ramByte[transStatusOff] == G_TranStatus_CAPP2))
        {
            ISOException.throwIt(TRANS_STATUS_NOT_SATISFIED);
        }
        ramByte[transStatusOff] = 0x00;
        GetEDEPETBalance(ramByte[EP0ED1ET2FLAGOff], (byte)0x00, (byte)0x00);
        if (cmEP)// add for CM-EP
        {
            FourBytesSub(balance, overDrawLimit, init); // CMEP普通消费不允许透支
            if (arrayCompare(init, (short)0, transSum, (short)0, (short)4) == -1)
            {
                ISOException.throwIt(BALANCE_ZERO_ERROR);
            }
        }
        else
        {
            if (arrayCompare(balance, (short)0, transSum, (short)0, (short)4) == -1)
            {
                ISOException.throwIt(BALANCE_ZERO_ERROR);
            }
        }
        ramByte[transStatusOff] = G_TranStatus_P;
        ProduceRandom((byte)4);
        PrepareSendData(ramByte[transStatusOff]);
        Util.arrayCopyNonAtomic(buffer, (short)(0x40), buf, (short)0, (short)0x0f);
    }

    /**
     * 初始化取现
     * 
     * @param[buf] [APDU 缓冲区字节数组]
     */
    public void IntializeWithdraw(byte[] buf)
    {
        if (buf[ISO7816.OFFSET_P2] == 0x01)// P2 ERROR
        {
            ramByte[EP0ED1ET2FLAGOff] = FLAG_ED;
        }
        else
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (buf[ISO7816.OFFSET_LC] != (byte)0x0b)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if ((ramShort[0] = getRecordByKID(DPK_TYPE, ramByte[KeyIndexOff])) == -1)
        {
            ISOException.throwIt(COMM_WARNING_ERROR);
        }
        if (!checkSecurity(MF[(short)(ramShort[0] + 3)]))// 校验密钥文件的使用权限 modify
                                                         // by zhengtao 20140220
        {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if ((ramByte[transStatusOff] == G_TranStatus_CAPP1)
                        || (ramByte[transStatusOff] == G_TranStatus_CAPP2))
        {
            ISOException.throwIt(TRANS_STATUS_NOT_SATISFIED);
        }
        ramByte[transStatusOff] = 0x00;
        ramByte[0] = EDWD;
        GetEDEPETBalance(ramByte[EP0ED1ET2FLAGOff], (byte)0x00, (byte)0x00);
        if (arrayCompare(balance, (short)0, transSum, (short)0, (short)4) == -1)
        {
            ISOException.throwIt(BALANCE_ZERO_ERROR);
        }
        ramByte[transStatusOff] = G_TranStatus_P;
        ProduceRandom((byte)4);
        PrepareSendData(ramByte[transStatusOff]);
        Util.arrayCopyNonAtomic(buffer, (short)(0x40), buf, (short)0, (short)0x0f);
    }

    /**
     * 初始化复合交易 modify by zhengtao 20131223 连续的初始化指令是可以执行的，后面的初始化指令可以冲掉之前的。
     * 
     * @param[buf] [APDU缓冲区字节数组]
     */
    public void IntializeCAPP(byte[] buf)
    {
        byte P2 = buf[ISO7816.OFFSET_P2];
        byte LC = buf[ISO7816.OFFSET_LC];
        
        if (P2 == 0x02)
        {
            ramByte[EP0ED1ET2FLAGOff] = 0x00;
        }
        else
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (LC != (byte)0x0b)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        /* modify by zhengtao 20131231 8050指令可以重复发，交易状态以最近的一次为准*/
        if (ramByte[transStatusOff] != 0x00)
        {
            ISOException.throwIt(TRANS_STATUS_NOT_SATISFIED);
        }
        ramByte[transStatusOff] = 0x00;
        ramByte[0] = CAPP;
        GetEDEPETBalance(ramByte[EP0ED1ET2FLAGOff], (byte)0x00, (byte)0x00);
        if ((ramShort[0] = getRecordByKID(DPK_TYPE, ramByte[KeyIndexOff])) == -1)
        {
            ISOException.throwIt(COMM_WARNING_ERROR);
        }
        if (arrayCompare(balance, (short)0, transSum, (short)0, (short)4) == -1)
        {
            ISOException.throwIt(BALANCE_ZERO_ERROR);
        }
        ramByte[transStatusOff] = G_TranStatus_CAPP1;
        ProduceRandom((byte)4);
        PrepareSendData(ramByte[transStatusOff]);
        Util.arrayCopyNonAtomic(buffer, (short)(0x40), buf, (short)0, (short)0x0f);
    }

    /**
     * 初始化改限
     * 
     * @param[buf] [APDU 缓冲区字节数组]
     */
    public void IntializeUpdate(byte[] buf)
    {
        if (!cmEP)// 判断是否为移动EDEP
        {
            if (buf[ISO7816.OFFSET_P2] != 0x01)// P2 ERROR
            {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        }
        else
        {
            if (buf[ISO7816.OFFSET_P2] != 0x02)// P2 ERROR
            {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        }
        if (buf[ISO7816.OFFSET_LC] != (byte)0x07)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (((ramShort[0] = getRecordByKID(DUK_TYPE, ramByte[KeyIndexOff])) == -1)
                        || ((ramShort[0] = getRecordByKID(DUK_TYPE, ramByte[KeyIndexOff])) == -2))
        {
            ISOException.throwIt(COMM_WARNING_ERROR);
        }
        if (ramByte1[SecuRegOff] == 0)// 兼容Native// modify by zhengtao 20140220
                                      // 需要校验相应密钥的使用权限
        {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if ((ramByte[transStatusOff] == G_TranStatus_CAPP1)
                        || (ramByte[transStatusOff] == G_TranStatus_CAPP2))
        {
            ISOException.throwIt(TRANS_STATUS_NOT_SATISFIED);
        }
        ramByte[transStatusOff] = 0x00;

        if (buf[ISO7816.OFFSET_P2] == 0x02)// 8050 0702
        {
            ramByte[EP0ED1ET2FLAGOff] = 0x00;// 钱包
        }
        else
        {
            ramByte[EP0ED1ET2FLAGOff] = FLAG_ED;// 存折
        }
        if (!cmEP)
        {
            ramByte[0] = EDU;
        }
        else
        {
            ramByte[0] = EDU1;
        }
        GetEDEPETBalance(ramByte[EP0ED1ET2FLAGOff], (byte)0x00, FLAG_ONLINE);

        if ((cmEP) && (arrayCompare(balance, (short)0, overDrawLimit, (short)0, (short)4) == -1))// 移动钱包透支后不能改限，
                                                                                                      // 返6985(if(移动钱包且balance<overDrawLimit))
        {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        Util.arrayCopyNonAtomic(buf, (short)(ISO7816.OFFSET_CDATA + 1), machineNUM, (short)0, (short)6);
        ramByte[transStatusOff] = G_TranStatus_U;
        ProduceRandom((byte)4);
        SESKEYOnline();
        Util.arrayCopyNonAtomic(balance, (short)0, buffer, (short)0, (short)4);// 计算MAC1
        Util.arrayCopyNonAtomic(overDrawLimit, (short)1, buffer, (short)4, (short)3);
        buffer[7] = ramByte[0];
        Util.arrayCopyNonAtomic(machineNUM, (short)0, buffer, (short)8, (short)6);
        DEA_MAC(init, buffer, (short)0, (short)14, (short)0, (byte)1);
        PrepareSendData(ramByte[transStatusOff]);
        Util.arrayCopyNonAtomic(buffer, (short)(0x40), buf, (short)0, (short)0x13);
    }

    /**
     * 初始化圈提
     * 
     * @param[buf] [APDU 缓冲区字节数组]
     */
    public void IntializeUnload(byte[] buf)
    {
        if ((buf[ISO7816.OFFSET_P2] != 0x01)// P2 ERROR
                        || (cmEP))// 移动钱包不支持圈提
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (buf[ISO7816.OFFSET_LC] != (byte)0x0B)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (((ramShort[0] = getRecordByKID(DULK_TYPE, ramByte[KeyIndexOff])) == -1)
                        || ((ramShort[0] = getRecordByKID(DULK_TYPE, ramByte[KeyIndexOff])) == -2))
        {
            ISOException.throwIt(COMM_WARNING_ERROR);
        }
        if (ramByte1[SecuRegOff] == 0)// 兼容Native// modify by zhengtao 20140220
                                      // 需要校验相应密钥的使用权限
        {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if ((ramByte[transStatusOff] == G_TranStatus_CAPP1)
                        || (ramByte[transStatusOff] == G_TranStatus_CAPP2))
        {
            ISOException.throwIt(TRANS_STATUS_NOT_SATISFIED);
        }
        ramByte[transStatusOff] = 0x00;
        ramByte[EP0ED1ET2FLAGOff] = FLAG_ED;
        ramByte[0] = EDUL;
        GetEDEPETBalance(ramByte[EP0ED1ET2FLAGOff], (byte)0x00, FLAG_ONLINE);
        if (arrayCompare(balance, (short)0, transSum, (short)0, (short)4) == -1)
        {
            ISOException.throwIt(BALANCE_ZERO_ERROR);
        }
        ramByte[transStatusOff] = G_TranStatus_UL;
        ProduceRandom((byte)4);
        SESKEYOnline();
        MAC1Online();
        PrepareSendData(ramByte[transStatusOff]);
        Util.arrayCopyNonAtomic(buffer, (short)(0x40), buf, (short)0, (short)0x10);
    }

    /**
     * INITIALIZE FOR CASH WITHDRAW 初始化取现交易 INITIALIZE FOR LOAD 初始化圈存交易
     * INITIALIZE FOR PURCHASE 初始化消费交易 INITIALIZE FOR UNLOAD 初始化圈提交易 INITIALIZE
     * FOR UPDATE 初始化修改透支限额交易 INITIALIZE FOR CAPP 初始化复合消费
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_8050(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();

        if (buf[ISO7816.OFFSET_CLA] != (byte)0x80)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing

        short lenth = initTrans(buf);
        apdu.setOutgoingAndSend((short)0, lenth);
    }

    /**
     * CREDIT FOR LOAD 圈存交易
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_8052(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();

        if (buf[ISO7816.OFFSET_CLA] != (byte)0x80)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
        creditForLoad(buf);
        apdu.setOutgoingAndSend((short)0, (short)0x4);
    }

    /**
     * DEBIT FOR PURCHASE 消费 DEBIT FOR UNLOAD 圈提交易 DEBIT FOR CAPP
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_8054(APDU apdu)
    {
        short series;
        short fileAdd;
        //short recordaddr;// =0; hsp
        short CAPPfileAdd;// = 0; hsp
        //short recLen;
        short offset;// =0; hsp
        short KeyAdd;
        short ADF_fileADDR_Offset = 40;
        byte i;
        byte[] buf = apdu.getBuffer();
        byte P1 = buf[ISO7816.OFFSET_P1];
        byte P2 = buf[ISO7816.OFFSET_P2];
        byte CLA = buf[ISO7816.OFFSET_CLA];
        byte LC = buf[ISO7816.OFFSET_LC];
        
        KeyAdd = Util.getShort(MF, (short)(ramShort1[0] + 40));// 性能优化 20140429
                                                               // zhengtao
                                                               // key文件地址直接从ADF文件头中读取

        if (CLA != (byte)0x80)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (P2 != (byte)0x0)// P2 ERROR
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        Util.arrayFillNonAtomic(init, (short)0, (byte)8, (byte)0);
        switch (P1)
        {
            case 0x01:// 消费取现指令No processkey
                if (LC != (byte)0x0f)
                {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
                Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, tillTransNO, (short)0, (short)4);
                Util.arrayCopyNonAtomic(buf, (short)(ISO7816.OFFSET_CDATA + 4), dateandTime, (short)0, (short)7);
                Util.arrayCopyNonAtomic(buf, (short)(ISO7816.OFFSET_LC + 12), MAC_BUF, (short)8, (short)4);// 性能优化
                                                                                                           // 20140429
                                                                                                           // zhengtao
                                                                                                           // MAC的两个buf合并为1个

                if ((ramByte[transStatusOff] == G_TranStatus_P) || (ramByte[transStatusOff] == G_TranStatus_CAPP2))// 判断交易状态//消费 取现状态
                {
                    SESKEYOffline();
                    if (((ramByte[appTypeOff] & APP_ZJB) == APP_ZJB)
                                    && (g_tradeFlag[0] == (byte)1))// add by
                                                                   // zhengtao
                                                                   // 20140120
                                                                   // 添加复合应用下建设部认证码参与的MAC计算
                    {
                        api_getMAC1Offline();
                    }
                    else
                    {
                        MAC1Offline();
                    }
                }
                else
                {
                    ISOException.throwIt(TRANS_STATUS_NOT_SATISFIED);
                }
                if (Util.arrayCompare(MAC_BUF, (short)8, MAC_BUF, (short)0, (short)4) != 0)// 性能优化
                                                                                           // 20140429
                                                                                           // zhengtao
                                                                                           // 两个MAC相关buf调整
                {
                    JCSystem.beginTransaction();
                    /* modify by zhengtao 20140325 交易相关密钥的错误计数使用key文件的使用权限字段*/
                    if ((MF[(short)(KeyAdd + KeyNextStateOff)] != 0x00)
                                    && (ramByte[transStatusOff] != G_TranStatus_CAPP2)
                                    && (DeduceCounter(KeyAdd, (byte)0) == 0x0)) // MAC错3次锁应用,配置为要锁应用
                    {
                        MF[(short)(ramShort1[0] + LockAttrOff)] |= 0x01;
                        JCSystem.commitTransaction();
                        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    }

                    JCSystem.commitTransaction();
                    ISOException.throwIt(MAC_ERROR);
                }
                MAC2Offline();
                Util.arrayCopyNonAtomic(MAC_BUF, (short)0x0, MAC_BUF, (short)8, (short)4);// 性能优化
                                                                                          // 20140429
                                                                                          // zhengtao
                                                                                          // MAC相关的两个BUF调整
                /* TAC密钥
                                                   性能优化 20140507*/
                fileAdd = Util.getShort(MF, (short)(ramShort1[0]
                                + ADF_fileADDR_Offset + 14));
                if ((fileAdd == -1) || (fileAdd == -2))
                {
                    if (((fileAdd = getRecordByKID(DTK_TYPE, ramByte[KeyIndexOff])) == -1)
                                    || ((fileAdd = getRecordByKID(DTK_TYPE, ramByte[KeyIndexOff])) == -2))
                        ISOException.throwIt(COMM_WARNING_ERROR);
                }
                CalculateTACSESKEY(fileAdd);// TAC生成过程密钥
                TACOffline();
                FourBytesSub(balance, transSum, balance);
                series = Util.getShort(transNO, (short)0);
                series++;
                Util.setShort(transNO, ((short)0), series);
                JCSystem.beginTransaction();
                /* 写复合交易专用文件*/
                offset = 30;
                if (ramByte[transStatusOff] == G_TranStatus_CAPP2)
                {
                    for (i = 0; i < capp_cache_num[0]; i++)
                    {
                        if ((CAPPfileAdd = searchFileAddrBySFI(buffer[(short)(offset + 0)], (byte)1)) == -1)
                        {
                            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                        }
                        /*
                        recordaddr = getRecordByRecNo(CAPPfileAdd, buffer[(short)(offset + 1)]);
                        //如果记录长度大雨数据长度，补0
                        recLen = (short)((MF[(short)(recordaddr + 1)] & 0x00ff) + 2);
                        ramShort[CAPPBufLenOff] = recLen;
                        recLen = (short)(recLen - buffer[(short)(offset + 2)]);
                        Util.arrayCopyNonAtomic(buffer, (short)(offset + 3), buf, (short)0, (short)buffer[(short)(offset + 2)]);
                        Util.arrayFillNonAtomic(buf, buffer[(short)(offset + 2)], recLen, (byte)0);
                        updateVarRecord(CAPPfileAdd, buffer[(short)(offset + 1)], buf, (short)0, ramShort[CAPPBufLenOff]);
                        */
                        updateVarRecord(CAPPfileAdd, buffer[(short)(offset + 1)], buffer, (short)(offset + 3), (short)((short)buffer[(short)(offset + 2)]&0x00ff));
                        offset = (short)(offset + 3 + (short)((short)buffer[(short)(offset + 2)]&0x00ff));
                    }
                    capp_cache_num[0] = 0;
                }
                RestoreCounter(KeyAdd, (byte)0);// modify by zhengtao 20140325
                                                // 交易相关密钥的错误计数器使用Key文件的使用权限字段
                api_AppendHLHTDetail();// 更新交易明细
                GetEDEPETBalance(ramByte[EP0ED1ET2FLAGOff], FLAG_WRITE, (byte)0x00);// 更新钱包存折文件（保留地址）
                ProduceTransProof(MAC_BUF, (short)8, MAC_BUF, (short)0);// 更新交易证明

                /* 性能优化 hsp*/
                if ((fileAdd = Util.getShort(MF, (short)(ramShort1[0]
                                + ADF_fileADDR_Offset + 4))) == -1)
                {
                    ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                }
                fileAdd += EFHeadLen;
                if (ramByte[EP0ED1ET2FLAGOff] == 0)// 钱包
                {
                    Util.arrayCopy(buffer, (short)0, MF, fileAdd, (short)20);
                }
                else
                {
                    Util.arrayCopy(buffer, (short)8, MF, (short)(fileAdd + 8), (short)12);
                }

                JCSystem.commitTransaction();
                ramByte[transStatusOff] = 0x00; // 空闲状态
                Util.arrayCopyNonAtomic(MAC_BUF, (short)0x0, buf, (short)0, (short)4);// 性能优化
                                                                                      // 20140429
                                                                                      // zhengtao
                                                                                      // 两个MAC相关的buf进行调整
                Util.arrayCopyNonAtomic(MAC_BUF, (short)0x8, buf, (short)4, (short)4);
                apdu.setOutgoingAndSend((short)0, (short)0x8);
                break;
            case 0x03: // 圈提
                if (LC != (byte)0x0b)
                {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
                Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, dateandTime, (short)0, (short)7);
                if (ramByte[transStatusOff] != G_TranStatus_UL)
                {
                    ISOException.throwIt(TRANS_STATUS_NOT_SATISFIED);
                }
                MAC2Online();
                if (Util.arrayCompare(buf, (short)(ISO7816.OFFSET_LC + 8), MAC_BUF, (short)0, (short)4) != 0)// 如果MAC为错误
                                                                                                             // //
                                                                                                             // 性能优化
                                                                                                             // 20140429
                                                                                                             // zhengtao
                {
                    ramByte[transStatusOff] = 0x00; // 空闲状态
                    JCSystem.beginTransaction();
                    if ((MF[(short)(KeyAdd + KeyNextStateOff)] != 0x00)
                                    && (DeduceCounter(KeyAdd, (byte)0) == 0x0))// MAC错3次锁应用
                                                                               // modify
                                                                               // by
                                                                               // zhengtao
                                                                               // 20140325
                                                                               // 交易相关密钥的错误计数器使用key文件的使用权限
                    {
                        MF[(short)(ramShort1[0] + LockAttrOff)] |= 0x01;
                        JCSystem.commitTransaction();
                        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    }

                    JCSystem.commitTransaction();
                    ISOException.throwIt(MAC_ERROR);
                }
                FourBytesSub(balance, transSum, balance);
                MAC3Online();
                series = Util.getShort(transNO, (short)0);
                series++;
                Util.setShort(transNO, ((short)0), series);
                JCSystem.beginTransaction();
                RestoreCounter(KeyAdd, (byte)0);
                ProduceTransDaily(); // 更新交易明细
                GetEDEPETBalance(ramByte[EP0ED1ET2FLAGOff], FLAG_WRITE, FLAG_ONLINE);// 更新钱包存折文件（保留地址）
                ProduceTransProof(MAC_BUF, (short)0, init, (short)0);// 更新交易证明
                                                                     // 性能优化
                                                                     // 20140429

                if ((fileAdd = Util.getShort(MF, (short)(ramShort1[0]
                                + ADF_fileADDR_Offset + 4))) == -1)// 性能优化 hsp
                {
                    ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                }
                fileAdd += EFHeadLen;
                if (ramByte[EP0ED1ET2FLAGOff] == 0)// 钱包
                {
                    Util.arrayCopy(buffer, (short)0, MF, fileAdd, (short)20);
                }
                else
                {
                    Util.arrayCopy(buffer, (short)8, MF, (short)(fileAdd + 8), (short)12);
                }

                JCSystem.commitTransaction();
                ramByte[transStatusOff] = 0x00; // 空闲状态
                Util.arrayCopyNonAtomic(MAC_BUF, (short)0x0, buf, (short)0, (short)4);  // 性能优化
                                                                                        // 20140429
                apdu.setOutgoingAndSend((short)0, (short)0x4);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                break;
        }
    }

    /**
     * UPDATE OVERDRAW LIMIT 修改透支限制 修改钱包（复合消费）指令
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_8058(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();
        short series;
        short fileAdd;
        short KeyAdd;

        if (buf[ISO7816.OFFSET_CLA] != (byte)0x80)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        KeyAdd = searchFileAddrByFID((short)0x0000, (byte)1);
        Util.arrayFillNonAtomic(init, (short)0, (byte)8, (byte)0);
        if (!cmEP)
        {
            if ((buf[ISO7816.OFFSET_P1] != 0x00)
                            || (buf[ISO7816.OFFSET_P2] != 0x00))// P2 ERROR
            {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        }
        else
        {
            if ((buf[ISO7816.OFFSET_P1] != 0x07)
                            || (buf[ISO7816.OFFSET_P2] != 0x02))// P2 ERROR
            {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        }
        if (buf[ISO7816.OFFSET_LC] != (byte)0x0e)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing

        if (ramByte[transStatusOff] != G_TranStatus_U)
        {
            ISOException.throwIt(TRANS_STATUS_NOT_SATISFIED);
        }
        transSum[0] = 0x0;// 新限额
        Util.arrayCopyNonAtomic(buf, (short)(ISO7816.OFFSET_CDATA), transSum, (short)1, (short)0x3);
        Util.arrayCopyNonAtomic(buf, (short)(ISO7816.OFFSET_CDATA + 3), dateandTime, (short)0, (short)7);

        if (arrayCompare(balance, (short)0, overDrawLimit, (short)0, (short)4) != -1)
        {
            FourBytesSub(balance, overDrawLimit, balance);
            if ((!FourBytesAdd(balance, transSum, balance, (short)0))
                            || (arrayCompare(balance, (short)0, MF, ramShort[MaxBalanceOff], (short)4) == 1))
            {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }
        else
        {
            FourBytesSub(overDrawLimit, balance, balance); // 移动钱包透支后不能改限，返6985//此处不用判断，因为在初始化时已经判断
            if (arrayCompare(balance, (short)0, transSum, (short)0, (short)4) == 1)
            {
                ISOException.throwIt(BALANCE_ZERO_ERROR);
            }

            FourBytesSub(transSum, balance, balance);
        }

        Util.arrayCopyNonAtomic(transSum, (short)0, overDrawLimit, (short)0, (short)4);// 新透支限额
        Util.arrayCopyNonAtomic(transSum, (short)1, buffer, (short)0, (short)3);// 计算MAC2
        buffer[3] = ramByte[0];// 交易类型
        Util.arrayCopyNonAtomic(machineNUM, (short)0, buffer, (short)4, (short)6);
        Util.arrayCopyNonAtomic(dateandTime, (short)0, buffer, (short)10, (short)7);
        DEA_MAC(init, buffer, (short)0, (short)17, (short)0, (byte)1);
        if (Util.arrayCompare(buf, (short)(ISO7816.OFFSET_LC + 11), MAC_BUF, (short)0, (short)4) != 0)// 如果MAC为错误
                                                                                                      // 性能优化
        {
            JCSystem.beginTransaction();
            if ((MF[(short)(KeyAdd + KeyNextStateOff)] != 0x00)
                            && (DeduceCounter(KeyAdd, (byte)0) == 0x0))// MAC错3次锁应用
                                                                       // modify
                                                                       // by
                                                                       // zhengtao
                                                                       // 20140328
                                                                       // 交易密钥的错误计数器使用key文件的读权限字段
            {
                MF[(short)(ramShort1[0] + LockAttrOff)] |= 0x01;
                JCSystem.commitTransaction();
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            JCSystem.commitTransaction();
            ISOException.throwIt(MAC_ERROR);
        }

        if (((fileAdd = getRecordByKID(DTK_TYPE, KEY_INDEX)) == -1)
                        || ((fileAdd = getRecordByKID(DTK_TYPE, KEY_INDEX)) == -2))
        {
            if (((fileAdd = getRecordByKID(DTK_TYPE, ramByte[KeyIndexOff])) == -1)
                            || ((fileAdd = getRecordByKID(DTK_TYPE, ramByte[KeyIndexOff])) == -2))
                ISOException.throwIt(COMM_WARNING_ERROR);
        }

        CalculateTACSESKEY(fileAdd);// TAC生成过程密钥
        Util.arrayCopyNonAtomic(balance, (short)0, buffer, (short)0, (short)4);
        Util.arrayCopyNonAtomic(transNO, (short)0, buffer, (short)4, (short)2);
        Util.arrayCopyNonAtomic(transSum, (short)1, buffer, (short)6, (short)3);
        buffer[9] = ramByte[0];
        Util.arrayCopyNonAtomic(machineNUM, (short)0, buffer, (short)10, (short)6);
        Util.arrayCopyNonAtomic(dateandTime, (short)0, buffer, (short)16, (short)7);// 交易日期
                                                                                    // ＋
                                                                                    // 交易时间
        DEA_MAC(init, buffer, (short)0, (short)23, (short)0, (byte)1);// DES_MAC为MAC3
        series = Util.getShort(transNO, (short)0);
        series++;
        Util.setShort(transNO, ((short)0), series);
        JCSystem.beginTransaction();
        RestoreCounter(KeyAdd, (byte)0);// modify by zhengtao 20140328
                                        // 交易密钥的错误计数器使用key文件的读权限字段
        ProduceTransDaily();// 更新交易明细
        GetEDEPETBalance(ramByte[EP0ED1ET2FLAGOff], FLAG_WRITE, FLAG_ONLINE);// 更新钱包存折文件（保留地址）
        ProduceTransProof(init, (short)0, MAC_BUF, (short)0); // 更新交易证明 性能优化

        /* 性能优化 hsp*/
        if ((fileAdd = Util.getShort(MF, (short)(ramShort1[0] + 40 + 4))) == -1)
        {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        fileAdd += EFHeadLen;
        if (ramByte[EP0ED1ET2FLAGOff] == 0)// 钱包
        {
			Util.arrayCopy(buffer,(short)0,MF,fileAdd,(short)20);
        }
        else
        {
			Util.arrayCopy(buffer,(short)8,MF,(short)(fileAdd+8),(short)12);
        }

        JCSystem.commitTransaction();
        ramByte[transStatusOff] = 0x00; // 空闲状态
        Util.arrayCopyNonAtomic(MAC_BUF, (short)0x0, buf, (short)0, (short)4);// 性能优化
        apdu.setOutgoingAndSend((short)0, (short)0x4);
    }

    /**
     * GET BALANCE 查询余额
     * 
     * @param[bufferapdu] [STK菜单通过共享接口调用805C指令时传入的指令数据]
     * @param[apdu] [APDU对象]
     * @param[flag] [00：通过APDU指令执行805C指令，FCI信息直接返回；其他：共享接口调用805C指令，
                                    FCI信息存储在buf中，供STK菜单读取，不能直接返回]
     */
    public void CMD_805C(byte[] bufferapdu, APDU apdu, byte flag)
    {
        byte[] buf;// 接口修改
        
        if (flag == (byte)0x00)
        {
            buf = apdu.getBuffer();
        }
        else
        {
            buf = bufferapdu;
            apdu = null;
        }

        short fileAdd;// = 0; hsp
        byte p2 = buf[ISO7816.OFFSET_P2];
        byte sum;// =0; hsp
        short i;// =0; hsp
        short ADF_fileADDR_Offset = 40;

        if (buf[ISO7816.OFFSET_CLA] != (byte)0x80)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (!cmEP)
        {
            if ((buf[ISO7816.OFFSET_P1] != 0x00)
                            || ((p2 != 0x01) & (p2 != 0x02)))
            {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if (buf[ISO7816.OFFSET_LC] != (byte)0x04)
            {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            if (p2 == 1)// ED交易
            {
                if (ramByte1[SecuRegOff] == 0)// 兼容Native版本，此处不和PIN绑定，只需要检查安全状态寄存器为0即可
                                              // modify by zhengtao 20140225
                {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                fileAdd = Util.getShort(MF, (short)(ramShort1[0]
                                + ADF_fileADDR_Offset + 2));// 性能优化 hsp

            }
            else
            {
                fileAdd = Util.getShort(MF, (short)(ramShort1[0]
                                + ADF_fileADDR_Offset + 4));// modify by
                                                            // zhengtao 20140303
                                                            // 为了防止部分金融文件结构的SFI和FID不一致，此处修改为通过FID查找
                                                            // 性能优化 hsp
            }
            if (fileAdd == -1)
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }

            if (MF[(short)(fileAdd + 4)] == (short)0x0c)// modify by zhengtao
                                                        // 20131210
            {
                sum = 0;
                for (i = 0; i < (short)0x0b; i++)
                {
                    sum += MF[(short)(fileAdd + EFHeadLen + i)];
                }

                if (sum != MF[(short)(fileAdd + EFHeadLen + 0x0b)])
                {
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                }
            }

            fileAdd += EFHeadLen;
            Util.arrayCopyNonAtomic(MF, (short)(fileAdd + 4), buf, (short)1, (short)4);// 为配合接口将此处改为1
            if (apdu != null)
            {
                apdu.setOutgoingAndSend((short)1, (short)0x4);// 为配合接口将此处改为1
            }
            else
            {
                buf[0] = (byte)0x04;
                buf[(short)(buf[0] + 1)] = (byte)0x90;
                buf[(short)(buf[0] + 2)] = (byte)0x00;
            }
        }
        else
        {
            getCMEPBalance(apdu, buf);
        }
    }

    /**
     * 读取移动钱包余额
     * 输出：余额信息
     * 
     * @param[apdu] [APDU对象]
     * @param[buf] [指令数据，扩展共享接口后添加的]
     */
    public void getCMEPBalance(APDU apdu, byte[] buf)
    {
        byte p2 = buf[ISO7816.OFFSET_P2];
        byte lc = buf[ISO7816.OFFSET_LC];
        short fileAdd;// = 0; hsp

        if ((buf[ISO7816.OFFSET_P1] != 0x00)
                        || ((p2 != 0x01) & (p2 != 0x02) & (p2 != (byte)0xA0)))
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if ((((p2 == 01) || (p2 == 02)) && (lc != (byte)0x04))
                        || ((p2 == (byte)0xA0) && (lc != (byte)0x07)))
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (p2 == 1)// ED交易
        {
            if (ramByte1[SecuRegOff] == 0)
            {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            fileAdd = searchFileAddrByFID(EDFID, (byte)1);
        }
        else
        {
            fileAdd = searchFileAddrByFID(EPFID, (byte)1);
        }

        if (fileAdd == -1)
        {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        fileAdd += EFHeadLen;// 到文件体处

        if (p2 == 1)
        {
            Util.arrayCopyNonAtomic(MF, (short)(fileAdd + 4), buf, (short)0, (short)4);
            apdu.setOutgoingAndSend((short)0, (short)0x4);
        }
        else if (p2 == 2)
        {
            Util.arrayCopyNonAtomic(MF, (short)(fileAdd + 0x4), init, (short)0, (short)0x4);// balance
            buf[0] = 0;
            Util.arrayCopyNonAtomic(MF, (short)(fileAdd + 0x8), buf, (short)1, (short)0x3);// overDrawLimit
            if (arrayCompare(init, (short)0, buf, (short)0, (short)4) != 1)// balance<=overDrawLimit,如果真实余额小等于0,805C
                                                                           // 0002
                                                                           // 04指令返回0
            {
                Util.arrayFillNonAtomic(buf, (short)4, (short)4, (byte)0);// 清零
                apdu.setOutgoingAndSend((short)4, (short)0x4);
            }
            else
            {
                FourBytesSub(init, buf, init);// balance = balance -
                                              // overDrawLimit，真实余额
                apdu.setOutgoing();
                apdu.setOutgoingLength((short)0x04);
                apdu.sendBytesLong(init, (short)0, (short)4);
            }
        }
        else// p2=0A,同时读取余额(真实余额+透支限额)和透支限额
        {
            apdu.setOutgoing();
            apdu.setOutgoingLength((short)0x07);
            apdu.sendBytesLong(MF, (short)(fileAdd + 0x4), (short)0x07);
        }
    }

    /**
     * GET TRANSACTION PROVE 交易证明
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_805A(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();
        byte CLA = buf[ISO7816.OFFSET_CLA];
        short p2 = buf[ISO7816.OFFSET_P2];
        short fileAdd;// = 0; hsp
        short ADF_fileADDR_Offset = 40;
        byte paraFlag = 0;
        
        if (CLA != (byte)0x80)
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        if (buf[ISO7816.OFFSET_P1] != 0x00)
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (((p2 >= 0x1) && (p2 <= 0x7)) || (p2 == 0x09))
        {
            paraFlag = 1;
        }

        if (paraFlag == 0x00)
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (buf[ISO7816.OFFSET_LC] != 0x02)// P2 ERROR
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
        if ((fileAdd = Util.getShort(MF, (short)(ramShort1[0]
                        + ADF_fileADDR_Offset + 4))) == -1)
        {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        fileAdd += (EFHeadLen + 8);// 性能优化 hsp
        if (p2 != MF[fileAdd])
        {
            ISOException.throwIt(MAC_TAC_USELESS);
        }
        /* 比较ED(EP)联机(脱机)交易序号*/
        if (Util.arrayCompare(buf, (short)(ISO7816.OFFSET_CDATA), MF, (short)(fileAdd + 1), (short)2) != 0x0)
        {
            ISOException.throwIt(MAC_TAC_USELESS);
        }
        Util.arrayCopyNonAtomic(MF, (short)(fileAdd + 4), buf, (short)0, (short)8);
        apdu.setOutgoingAndSend((short)0, (short)0x8);
    }

    /**
     * 读取变长记录文件中记录号对应记录的TAG和长度 add by zhengtao 20140411
     * 
     * @param[efAddr] [变长记录文件地址]
     * @param[RecNo] [记录号]
     * @return[变长记录文件中记录号对应记录的TAG和长度]
     */
    public short getVarRecordTAGandLentch(short efAddr, short RecNo)
    {
        short addr;// =0; hsp
        short TAGandL;// =0; hsp
        byte recordNum = MF[(short)(efAddr + RecNumOff)];// 记录数
        
        if ((RecNo > recordNum) || (RecNo <= 0))// 查询记录不在记录数范围内
        {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }
        addr = getRecordByRecNo(efAddr, RecNo);// 相应记录的地址
        if (addr == -1)
        {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }
        TAGandL = (short)(MF[addr] << 8 | MF[(short)(addr + 1)]);
        return TAGandL;
    }

    /**
     * 更新复合应用读写buffer
     * 
     * @param[buf] [待更新的数据源]
     */ 
    public void UPDATE_CAPP_WRBuffer(byte[] buf)
    {
        short offset = 30;
        byte i;
        byte LC = buf[ISO7816.OFFSET_LC];
        
        if ((short)(LC & 0x00ff) > ramShort[CAPPBufLenOff])
        {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        if (((short)(LC & 0x00ff) - ((short)buf[ISO7816.OFFSET_LC + (byte)2] & 0x00ff)) != (byte)2)// added
                                                                                   // by
                                                                                   // lrl
                                                                                   // 20100906
                                                                                   // 添加数据域判断
        {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        buf[ISO7816.OFFSET_CDATA + 1] = (byte)(ramShort[CAPPBufLenOff] - 2);
        Util.arrayFillNonAtomic(buf, (short)(ISO7816.OFFSET_CDATA + ((short)LC & 0x00ff)), (short)(((short)(ramShort[CAPPBufLenOff]&0x00ff) - ((short)LC & 0x00ff))), (byte)0x00);

        for (i = 0; i < capp_cache_num[0]; i++)
        {
            offset = (short)(3 + ((short)buffer[(short)(offset + 2)]&0x00ff) + offset);
        }
        if ((short)(offset + 3 + ramShort[CAPPBufLenOff]) > (short)0x011D)
        {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        buffer[(short)(offset + 0)] = ramByte[CAPPSFIOff];
        buffer[(short)(offset + 1)] = (byte)ramShort[CAPPRecNOOff];
        buffer[(short)(offset + 2)] = (byte)ramShort[CAPPBufLenOff];
        //Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, buffer, (short)(offset + 3), ramShort[CAPPBufLenOff]);
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, buffer, (short)(offset + 3), ramShort[CAPPBufLenOff]);
        capp_cache_num[0]++;
    }

    /**
     * UPDATE CAPP 需要保留：SFI、记录号、复合应用类型标识符和数据域 注意：不要更新复合应用数据文件
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_80DC(APDU apdu)
    {
        short fileAdd;
        short recordaddr;// =0; hsp
        byte i;
        byte tempByte;
        byte[] buf = apdu.getBuffer();
        byte P1 = buf[ISO7816.OFFSET_P1];
        byte P2 = buf[ISO7816.OFFSET_P2];
        byte CLA = buf[ISO7816.OFFSET_CLA];
        byte LC = buf[ISO7816.OFFSET_LC];
        
        /* hsp*/
        if ((CLA != (byte)0x00)
                        && (CLA != (byte)0x04)
                        && (CLA != (byte)0x80))
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        tempByte = (byte)((P2 & 0x0f8) >> 3);
        if ((ramByte[appTypeOff] & (byte)(0xF6)) == APP_HLHT)// HLHT应用
        {
            if (((P2 & 0x07) != (byte)0x0)
                            && ((P2 & 0x07) != (byte)0x4))
            {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        }
        else
        {
            if (((P2 & 0x07) != (byte)0x0))
            {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        }

        if ((LC < (byte)0x2)
                        && ((LC & 0x80) == (byte)0))
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
        if ((ramByte[transStatusOff] != G_TranStatus_CAPP1)
                        && (ramByte[transStatusOff] != G_TranStatus_CAPP2))
        {
            ISOException.throwIt(TRANS_STATUS_NOT_SATISFIED);
        }

        if ((ramByte[appTypeOff] & (byte)(0xF6)) == APP_HLHT)// HLHT应用
        {
            /* modify by zhengtao 20140326 代码复用，节省代码量 */
            if (tempByte == 0)
            {
                tempByte = 0x17;
            }
            if ((fileAdd = (short)(searchFileAddrBySFI((byte)tempByte, (byte)0x00))) == -1)
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            if ((MF[(short)(fileAdd + 2)] & 0x07) != 0x04)// 如果所找文件不是变长记录文件
            {
                ISOException.throwIt(FILE_TYPE_NOT_MATCHED);
            }
            ramByte[CAPPSFIOff] = tempByte;
            if ((byte)(P2 & (byte)0x07) == 0)
            {
                ramByte[CAPPTypeIDOff] = P1;
                for (i = 1; i <= MF[(short)(fileAdd + RecNumOff)]; i++)
                {
                    recordaddr = getRecordByRecNo(fileAdd, (short)i);
                    if (recordaddr == -1)
                    {
                        ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
                    }
                    if (ramByte[CAPPTypeIDOff] == MF[recordaddr])
                    {
                        ramShort[CAPPRecNOOff] = i;
                        ramShort[CAPPBufLenOff] = (short)((short)(MF[(short)(recordaddr + 1)] & 0x00ff) + 2);
                       
                        if(tempByte != 0x19 || Util.getShort(MF, ramShort1[0])!=(short)0x1001) //mdy by zhengtao 20141103
                        {																		//1001下19文件不需要判断锁定标志位
                            if (MF[(short)(recordaddr + 2)] == (byte)1)// 应用是否被锁定
                            {
                                ISOException.throwIt(CAPP_LOCK_ERROR);
                            }
                        }
                        UPDATE_CAPP_WRBuffer(buf);
                        ramByte[transStatusOff] = G_TranStatus_CAPP2;
                        return;
                    }
                }
            }
            else
            {
                recordaddr = getRecordByRecNo(fileAdd, (short)P1);
                if (recordaddr == -1)
                {
                    ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
                }
                ramByte[CAPPTypeIDOff] = MF[recordaddr];
                ramShort[CAPPRecNOOff] = (short)P1;
                ramShort[CAPPBufLenOff] = (short)((short)(MF[(short)(recordaddr + 1)] & 0x00ff) + 2);
                if(tempByte != 0x19 || Util.getShort(MF, ramShort1[0])!=(short)0x1001) //mdy by zhengtao 20141103
                {																		//1001下19文件不需要判断锁定标志位
                    if (MF[(short)(recordaddr + 2)] == (byte)1)// 应用是否被锁定
                    {
                        ISOException.throwIt(CAPP_LOCK_ERROR);
                    }
                }
                UPDATE_CAPP_WRBuffer(buf);
                ramByte[transStatusOff] = G_TranStatus_CAPP2;
                return;
            }
        }
        else
        {
            if ((fileAdd = (short)(searchFileAddrBySFI(tempByte, (byte)0x00))) == -1)
            {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            if ((MF[(short)(fileAdd + 2)] & 0x07) != 0x04)// 如果所找文件不是变长记录文件
            {
                ISOException.throwIt(FILE_TYPE_NOT_MATCHED);
            }
            ramByte[CAPPSFIOff] = tempByte;
            ramByte[CAPPTypeIDOff] = P1;

            for (i = 1; i <= MF[(short)(fileAdd + RecNumOff)]; i++)
            {
                recordaddr = getRecordByRecNo(fileAdd, (short)i);
                if (recordaddr == -1)
                {
                    ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
                }
                if (ramByte[CAPPTypeIDOff] == MF[recordaddr])
                {
                    ramShort[CAPPRecNOOff] = i;
                    ramShort[CAPPBufLenOff] = (short)((short)(MF[(short)(recordaddr + 1)] & 0x00ff) + 2);
                    if(tempByte != 0x19 || Util.getShort(MF, ramShort1[0])!=(short)0x1001) //mdy by zhengtao 20141103
                    {																		//1001下19文件不需要判断锁定标志位                  
                        if (MF[(short)(recordaddr + 2)] == (byte)1)// 应用是否被锁定
                        {
                            ISOException.throwIt(CAPP_LOCK_ERROR);
                        }
                    }
                    UPDATE_CAPP_WRBuffer(buf);

                    ramByte[transStatusOff] = G_TranStatus_CAPP2;
                    return;
                }
            }
        }
        ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    }

    /**
     * 准备专用交易明细数据
     * 
     * @param[transsum] [交易金额]
     * @param[mac] [mac值]
     * @param[tac] [tac值]
     */
    public void PrepareSpecialDaily(byte[] transsum, byte[] mac, byte[] tac)
    {
        short fileAdd;
        
        buffer[0x30] = ramByte[0];
        buffer[0x31] = 0x01;
        Util.arrayCopyNonAtomic(balance, (short)0, buffer, (short)0x32, (short)4);
        Util.arrayCopyNonAtomic(transNO, (short)0, buffer, (short)0x36, (short)2);
        Util.arrayCopyNonAtomic(machineNUM, (short)0, buffer, (short)0x38, (short)6);
        Util.arrayCopyNonAtomic(dateandTime, (short)0, buffer, (short)0x3e, (short)7);
        Util.arrayCopyNonAtomic(transsum, (short)0, buffer, (short)0x45, (short)4);
        Util.arrayCopyNonAtomic(mac, (short)0, buffer, (short)0x49, (short)4);
        Util.arrayCopyNonAtomic(tac, (short)0, buffer, (short)0x4D, (short)4);
        if ((fileAdd = searchFileAddrBySFI(PETROLSPECIALSFI, (byte)0x01)) == -1)
        {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        appendCycRecord(fileAdd, buffer, (short)0x30, (short)33);
    }

    /**
     * 取交易状态
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_8088(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();

        /* hsp*/
        if ((buf[ISO7816.OFFSET_CLA] != (byte)0x80))
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (buf[ISO7816.OFFSET_P1] == 0X02)
        {
            buf[0] = ramByte[transStatusOff];
            apdu.setOutgoingAndSend((short)0, (short)0x1);
        }
        else
        {
            if (buf[ISO7816.OFFSET_P1] == 0X01)
            {
                buf[0] = ramByte1[SecuRegOff];
                apdu.setOutgoingAndSend((short)0, (short)0x1);
            }
            else
            {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        }
    }

    /**
     * Credit For Load圈存交易 返回异常值或者9000//091221(恢复)
     * 1.当前应用下的Key文件地址直接从ADF文件头中读取，不需要重新查找；
     * 2.TAC密钥0x2500地址直接从ADF文件头中读取；
     * 3.为了优化性能，把交易证明文件内容、18文件头中的记录数和最新记录位置合并到EF02文件尾部，
     *   减少写E2次数
     *   
     * @param[buf] [圈存交易指令数据]
     */
    public void creditForLoad(byte[] buf)
    {
        short series;
        short fileAdd;
        short KeyAdd;
        short ADF_fileADDR_Offset = 40;

        KeyAdd = Util.getShort(MF, (short)(ramShort1[0] + ADF_fileADDR_Offset));// 性能优化
                                                                                // 20140429
                                                                                // zhengtao
                                                                                // Key文件地址直接从ADF文件头中读取
        if ((buf[ISO7816.OFFSET_P1] != (byte)0x0)
                        || (buf[ISO7816.OFFSET_P2] != (byte)0x0))// P2 ERROR
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (buf[ISO7816.OFFSET_LC] != (byte)0x0b)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (ramByte[transStatusOff] != G_TranStatus_L)// 判断交易状态
        {
            ISOException.throwIt(TRANS_STATUS_NOT_SATISFIED);
        }
        Util.arrayFillNonAtomic(init, (short)0, (byte)8, (byte)0);
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, dateandTime, (short)0, (short)7);

        Util.arrayCopyNonAtomic(buf, (short)(ISO7816.OFFSET_LC + 8), MAC_BUF, (short)8, (short)4);// 把MAC2存放到MAC_BUF
                                                                                                  // 性能优化
                                                                                                  // 20140429
                                                                                                  // zhengtao
                                                                                                  // 两个MAC相关的buf进行调整
        Util.arrayCopyNonAtomic(transSum, (short)0, buffer, (short)6, (short)4);// 性能优化
                                                                                // hsp
        buffer[10] = ramByte[0];
        Util.arrayCopyNonAtomic(machineNUM, (short)0, buffer, (short)11, (short)6);
        Util.arrayCopyNonAtomic(dateandTime, (short)0, buffer, (short)17, (short)7);// 交易日期
                                                                                    // ＋
                                                                                    // 交易时间
        DEA_MAC(init, buffer, (short)6, (short)18, (short)0, (byte)1);// DES_MAC为MAC2

        /* 性能优化*/
        if (Util.arrayCompare(buf, (short)(ISO7816.OFFSET_LC + 8), MAC_BUF, (short)0, (short)4) != 0)// 如果MAC为错误
        {
            JCSystem.beginTransaction();
            if ((MF[(short)(KeyAdd + KeyNextStateOff)] != 0x00)
                            && (DeduceCounter(KeyAdd, (byte)0) == 0x0)) // MAC错3次锁应用
                                                                        // modify
                                                                        // by
                                                                        // zhengtao
                                                                        // 20140325
                                                                        // 交易相关密钥的错误计数器使用Key文件的读权限字节；
            {
                MF[(short)(ramShort1[0] + LockAttrOff)] |= 0x01;
                JCSystem.commitTransaction();
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            JCSystem.commitTransaction();
            ISOException.throwIt(MAC_ERROR);
        }

        fileAdd = Util.getShort(MF, (short)(ramShort1[0] + ADF_fileADDR_Offset + 14));// 计算TAC
                                                                                      // 性能优化
                                                                                      // 20140429
                                                                                      // zhengtao
                                                                                      // 两个读取密钥记录语句合并为1个
        if ((fileAdd == -1) || (fileAdd == -2))
        {
            fileAdd = getRecordByKID(DTK_TYPE, ramByte[KeyIndexOff]);
            if ((fileAdd == -1) || (fileAdd == -2))
            {
                ISOException.throwIt(COMM_WARNING_ERROR);
            }
        }
        CalculateTACSESKEY(fileAdd);// TAC生成过程密钥
        /* 性能优化 hsp*/
        Util.arrayCopyNonAtomic(balance, (short)0, buffer, (short)0, (short)4);
        Util.arrayCopyNonAtomic(transNO, (short)0, buffer, (short)4, (short)2);
        DEA_MAC(init, buffer, (short)0, (short)24, (short)0, (byte)1);// DES_MAC为MAC3

        series = Util.getShort(transNO, (short)0);
        series++;
        Util.setShort(transNO, (short)0, series);

        JCSystem.beginTransaction();
        RestoreCounter(KeyAdd, (byte)0);// modify by zhengtao 20140325
                                        // 交易相关密钥的错误计数器使用Key文件的读权限字节；

        api_AppendHLHTDetail();// 更新交易明细 hsp

        GetEDEPETBalance(ramByte[EP0ED1ET2FLAGOff], FLAG_WRITE, FLAG_ONLINE);// 更新钱包存折文件（保留地址）
        ProduceTransProof(init, (short)0, MAC_BUF, (short)0); // 更新交易证明 性能优化

        if ((fileAdd = Util.getShort(MF, (short)(ramShort1[0]
                        + ADF_fileADDR_Offset + 4))) == -1)// 性能优化 hsp
        {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        fileAdd += EFHeadLen;
        if (ramByte[EP0ED1ET2FLAGOff] == 0)// 钱包
        {
			Util.arrayCopy(buffer,(short)0,MF,fileAdd,(short)20);
        }
        else
        {
			Util.arrayCopy(buffer,(short)8,MF,(short)(fileAdd+8),(short)12);
        }

        JCSystem.commitTransaction();
        ramByte[transStatusOff] = 0x00; // 空闲状态
        Util.arrayCopyNonAtomic(MAC_BUF, (short)0x0, buf, (short)0, (short)4);// 性能优化
    }

    /**
     * 初始化交易指令函数，包括初始化圈存，初始化圈提，初始化交易等
     * 
     * @param[buf] [apdu数据]
     * @return[返回SW2]
     */
    public short initTrans(byte[] buf)
    {
        short ADF_fileADDR_Offset = 40;
        byte P1 = buf[ISO7816.OFFSET_P1];
        byte P2 = buf[ISO7816.OFFSET_P2];
        
        ramByte[KeyIndexOff] = buf[ISO7816.OFFSET_CDATA];
        if (P1 != 04)
        {
            Util.arrayCopyNonAtomic(buf, (short)(ISO7816.OFFSET_LC + 2), transSum, (short)0, (short)4);
            Util.arrayCopyNonAtomic(buf, (short)(ISO7816.OFFSET_LC + 6), machineNUM, (short)0, (short)6);
        }
        else
        {
            Util.arrayCopyNonAtomic(buf, (short)(ISO7816.OFFSET_LC + 2), machineNUM, (short)0, (short)6);
        }
        if ((ramShort[MaxBalanceOff] = Util.getShort(MF, (short)(ramShort1[0]
                        + ADF_fileADDR_Offset + 8))) == -1)// 性能优化 20140429
                                                           // zhengtao
                                                           // EF05文件直接从当前应用的ADF文件头中读取
        {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        ramShort[MaxBalanceOff] += EFHeadLen;
        if (P2 == 2)
        {
            ramShort[MaxBalanceOff] += 4;// 存折文件或ET
        }

        Util.arrayFillNonAtomic(init, (short)0, (byte)8, (byte)0);
        switch (P1)
        {
            case (byte)0x00:
                IntializeLoad(buf);
                return (short)0x10;
            case (byte)0x01:
                IntializePurchase(buf);
                return (short)0x0f;
            case (byte)0x02:
                IntializeWithdraw(buf);
                return (short)0x0f;
            case (byte)0x03:
                IntializeCAPP(buf);
                capp_cache_num[0] = 0;
                return (short)0x0f;
            case (byte)0x04:
                if (!cmEP)
                {
                    IntializeUpdate(buf);
                    return (short)0x13;
                }
                else
                {
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
            case (byte)0x05:
                IntializeUnload(buf);
                return (short)0x10;
            case (byte)0x07:
                if (cmEP)
                {
                    IntializeUpdate(buf);
                    return (short)0x13;
                }
                else
                {
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                break;
        }
        return 0;
    }

    /**
     * 取响应
     * 1.指令在应用下执行，而且应用永久锁定时，返回0x9303;
     * 2.如果当前指令不允许执行00c0指令，返回0x6f00；
     * 3.正常最多返回0xff个数据
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_00C0(APDU apdu)
    {
        short len = 0;
        
        if ((MF[(short)(ramShort1[0] + 2)] == ADFType)
                        && ((MF[(short)(ramShort1[0] + LockAttrOff)] & 0x03) == 0x02))// 如果当前应用（ADF）被永久锁定
        {
            ISOException.throwIt(APPLICATION_LOCED_PERMANENT);// 应用被永久锁定
        }

        byte[] buf = apdu.getBuffer();

        if (buf[ISO7816.OFFSET_CLA] != (byte)0)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if ((buf[ISO7816.OFFSET_P1] != (byte)0x00)
                        || (buf[ISO7816.OFFSET_P2] != (byte)0x00))
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (ramByte[GET_RESPONSE_FLAG] == (byte)0)
        {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        ramByte[GET_RESPONSE_FLAG] = 0;
        len = (short)((buffer[1] + 2) & 0x00FF);
        apdu.setOutgoing();
        apdu.setOutgoingLength(len);
        apdu.sendBytesLong(buffer, (short)0, len);
    }

    /**
     * 开卡指令 add by zhengtao 20131230
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_80DF(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        byte lc = buf[ISO7816.OFFSET_LC];
        
        if ((p1 != 0) || (p2 != 0))
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (lc != 0)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
        OpenCard_flag = 1;
    }

    /**
     * 软写建设部认证码 指令格式固定为80DE 0000 0D 00006F 01 +认证码
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_8002(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();
        byte CLA = buf[ISO7816.OFFSET_CLA];
        byte P1 = buf[ISO7816.OFFSET_P1];
        byte P2 = buf[ISO7816.OFFSET_P2];
        byte LC = buf[ISO7816.OFFSET_LC];

        if (CLA != (byte)0x80)// cla判断 hsp
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if ((P1 != (byte)0) || (P2 != (byte)0))
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);// 参数错误
        }
        if (LC != (byte)0x0A)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);// 长度错误
        }
        apdu.setIncomingAndReceive();//参数检查结束后再读取数据域数据 modify by yujing
        if ((byte)((MF[CardStatusFlagOff] >> 2) & 0x01) != 0x01)// 如果传输码未校验或个人化已经结束
        {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        Util.arrayCopy(buf, (short)5, ZJB_Number, (short)(0), (short)10);
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    /**
     * 取建设部认证码 建设部认证码固定存放在ZJB_Number中，执行该指令后只要将标志位置位即可
     * 说明已经取过建设部认证码，后续直接应用ZJB_Number中数据 zhengtao 20140117 add 20140226 去代码版本信息
     * 
     * @param[apdu] [APDU对象]
     */
    public void CMD_80CA(APDU apdu)
    {
        byte[] buf = apdu.getBuffer();
        byte P1 = buf[ISO7816.OFFSET_P1];
        byte P2 = buf[ISO7816.OFFSET_P2];
        byte LC = buf[ISO7816.OFFSET_LC];

        if ((P1 == (byte)0x9F) && (P2 == (byte)0x7D))
        {
            if ((LC != (byte)0x00) && (LC != (byte)0x06))
            {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);// 长度错误
            }
            Util.arrayCopy(Version_inf, (short)0, buf, (short)(0), (short)6);
            apdu.setOutgoingAndSend((short)0, (short)6);
        }
        else
        {
            g_tradeFlag[0] = 0;
            if ((P1 != (byte)0) || (P2 != (byte)0))
            {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);// 参数错误
            }
            if (LC != (byte)0x09)
            {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);// 长度错误
            }

            Util.arrayCopy(ZJB_Number, (short)1, buf, (short)(0), (short)9);
            apdu.setOutgoingAndSend((short)0, (short)9);
            g_tradeFlag[0] = 1;
        }
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    /**
     * 复合应用下建设部认证码参与的生成脱机MAC1
     */
    public void api_getMAC1Offline()
    {
        Util.arrayCopyNonAtomic(transSum, (short)0, buffer, (short)0, (short)4);
        buffer[4] = ramByte[0];
        Util.arrayCopyNonAtomic(machineNUM, (short)0, buffer, (short)5, (short)6);
        Util.arrayCopyNonAtomic(dateandTime, (short)0, buffer, (short)11, (short)7);// 交易日期＋交易时间
        Util.arrayCopyNonAtomic(ZJB_Number, (short)1, buffer, (short)18, (short)9);// 建设部认证码
        DEA_MAC(init, buffer, (short)0, (short)27, (short)0, (byte)1);// DES_MAC为MAC1
    }

    /**
     * 生成交易记录 每条记录包括交易序号、透支限额、交易金额、交易类型标识、终端机编号、交易日期+交易时间
     */
    public void api_AppendHLHTDetail()
    {
        short fileAdd;

        if ((ramByte[appTypeOff] & (byte)(0xF6)) == APP_HLHT)
        {
            Util.arrayCopyNonAtomic(transNO, (short)0, buffer, (short)0, (short)2);
            Util.arrayCopyNonAtomic(overDrawLimit, (short)1, buffer, (short)2, (short)3);
            Util.arrayCopyNonAtomic(transSum, (short)0, buffer, (short)5, (short)4);
            buffer[9] = ramByte[0];
            Util.arrayCopyNonAtomic(machineNUM, (short)0, buffer, (short)10, (short)6);
            Util.arrayCopyNonAtomic(dateandTime, (short)0, buffer, (short)16, (short)7);// 交易日期＋交易时间

            if ((ramByte[0] == EDL) || (ramByte[0] == EPL))
            {
                if ((fileAdd = searchFileAddrBySFI((byte)0x1a, (byte)0x01)) == -1)
                {
                    ProduceTransDaily();
                }
                else
                {
                    appendCycRecord(fileAdd, buffer, (short)0x0, (short)0x17);
                }
            }
            else
            {
                if ((fileAdd = searchFileAddrBySFI((byte)0x15, (byte)0x01)) == -1)
                {
                    ProduceTransDaily();
                }
                else
                {
                    if ((MF[(short)(fileAdd + EFHeadLen + 2)] != machineNUM[0])
                                    || (MF[(short)(fileAdd + EFHeadLen + 3)] != machineNUM[1]))
                    {
                        if ((fileAdd = searchFileAddrBySFI((byte)0x10, (byte)0x01)) == -1)
                        {
                            ProduceTransDaily();
                        }
                        else
                        {
                            appendCycRecord(fileAdd, buffer, (short)0x0, (short)0x17);
                        }
                    }
                    else
                    {
                        ProduceTransDaily();
                    }
                }

            }
        }
        else
        {
            ProduceTransDaily();
        }
    }

    /**
     * 读密钥记录
     * 
     * @param[buffer] [STK菜单通过共享接口调用00F1指令时传入的指令数据]
     * @param[apdu] [APDU对象]
     * @param[flag] [00：通过APDU指令执行00F1指令，FCI信息直接返回；其他：共享接口调用00F1指令，
                                    FCI信息存储在buf中，供STK菜单读取，不能直接返回]
     */
    public void CMD_00F1(byte[] buffer, APDU apdu, byte flag)
    {
        short length;// =0; hsp
        byte[] buf = buffer;
        apdu = null;

        short KFAddr;// =0; hsp
        short kAddr;// = 0; hsp
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short typeKID;// =0; hsp 密钥类型和密钥标识(唯一标识了一个密钥)

        KFAddr = searchFileAddrByFID((short)0x0000, (byte)1);// 寻找当前DF下的密钥文件
        if (KFAddr == -1)
        {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);// 密钥文件找不到
        }
        if ((short)(Util.getShort(MF, (short)(KFAddr + FileLenOff)) - EFHeadLen) == 0)// 密钥文件体大小为0
        {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        length = (short)(buf[ISO7816.OFFSET_LC] & 0x00FF);
        typeKID = Util.makeShort(buf[ISO7816.OFFSET_CDATA], p2);

        kAddr = getRecordByKID((byte)p1, (byte)typeKID);// 要找的密钥的起始地址

        Util.arrayCopy(MF, (short)(kAddr + KeyHeadLength), buf, (short)1, (short)length);

        /* 接口返回的数据,现已存在于buf中偏移1.*/
        buf[0] = (byte)length;
        buf[(short)(buf[0] + 1)] = (byte)0x90;
        buf[(short)(buf[0] + 2)] = (byte)0x00;
    }

    /**
     * AID方式选择应用实例
     * 输出：实例的FCI控制信息
     * 
     * @param[apdu] [APDU对象]
     * @return[0:不需要返回实例的FCI信息；1：正常返回实例的FCI信息]
     */
    public byte AIDSelect(APDU apdu)
    {
        byte[] buf;// 接口修改
        buf = apdu.getBuffer();

        if (OpenCard_flag == 0)
        {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        if (cardLock == 1)// 卡片锁定
        {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        short p1p2;// =0; hsp
        short length;// = 0;//记录长度 hsp
        p1p2 = Util.getShort(buf, ISO7816.OFFSET_P1);
        ramByte[GET_RESPONSE_FLAG] = 0;

        if ((p1p2 != 0x0000) && (p1p2 != 0x0400) && (p1p2 != 0x0402)
                        && (p1p2 != 0x0404))
        {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if ((C9_Flag[1] == 0)
                        || ((C9_Flag[1] == 1) && ((Util.getShort(MF, (short)0)) == 0)))
        {
            /* 返回FCI响应数据*/
            buf[0] = 0x6F;
            buf[2] = (byte)0x84;

            buf[3] = JCSystem.getAID().getBytes(buf, (short)4);// 将AID放到84和LC后面
            length = (byte)(buf[3] + 4);// A5之前的所有数据的长度
            buf[length] = (byte)0xA5;
            buf[(short)(length + 1)] = (byte)0x03;
            buf[(short)(length + 2)] = (byte)0x88;
            buf[(short)(length + 3)] = (byte)0x01;
            buf[(short)(length + 4)] = (byte)0x01;
            length += 5;
            buf[1] = (byte)(length - 2);
            ramShort1[0] = 0;
            if (apdu != null)
            {
                apdu.setOutgoingAndSend((byte)0, length);
            }
            else
            {
                Util.arrayCopyNonAtomic(buf, (short)0, buf, (short)1, length);
                buf[0] = (byte)length;
                buf[(short)(buf[0] + 1)] = (byte)0x90;
                buf[(short)(buf[0] + 2)] = (byte)0x00;
            }
            return (byte)1;
        }

        return (byte)0;
    }

    /**
     * select指令中的变量设置 auther:hsp date: 2014.07.02
     */
    public void setSelectRamVar()
    {
        ramByte[transStatusOff] = 0; // 交易状态
        ramByte[randomFlagOff] = 0; // 随机数生成标识
        ramByte[appTypeOff] = 0; // 应用类型
        ramByte1[SecuRegOff] = 0;// 安全状态寄存器清0
        g_tradeFlag[0] = 0;// 住建部标示
        ramShort1[NEFAddrOff] = 0x00; // 当前EF设置为0
    }
    
    /** 读MF中的数据(用于调试)
     *  数据域为偏移MF中的偏移+长度，偏移是从MF的最后开始计算
     */
    /*
    public void CMD_8004(APDU apdu)
    {
        byte[]buf = apdu.getBuffer();
        byte CLA = buf[ISO7816.OFFSET_CLA];
        byte P1 = buf[ISO7816.OFFSET_P1];
        byte P2 = buf[ISO7816.OFFSET_P2];
        byte LC = buf[ISO7816.OFFSET_LC];
        short INdex = 0;
        short lenth = 0;
        
        if(CLA != (byte)0x80) 
        {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        if((P1 != (byte)0) || (P2 != (byte)0))
        {   
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);//参数错误
        }
        if(LC != (byte)0x04)
        {   
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);//长度错误
        }
        apdu.setIncomingAndReceive();
        INdex = Util.getShort( buf,(short)(5));
        lenth = Util.getShort( buf,(short)(7));
        Util.arrayCopy(MF,(short)(INdex),buf,(short)(0),(short)lenth);
        apdu.setOutgoingAndSend((byte)0,lenth);
        //ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }
  */
}
