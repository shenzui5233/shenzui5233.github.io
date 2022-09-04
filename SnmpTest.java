package work.jimmmy.snmp;

import org.snmp4j.*;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;

public class SnmpTest {
    public static void main(String[] args) {
        MySnmp snmpAgent = new MySnmp();
        snmpAgent.listen();
    }
}

class MySnmp implements CommandResponder {
    private static final String SECURITY_NAME = "security";

    private static final String AUTH_PASSWORD = "password12#$";

    private static final String PRIV_PASSWORD = "password12#$%";

    private Snmp snmp;

    public void listen() {
        try {
            initSnmp();
            snmp.addCommandResponder(this);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    /**
     * 实现CommandResponder的processPdu方法，用于处理传入的请求，PDU等信息
     * 当接收到trap时，会自动进入这个方法
     *
     * @param commandResponderEvent respEvent
     */
    @Override
    public void processPdu(CommandResponderEvent commandResponderEvent) {
        // 解析response
        try {
            if (commandResponderEvent != null && commandResponderEvent.getPDU() != null) {
                for (int i = 0; i < commandResponderEvent.getPDU().getVariableBindings().size(); i++) {
                    System.out.println("消息体oid: " + commandResponderEvent.getPDU().getVariableBindings().elementAt(i).getOid());
                    System.out.println("消息体oid对应值: " + commandResponderEvent.getPDU().getVariableBindings().elementAt(i).getVariable());
                }
            }
        } catch (Exception e) {
             // https://blog.csdn.net/weixin_44936331/article/details/111300480
            e.printStackTrace();
        }
    }

    private void initSnmp() throws IOException {
        // 1.初始化多线程消息转发类
        MessageDispatcher messageDispatcher = new MessageDispatcherImpl();
        // 其中要增加三种处理模型，如果snmp初始化使用的是Snmp(TransportMapping<? extends Address> transportMapping), 就不需要增加
        messageDispatcher.addMessageProcessingModel(new MPv1());
        messageDispatcher.addMessageProcessingModel(new MPv2c());
        // 当要支持snmpv3时版本时，需要配置user
        OctetString localEngineId = new OctetString(MPv3.createLocalEngineID());
        USM usm = new USM(SecurityProtocols.getInstance().addDefaultProtocols(), localEngineId, 0);

        OctetString userName = new OctetString(SECURITY_NAME);
        OctetString authPass = new OctetString(AUTH_PASSWORD);
        OctetString privPass = new OctetString(PRIV_PASSWORD);
        UsmUser usmUser = new UsmUser(userName, AuthHMAC384SHA512.ID, authPass, PrivAES256.ID, privPass);

        usm.addUser(usmUser.getSecurityName(), usmUser);
        messageDispatcher.addMessageProcessingModel(new MPv3(usm));
        // 2. 创建transport ip为本地ip时，可以不设置
        UdpAddress udpAddress = (UdpAddress) GenericAddress.parse("udp:127.0.0.1/161");
        TransportMapping<?> transportMapping = new DefaultUdpTransportMapping(udpAddress);
        // 3. 正式创建snmp
        snmp = new Snmp(messageDispatcher, transportMapping);
        // 4. 开启监听
        snmp.listen();
    }

    private Target createTarget(int version) {
        switch (version) {
            case SnmpConstants.version1:
            case SnmpConstants.version2c:
                return processTarget(version);
            case SnmpConstants.version3:
                return processV3Target(version);
            default:
                return null;
        }
    }

    /**
     * 初始化get和walk方式请求的目标对象信息
     *
     * @param version snmp版本号
     * @return target
     */
    private Target processTarget(int version) {
        // snmp v1和v2需要指定团体名名称
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString(SECURITY_NAME));
        if (version == SnmpConstants.version2c) {
            target.setSecurityModel(SecurityModel.SECURITY_MODEL_SNMPv2c);
        }
        setCommonProperties(target, version);
        return target;
    }
    
    private Target processV3Target(int version) {
        Target target = new UserTarget();
        // snmpv3 需要设置安全级别和安全名称，其中安全名称时创建snmp指定user设置的new OctetString("SNMPV3")
        target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        target.setSecurityName(new OctetString(SECURITY_NAME));
        setCommonProperties(target, version);
        return target;
    }
    
    private void setCommonProperties(Target target, int version) {
        target.setVersion(version);
        // 必须指定，没有设置会报错
        target.setAddress(GenericAddress.parse("udp:127.0.0.1/161"));
        target.setRetries(3);
        target.setTimeout(2000);
    }
}
