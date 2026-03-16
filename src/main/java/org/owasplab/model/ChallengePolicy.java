package org.owasplab.model;

import java.util.HashSet;
import java.util.Set;

/**
 * 挑战策略模型
 * 描述允许的命令、文件、参数校验和弱化规则
 */
public class ChallengePolicy {
    public String id;
    public String title;
    
    // 允许的命令
    public Set<String> allowedCommands = new HashSet<>();
    
    // 文件白名单（相对 data 目录）
    public Set<String> safeFiles = new HashSet<>();
    
    // 命令选项配置
    public boolean allowLsOptionLa = true;  // 是否允许 ls -la
    public boolean grepAllowRegex = false;  // 是否允许正则表达式
    
    // 参数校验正则
    public String grepKeywordPattern = "^[a-zA-Z0-9._-]+$";  // grep 关键字允许的正则
    public String hostPattern = "^[a-zA-Z0-9.-]+$";          // ping 主机名/IP的正则
    public String pathPattern = "^[a-zA-Z0-9._/-]+$";        // 路径允许的正则
    
    // 弱化规则（内层可绕过，外层仍限制）
    public boolean weakenPathTraversal = false;  // 是否故意不拦 ../（仅内层）
    public boolean transformRemoveSpaces = false; // 弱化：移除空格
    public boolean transformDecodeUrl = false;    // 弱化：URL 解码
    
    // 默认策略（最严格）
    public static ChallengePolicy createDefault() {
        ChallengePolicy policy = new ChallengePolicy();
        policy.id = "default";
        policy.title = "默认策略（最严格）";
        policy.allowedCommands.add("ping");
        policy.allowedCommands.add("ls");
        policy.allowedCommands.add("grep");
        policy.allowedCommands.add("cat");
        policy.safeFiles.add("hosts");
        policy.safeFiles.add("app.log");
        policy.safeFiles.add("passwd.mock");
        policy.allowLsOptionLa = true;
        policy.grepAllowRegex = false;
        policy.grepKeywordPattern = "^[a-zA-Z0-9._-]+$";
        policy.hostPattern = "^[a-zA-Z0-9.-]+$";
        policy.pathPattern = "^[a-zA-Z0-9._/-]+$";
        policy.weakenPathTraversal = false;
        policy.transformRemoveSpaces = false;
        policy.transformDecodeUrl = false;
        return policy;
    }
    
    // VULN 策略（无防护）
    public static ChallengePolicy createVuln() {
        ChallengePolicy policy = createDefault();
        policy.id = "vuln";
        policy.title = "VULN（原始漏洞，无防护）";
        return policy;
    }
    
    // WEAK 策略（错误修复）
    public static ChallengePolicy createWeak(int level) {
        ChallengePolicy policy = createDefault();
        policy.id = "weak-" + level;
        policy.title = "WEAK-" + level + "（错误修复）";
        
        switch (level) {
            case 1:
                // 拦截反引号、换行符
                policy.pathPattern = "^[a-zA-Z0-9._/\\- ]+$"; // 允许空格，但拦截反引号和换行
                policy.hostPattern = "^[a-zA-Z0-9.\\- ]+$";
                break;
            case 2:
                // 拦截反引号、换行符（更严格）
                policy.pathPattern = "^[a-zA-Z0-9._/\\-]+$"; // 不允许空格
                policy.hostPattern = "^[a-zA-Z0-9.\\-]+$";
                break;
            case 3:
                // 移除空格
                policy.transformRemoveSpaces = true;
                break;
            case 4:
                // 拦截斜杠、cat、passwd
                policy.pathPattern = "^[a-zA-Z0-9._-]+$"; // 不允许斜杠
                policy.hostPattern = "^[a-zA-Z0-9.\\-]+$";
                break;
            case 5:
                // 拦截 cat、passwd（需要自解码）
                policy.transformDecodeUrl = true;
                policy.pathPattern = "^[a-zA-Z0-9._/\\-]+$";
                policy.hostPattern = "^[a-zA-Z0-9.\\-]+$";
                break;
            default:
                break;
        }
        return policy;
    }
    
    // SAFE 策略（正确修复）
    public static ChallengePolicy createSafe() {
        ChallengePolicy policy = createDefault();
        policy.id = "safe";
        policy.title = "SAFE（正确修复，参数化执行）";
        policy.pathPattern = "^[0-9a-zA-Z.:-]+$"; // 只允许字母、数字、点、冒号、连字符
        return policy;
    }
}
