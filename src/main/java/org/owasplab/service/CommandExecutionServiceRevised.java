package org.owasplab.service;

import org.owasplab.core.Mode;
import org.owasplab.model.ChallengePolicy;

import java.nio.file.Path;
import java.util.Map;

/**
 * 命令执行服务（重构版）
 * 实现外层不可绕过的基线防护 + 内层可控漏洞
 */
public class CommandExecutionServiceRevised {
    
    /**
     * 执行 ping 命令
     * 
     * @param challengeId 挑战ID
     * @param mode 模式（VULN/WEAK/SAFE）
     * @param host 主机名/IP
     * @param weakLevel 弱化级别
     * @return 执行结果
     */
    public Map<String, Object> executePing(String challengeId, Mode mode, String host, int weakLevel) {
        long startTime = System.currentTimeMillis();
        
        // 加载策略
        ChallengePolicy policy = loadPolicy(challengeId, mode, weakLevel);
        
        // 应用转换（内层可绕过）
        host = BaselineSecurityUtils.applyTransforms(policy, host);
        
        // 内层校验（可弱化）
        if (!policy.weakenPathTraversal && host.contains("..")) {
            return CommandExecutionServiceImpl.buildBlockedResult("ping -c 1 " + host, "Blocked: 路径遍历");
        }
        
        // 参数校验（外层不可绕过）
        if (!host.matches(policy.hostPattern)) {
            return CommandExecutionServiceImpl.buildBlockedResult("ping -c 1 " + host, "Blocked: host 非法");
        }
        
        // 专用构建（外层不可绕过：使用参数数组，禁止 shell 解析）
        return BaselineSecurityUtils.runProcess(startTime, policy, "ping", "-c", "1", host);
    }
    
    /**
     * 执行 ls 命令
     * 
     * @param challengeId 挑战ID
     * @param mode 模式
     * @param path 路径
     * @param weakLevel 弱化级别
     * @return 执行结果
     */
    public Map<String, Object> executeLs(String challengeId, Mode mode, String path, int weakLevel) {
        long startTime = System.currentTimeMillis();
        
        // 加载策略
        ChallengePolicy policy = loadPolicy(challengeId, mode, weakLevel);
        
        // 应用转换（内层可绕过）
        path = BaselineSecurityUtils.applyTransforms(policy, path);
        
        // 内层校验（可弱化）
        if (!policy.weakenPathTraversal && path.contains("..")) {
            return CommandExecutionServiceImpl.buildBlockedResult("ls -la " + path, "Blocked: 路径遍历");
        }
        
        // 外层不可绕过：解析路径，确保在 data 目录内
        Path target = BaselineSecurityUtils.resolveUnderChallengeData(challengeId, path, false);
        if (target == null) {
            return CommandExecutionServiceImpl.buildBlockedResult("ls -la " + path, "Blocked: 超出挑战数据目录");
        }
        
        // 专用构建（外层不可绕过：使用参数数组）
        return BaselineSecurityUtils.runProcess(startTime, policy, "ls", "-la", target.toString());
    }
    
    /**
     * 执行 grep 命令
     * 
     * @param challengeId 挑战ID
     * @param mode 模式
     * @param keyword 关键字
     * @param weakLevel 弱化级别
     * @return 执行结果
     */
    public Map<String, Object> executeGrep(String challengeId, Mode mode, String keyword, int weakLevel) {
        long startTime = System.currentTimeMillis();
        
        // 加载策略
        ChallengePolicy policy = loadPolicy(challengeId, mode, weakLevel);
        
        // 应用转换（内层可绕过）
        keyword = BaselineSecurityUtils.applyTransforms(policy, keyword);
        
        // 内层校验（可弱化）
        if (!keyword.matches(policy.grepKeywordPattern)) {
            return CommandExecutionServiceImpl.buildBlockedResult("grep " + keyword + " app.log", "Blocked: 关键字包含非法字符");
        }
        
        // 外层不可绕过：文件路径固定为 data/app.log
        Path target = BaselineSecurityUtils.resolveUnderChallengeData(challengeId, "app.log", true);
        if (target == null) {
            return CommandExecutionServiceImpl.buildBlockedResult("grep " + keyword + " app.log", "Blocked: 文件不存在");
        }
        
        // 专用构建（外层不可绕过：使用参数数组）
        return BaselineSecurityUtils.runProcess(startTime, policy, "grep", keyword, target.toString());
    }
    
    /**
     * 执行 cat 命令
     * 
     * @param challengeId 挑战ID
     * @param mode 模式
     * @param filename 文件名
     * @param weakLevel 弱化级别
     * @return 执行结果
     */
    public Map<String, Object> executeCat(String challengeId, Mode mode, String filename, int weakLevel) {
        long startTime = System.currentTimeMillis();
        
        // 加载策略
        ChallengePolicy policy = loadPolicy(challengeId, mode, weakLevel);
        
        // 应用转换（内层可绕过）
        filename = BaselineSecurityUtils.applyTransforms(policy, filename);
        
        // 内层校验（可弱化）
        if (!filename.matches(policy.pathPattern)) {
            return CommandExecutionServiceImpl.buildBlockedResult("cat " + filename, "Blocked: 文件名包含非法字符");
        }
        
        // 外层不可绕过：解析路径，确保在 data 目录内
        Path target = BaselineSecurityUtils.resolveUnderChallengeData(challengeId, filename, true);
        if (target == null) {
            return CommandExecutionServiceImpl.buildBlockedResult("cat " + filename, "Blocked: 超出挑战数据目录或文件不存在");
        }
        
        // 外层不可绕过：文件白名单检查
        String fileName = target.getFileName().toString();
        if (!policy.safeFiles.contains(fileName)) {
            return CommandExecutionServiceImpl.buildBlockedResult("cat " + filename, "Denied: 文件不在白名单中");
        }
        
        // 专用构建（外层不可绕过：使用参数数组）
        return BaselineSecurityUtils.runProcess(startTime, policy, "cat", target.toString());
    }
    
    /**
     * 加载挑战策略
     * 
     * @param challengeId 挑战ID
     * @param mode 模式
     * @param weakLevel 弱化级别
     * @return 策略对象
     */
    private ChallengePolicy loadPolicy(String challengeId, Mode mode, int weakLevel) {
        // 根据 mode 和 weakLevel 创建策略
        switch (mode) {
            case VULN:
                return ChallengePolicy.createVuln();
            case WEAK:
                return ChallengePolicy.createWeak(weakLevel);
            case SAFE:
                return ChallengePolicy.createSafe();
            default:
                return ChallengePolicy.createDefault();
        }
    }
}
