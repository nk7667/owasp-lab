package org.owasplab.service;

import org.owasplab.model.ChallengePolicy;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 基线防护工具类
 * 提供外层不可绕过的安全防护
 */
public class BaselineSecurityUtils {
    
    private static final int TIMEOUT_SECONDS = 5;
    private static final int MAX_OUTPUT_LENGTH = 2000;
    private static final String LAB_DIR = System.getProperty("user.dir") + "/lab";
    
    /**
     * 解析挑战目录下的 data 路径
     * 外层不可绕过：确保路径在 data 目录内
     * 
     * ⚠️ 靶场场景说明：
     * - 此方法用于文件操作类命令（cat, ls 等）
     * - 对于命令注入场景，应直接使用命令白名单，而不是路径检查
     * 
     * @param challengeId 挑战ID
     * @param userPath 用户输入的路径
     * @param mustExist 是否必须存在
     * @return 规范化后的路径，越界返回null
     */
    public static Path resolveUnderChallengeData(String challengeId, String userPath, boolean mustExist) {
        Path base = Paths.get(LAB_DIR, "challenges", challengeId, "data").toAbsolutePath().normalize();
        
        // 先进行 URL 解码（处理 %2F, %2E 等编码）
        String decodedPath = decodeUrl(userPath);
        
        // 规范化用户路径
        Path target = base.resolve(decodedPath).normalize();
        
        // 外层不可绕过：确保在 base 目录内
        if (!target.startsWith(base.toString())) {
            return null; // 越界
        }
        
        if (mustExist) {
            if (!java.nio.file.Files.exists(target)) {
                return null;
            }
        }
        
        return target;
    }
    
    /**
     * 统一运行进程
     * 外层不可绕过：使用参数数组，禁止 shell 解析（隔离靶场和主机）
     * @param startTime 开始时间
     * @param args 命令参数数组
     * @return 执行结果
     */
    public static Map<String, Object> runProcess(long startTime, ChallengePolicy policy, String... args) {
        try {
            // 使用 ProcessBuilder 参数数组，禁止 "/bin/sh -c"
            ProcessBuilder pb = new ProcessBuilder(args);
            
            // 设置工作目录
            pb.directory(new File(LAB_DIR));
            
            // 重定向错误流
            pb.redirectErrorStream(true);
            
            // 可选：清理环境变量
            // pb.environment().clear();
            
            Process p = pb.start();
            
            if (!p.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return CommandExecutionServiceImpl.buildResult(String.join(" ", args), -1, "", "Command timeout", System.currentTimeMillis() - startTime);
            }
            
            int exitCode = p.exitValue();
            
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder out = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) {
                out.append(line).append("\n");
                if (out.length() > MAX_OUTPUT_LENGTH) {
                    out.setLength(MAX_OUTPUT_LENGTH);
                    out.append("\n... (output truncated)");
                    break;
                }
            }
            r.close();
            
            return CommandExecutionServiceImpl.buildResult(String.join(" ", args), exitCode, out.toString(), "", System.currentTimeMillis() - startTime);
            
        } catch (Exception e) {
            return CommandExecutionServiceImpl.buildResult(String.join(" ", args), -1, "", "Error: " + e.getMessage(), System.currentTimeMillis() - startTime);
        }
    }
    
    /**
     * 应用转换规则（内层可绕过）
     * 
     * @param policy 策略
     * @param input 输入字符串
     * @return 转换后的字符串
     */
    public static String applyTransforms(ChallengePolicy policy, String input) {
        String result = input;
        
        // URL 解码
        if (policy.transformDecodeUrl) {
            result = decodeUrl(result);
        }
        
        // 移除空格
        if (policy.transformRemoveSpaces) {
            result = result.replaceAll("\\s+", "");
        }
        
        return result;
    }
    
    /**
     * 简单的 URL 解码
     * 
     * @param input 输入字符串
     * @return 解码后的字符串
     */
    private static String decodeUrl(String input) {
        if (input == null) {
            return null;
        }
        
        // 简单实现：处理常见的 URL 编码
        // 实际应用中可以使用 java.net.URLDecoder
        return input
            .replace("%20", " ")
            .replace("%3B", ";")
            .replace("%26", "&")
            .replace("%7C", "|")
            .replace("%2F", "/")
            .replace("%2E", ".")
            .replace("%2D", "-");
    }
    
    /**
     * 检查路径是否在允许的模式内
     * 
     * @param path 路径
     * @param pattern 允许的正则模式
     * @return 是否合法
     */
    public static boolean isValidPath(String path, String pattern) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        return path.matches(pattern);
    }
    
    /**
     * 检查命令是否在白名单中
     * 
     * @param command 命令
     * @param allowedCommands 允许的命令集合
     * @return 是否合法
     */
    public static boolean isAllowedCommand(String command, java.util.Set<String> allowedCommands) {
        if (command == null || command.isEmpty()) {
            return false;
        }
        
        String[] parts = command.trim().split("\\s+");
        return allowedCommands.contains(parts[0]);
    }
}
