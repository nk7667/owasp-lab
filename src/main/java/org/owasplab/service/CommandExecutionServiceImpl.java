package org.owasplab.service;

import org.springframework.stereotype.Service;
import org.owasplab.core.Mode;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

@Service
public class CommandExecutionServiceImpl implements CommandExecutionService {
    private static final int TIMEOUT_SECONDS = 5;
    private static final int MAX_OUTPUT_LENGTH = 2000;
    private static final String LAB_DIR = System.getProperty("user.dir") + "/lab";
    
    // 白名单文件列表（cat 类命令只允许读取这些文件）
    private static final Set<String> SAFE_FILES = new HashSet<>(Arrays.asList(
        "hosts", "app.log", "passwd.mock"
    ));
    
    // 命令白名单（只允许执行这些命令）
    private static final Set<String> ALLOWED_COMMANDS = new HashSet<>(Arrays.asList(
        "ping", "ls", "grep", "cat"
    ));

    @Override
    public Map<String, Object> executePing(Mode mode, String host, int weakLevel) {
        LevelConfig config = getLevelConfig(mode, weakLevel);
        String effectiveHost = decodeParamOnce(host);
        CheckResult checkResult = config.check(effectiveHost);

        if (checkResult.isBlocked()) {
            return buildResult("ping -c 1 " + effectiveHost, -1, "", checkResult.getReason(), 0L);
        }

        String transformed = config.transform(effectiveHost);

        if (mode == Mode.SAFE) {
            return executePingSafe(transformed);
        }

        String command = "ping -c 1 " + transformed;
        return executeCommand(mode, command);
    }

    @Override
    public Map<String, Object> executeLs(Mode mode, String path, int weakLevel) {
        LevelConfig config = getLevelConfig(mode, weakLevel);
        String pathDecoded = decodeParamOnce(path);

        // 兜底：所有模式都将路径解析并限制在 LAB_DIR 内，防止靶场与主机环境混淆
        String effectivePath;
        if (mode != Mode.VULN) {
            CheckResult pathCheckResult = checkPathSecurity(pathDecoded);
            if (pathCheckResult.isBlocked()) {
                return buildBlockedResult("ls -la " + pathDecoded, pathCheckResult.getReason());
            }
            effectivePath = normalizeLabPath(pathDecoded);
        } else {
            effectivePath = resolvePathUnderLab(pathDecoded);
        }

        CheckResult checkResult = config.check(effectivePath);
        
        if (checkResult.isBlocked()) {
            return buildBlockedResult("ls -la " + effectivePath, checkResult.getReason());
        }

        String transformed = config.transform(effectivePath);
        if (mode == Mode.SAFE) {
            return executeArgs("ls", "-la", transformed);
        }
        String command = "ls -la " + transformed;
        return executeCommand(mode, command);
    }

    @Override
    public Map<String, Object> executeGrep(Mode mode, String keyword, int weakLevel) {
        LevelConfig config = getLevelConfig(mode, weakLevel);
        String effectiveKeyword = decodeParamOnce(keyword);

        String normalizedPath = normalizeLabPath("app.log");

        CheckResult checkResult = config.check(effectiveKeyword);

        if (checkResult.isBlocked()) {
            return buildBlockedResult("grep " + effectiveKeyword + " " + normalizedPath, checkResult.getReason());
        }

        String transformed = config.transform(effectiveKeyword);
        if (mode == Mode.SAFE) {
            return executeArgs("grep", transformed, normalizedPath);
        }
        String command = "grep " + transformed + " " + normalizedPath;
        return executeCommand(mode, command);
    }

    /** URL 解码至稳定，使前端传参中的 %0a/%26 等生效（axios 可能把 % 编码成 %25，需多轮解码） */
    private static String decodeParamOnce(String raw) {
        if (raw == null || raw.isEmpty()) return raw;
        String prev = "";
        String cur = raw;
        int maxPasses = 5;
        while (!cur.equals(prev) && maxPasses-- > 0) {
            prev = cur;
            try {
                cur = URLDecoder.decode(prev, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                break;
            }
        }
        return cur;
    }
    
    @Override
    public Map<String, Object> executeCat(Mode mode, String filename, int weakLevel) {
        LevelConfig config = getLevelConfig(mode, weakLevel);
        String filenameDecoded = decodeParamOnce(filename);

        // 兜底：所有模式都将路径解析并限制在 LAB_DIR 内
        String effectivePath;
        if (mode != Mode.VULN) {
            CheckResult pathCheckResult = checkPathSecurity(filenameDecoded);
            if (pathCheckResult.isBlocked()) {
                return buildBlockedResult("cat " + filenameDecoded, pathCheckResult.getReason());
            }
            effectivePath = normalizeLabPath(filenameDecoded);
            CheckResult whitelistCheckResult = checkWhitelist(effectivePath);
            if (whitelistCheckResult.isBlocked()) {
                return buildBlockedResult("cat " + effectivePath, whitelistCheckResult.getReason());
            }
        } else {
            effectivePath = resolvePathUnderLab(filenameDecoded);
        }

        CheckResult checkResult = config.check(effectivePath);
        
        if (checkResult.isBlocked()) {
            return buildBlockedResult("cat " + effectivePath, checkResult.getReason());
        }

        String transformed = config.transform(effectivePath);
        if (mode == Mode.SAFE) {
            return executeArgs("cat", transformed);
        }
        String command = "cat " + transformed;
        return executeCommand(mode, command);
    }

    private CheckResult checkPathSecurity(String userPath) {
        // 白名单验证：只允许字母、数字、点、连字符、下划线和斜杠
        if (!userPath.matches("^[0-9a-zA-Z._/-]+$")) {
            return new CheckResult(true, "Blocked: 路径包含非法字符");
        }
        
        // 拒绝绝对路径（只允许相对路径）
        if (userPath.startsWith("/")) {
            return new CheckResult(true, "Blocked: 不允许使用绝对路径");
        }
        
        // 拒绝路径遍历
        if (userPath.contains("..")) {
            return new CheckResult(true, "Blocked: 不允许路径遍历 (..)");
        }
        
        // 拒绝 ~ 符号
        if (userPath.contains("~")) {
            return new CheckResult(true, "Blocked: 不允许使用 ~ 符号");
        }
        
        // 拒绝特殊字符
        if (userPath.contains(";") || userPath.contains("&") || userPath.contains("|")) {
            return new CheckResult(true, "Blocked: 不允许使用特殊字符");
        }
        
        return new CheckResult(false, null);
    }
    
    private CheckResult checkWhitelist(String normalizedPath) {
        String filename = Paths.get(normalizedPath).getFileName().toString();
        
        // 白名单验证：文件名只允许字母、数字、点、连字符
        if (!filename.matches("^[a-zA-Z0-9._-]+$")) {
            return new CheckResult(true, "Denied: 文件名包含非法字符");
        }
        
        if (!SAFE_FILES.contains(filename)) {
            return new CheckResult(true, "Denied: 文件不在白名单中 (hosts/app.log/passwd.mock)");
        }
        return new CheckResult(false, null);
    }
    
    private CheckResult checkCommandWhitelist(String command) {
        // 白名单验证：只允许字母、数字、点、连字符、下划线和空格
        // 注意：- 放在字符类的末尾，避免被解释为范围
        if (!command.matches("^[a-zA-Z0-9._/\\-]+\\s*[a-zA-Z0-9._/\\-]*$")) {
            return new CheckResult(true, "Blocked: 命令包含非法字符");
        }
        
        // 提取命令名（第一个单词）
        String[] parts = command.trim().split("\\s+");
        if (parts.length == 0) {
            return new CheckResult(true, "Blocked: 空命令");
        }
        
        String commandName = parts[0];
        if (!ALLOWED_COMMANDS.contains(commandName)) {
            return new CheckResult(true, "Blocked: 命令不在白名单中 (ping/ls/grep/cat)");
        }
        
        return new CheckResult(false, null);
    }
    
    private String normalizeLabPath(String userPath) {
        // 确保路径是相对于 LAB_DIR 的
        if (userPath.startsWith("./")) {
            userPath = userPath.substring(2);
        }
        
        // 拼接到 LAB_DIR
        Path fullPath = Paths.get(LAB_DIR, userPath);
        
        // 规范化路径
        try {
            Path normalized = fullPath.toRealPath();
            Path labDirPath = Paths.get(LAB_DIR).toAbsolutePath().normalize();
            
            // 确保在 LAB_DIR 内
            if (!normalized.startsWith(labDirPath)) {
                return LAB_DIR + "/app.log";
            }
            return normalized.toString();
        } catch (Exception e) {
            return LAB_DIR + "/app.log"; // 异常时安全回退
        }
    }

    /**
     * 兜底：将用户路径解析到 LAB_DIR 下，若会逃逸出靶场目录则回退到 LAB_DIR，防止靶场与主机环境混淆。
     * 不要求路径存在，仅做规范化与边界检查。
     */
    private String resolvePathUnderLab(String userPath) {
        if (userPath == null || userPath.trim().isEmpty()) {
            return LAB_DIR;
        }
        Path base = Paths.get(LAB_DIR).toAbsolutePath().normalize();
        Path resolved = base.resolve(userPath.trim()).normalize();
        if (!resolved.startsWith(base)) {
            return base.toString();
        }
        return resolved.toString();
    }

    private LevelConfig getLevelConfig(Mode mode, int weakLevel) {
        switch (mode) {
            case VULN:
                return new LevelConfig("", "无防护");
            case WEAK:
                switch (weakLevel) {
                    case 1:
                        return new LevelConfig("[`\\r\\n]", "拦截反引号、换行符");
                    case 2:
                        return new LevelConfig("[`\\r\\n]", "拦截反引号、换行符");
                    case 3:
                        return new LevelConfig("\\s", "拦截空格（替换为空）");
                    case 4:
                        return new LevelConfig("[/]|cat|passwd", "拦截斜杠、cat、passwd");
                    case 5:
                        return new LevelConfig("cat|passwd", "拦截 cat、passwd（需要自解码）");
                    default:
                        return new LevelConfig("[`\\r\\n]", "拦截反引号、换行符");
                }
            case SAFE:
                return new LevelConfig("[^0-9a-zA-Z.:-]", "只允许字母、数字、点、冒号、连字符");
            default:
                return new LevelConfig("", "无防护");
        }
    }

    private Map<String, Object> executeCommand(Mode mode, String command) {
        // VULN/WEAK：走 shell（允许拼接/注入演示；WEAK 由上层 LevelConfig 做“错误修复”过滤）
        if (mode == Mode.VULN || mode == Mode.WEAK) {
            return executeShell(command);
        }

        // SAFE：外层基线校验 + 不走 shell
        CheckResult commandCheckResult = checkCommandWhitelist(command);
        if (commandCheckResult.isBlocked()) {
            return buildBlockedResult(command, commandCheckResult.getReason());
        }

        // SAFE：检查解码后的命令中是否包含路径遍历
        String decodedCommand = command;
        String prevCommand = "";
        int maxIterations = 10;
        int iteration = 0;
        while (!decodedCommand.equals(prevCommand) && iteration < maxIterations) {
            prevCommand = decodedCommand;
            decodedCommand = decodeUrlOnce(decodedCommand);
            iteration++;
        }
        if (decodedCommand.contains("../") || decodedCommand.contains("..\\") || decodedCommand.contains(".. ")) {
            return buildBlockedResult(command, "Blocked: 命令中包含路径遍历 (..)");
        }

        // SAFE：禁止危险字符（即便不走 shell，也避免误解/误用）
        if (command.contains(";") || command.contains("&") || command.contains("|") ||
                command.contains("`") || command.contains("$") || command.contains("(") ||
                command.contains(")") || command.contains("<") || command.contains(">")) {
            return buildBlockedResult(command, "Blocked: 命令中包含危险字符");
        }

        // SAFE：按空白拆分为参数数组（本项目只需要覆盖 ping/ls/grep/cat 的常见形态）
        String[] parts = command.trim().split("\\s+");
        if (parts.length == 0) {
            return buildBlockedResult(command, "Blocked: 空命令");
        }
        return executeArgs(parts);
    }

    private Map<String, Object> executeShell(String command) {
        long startTime = System.currentTimeMillis();
        try {
            ProcessBuilder pb;
            String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
            if (os.contains("win")) {
                pb = new ProcessBuilder("cmd.exe", "/c", command);
            } else {
                pb = new ProcessBuilder("/bin/sh", "-c", command);
            }
            pb.directory(new File(LAB_DIR));
            pb.redirectErrorStream(true);
            Process process = pb.start();

            if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                long tookMs = System.currentTimeMillis() - startTime;
                return buildResult(command, -1, "", "Command timeout", tookMs);
            }

            int exitCode = process.exitValue();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder stdout = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                stdout.append(line).append("\n");
                if (stdout.length() > MAX_OUTPUT_LENGTH) {
                    stdout.setLength(MAX_OUTPUT_LENGTH);
                    stdout.append("\n... (output truncated)");
                    break;
                }
            }
            reader.close();
            long tookMs = System.currentTimeMillis() - startTime;
            return buildResult(command, exitCode, stdout.toString(), "", tookMs);
        } catch (Exception e) {
            long tookMs = System.currentTimeMillis() - startTime;
            return buildResult(command, -1, "", "Error: " + e.getMessage(), tookMs);
        }
    }

    private Map<String, Object> executeArgs(String... args) {
        long startTime = System.currentTimeMillis();
        try {
            ProcessBuilder pb = new ProcessBuilder(args);
            pb.directory(new File(LAB_DIR));
            pb.redirectErrorStream(true);
            Process process = pb.start();

            if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                long tookMs = System.currentTimeMillis() - startTime;
                return buildResult(String.join(" ", args), -1, "", "Command timeout", tookMs);
            }

            int exitCode = process.exitValue();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder stdout = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                stdout.append(line).append("\n");
                if (stdout.length() > MAX_OUTPUT_LENGTH) {
                    stdout.setLength(MAX_OUTPUT_LENGTH);
                    stdout.append("\n... (output truncated)");
                    break;
                }
            }
            reader.close();
            long tookMs = System.currentTimeMillis() - startTime;
            return buildResult(String.join(" ", args), exitCode, stdout.toString(), "", tookMs);
        } catch (Exception e) {
            long tookMs = System.currentTimeMillis() - startTime;
            return buildResult(String.join(" ", args), -1, "", "Error: " + e.getMessage(), tookMs);
        }
    }

    private Map<String, Object> executePingSafe(String host) {
        long startTime = System.currentTimeMillis();
        try {
            ProcessBuilder processBuilder = new ProcessBuilder("ping", "-c", "1", host);
            processBuilder.directory(new File(LAB_DIR)); // 设置工作目录为 lab
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();

            if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                long tookMs = System.currentTimeMillis() - startTime;
                return buildResult("ping -c 1 " + host, -1, "", "Command timeout", tookMs);
            }

            int exitCode = process.exitValue();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder stdout = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                stdout.append(line).append("\n");
                if (stdout.length() > MAX_OUTPUT_LENGTH) {
                    stdout.setLength(MAX_OUTPUT_LENGTH);
                    stdout.append("\n... (output truncated)");
                    break;
                }
            }
            reader.close();

            long tookMs = System.currentTimeMillis() - startTime;
            return buildResult("ping -c 1 " + host, exitCode, stdout.toString(), "", tookMs);

        } catch (Exception e) {
            long tookMs = System.currentTimeMillis() - startTime;
            return buildResult("ping -c 1 " + host, -1, "", "Error: " + e.getMessage(), tookMs);
        }
    }

    public static Map<String, Object> buildResult(String cmdBuilt, int exitCode, String stdout, String stderr, long tookMs) {
        Map<String, Object> result = new HashMap<>();
        result.put("cmdBuilt", cmdBuilt);
        result.put("exitCode", exitCode);
        result.put("stdoutPreview", stdout);
        result.put("stderrPreview", stderr);
        result.put("tookMs", tookMs);
        result.put("blocked", false);
        result.put("timestamp", System.currentTimeMillis());
        return result;
    }
    
    public static Map<String, Object> buildBlockedResult(String cmdBuilt, String reason) {
        Map<String, Object> result = new HashMap<>();
        result.put("cmdBuilt", cmdBuilt);
        result.put("exitCode", -1);
        result.put("stdoutPreview", "");
        result.put("stderrPreview", reason);
        result.put("tookMs", 0L);
        result.put("blocked", true);
        result.put("blockedReason", reason);
        result.put("timestamp", System.currentTimeMillis());
        return result;
    }

    private static class LevelConfig {
        final String blockedPattern;
        final String description;
        final Pattern pattern;

        LevelConfig(String blockedPattern, String description) {
            this.blockedPattern = blockedPattern;
            this.description = description;
            this.pattern = blockedPattern.isEmpty() ? null : Pattern.compile(blockedPattern);
        }

        CheckResult check(String input) {
            if (pattern == null) {
                return new CheckResult(false, null);
            }

            if (pattern.matcher(input).find()) {
                return new CheckResult(true, "Blocked: " + description);
            }

            return new CheckResult(false, null);
        }

        String transform(String input) {
            if (blockedPattern.contains("\\s")) {
                return input.replaceAll("\\s", "");
            }
            return input;
        }
    }

    private static class CheckResult {
        final boolean blocked;
        final String reason;

        CheckResult(boolean blocked, String reason) {
            this.blocked = blocked;
            this.reason = reason;
        }

        boolean isBlocked() {
            return blocked;
        }

        String getReason() {
            return reason;
        }
    }
    
    /**
     * 单次 URL 解码
     * 
     * @param input 输入字符串
     * @return 解码后的字符串
     */
    private static String decodeUrlOnce(String input) {
        if (input == null) {
            return null;
        }
        
        // 处理常见的 URL 编码
        String result = input
            .replace("%20", " ")
            .replace("%3B", ";")
            .replace("%26", "&")
            .replace("%7C", "|")
            .replace("%2F", "/")
            .replace("%2E", ".")
            .replace("%2D", "-")
            .replace("%25", "%")  // 处理 %25（% 的编码）
            .replace("%3A", ":")
            .replace("%40", "@")
            .replace("%23", "#")
            .replace("%3F", "?");
        
        return result;
    }
}
