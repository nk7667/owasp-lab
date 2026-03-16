package org.owasplab.config;

import org.owasplab.entity.News;
import org.owasplab.entity.User;
import org.owasplab.repository.NewsRepository;
import org.owasplab.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import javax.persistence.EntityManager;
import java.time.LocalDateTime;

@Component
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final NewsRepository newsRepository;
    private final EntityManager entityManager;

    public DataInitializer(UserRepository userRepository,
                           PasswordEncoder passwordEncoder,
                           NewsRepository newsRepository,
                           EntityManager entityManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.newsRepository = newsRepository;
        this.entityManager = entityManager;
    }
    @Override
    @Transactional
    public void run(String... args) {
        // users：只在空库时初始化
        if (userRepository.count() == 0) {
            userRepository.save(new User("admin",passwordEncoder.encode("admin123"), "admin@owasp-lab.local", "admin", "flag{admin_secret}"));
            userRepository.save(new User("john", passwordEncoder.encode("password123"), "john@example.com", "user", "flag{user_john}"));
            userRepository.save(new User("jane", passwordEncoder.encode("qwerty"), "jane@example.com", "user", "flag{user_jane}"));
            // 为 ORDER BY / LIMIT 关卡准备更多 user 数据（默认 LIMIT 3 才有“边界”可绕过）
            userRepository.save(new User("bob", passwordEncoder.encode("bob123"), "bob@example.com", "user", "flag{user_bob}"));
            userRepository.save(new User("alice", passwordEncoder.encode("alice123"), "alice@example.com", "user", "flag{user_alice}"));
            userRepository.save(new User("tom", passwordEncoder.encode("tom123"), "tom@example.com", "user", "flag{user_tom}"));
            userRepository.save(new User("lucy", passwordEncoder.encode("lucy123"), "lucy@example.com", "user", "flag{user_lucy}"));
            userRepository.save(new User("mark", passwordEncoder.encode("mark123"), "mark@example.com", "user", "flag{user_mark}"));
            System.out.println("[DataInitializer] 已初始化 users：admin + 7 个 user（john/jane/bob/alice/tom/lucy/mark）");
        }

        // news：只在空库时初始化（为 news_union_users 链路准备“公开/隐藏”）
        if (newsRepository.count() == 0) {
            LocalDateTime now = LocalDateTime.now();
            // public
            newsRepository.save(new News("【公开】系统公告：欢迎来到 OWASP Lab",
                    "这里是公开新闻。目标：默认只能看到公开内容。",
                    true, 1L, now.minusDays(2)));
            newsRepository.save(new News("【公开】新闻 1：输入校验与注入",
                    "LIKE 查询里把用户输入拼 SQL，会导致结构被改写。",
                    true, 1L, now.minusDays(1)));
            newsRepository.save(new News("【公开】新闻 2：排序与分页边界",
                    "ORDER BY/LIMIT 属于结构片段，不能靠参数化占位符解决。",
                    true, 1L, now.minusHours(20)));
            newsRepository.save(new News("【公开】新闻 3：错误回显与信号通道",
                    "吞错/回显/响应差异，都会成为攻击者的信号。",
                    true, 1L, now.minusHours(10)));
            newsRepository.save(new News("【公开】新闻 4：安全实现要点",
                    "参数化 + allowlist + 固定边界 + 统一错误处理。",
                    true, 1L, now.minusHours(2)));

            // hidden（成功信号：能看到这些标题）
            newsRepository.save(new News("【隐藏】草稿：内部账号线索（仅管理员可见）",
                    "如果你能看到这条，说明你已经绕过了 is_public=true 的边界。",
                    false, 1L, now.minusHours(1)));
            newsRepository.save(new News("【隐藏】TODO：下一步尝试 UNION 跨表",
                    "提示：把 users.username/email 通过 UNION 映射到 title/snippet 回显列。",
                    false, 1L, now));

            System.out.println("[DataInitializer] 已初始化 news：5 条公开 + 2 条隐藏");
        }
        // vw_accounts：为 news_adv_func_view（难度2）准备视图与别名字段
        try {
            entityManager.createNativeQuery("DROP VIEW IF EXISTS vw_accounts").executeUpdate();

            entityManager.createNativeQuery(
                    "CREATE VIEW vw_accounts(alias_username, alias_email, alias_created_at) " +
                            "AS SELECT username, email, CAST(CURRENT_TIMESTAMP AS TIMESTAMP) FROM users"
            ).executeUpdate();

            System.out.println("[DataInitializer] 已创建视图 vw_accounts(alias_username, alias_email, alias_created_at)");
        } catch (Exception e) {
            System.out.println("[DataInitializer] 创建视图 vw_accounts 失败: " + e.getMessage());
        }

        // 时间盲注关卡已经在 Java 层使用 Thread.sleep 固定延迟，不再强依赖 H2 的 SLEEP 别名。
        // 这里不额外创建数据库函数，以避免在不同 JDK/H2 版本上因重载解析差异导致启动失败。
    }
}
