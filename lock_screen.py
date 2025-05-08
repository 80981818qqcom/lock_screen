import tkinter as tk
from tkinter import messagebox
import keyboard
import threading
import sys
import ctypes
import os
import time
from ctypes import wintypes
import win32con
import win32gui
import win32api
import winreg
import psutil
import configparser
import logging
import traceback
from datetime import datetime

# 配置文件路径
CONFIG_FILE = "lockscreen_config.ini"
# 日志目录
LOG_DIR = "logs"
# 日志文件路径 - 使用日期命名
LOG_FILE = os.path.join(LOG_DIR, f"lockscreen_{datetime.now().strftime('%Y%m%d')}.log")

# 设置日志记录器
def setup_logger():
    """配置日志记录器"""
    # 创建日志目录
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
        
    # 配置根日志记录器
    logger = logging.getLogger('lockscreen')
    logger.setLevel(logging.DEBUG)
    
    # 清除已有的处理器
    if logger.handlers:
        logger.handlers.clear()
    
    # 检查是否启用日志记录
    enable_logging = True
    try:
        # 检查配置文件中的日志开关设置
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE, encoding='utf-8')
        if 'Security' in config and 'enablelogging' in config['Security']:
            enable_logging = config['Security']['enablelogging'].lower() == 'yes'
    except Exception:
        # 配置文件读取失败，默认启用日志
        enable_logging = True
    
    # 如果禁用日志，则只添加一个NULL处理器
    if not enable_logging:
        null_handler = logging.NullHandler()
        logger.addHandler(null_handler)
        return logger
    
    # 创建文件处理器，使用日期命名的日志文件
    file_handler = logging.FileHandler(LOG_FILE, 'a', 'utf-8')
    file_handler.setLevel(logging.DEBUG)
    
    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # 设置格式化器
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(funcName)s:%(lineno)d] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # 添加处理器到日志记录器
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# 创建全局日志记录器
logger = setup_logger()

# 定义错误处理装饰器
def log_exceptions(func):
    """装饰器，用于捕获和记录函数中的异常"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # 获取详细的异常堆栈
            error_details = traceback.format_exc()
            # 记录错误
            logger.error(f"函数 {func.__name__} 执行出错: {str(e)}\n{error_details}")
            # 根据函数名确定是否是关键函数，如果是则可能需要特殊处理
            if func.__name__ in ['start', 'check_password', 'monitor_window_visibility']:
                logger.critical(f"关键功能 {func.__name__} 失败，这可能会导致锁屏不稳定")
            return None
    return wrapper

# 全局快捷键处理函数
def global_hook_handler(event):
    """全局键盘钩子函数，用于捕获Alt+F4等系统组合键"""
    return False  # 阻止所有按键事件传递

class LockScreen:
    def __init__(self, config_file=CONFIG_FILE):
        try:
            logger.info("===== 锁屏程序启动 =====")
            # 记录操作系统信息
            logger.info(f"操作系统: {os.name}, 版本: {sys.platform}")
            if os.name == 'nt':
                try:
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                    logger.info(f"管理员权限: {'是' if is_admin else '否'}")
                except Exception as e:
                    logger.warning(f"无法检查管理员权限: {e}")
            
            # 加载配置和密码
            self.config_file = config_file
            logger.info(f"使用配置文件: {self.config_file}")
            self.password = self.load_password()
            
            self.locked = False
            self.stop_flag = False
            self.input_allowed = False  # 控制是否允许输入
            self.key_monitor_thread = None
            
            # 先注册全局快捷键拦截
            logger.info("注册全局快捷键拦截")
            self.register_global_hotkeys()
            
            # 所有阻止的单个按键
            self.blocked_keys = [
                'alt', 'tab', 'win', 'esc', 'delete', 
                'f4', 'f1', 'f2', 'f3', 'f5', 'f6', 'f7', 'f8', 'f9', 'f10', 'f11', 'f12'
            ]
            
            # 创建主窗口
            logger.info("创建主窗口")
            self.root = tk.Tk()
            self.root.attributes("-fullscreen", True)
            self.root.attributes("-topmost", True)
            self.root.protocol("WM_DELETE_WINDOW", self.disable_close)
            self.root.title("锁屏")
            
            # 设置背景颜色
            self.root.configure(bg="#2c3e50")
            
            # 创建界面元素
            self.create_widgets()
            
            # 在Windows系统上禁用输入和任务管理器
            if os.name == 'nt':
                try:
                    # 禁用任务管理器
                    logger.info("尝试禁用任务管理器")
                    self.disable_task_manager_registry()
                except Exception as e:
                    logger.error(f"禁用任务管理器失败: {e}")
                
                # 设置其他锁定
                logger.info("设置全局锁定")
                self.setup_global_lock()

                # 创建窗口隐藏监视器
                logger.info("创建窗口监视器")
                self.create_window_hide_monitor()
                
            # 绑定键盘事件到主窗口
            self.root.bind("<Key>", self.on_root_key)
            self.root.bind("<Alt-F4>", self.on_alt_f4)
            self.root.bind("<Alt-Tab>", self.on_alt_tab)
            self.root.bind("<Control-Escape>", self.on_ctrl_esc)
            self.root.bind("<Control-Alt-Delete>", self.on_ctrl_alt_del)
            
        except Exception as e:
            logger.critical(f"初始化锁屏程序时发生严重错误: {e}\n{traceback.format_exc()}")
            raise

    @log_exceptions
    def register_global_hotkeys(self):
        """注册全局快捷键拦截"""
        # 使用keyboard库注册全局钩子
        keyboard.hook(global_hook_handler)
        
        # 明确阻止Windows系统常用组合键
        try:
            # Windows常用系统组合键
            windows_hotkeys = [
                'alt+tab', 'alt+f4', 'ctrl+alt+del', 'ctrl+shift+esc',
                'win+d', 'win+e', 'win+r', 'win+l', 'alt+esc', 'alt+space',
                'win+tab', 'win+up', 'win+down', 'win+left', 'win+right',
                'win+home', 'win+m', 'win+1', 'win+2', 'win+3', 'win+4',
                'win+5', 'win+6', 'win+7', 'win+8', 'win+9', 'win+0',
                'alt+enter', 'ctrl+esc', 'win+break', 'win+pause',
                'win+x', 'win+i', 'win+a', 'win+g', 'win+k', 'win+p',
                'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'f10', 'f11', 'f12'
            ]
            
            # 浏览器常用组合键
            browser_hotkeys = [
                'ctrl+t', 'ctrl+w', 'ctrl+n', 'ctrl+shift+n', 'ctrl+f5', 
                'alt+f', 'alt+e', 'alt+v', 'alt+h', 'ctrl+shift+t'
            ]
            
            # 文本编辑常用组合键
            editor_hotkeys = [
                'ctrl+c', 'ctrl+x', 'ctrl+v', 'ctrl+z', 'ctrl+y',
                'ctrl+a', 'ctrl+s', 'ctrl+f', 'ctrl+p', 'ctrl+o',
                'ctrl+b', 'ctrl+i', 'ctrl+u'
            ]
            
            # 系统控制组合键
            system_hotkeys = [
                'ctrl+alt+arrow_up', 'ctrl+alt+arrow_down', 
                'ctrl+alt+arrow_left', 'ctrl+alt+arrow_right',
                'alt+print_screen', 'win+print_screen', 'ctrl+shift+tab'
            ]
            
            # 单个修饰键
            modifier_keys = [
                'alt', 'ctrl', 'shift', 'win', 'left alt', 'right alt',
                'left ctrl', 'right ctrl', 'left shift', 'right shift'
            ]
            
            # 合并所有需要屏蔽的组合键
            all_hotkeys = windows_hotkeys + browser_hotkeys + editor_hotkeys + system_hotkeys
            
            # 阻止所有组合键
            for hotkey in all_hotkeys:
                try:
                    keyboard.add_hotkey(hotkey, lambda: None, suppress=True)
                except Exception as e:
                    logger.error(f"无法阻止组合键 {hotkey}: {e}")
            
            # 阻止所有修饰键
            for key in modifier_keys:
                try:
                    keyboard.block_key(key)
                except Exception as e:
                    logger.error(f"无法阻止修饰键 {key}: {e}")
                    
            # 阻止功能键
            for i in range(1, 13):
                keyboard.block_key(f'f{i}')
            
            logger.info("已注册全部快捷键拦截")
                
        except Exception as e:
            logger.error(f"注册全局快捷键失败: {e}\n{traceback.format_exc()}")
            
    @log_exceptions
    def handle_system_hotkey(self, event=None, hotkey_name=""):
        """统一处理系统热键事件"""
        logger.debug(f"捕获到系统热键: {hotkey_name}")
        self.root.focus_force()
        return "break"  # 阻止事件传递
        
    @log_exceptions
    def on_alt_f4(self, event=None):
        """处理Alt+F4组合键"""
        return self.handle_system_hotkey(event, "Alt+F4")
        
    @log_exceptions
    def on_alt_tab(self, event=None):
        """处理Alt+Tab组合键"""
        return self.handle_system_hotkey(event, "Alt+Tab")
        
    @log_exceptions
    def on_ctrl_esc(self, event=None):
        """处理Ctrl+Esc组合键"""
        return self.handle_system_hotkey(event, "Ctrl+Esc")
        
    @log_exceptions
    def on_ctrl_alt_del(self, event=None):
        """处理Ctrl+Alt+Del组合键"""
        return self.handle_system_hotkey(event, "Ctrl+Alt+Del")
        
    @log_exceptions
    def on_root_key(self, event):
        """主窗口键盘事件处理"""
        # 获取当前焦点控件
        focused = self.root.focus_get()
        
        # 只允许在密码框内输入
        if focused == self.pw_entry:
            return  # 允许正常处理
            
        # 阻止所有其他键盘输入
        return "break"  # 阻止事件传递
    
    @log_exceptions
    def disable_task_manager_registry(self):
        """尝试通过注册表禁用任务管理器（需要管理员权限）"""
        try:
            try:
                # 方法1: 直接创建和设置HKCU策略路径
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
                registry_key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(registry_key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
                winreg.CloseKey(registry_key)
                logger.info("已禁用任务管理器(方法1)")
                return True
            except Exception as e:
                logger.warning(f"方法1失败: {e}")
                
            try:
                # 方法2: 尝试禁用HKLM策略路径
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
                registry_key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(registry_key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
                winreg.CloseKey(registry_key)
                logger.info("已禁用任务管理器(方法2)")
                return True
            except Exception as e:
                logger.warning(f"方法2失败: {e}")
                
            try:
                # 方法3: 使用Group Policy路径
                key_path = r"Software\Policies\Microsoft\Windows\System"
                registry_key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(registry_key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
                winreg.CloseKey(registry_key)
                logger.info("已禁用任务管理器(方法3)")
                return True
            except Exception as e:
                logger.warning(f"方法3失败: {e}")
            
            # 如果注册表方法都失败，我们将使用进程监控来替代
            logger.warning("所有注册表方法都失败，将使用进程监控来防止任务管理器")
            return False
        except Exception as e:
            logger.error(f"禁用任务管理器失败: {e}\n{traceback.format_exc()}")
            return False
            
    @log_exceptions
    def enable_task_manager_registry(self):
        """重新启用任务管理器"""
        try:
            # 尝试恢复所有可能的注册表路径
            try:
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
                registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(registry_key, "DisableTaskMgr", 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(registry_key)
                logger.debug("已恢复HKCU任务管理器注册表项")
            except Exception as e:
                logger.debug(f"恢复HKCU任务管理器注册表项失败: {e}")
                
            try:
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
                registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(registry_key, "DisableTaskMgr", 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(registry_key)
                logger.debug("已恢复HKLM任务管理器注册表项")
            except Exception as e:
                logger.debug(f"恢复HKLM任务管理器注册表项失败: {e}")
                
            try:
                key_path = r"Software\Policies\Microsoft\Windows\System"
                registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(registry_key, "DisableTaskMgr", 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(registry_key)
                logger.debug("已恢复Group Policy任务管理器注册表项")
            except Exception as e:
                logger.debug(f"恢复Group Policy任务管理器注册表项失败: {e}")
                
            return True
        except Exception as e:
            logger.error(f"恢复任务管理器权限失败: {e}")
            return False
    
    @log_exceptions
    def create_window_hide_monitor(self):
        """创建一个线程监视窗口是否被隐藏或最小化"""
        self.start_time = time.time()  # 记录开始时间
        logger.info("创建窗口隐藏监视线程")
        self.hide_monitor = threading.Thread(target=self.monitor_window_visibility, daemon=True)
        self.hide_monitor.start()
        
        # 启动一个线程专门监控Alt+F4组合键
        logger.info("创建Alt+F4监视线程")
        self.alt_f4_monitor = threading.Thread(target=self.monitor_alt_f4, daemon=True)
        self.alt_f4_monitor.start()
    
    @log_exceptions
    def monitor_window_visibility(self):
        """监视窗口是否被隐藏，如果是则立即恢复"""
        try:
            logger.info("启动窗口可见性监控")
            while not self.stop_flag:
                try:
                    # 检查窗口是否可见
                    hwnd = self.get_window_handle()
                    if hwnd:
                        # 如果窗口不可见或最小化
                        if not win32gui.IsWindowVisible(hwnd) or win32gui.IsIconic(hwnd):
                            # 恢复窗口
                            logger.warning("检测到窗口被隐藏，正在恢复")
                            self.ensure_window_focus()
                
                    # 杀死任务管理器等系统进程
                    self.kill_system_processes()
                    
                    # 动态调整扫描频率 - 起初快速扫描
                    scan_interval = 0.1
                    # 每10秒后逐渐减慢至0.5秒，减少CPU使用率
                    if hasattr(self, 'start_time') and time.time() - self.start_time > 10:
                        scan_interval = 0.5
                    
                    time.sleep(scan_interval)
                except Exception as e:
                    logger.error(f"窗口可见性监控循环出错: {e}")
                    time.sleep(0.2)
        except Exception as e:
            logger.critical(f"窗口可见性监控线程崩溃: {e}\n{traceback.format_exc()}")
    
    @log_exceptions
    def kill_system_processes(self):
        """尝试杀死任务管理器等系统进程"""
        try:
            # 系统管理类进程
            target_processes = [
                "taskmgr.exe", "Taskmgr.exe", "ProcessHacker.exe", 
                "procexp.exe", "procexp64.exe", "perfmon.exe",
                "resmon.exe", "mmc.exe", "regedit.exe", "cmd.exe",
                "powershell.exe", "WindowsPowerShell.exe", "RegEdit.exe"
            ]
            
            # 配置文件中检查是否需要终止危险进程
            kill_dangerous = True
            try:
                config = configparser.ConfigParser()
                config.read(self.config_file, encoding='utf-8')
                if 'Security' in config and 'killdangerousprocesses' in config['Security']:
                    kill_dangerous = config['Security']['killdangerousprocesses'].lower() == 'yes'
            except Exception:
                pass  # 使用默认设置
            
            # 如果不需要终止进程，直接返回
            if not kill_dangerous:
                return
            
            # 尝试杀死系统管理进程
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] in target_processes:
                    try:
                        proc_obj = psutil.Process(proc.info['pid'])
                        # 确保不是我们自己的进程
                        if proc_obj.pid != os.getpid():
                            proc_obj.kill()
                            logger.info(f"已终止进程: {proc.info['name']}")
                    except Exception as e:
                        logger.debug(f"无法终止进程 {proc.info['name']}: {e}")
                        
            # 检测当前是否有其他窗口获取焦点
            if os.name == 'nt':
                try:
                    hwnd = self.get_window_handle()
                    focused_hwnd = win32gui.GetForegroundWindow()
                    
                    if hwnd and focused_hwnd != hwnd:
                        # 如果其他窗口获取了焦点，立即恢复我们的窗口
                        logger.warning("检测到其他窗口获得焦点，重新获取焦点")
                        self.ensure_window_focus()
                except Exception as e:
                    logger.debug(f"焦点检查错误: {e}")
                    
        except Exception as e:
            logger.error(f"监控进程失败: {e}\n{traceback.format_exc()}")
    
    @log_exceptions
    def create_widgets(self):
        logger.info("创建UI界面元素")
        # 创建标题标签
        title_label = tk.Label(
            self.root, 
            text="系统已锁定", 
            font=("Arial", 24, "bold"),
            bg="#2c3e50",
            fg="white"
        )
        title_label.pack(pady=(100, 20))
        
        # 创建说明标签
        info_label = tk.Label(
            self.root, 
            text="请输入密码解锁系统", 
            font=("Arial", 14),
            bg="#2c3e50",
            fg="white"
        )
        info_label.pack(pady=(0, 40))
        
        # 创建密码输入框
        pw_frame = tk.Frame(self.root, bg="#2c3e50")
        pw_frame.pack(pady=10)
        
        pw_label = tk.Label(
            pw_frame, 
            text="密码:", 
            font=("Arial", 12),
            bg="#2c3e50",
            fg="white"
        )
        pw_label.grid(row=0, column=0, padx=5)
        
        # 创建密码输入框
        self.pw_entry = tk.Entry(pw_frame, show="*", font=("Arial", 12), width=20)
        self.pw_entry.grid(row=0, column=1, padx=5)
        self.pw_entry.bind("<Return>", self.check_password)
        self.pw_entry.bind("<FocusIn>", self.on_entry_focus)
        self.pw_entry.bind("<FocusOut>", self.on_entry_unfocus)
        
        # 将焦点设置到密码输入框
        self.pw_entry.focus_set()
        self.input_allowed = True  # 初始允许输入
        
        # 创建解锁按钮
        unlock_button = tk.Button(
            self.root,
            text="解锁",
            font=("Arial", 12),
            command=self.check_password,
            bg="#3498db",
            fg="white",
            activebackground="#2980b9",
            width=10
        )
        unlock_button.pack(pady=10)
        
        # 添加虚拟键盘支持
        self.create_virtual_keyboard()
        
        # 提示正在运行锁屏状态
        status_label = tk.Label(
            self.root,
            text="锁屏程序正在运行，组合键已被禁用",
            font=("Arial", 10),
            bg="#2c3e50", 
            fg="#95a5a6"
        )
        status_label.pack(side=tk.BOTTOM, pady=5)
        
        # 阻止Alt+F4和其他系统快捷键
        self.root.bind("<Alt-F4>", lambda e: "break")
        self.root.bind("<Alt-Tab>", lambda e: "break")
        self.root.bind("<Control-Escape>", lambda e: "break")
        self.root.bind("<Control-Alt-Delete>", lambda e: "break")
        
        # 定期将窗口置顶（防止被其他窗口覆盖）
        self.keep_on_top()
        
        # 设置窗口在接收到WM_DELETE_WINDOW消息时的行为
        self.root.protocol("WM_DELETE_WINDOW", self.disable_close)
    
    def create_virtual_keyboard(self):
        """创建简单的虚拟键盘"""
        keyboard_frame = tk.Frame(self.root, bg="#2c3e50")
        keyboard_frame.pack(pady=20)
        
        # 数字按键
        numbers = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0']
        num_frame = tk.Frame(keyboard_frame, bg="#2c3e50")
        num_frame.pack(pady=5)
        
        for i, num in enumerate(numbers):
            btn = tk.Button(
                num_frame, 
                text=num, 
                width=3, 
                height=1, 
                font=("Arial", 10),
                command=lambda n=num: self.virtual_key_press(n),
                bg="#34495e",
                fg="white"
            )
            btn.grid(row=0, column=i, padx=2, pady=2)
        
        # 字母按键（第一行）
        letters1 = ['q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p']
        letters_frame1 = tk.Frame(keyboard_frame, bg="#2c3e50")
        letters_frame1.pack(pady=2)
        
        for i, letter in enumerate(letters1):
            btn = tk.Button(
                letters_frame1, 
                text=letter, 
                width=3, 
                height=1, 
                font=("Arial", 10),
                command=lambda l=letter: self.virtual_key_press(l),
                bg="#34495e",
                fg="white"
            )
            btn.grid(row=0, column=i, padx=2, pady=2)
            
        # 字母按键（第二行）
        letters2 = ['a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l']
        letters_frame2 = tk.Frame(keyboard_frame, bg="#2c3e50")
        letters_frame2.pack(pady=2)
        
        for i, letter in enumerate(letters2):
            btn = tk.Button(
                letters_frame2, 
                text=letter, 
                width=3, 
                height=1, 
                font=("Arial", 10),
                command=lambda l=letter: self.virtual_key_press(l),
                bg="#34495e",
                fg="white"
            )
            btn.grid(row=0, column=i, padx=2, pady=2)
            
        # 字母按键（第三行）
        letters3 = ['z', 'x', 'c', 'v', 'b', 'n', 'm']
        letters_frame3 = tk.Frame(keyboard_frame, bg="#2c3e50")
        letters_frame3.pack(pady=2)
        
        for i, letter in enumerate(letters3):
            btn = tk.Button(
                letters_frame3, 
                text=letter, 
                width=3, 
                height=1, 
                font=("Arial", 10),
                command=lambda l=letter: self.virtual_key_press(l),
                bg="#34495e",
                fg="white"
            )
            btn.grid(row=0, column=i, padx=2, pady=2)
        
        # 清除按钮和退格按钮
        control_frame = tk.Frame(keyboard_frame, bg="#2c3e50")
        control_frame.pack(pady=5)
        
        clear_btn = tk.Button(
            control_frame, 
            text="清除", 
            width=8, 
            height=1, 
            font=("Arial", 10),
            command=self.clear_password,
            bg="#e74c3c",
            fg="white"
        )
        clear_btn.grid(row=0, column=0, padx=5)
        
        backspace_btn = tk.Button(
            control_frame, 
            text="退格", 
            width=8, 
            height=1, 
            font=("Arial", 10),
            command=self.backspace,
            bg="#e67e22",
            fg="white"
        )
        backspace_btn.grid(row=0, column=1, padx=5)
        
        # 空格键
        space_btn = tk.Button(
            control_frame,
            text="空格",
            width=8,
            height=1,
            font=("Arial", 10),
            command=lambda: self.virtual_key_press(' '),
            bg="#3498db",
            fg="white"
        )
        space_btn.grid(row=0, column=2, padx=5)
    
    def virtual_key_press(self, key):
        """处理虚拟键盘按键"""
        current = self.pw_entry.get()
        self.pw_entry.delete(0, tk.END)
        self.pw_entry.insert(0, current + key)
    
    def clear_password(self):
        """清除密码框内容"""
        self.pw_entry.delete(0, tk.END)
    
    def backspace(self):
        """删除最后一个字符"""
        current = self.pw_entry.get()
        if current:
            self.pw_entry.delete(0, tk.END)
            self.pw_entry.insert(0, current[:-1])
    
    def on_entry_focus(self, event):
        """当密码框获得焦点时"""
        self.input_allowed = True
    
    def on_entry_unfocus(self, event):
        """当密码框失去焦点时"""
        self.input_allowed = False
        # 重新获取焦点，确保用户可以继续输入
        self.pw_entry.focus_set()
    
    @log_exceptions
    def ensure_window_focus(self):
        """强制获取和保持窗口焦点的统一方法"""
        try:
            # 强制窗口置顶
            self.root.lift()
            self.root.attributes('-topmost', True)
            self.root.update()
            
            # 确保窗口可见且全屏
            self.root.deiconify()
            self.root.attributes("-fullscreen", True)
            
            # 强制获取焦点
            self.root.focus_force()
            
            # 确保密码框获得焦点
            self.pw_entry.focus_set()
            
            # 如果是Windows系统，使用Win32API额外确保窗口为前台窗口
            if os.name == 'nt':
                hwnd = self.get_window_handle()
                if hwnd and win32gui.IsWindow(hwnd):
                    # 如果不是当前前台窗口，设置为前台窗口
                    if win32gui.GetForegroundWindow() != hwnd:
                        win32gui.SetForegroundWindow(hwnd)
                        
            return True
        except Exception as e:
            logger.error(f"获取窗口焦点失败: {e}")
            return False

    def keep_on_top(self):
        """定期保持窗口置顶"""
        if self.locked and not self.stop_flag:
            # 使用统一的焦点管理方法
            self.ensure_window_focus()
            
            # 每隔100毫秒调用一次
            self.root.after(100, self.keep_on_top)
    
    @log_exceptions
    def monitor_alt_f4(self):
        """专门监控Alt+F4组合键"""
        logger.info("Alt+F4监控线程启动")
        while not self.stop_flag:
            try:
                # 检测Alt键和F4键是否同时按下
                alt_pressed = win32api.GetAsyncKeyState(win32con.VK_MENU) & 0x8000 != 0
                f4_pressed = win32api.GetAsyncKeyState(win32con.VK_F4) & 0x8000 != 0
                
                if alt_pressed and f4_pressed:
                    logger.info("检测到Alt+F4组合键，阻止关闭窗口")
                    # 使用统一的焦点管理方法
                    self.ensure_window_focus()
                
                time.sleep(0.05)
            except Exception as e:
                logger.error(f"Alt+F4监控出错: {e}")
                time.sleep(0.2)
        logger.info("Alt+F4监控线程结束")

    def get_window_handle(self):
        """获取当前Tkinter窗口的句柄"""
        if os.name == 'nt':
            try:
                return win32gui.FindWindow(None, self.root.title())
            except:
                return None
        return None
    
    @log_exceptions
    def check_password(self, event=None):
        entered_password = self.pw_entry.get()
        logger.info(f"尝试解锁，密码长度: {len(entered_password)}")
        
        if entered_password == self.password:
            logger.info("密码正确，解锁成功")
            self.locked = False
            self.stop_flag = True
            messagebox.showinfo("成功", "解锁成功！")
            
            self.release_locks()
            self.root.destroy()
        else:
            logger.warning(f"密码错误，用户输入: {entered_password[:1]}***")
            messagebox.showerror("错误", "密码错误，请重试！")
            self.pw_entry.delete(0, tk.END)
            self.pw_entry.focus_set()
    
    def disable_close(self):
        """禁用关闭窗口按钮"""
        # 不做任何事情，阻止窗口关闭
        return "break"
    
    def setup_global_lock(self):
        """设置全局输入锁定"""
        # 使用keyboard库阻止常用快捷键
        self.block_keyboard_shortcuts()
        
        # 启动持续监视Ctrl+Alt+Del和其他组合键的线程
        self.key_monitor_thread = threading.Thread(target=self.monitor_key_combinations, daemon=True)
        self.key_monitor_thread.start()
        
        # 创建鼠标钩子线程来阻止窗口外的点击
        self.mouse_watcher = threading.Thread(target=self.monitor_mouse, daemon=True)
        self.mouse_watcher.start()
        
        # 添加Windows消息钩子（仅Windows系统）
        if os.name == 'nt':
            # 在主窗口中截获按键
            self.root.bind("<KeyPress>", self.on_key_press, add="+")
            
            # 捕获所有常用组合键
            self.bind_all_common_hotkeys()
            
            # 捕获所有键盘事件
            self.root.bind_all("<KeyPress>", self.on_all_keys)
            
    def bind_all_common_hotkeys(self):
        """绑定所有常用组合键，确保它们被阻止"""
        # 阻止Alt系列组合键
        alt_combos = ["<Alt-Tab>", "<Alt-F4>", "<Alt-Escape>", "<Alt-space>", 
                     "<Alt-F>", "<Alt-E>", "<Alt-V>", "<Alt-H>", "<Alt-Enter>"]
        
        # 阻止Ctrl系列组合键
        ctrl_combos = ["<Control-c>", "<Control-v>", "<Control-x>", "<Control-z>", 
                      "<Control-a>", "<Control-s>", "<Control-o>", "<Control-p>",
                      "<Control-t>", "<Control-w>", "<Control-n>", "<Control-f>"]
        
        # 阻止Win系列组合键 (Tkinter中通常不能直接捕获Win键)
        # 但可以尝试一些常见的组合
        
        # 功能键阻止
        function_keys = [f"<F{i}>" for i in range(1, 13)]
        
        # 阻止Ctrl+Alt系列组合
        ctrl_alt_combos = ["<Control-Alt-Delete>", "<Control-Alt-Tab>", 
                          "<Control-Alt-Escape>"]
        
        # 阻止Ctrl+Shift系列组合
        ctrl_shift_combos = ["<Control-Shift-Escape>", "<Control-Shift-Tab>", 
                            "<Control-Shift-n>", "<Control-Shift-t>"]
        
        # 合并所有组合键并进行绑定
        all_combos = alt_combos + ctrl_combos + function_keys + ctrl_alt_combos + ctrl_shift_combos
        
        for combo in all_combos:
            try:
                self.root.bind_all(combo, lambda e: "break")
            except:
                pass
    
    def on_key_press(self, event):
        """处理按键事件，特别关注功能键、Alt和Ctrl"""
        # 获取当前焦点控件
        focused = self.root.focus_get()
        
        # 总是屏蔽所有功能键
        if event.keysym in ['F1', 'F2', 'F3', 'F4', 'F5', 'F6', 
                           'F7', 'F8', 'F9', 'F10', 'F11', 'F12',
                           'Alt_L', 'Alt_R', 'Control_L', 'Control_R']:
            logger.debug(f"阻止了按键: {event.keysym}")
            return "break"
            
        # 如果是Alt或Ctrl键
        if event.keysym.lower() in ['alt', 'control']:
            logger.debug(f"阻止了按键: {event.keysym}")
            return "break"
        
        # 检测Alt键状态
        alt_pressed = (event.state & 0x20000) != 0 or (event.state & 0x8) != 0
        
        # 如果Alt被按下，阻止所有按键
        if alt_pressed:
            logger.debug(f"阻止了Alt组合键: Alt+{event.keysym}")
            return "break"
        
        # 检测Control键状态
        ctrl_pressed = (event.state & 0x4) != 0
        if ctrl_pressed:
            logger.debug(f"阻止了Ctrl组合键: Ctrl+{event.keysym}")
            return "break"
            
        # 只允许在密码框内输入
        if focused == self.pw_entry:
            return None  # 允许正常处理
            
        # 阻止所有其他键盘输入
        return "break"
    
    def monitor_key_combinations(self):
        """持续监视并截获关键组合键"""
        # 关键系统组合键的虚拟键码列表
        dangerous_combinations = [
            {"keys": [162, 164, 46], "name": "Ctrl+Alt+Del"},  # Ctrl+Alt+Del
            {"keys": [162, 160, 27], "name": "Ctrl+Shift+Esc"},  # Ctrl+Shift+Esc
            {"keys": [164, 9], "name": "Alt+Tab"},  # Alt+Tab
            {"keys": [164, 115], "name": "Alt+F4"},  # Alt+F4
            {"keys": [91, 68], "name": "Win+D"},  # Win+D
            {"keys": [91, 69], "name": "Win+E"},  # Win+E
            {"keys": [91, 82], "name": "Win+R"},  # Win+R
            {"keys": [91, 76], "name": "Win+L"},  # Win+L
            {"keys": [164, 27], "name": "Alt+Esc"},  # Alt+Esc
            {"keys": [164, 32], "name": "Alt+Space"},  # Alt+Space
            {"keys": [91, 9], "name": "Win+Tab"},  # Win+Tab
            {"keys": [162, 67], "name": "Ctrl+C"},  # Ctrl+C
            {"keys": [162, 86], "name": "Ctrl+V"},  # Ctrl+V
            {"keys": [162, 65], "name": "Ctrl+A"},  # Ctrl+A
            {"keys": [162, 83], "name": "Ctrl+S"},  # Ctrl+S
            {"keys": [162, 79], "name": "Ctrl+O"},  # Ctrl+O
            {"keys": [162, 87], "name": "Ctrl+W"},  # Ctrl+W
            {"keys": [162, 116], "name": "Ctrl+F5"}  # Ctrl+F5
        ]
        
        # 添加Win+数字键的组合
        for i in range(48, 58):  # 0-9的虚拟键码
            dangerous_combinations.append({"keys": [91, i], "name": f"Win+{i-48}"})
        
        # 添加F1-F12的监控
        function_keys = []
        for i in range(112, 124):  # F1-F12的虚拟键码
            function_keys.append({"keys": [i], "name": f"F{i-111}"})
            
        # 添加Alt键和Ctrl键的监控
        modifier_keys = [
            {"keys": [164], "name": "Alt"},  # Alt
            {"keys": [165], "name": "AltGr"},  # AltGr
            {"keys": [162], "name": "Ctrl"},  # Ctrl
            {"keys": [163], "name": "RightCtrl"},  # 右Ctrl
            {"keys": [160], "name": "Shift"},  # Shift
            {"keys": [161], "name": "RightShift"},  # 右Shift
            {"keys": [91], "name": "Win"}  # Win
        ]
        
        # 合并所有需要监控的键
        all_keys = dangerous_combinations + function_keys + modifier_keys
        
        key_states = {k: False for k in range(256)}
        
        while not self.stop_flag:
            try:
                # 检查所有受监控的键
                for combo in all_keys:
                    active = True
                    for key in combo["keys"]:
                        if not (win32api.GetAsyncKeyState(key) & 0x8000):
                            active = False
                            break
                    
                    if active:
                        # 检测到按键，立即重新聚焦窗口
                        logger.debug(f"检测到按键组合: {combo['name']}")
                        self.ensure_window_focus()
                        
                        # 对于特殊组合键，可能需要额外处理
                        if "Win+L" in combo["name"]:
                            # 对于Win+L，我们需要额外阻断它，因为这个组合键会锁定系统
                            self.prevent_windows_lock()
                
                time.sleep(0.05)
            except Exception as e:
                logger.error(f"监控键盘组合键出错: {e}")
                time.sleep(0.1)
    
    def prevent_windows_lock(self):
        """尝试防止Windows锁定屏幕"""
        try:
            # 模拟按下Escape键，可能会取消某些操作
            keyboard.press_and_release('esc')
            # 立即恢复窗口
            self.ensure_window_focus()
        except Exception as e:
            logger.error(f"防止Windows锁定失败: {e}")
    
    def block_keyboard_shortcuts(self):
        """阻止常用的键盘快捷键"""
        try:
            # 钩住所有键盘按键
            keyboard.hook(self.on_key_event)
            
            # 阻止所有功能键
            for i in range(1, 13):
                keyboard.block_key(f'f{i}')
            
            # 阻止Alt和Ctrl键
            keyboard.block_key('alt')
            keyboard.block_key('ctrl')
        except Exception as e:
            logger.error(f"阻止键盘快捷键失败: {e}")
    
    def on_key_event(self, event):
        """处理键盘事件，允许在密码框中输入"""
        try:
            # 如果密码框有焦点，允许输入相关按键
            if self.input_allowed and self.pw_entry == self.root.focus_get():
                # 允许所有字母和数字
                if event.name.isalnum() and len(event.name) == 1:
                    return True
                
                # 允许特殊键如退格键、回车键
                if event.name in ['backspace', 'enter', 'return', 'shift', 'space']:
                    return True
            
            # 检测危险组合键
            if (hasattr(event, 'ctrl') and event.ctrl and 
                hasattr(event, 'alt') and event.alt and 
                event.name == 'delete'):
                # Ctrl+Alt+Del - 立即请求焦点回到我们的窗口
                logger.debug("捕获到Ctrl+Alt+Del组合键")
                self.ensure_window_focus()
                return False
            
            # 阻止Alt, Ctrl等修饰键组合
            if hasattr(event, 'alt') and event.alt:
                logger.debug(f"阻止了Alt组合键: Alt+{event.name}")
                return False
            if hasattr(event, 'ctrl') and event.ctrl:
                logger.debug(f"阻止了Ctrl组合键: Ctrl+{event.name}")
                return False
            if hasattr(event, 'windows') or event.name == 'windows':
                logger.debug(f"阻止了Windows键")
                return False
                
            # 阻止系统关键键
            if event.name in self.blocked_keys:
                logger.debug(f"阻止了系统关键键: {event.name}")
                return False
                
            # 默认阻止所有其他按键
            return False
            
        except Exception as e:
            logger.error(f"处理键盘事件错误: {e}")
            return False
    
    def monitor_mouse(self):
        """监控鼠标点击，阻止窗口外的操作"""
        while not self.stop_flag:
            try:
                # 获取窗口位置
                win_x = self.root.winfo_rootx()
                win_y = self.root.winfo_rooty()
                win_width = self.root.winfo_width()
                win_height = self.root.winfo_height()
                
                # 获取当前鼠标位置
                cursor_pos = win32gui.GetCursorPos()
                cursor_x, cursor_y = cursor_pos
                
                # 如果鼠标在窗口外部且点击，重置鼠标位置
                if (cursor_x < win_x or cursor_x > win_x + win_width or
                    cursor_y < win_y or cursor_y > win_y + win_height):
                    
                    # 如果检测到鼠标点击，将光标移回窗口内部
                    if win32api.GetAsyncKeyState(0x01) < 0 or win32api.GetAsyncKeyState(0x02) < 0:  # 鼠标左键或右键
                        center_x = win_x + win_width // 2
                        center_y = win_y + win_height // 2
                        win32api.SetCursorPos((center_x, center_y))
                
                time.sleep(0.05)  # 降低CPU使用率
            except Exception as e:
                logger.error(f"监控鼠标错误: {e}")
                time.sleep(0.1)
    
    def disable_task_manager_registry(self):
        """禁用任务管理器（需要管理员权限）"""
        try:
            # 尝试禁用Alt+Tab切换
            win32gui.SystemParametersInfo(win32con.SPI_SETFOREGROUNDLOCKTIMEOUT, 0, 1)
        except Exception as e:
            logger.error(f"禁用任务管理器失败: {e}")
    
    @log_exceptions
    def release_locks(self):
        """解除所有锁定"""
        logger.info("开始解除所有锁定")
        # 重新启用任务管理器
        if self.enable_task_manager_registry():
            logger.info("已重新启用任务管理器")
        else:
            logger.warning("重新启用任务管理器失败")
        
        # 解除键盘锁定
        try:
            keyboard.unhook_all()
            logger.info("已解除键盘锁定")
        except Exception as e:
            logger.error(f"解除键盘锁定失败: {e}")
        
        # 解除鼠标锁定
        self.stop_flag = True
        logger.info("已设置停止标志，线程将终止")
        
        # 解除系统输入锁定
        if os.name == 'nt':
            try:
                # 恢复Alt+Tab窗口切换
                win32gui.SystemParametersInfo(win32con.SPI_SETFOREGROUNDLOCKTIMEOUT, 0, 0)
                logger.info("已恢复Alt+Tab窗口切换")
            except Exception as e:
                logger.error(f"恢复Alt+Tab窗口切换失败: {e}")
        
        logger.info("===== 锁屏程序结束 =====")
    
    @log_exceptions
    def start(self):
        """启动锁屏程序"""
        logger.info("锁屏程序主循环开始")
        # 标记为已锁定
        self.locked = True
        
        # 启动焦点监视线程
        focus_thread = threading.Thread(target=self.ensure_focus, daemon=True)
        focus_thread.start()
        logger.info("焦点监视线程已启动")
        
        # 进入主循环
        try:
            self.root.mainloop()
            logger.info("Tkinter主循环结束")
        except Exception as e:
            logger.critical(f"Tkinter主循环出错: {e}\n{traceback.format_exc()}")
        
        # 程序结束时释放所有锁定
        logger.info("释放所有锁定")
        self.release_locks()
    
    @log_exceptions
    def ensure_window_focus(self):
        """强制获取和保持窗口焦点的统一方法"""
        try:
            # 强制窗口置顶
            self.root.lift()
            self.root.attributes('-topmost', True)
            self.root.update()
            
            # 确保窗口可见且全屏
            self.root.deiconify()
            self.root.attributes("-fullscreen", True)
            
            # 强制获取焦点
            self.root.focus_force()
            
            # 确保密码框获得焦点
            self.pw_entry.focus_set()
            
            # 如果是Windows系统，使用Win32API额外确保窗口为前台窗口
            if os.name == 'nt':
                hwnd = self.get_window_handle()
                if hwnd and win32gui.IsWindow(hwnd):
                    # 如果不是当前前台窗口，设置为前台窗口
                    if win32gui.GetForegroundWindow() != hwnd:
                        win32gui.SetForegroundWindow(hwnd)
                        
            return True
        except Exception as e:
            logger.error(f"获取窗口焦点失败: {e}")
            return False

    def keep_on_top(self):
        """定期保持窗口置顶"""
        if self.locked and not self.stop_flag:
            # 使用统一的焦点管理方法
            self.ensure_window_focus()
            
            # 每隔100毫秒调用一次
            self.root.after(100, self.keep_on_top)
    
    @log_exceptions
    def ensure_focus(self):
        """确保窗口保持焦点"""
        while not self.stop_flag:
            try:
                # 使用统一的焦点管理方法
                self.ensure_window_focus()
                
                time.sleep(0.2)
            except Exception as e:
                logger.error(f"焦点监视线程错误: {e}")
                time.sleep(0.5)

    @log_exceptions
    def monitor_window_visibility(self):
        """监视窗口是否被隐藏，如果是则立即恢复"""
        try:
            logger.info("启动窗口可见性监控")
            while not self.stop_flag:
                try:
                    # 检查窗口是否可见
                    hwnd = self.get_window_handle()
                    if hwnd:
                        # 如果窗口不可见或最小化
                        if not win32gui.IsWindowVisible(hwnd) or win32gui.IsIconic(hwnd):
                            # 恢复窗口
                            logger.warning("检测到窗口被隐藏，正在恢复")
                            self.ensure_window_focus()
                
                    # 杀死任务管理器等系统进程
                    self.kill_system_processes()
                    
                    # 动态调整扫描频率 - 起初快速扫描
                    scan_interval = 0.1
                    # 每10秒后逐渐减慢至0.5秒，减少CPU使用率
                    if hasattr(self, 'start_time') and time.time() - self.start_time > 10:
                        scan_interval = 0.5
                    
                    time.sleep(scan_interval)
                except Exception as e:
                    logger.error(f"窗口可见性监控循环出错: {e}")
                    time.sleep(0.2)
        except Exception as e:
            logger.critical(f"窗口可见性监控线程崩溃: {e}\n{traceback.format_exc()}")

    @log_exceptions
    def on_all_keys(self, event):
        """处理所有键盘事件，确保特殊键被阻止"""
        try:
            # 记录特殊键的键盘事件
            if event.keysym in ['Alt_L', 'Alt_R', 'Control_L', 'Control_R', 'F4'] or event.keysym.startswith('F'):
                logger.debug(f"键盘事件: {event.keysym} (状态: {event.state})")
            
            # 阻止所有修饰键
            if event.keysym in ['Alt_L', 'Alt_R', 'Control_L', 'Control_R', 
                            'Shift_L', 'Shift_R', 'Win_L', 'Win_R']:
                return "break"
                
            # 阻止所有功能键
            if event.keysym.startswith('F') and len(event.keysym) <= 3:
                try:
                    key_num = int(event.keysym[1:])
                    if 1 <= key_num <= 12:  # F1-F12
                        return "break"
                except ValueError:
                    pass
                    
            # 检查Alt键状态
            alt_pressed = event.state & 0x8 != 0 or event.state & 0x80 != 0
            
            # 检查Ctrl键状态
            ctrl_pressed = event.state & 0x4 != 0
            
            # 如果是输入框有焦点且不是修饰键组合，允许输入
            if self.pw_entry == self.root.focus_get():
                if not (alt_pressed or ctrl_pressed):
                    if event.char.isalnum() or event.keysym in ["BackSpace", "Return", "space"]:
                        return None  # 允许输入
            
            # 阻止所有其他按键
            return "break"
            
        except Exception as e:
            logger.error(f"处理所有键盘事件错误: {e}")
            return "break"

    @log_exceptions
    def save_password(self, new_password):
        """保存新密码到配置文件"""
        try:
            config = configparser.ConfigParser()
            
            # 如果文件存在，先读取现有配置
            if os.path.exists(self.config_file):
                config.read(self.config_file, encoding='utf-8')
                
            # 确保Security部分存在
            if 'Security' not in config:
                config['Security'] = {}
                
            # 更新密码
            config['Security']['Password'] = new_password
            
            # 写入配置文件，使用UTF-8编码
            with open(self.config_file, 'w', encoding='utf-8') as f:
                config.write(f)
                
            # 更新当前密码
            self.password = new_password
            
            return True
        except Exception as e:
            logger.error(f"保存密码错误: {e}\n{traceback.format_exc()}")
            return False

    @log_exceptions
    def load_password(self):
        """从配置文件加载密码"""
        # 默认密码
        default_password = "123456"
        
        # 如果配置文件不存在，创建它
        if not os.path.exists(self.config_file):
            logger.info(f"配置文件 {self.config_file} 不存在，创建默认配置")
            self.create_default_config(default_password)
            return default_password
            
        # 读取配置文件
        try:
            config = configparser.ConfigParser()
            # 使用UTF-8编码读取配置文件，避免中文编码问题
            config.read(self.config_file, encoding='utf-8')
            
            # 获取密码
            if 'Security' in config and 'Password' in config['Security']:
                password = config['Security']['Password']
                # 如果密码为空，使用默认密码
                if not password.strip():
                    logger.warning("配置中的密码为空，使用默认密码")
                    return default_password
                logger.info("成功从配置文件加载密码")
                return password
            else:
                # 如果节或密码键不存在，创建默认配置
                logger.warning("配置文件缺少 [Security] 部分或 Password 设置，创建默认配置")
                self.create_default_config(default_password)
                return default_password
                
        except Exception as e:
            logger.error(f"读取配置文件错误: {e}\n{traceback.format_exc()}")
            # 出错时使用默认密码
            return default_password
    
    @log_exceptions
    def create_default_config(self, default_password):
        """创建默认配置文件"""
        try:
            config = configparser.ConfigParser()
            
            # 安全设置
            config['Security'] = {
                'Password': default_password,
                'AllowVirtualKeyboard': 'yes',
                'KillDangerousProcesses': 'yes',
                'EnableLogging': 'yes'
            }
            
            # UI设置
            config['UI'] = {
                'BackgroundColor': '#2c3e50',
                'TextColor': 'white',
                'ButtonColor': '#3498db'
            }
            
            # 写入配置文件，使用UTF-8编码
            with open(self.config_file, 'w', encoding='utf-8') as f:
                config.write(f)
                
            logger.info(f"已创建默认配置文件: {self.config_file}")
        except Exception as e:
            logger.error(f"创建配置文件错误: {e}\n{traceback.format_exc()}")

if __name__ == "__main__":
    try:
        # 检查是否以管理员权限运行
        if os.name == 'nt':
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if not is_admin:
                    logger.warning("警告: 程序未以管理员权限运行，某些锁定功能可能受限")
                    print("警告: 程序未以管理员权限运行，某些锁定功能可能受限")
                    print("建议: 以管理员身份运行此程序以获得完全锁定功能")
            except Exception as e:
                logger.error(f"检查管理员权限失败: {e}")
        
        # 启动锁屏
        lock = LockScreen(config_file=CONFIG_FILE)  # 使用配置文件
        lock.start()
    except Exception as e:
        logger.critical(f"程序启动失败: {e}\n{traceback.format_exc()}")
        print(f"程序启动失败: {e}")
        print("错误详情已记录到日志文件中")
        input("按回车键退出...") 