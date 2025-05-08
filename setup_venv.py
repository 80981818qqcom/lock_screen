import os
import subprocess
import sys
import platform

def create_virtual_environment():
    """创建并配置锁屏程序的虚拟环境"""
    
    venv_name = "lockscreen_venv"
    print(f"正在创建虚拟环境: {venv_name}...")
    
    # 检查系统类型
    system = platform.system()
    is_windows = system == "Windows"
    
    # 创建虚拟环境
    try:
        subprocess.run([sys.executable, "-m", "venv", venv_name], check=True)
        print(f"✓ 虚拟环境创建成功")
    except subprocess.CalledProcessError:
        print("× 创建虚拟环境失败")
        return False
    
    # 确定激活脚本路径和pip路径
    if is_windows:
        activate_script = os.path.join(venv_name, "Scripts", "activate.bat")
        pip_path = os.path.join(venv_name, "Scripts", "pip.exe")
    else:
        activate_script = os.path.join(venv_name, "bin", "activate")
        pip_path = os.path.join(venv_name, "bin", "pip")
    
    # 升级pip
    print("正在升级pip...")
    if is_windows:
        subprocess.run(f"{pip_path} install --upgrade pip", shell=True)
    else:
        subprocess.run(f". {activate_script} && pip install --upgrade pip", shell=True)
    
    # 安装依赖
    print("正在安装依赖...")
    if is_windows:
        subprocess.run(f"{pip_path} install -r requirements.txt", shell=True)
    else:
        subprocess.run(f". {activate_script} && pip install -r requirements.txt", shell=True)
    
    print("\n虚拟环境设置完成!")
    print(f"\n要激活虚拟环境，请运行:")
    
    if is_windows:
        print(f"{venv_name}\\Scripts\\activate")
        # 创建启动脚本
        with open("run_lockscreen.bat", "w", encoding="utf-8") as f:
            f.write(f"@echo off\n")
            f.write(f"chcp 65001 > nul\n")
            f.write(f"call {venv_name}\\Scripts\\activate\n")
            f.write(f"python lock_screen.py\n")
            f.write(f"deactivate\n")
        print("已创建快速启动脚本: run_lockscreen.bat")
    else:
        print(f"source {venv_name}/bin/activate")
        # 创建启动脚本
        with open("run_lockscreen.sh", "w") as f:
            f.write("#!/bin/bash\n")
            f.write(f"source {venv_name}/bin/activate\n")
            f.write("python lock_screen.py\n")
            f.write("deactivate\n")
        os.chmod("run_lockscreen.sh", 0o755)
        print("已创建快速启动脚本: run_lockscreen.sh")
    
    return True

if __name__ == "__main__":
    # 检查Python版本
    py_version = sys.version_info
    if py_version.major < 3 or (py_version.major == 3 and py_version.minor < 6):
        print("错误: 需要Python 3.6或更高版本")
        sys.exit(1)
    
    # 检查requirements.txt是否存在
    if not os.path.exists("requirements.txt"):
        print("错误: 未找到requirements.txt文件")
        sys.exit(1)
    
    # 检查lock_screen.py是否存在
    if not os.path.exists("lock_screen.py"):
        print("错误: 未找到lock_screen.py文件")
        sys.exit(1)
    
    # 创建虚拟环境
    create_virtual_environment() 