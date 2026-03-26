#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
四川大学URP课程容量查询工具 (独立版)
SCU URP Course Capacity Query Tool (Standalone)

功能：查询四川大学URP教务系统中各课程的容量信息
作者：基于 SCU-URP-Helper 项目改编
版本：1.0.0
"""

import requests
import json
import os
import sys
import hashlib
import argparse
from datetime import datetime

# ============ 配置常量 ============

# URP系统URL
LOGIN_URL = "http://zhjw.scu.edu.cn/login"
SECURITY_CHECK_URL = "http://zhjw.scu.edu.cn/j_spring_security_check"
CAPTCHA_URL = "http://zhjw.scu.edu.cn/img/captcha.jpg"
COURSE_SELECT_URL = "http://zhjw.scu.edu.cn/student/courseSelect/courseSelect/index"
FREE_COURSE_SELECT_URL = "http://zhjw.scu.edu.cn/student/courseSelect/freeCourse/courseList"

# HTTP请求头
HTTP_HEAD = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 "
                  "Safari/537.36 Edg/105.0.1343.33"
}

# 查询课程数据的模板
QUERY_CLASS_DATA = {
    "kkxsh": "",
    "kch": "",
    "kcm": "",
    "skjs": "",
    "kclbdm": "",
    "xq": "0",
    "jc": "0"
}


# ============ 日志工具 ============

def print_log(message: str, level: str = "INFO") -> None:
    """
    打印格式化日志，带时间戳和级别标记
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lvl = (level or "INFO").upper()
    if lvl not in {"SUCCESS", "INFO", "DEBUG", "ERROR"}:
        lvl = "INFO"
    prefix = {
        "SUCCESS": "[+]",
        "INFO": "[*]",
        "ERROR": "[!]",
        "DEBUG": "[DEBUG]"
    }.get(lvl, "[*]")
    print(f"[{ts}]{prefix} {message}")


# ============ 配置管理 ============

def get_config_path() -> str:
    """
    获取配置文件路径
    """
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    
    return os.path.join(base_path, "config.json")


def load_config(path: str) -> dict:
    """
    从指定路径加载JSON配置
    """
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"配置文件不存在: {path}\n"
            "请复制 config.json.example 为 config.json 并填写相关信息。"
        )
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ============ 加密工具 ============

def encrypt_password(content: str) -> str:
    """
    使用URP系统的双重MD5加密密码
    """
    magic_str = "{Urp602019}"
    res1 = hashlib.md5((content + magic_str).encode()).hexdigest()
    res1 = hashlib.md5(res1.encode()).hexdigest()
    res2 = hashlib.md5(content.encode()).hexdigest()
    res2 = hashlib.md5(res2.encode()).hexdigest()
    return res1 + "*" + res2


# ============ 登录模块 ============

def user_login(session: requests.Session, username: str, password: str) -> requests.Session:
    """
    使用配置的凭据登录URP系统
    """
    try:
        import ddddocr
    except ImportError:
        print_log("错误：缺少 ddddocr 模块，请运行: pip install ddddocr", "ERROR")
        sys.exit(1)
    
    ocr = ddddocr.DdddOcr()
    login_attempts = 0
    max_attempts = 100
    
    while login_attempts < max_attempts:
        # 获取登录页面
        res = session.get(LOGIN_URL, headers=HTTP_HEAD)
        if res.status_code != 200:
            print_log("获取登录页面失败", "ERROR")
            login_attempts += 1
            continue
        
        # 提取token
        token_pos = res.text.find("tokenValue")
        if token_pos == -1:
            print_log("无法找到token，页面可能已更改", "ERROR")
            sys.exit(1)
        token = res.text[token_pos + 37: token_pos + 69]
        
        # 加密密码
        encrypted_pw = encrypt_password(password)
        
        # 获取验证码
        captcha_resp = session.get(CAPTCHA_URL, headers=HTTP_HEAD)
        captcha_code = ocr.classification(captcha_resp.content)
        
        # 准备登录数据
        login_data = {
            "lang": "zh",
            "tokenValue": token,
            "j_username": username,
            "j_password": encrypted_pw,
            "j_captcha": captcha_code
        }
        
        # 提交登录
        res = session.post(SECURITY_CHECK_URL, data=login_data, headers=HTTP_HEAD)
        
        if res.text.find('验证码错误') != -1:
            print_log("验证码不正确，正在重试...", "INFO")
            login_attempts += 1
            continue
        elif res.text.find('token校验失败') != -1:
            print_log("token校验失败", "ERROR")
            sys.exit(1)
        elif res.text.find('用户名或密码错误!') == -1:
            print_log("登录成功！", "SUCCESS")
            return session
        else:
            print_log("账号或密码错误", "ERROR")
            sys.exit(1)
    
    print_log("登录尝试次数过多", "ERROR")
    sys.exit(1)


# ============ 课程查询模块 ============

def sanitize_text(value: str) -> str:
    """
    标准化文本输入，去除无法编码为UTF-8的字符
    """
    if not isinstance(value, str):
        return str(value) if value else ""
    cleaned = value.encode("utf-8", "ignore").decode("utf-8", "ignore")
    return cleaned


def query_course_capacity(session: requests.Session, keyword: str) -> list:
    """
    根据课程名称关键词查询课程列表及其容量信息
    
    返回:
        课程列表，每个课程包含容量信息
    """
    class_list = []
    clean_keyword = sanitize_text(keyword)
    
    if not clean_keyword.strip():
        print_log("课程关键词为空，跳过查询。", "ERROR")
        return []
    
    # 复制查询模板并设置课程名
    local_query = QUERY_CLASS_DATA.copy()
    local_query['kcm'] = clean_keyword
    
    # 首先访问选课页面获取会话
    res = session.get(COURSE_SELECT_URL, headers=HTTP_HEAD)
    if res.status_code != 200 or res.text.find("自由选课") == -1:
        print_log("进入选课页面失败！网络错误或登录已过期。", "ERROR")
        return []
    
    print_log("成功进入选课页面，正在查询课程列表...", "SUCCESS")
    
    # 发送课程查询请求
    res_post = session.post(
        FREE_COURSE_SELECT_URL,
        data=local_query,
        headers=HTTP_HEAD
    )
    
    if res_post.status_code != 200:
        print_log(f"获取课程列表失败，状态码: {res_post.status_code}", "ERROR")
        return []
    
    raw_text = res_post.text or ""
    if not raw_text.strip():
        print_log("课程列表响应为空，可能网络异常或登录过期。", "ERROR")
        return []
    
    # 解析JSON响应
    try:
        res_json = json.loads(raw_text)
    except json.JSONDecodeError:
        snippet = raw_text.strip()[:200]
        print_log("课程列表响应不是有效的JSON格式。", "ERROR")
        print_log(f"响应片段: {snippet}", "DEBUG")
        return []
    
    if not isinstance(res_json, dict):
        print_log("课程列表响应格式异常，无法解析。", "ERROR")
        return []
    
    if "rwRxkZlList" not in res_json:
        print_log("课程列表响应缺少 rwRxkZlList 字段。", "ERROR")
        return []
    
    # 解析课程列表
    rw_rxk_zl_list = res_json['rwRxkZlList']
    if isinstance(rw_rxk_zl_list, str):
        try:
            class_list = json.loads(rw_rxk_zl_list)
        except json.JSONDecodeError:
            print_log("课程列表字段解析失败。", "ERROR")
            return []
    elif isinstance(rw_rxk_zl_list, list):
        class_list = rw_rxk_zl_list
    else:
        print_log("课程列表数据类型错误。", "ERROR")
        return []
    
    return class_list


def display_course_capacity(courses: list) -> None:
    """
    格式化显示课程容量信息，包括课容量和课余量
    """
    if not courses:
        print_log("未找到相关课程。", "INFO")
        return
    
    print("\n" + "=" * 110)
    print(f"{'序号':<6}{'课程号':<12}{'课序号':<8}{'课程名称':<26}{'教师':<10}{'课容量':<8}{'课余量':<8}{'已选':<6}")
    print("-" * 110)
    
    for idx, course in enumerate(courses, 1):
        # 获取课程基本信息
        course_id = course.get('kch') or ''
        seq_num = course.get('kxh') or ''
        name = course.get('kcm') or ''
        teacher = course.get('skjs') or ''
        
        # 获取容量信息
        # bkskrl: 本科生课容量（总人数）
        # bkskyl: 本科生课余量（剩余名额）
        total_capacity = course.get('bkskrl')
        remaining = course.get('bkskyl')
        
        # 处理容量数据，确保显示为数字
        if total_capacity is None:
            total_capacity = 0
        else:
            try:
                total_capacity = int(total_capacity)
            except (ValueError, TypeError):
                total_capacity = 0
        
        if remaining is None:
            remaining = 0
        else:
            try:
                remaining = int(remaining)
            except (ValueError, TypeError):
                remaining = 0
        
        # 计算已选人数
        selected = total_capacity - remaining
        
        # 截断过长的文本
        name = name[:24] if len(name) > 24 else name
        teacher = teacher[:8] if len(teacher) > 8 else teacher
        
        # 格式化输出
        print(f"{idx:<6}{course_id:<12}{seq_num:<8}{name:<26}{teacher:<10}"
              f"{total_capacity:<8}{remaining:<8}{selected:<6}")
    
    print("=" * 110)
    print_log(f"共找到 {len(courses)} 门课程", "SUCCESS")


def display_course_detail(course: dict) -> None:
    """
    显示单门课程的详细信息
    """
    print("\n" + "-" * 60)
    print(f"课程名称: {course.get('kcm', 'N/A')}")
    print(f"课程号: {course.get('kch', 'N/A')}")
    print(f"课序号: {course.get('kxh', 'N/A')}")
    print(f"教师: {course.get('skjs', 'N/A')}")
    print(f"学分: {course.get('xf', 'N/A')}")
    print(f"学时: {course.get('xs', 'N/A')}")
    print(f"课容量: {course.get('bkskrl', 'N/A')}")
    print(f"课余量: {course.get('bkskyl', 'N/A')}")
    print(f"校区: {course.get('kkxqm', 'N/A')}")
    print(f"教学楼: {course.get('jxlm', 'N/A')}")
    print(f"教室: {course.get('jasm', 'N/A')}")
    print(f"上课周次: {course.get('zcsm', 'N/A')}")
    print(f"课程类别: {course.get('kclbmc', 'N/A')}")
    print("-" * 60)


# ============ 主程序 ============

def interactive_mode(session: requests.Session):
    """
    交互式查询模式
    """
    print()
    print_log("=" * 50, "INFO")
    print_log("进入交互式查询模式", "INFO")
    print_log("命令: [关键词] 查询课程 | [d+序号] 查看详情 | [q] 退出", "INFO")
    print_log("=" * 50, "INFO")
    
    last_courses = []
    
    while True:
        print()
        user_input = input("请输入命令: ").strip()
        
        if not user_input:
            continue
        
        if user_input.lower() == 'q':
            print_log("感谢使用，再见！", "INFO")
            break
        
        # 查看详情命令
        if user_input.lower().startswith('d') and len(user_input) > 1:
            try:
                idx = int(user_input[1:]) - 1
                if 0 <= idx < len(last_courses):
                    display_course_detail(last_courses[idx])
                else:
                    print_log("无效的序号", "ERROR")
            except ValueError:
                print_log("无效的命令格式", "ERROR")
            continue
        
        # 查询课程
        print_log(f"正在查询: '{user_input}' ...", "INFO")
        courses = query_course_capacity(session, user_input)
        last_courses = courses
        display_course_capacity(courses)
        
        if courses:
            print_log("提示: 输入 d+序号 (如 d1) 查看课程详情", "INFO")


def main():
    """
    主函数
    """
    parser = argparse.ArgumentParser(
        description='四川大学URP课程容量查询工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  python course_capacity_query.py              # 交互式模式
  python course_capacity_query.py -k "高等数学" # 直接查询指定关键词
  python course_capacity_query.py --keyword "英语"

交互模式命令:
  [关键词]    查询课程
  d+序号      查看课程详情 (如 d1)
  q           退出程序
        '''
    )
    
    parser.add_argument(
        '-k', '--keyword',
        type=str,
        help='课程名称关键词（不指定则进入交互式模式）'
    )
    
    args = parser.parse_args()
    
    # 显示欢迎信息
    print_log("=" * 60, "INFO")
    print_log("四川大学URP课程容量查询工具", "INFO")
    print_log("=" * 60, "INFO")
    
    # 加载配置
    config_path = get_config_path()
    try:
        config = load_config(config_path)
    except FileNotFoundError as e:
        print_log(str(e), "ERROR")
        sys.exit(1)
    
    username = config.get("username", "").strip()
    password = config.get("password", "").strip()
    
    if not username or not password:
        print_log("错误：请在 config.json 中配置用户名和密码。", "ERROR")
        sys.exit(1)
    
    print_log(f"使用账号: {username}", "INFO")
    print_log("正在登录URP系统...", "INFO")
    
    # 创建会话并登录
    session = requests.Session()
    session = user_login(session, username, password)
    
    if args.keyword:
        # 直接查询模式
        print_log(f"正在查询关键词: '{args.keyword}' ...", "INFO")
        courses = query_course_capacity(session, args.keyword)
        display_course_capacity(courses)
    else:
        # 交互式模式
        interactive_mode(session)


if __name__ == "__main__":
    main()
