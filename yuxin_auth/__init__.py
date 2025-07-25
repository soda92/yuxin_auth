"""
认证与登录模块。

该模块负责处理与外部系统的用户认证流程。它包含以下主要功能：
- 针对需要图形验证码的系统，实现了自动识别和登录重试机制（LoginSystem类）。
- 针对基于Spring Security的系统，实现了模拟表单提交以获取会话Cookie。
- 提供了统一的接口函数，供其他模块调用以获取登录凭据（cookies, tokens等）。
"""
import re
import time
import requests
import hashlib
import ddddocr

def silent_ddddocr():
    return ddddocr.DdddOcr(show_ad=False)


class LoginSystem:
    """
    处理需要验证码的登录系统。
    通过自动识别验证码并重试，实现自动化登录。
    """
    def __init__(self, user):
        """
        初始化登录系统。

        Args:
            user (list or tuple): 包含登录信息，格式为 [url, username, password]。
        """
        url = user[0]
        username = user[1]
        password = user[2]

        # 对密码进行MD5加密
        password_md5 = hashlib.md5(password.encode()).hexdigest()

        self.session = requests.Session()  # 使用Session保持登录状态
        self.ocr = silent_ddddocr()  # 初始化验证码识别器
        self.max_retries = 10000  # 最大登录重试次数
        self.retry_interval = 3  # 每次重试的间隔时间（秒）
        self.login_url = url

        # 构造登录所需的表单数据
        self.credentials = {
            'orgCode': '08',
            'navigation': 'isNotNavigation',
            'phisname': username,
            'password': password_md5,
        }

    def _get_verify_code(self):
        """
        从服务器获取并使用OCR识别验证码。

        Returns:
            str: 识别出的验证码字符串，如果失败则返回None。
        """
        timestamp = int(time.time() * 1000)
        try:
            response = self.session.get(f"{self.login_url}/voCode?t={timestamp}",
                                        verify=False, timeout=10)
            response.raise_for_status()  # 确保请求成功
            return self.ocr.classification(response.content)
        except requests.RequestException as e:
            print(f"获取验证码失败: {e}")
            return None

    def _try_login(self, verify_code):
        """
        使用给定的验证码尝试登录。

        Args:
            verify_code (str): 识别出的验证码。

        Returns:
            requests.Response: 服务器的响应对象，如果请求失败则返回None。
        """
        data = {**self.credentials, 'verifyCode': verify_code}
        try:
            return self.session.post(self.login_url, data=data,
                                     verify=False, timeout=15)
        except requests.RequestException as e:
            print(f"登录请求失败: {e}")
            return None

    def auto_login(self):
        """
        执行全自动登录流程。
        循环尝试获取验证码、登录，直到成功或达到最大重试次数。

        Returns:
            tuple: 成功时返回 (cookies_dict, org_code)，失败时返回 (None, None)。
        """
        for attempt in range(1, self.max_retries + 1):
            print(f"正在进行第 {attempt} 次登录尝试...")
            verify_code = self._get_verify_code()
            if not verify_code:
                time.sleep(self.retry_interval)
                continue

            response = self._try_login(verify_code)
            if not response:
                time.sleep(self.retry_interval)
                continue

            # 检查响应文本中是否包含 "健康档案" 作为登录成功的标志
            if "健康档案" in response.text:
                # 使用正则表达式从返回的HTML中提取 'orgCode'
                pattern = r'var user\s*=\s*\{.*?orgCode\s*:\s*\'(.*?)\'.*?\}'
                match = re.search(pattern, response.text, re.DOTALL)
                if match:
                    org_code = match.group(1)
                    print("登录成功！")
                    return self.session.cookies.get_dict(), org_code
                else:
                    print("登录成功，但无法提取 orgCode。")
                    # 即使无法提取orgCode，也可能需要返回cookie
                    return self.session.cookies.get_dict(), None

            print("登录失败，验证码错误或响应无效。")
            time.sleep(self.retry_interval)

        print(f"超过最大重试次数 {self.max_retries}，登录失败。")
        return None, None


def get_login_cookies(user):
    """
    外部接口：获取第一个系统的登录Cookie和机构代码。

    Args:
        user (list or tuple): 包含登录信息 [url, username, password]。

    Returns:
        tuple: (cookies_dict, org_code)，其中 org_code 已添加 '%' 后缀。
    """
    login_system = LoginSystem(user)
    cookies, org_code = login_system.auto_login()
    if org_code:
        org_code += "%"  # 根据业务需求添加后缀
    return cookies, org_code


def get_cookie2(user):
    """
    为第二个系统（基于Spring Security）进行登录并获取JSESSIONID。

    Args:
        user (list or tuple): 包含登录信息，使用索引 [3], [4], [5] 分别代表 url, username, password。

    Returns:
        str: 成功时返回 JSESSIONID，失败时返回 None。
    """
    base_url = user[3]
    username = user[4]
    password = user[5]

    login_url = f'{base_url}j_spring_security_check'
    session = requests.Session()

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    }

    # 对密码进行 MD5 加密
    password_md5 = hashlib.md5(password.encode()).hexdigest()

    login_data = {
        'j_username': username,
        'j_password': password_md5
    }

    try:
        # 发送登录请求，禁止自动重定向以便检查响应头
        response = session.post(
            login_url,
            data=login_data,
            headers=headers,
            verify=False,
            allow_redirects=False, # 关键：禁止自动跳转以捕获302状态
            timeout=15
        )

        # 检查响应状态码是否为302，并且重定向地址是否包含 'desktop.jsp'
        if response.status_code == 302 and 'desktop.jsp' in response.headers.get('Location', ''):
            print("第二个系统登录成功。")
            return session.cookies.get('JSESSIONID')
        else:
            print(f"第二个系统登录失败。状态码: {response.status_code}, Location: {response.headers.get('Location')}")
            return None
    except requests.RequestException as e:
        print(f"第二个系统登录请求异常: {e}")
        return None

